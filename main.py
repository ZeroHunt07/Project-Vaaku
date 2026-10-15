#!/usr/bin/env python3
"""
main.py — Transparent, consent-based endpoint audit agent + TUI viewer.

Usage:
    python main.py init
    python main.py agent [--config config.json]
    python main.py tui   [--db audit.db]

System deps:
    sudo apt install -y xdotool wmctrl                          # Kali / Debian
Python deps:
    pip install "pywinctl[linux]" pystray Pillow watchdog psutil \
                opencv-python textual pynput evdev
GNOME extensions (Wayland):
    - Focused Window D-Bus  (id 5592)
    - Window Calls          (id 4724)

Typing pulse on Wayland requires input-group membership:
    sudo usermod -aG input $USER
    # then log out and back in
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import psutil

try:
    import pywinctl as pwc
except ImportError:
    pwc = None


# ===========================================================================
# PART 1 — AGENT
# ===========================================================================

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


class AuditAgent:
    def __init__(self, config_path: str):
        self.config = load_config(config_path)
        self.db_path = Path(self.config["db_path"]).expanduser()
        self.snapshot_dir = Path(self.config["snapshot_dir"]).expanduser()
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

        self.logging_active = True
        self.running = True
        self.session_id = None
        self.db_lock = threading.Lock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")

        self.observer = None
        self.web_server = None
        self.icon = None
        self.face_lock_hotkey_listener = None
        self._logged_errors = set()
        self._window_backend_errors = {}

        self._last_window = None
        self._last_window_lock = threading.Lock()
        self._file_debounce = {}
        self._file_debounce_lock = threading.Lock()

        self.face_lock_config = self.config.get("face_lock", {})
        self.face_lock_active = bool(self.face_lock_config.get("enabled", False))
        self.face_watcher = None

        self.init_db()
        self.start_session()
        self.cleanup()

    def init_db(self):
        schema = """
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            boot_id REAL,
            user TEXT,
            start_time TEXT,
            end_time TEXT,
            ip TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            ts TEXT,
            type TEXT,
            source TEXT,
            details TEXT
        );
        CREATE TABLE IF NOT EXISTS file_access (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            path TEXT,
            process TEXT,
            user TEXT,
            action TEXT
        );
        CREATE TABLE IF NOT EXISTS web_visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            browser TEXT,
            url TEXT,
            domain TEXT,
            title TEXT
        );
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            ts TEXT,
            path TEXT,
            consent INTEGER
        );
        CREATE TABLE IF NOT EXISTS window_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            window_id TEXT,
            app TEXT,
            title TEXT,
            pid INTEGER,
            start_ts TEXT,
            end_ts TEXT
        );
        CREATE TABLE IF NOT EXISTS form_submits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            url TEXT,
            domain TEXT,
            form_action TEXT,
            field_names TEXT
        );
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            event_id INTEGER,
            ts TEXT,
            pid INTEGER,
            ppid INTEGER,
            name TEXT,
            cmdline TEXT,
            cwd TEXT,
            user TEXT
        );
        CREATE TABLE IF NOT EXISTS web_downloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            event_id INTEGER,
            ts TEXT,
            browser TEXT,
            url TEXT,
            filename TEXT,
            file_size INTEGER,
            mime TEXT,
            state TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
        CREATE INDEX IF NOT EXISTS idx_events_sid ON events(session_id);
        CREATE INDEX IF NOT EXISTS idx_files_path ON file_access(path);
        CREATE INDEX IF NOT EXISTS idx_web_domain ON web_visits(domain);
        CREATE INDEX IF NOT EXISTS idx_wact_sid ON window_activity(session_id);
        CREATE INDEX IF NOT EXISTS idx_cmds_sid ON commands(session_id);
        CREATE INDEX IF NOT EXISTS idx_cmds_name ON commands(name);
        CREATE INDEX IF NOT EXISTS idx_cmds_ts ON commands(ts);
        CREATE INDEX IF NOT EXISTS idx_downloads_sid ON web_downloads(session_id);
        """
        with self.db_lock:
            self.conn.executescript(schema)
            self.conn.commit()

    def start_session(self):
        boot_id = psutil.boot_time()
        user = getpass.getuser()
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = None
        cur = self.conn.execute(
            "INSERT INTO sessions(boot_id, user, start_time, ip) VALUES (?,?,?,?)",
            (boot_id, user, datetime.datetime.now().isoformat(), ip),
        )
        self.session_id = cur.lastrowid
        self.conn.commit()
        self.log_event("session_start", "agent",
                       {"boot_id": boot_id, "user": user, "ip": ip})

    def cleanup(self):
        days = self.config.get("retention_days", 30)
        cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat()
        with self.db_lock:
            self.conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            self.conn.execute(
                "DELETE FROM file_access WHERE event_id NOT IN (SELECT id FROM events)")
            self.conn.execute(
                "DELETE FROM web_visits WHERE event_id NOT IN (SELECT id FROM events)")
            self.conn.execute("DELETE FROM snapshots WHERE ts < ?", (cutoff,))
            self.conn.execute(
                "DELETE FROM window_activity WHERE start_ts < ?", (cutoff,))
            self.conn.execute(
                "DELETE FROM form_submits WHERE event_id NOT IN (SELECT id FROM events)")
            self.conn.execute(
                "DELETE FROM commands WHERE event_id NOT IN (SELECT id FROM events)")
            self.conn.execute(
                "DELETE FROM web_downloads WHERE event_id NOT IN (SELECT id FROM events)")
            self.conn.commit()

    def log_event(self, type_, source, details):
        if not self.logging_active and type_ not in (
                "session_end", "session_start", "status",
                "window_debug", "window_error"):
            return None
        ts = datetime.datetime.now().isoformat()
        with self.db_lock:
            cur = self.conn.execute(
                "INSERT INTO events(session_id, ts, type, source, details) "
                "VALUES (?,?,?,?,?)",
                (self.session_id, ts, type_, source, json.dumps(details)),
            )
            self.conn.commit()
            return cur.lastrowid

    def log_error_once(self, tag, details):
        if tag in self._logged_errors:
            return
        self._logged_errors.add(tag)
        self.log_event("window_error", "poller", {"tag": tag, **details})

    def _cache_window(self, info):
        if info:
            with self._last_window_lock:
                self._last_window = dict(info)

    def _get_cached_window(self):
        with self._last_window_lock:
            return dict(self._last_window) if self._last_window else {}

    def log_file_event(self, path, action):
        if not self.logging_active:
            return
        if str(self.db_path) in path or str(self.snapshot_dir) in path:
            return
        win = self._get_cached_window()
        event_id = self.log_event("file", "watchdog",
                                  {"path": path, "action": action,
                                   "window": win})
        if event_id:
            with self.db_lock:
                self.conn.execute(
                    "INSERT INTO file_access(event_id, path, process, user, action) "
                    "VALUES (?,?,?,?,?)",
                    (event_id, path, win.get("app"), None, action),
                )
                self.conn.commit()

    def log_web_visit(self, url, title, browser=None):
        if not self.logging_active:
            return
        domain = urlparse(url).netloc
        win = self._get_cached_window()
        event_id = self.log_event("web", "extension",
                                  {"url": url, "title": title,
                                   "browser": browser, "window": win})
        if event_id:
            with self.db_lock:
                self.conn.execute(
                    "INSERT INTO web_visits(event_id, browser, url, domain, title) "
                    "VALUES (?,?,?,?,?)",
                    (event_id, browser, url, domain, title),
                )
                self.conn.commit()

    def log_form_submit(self, url, title, action, fields, browser=None):
        if not self.logging_active:
            return
        domain = urlparse(url).netloc
        win = self._get_cached_window()
        fields = fields or []
        event_id = self.log_event("form_submit", "extension", {
            "url": url,
            "title": title,
            "browser": browser,
            "form_action": action,
            "field_names": fields,
            "window": win,
        })
        if event_id:
            with self.db_lock:
                self.conn.execute(
                    "INSERT INTO form_submits(event_id, url, domain, "
                    "form_action, field_names) VALUES (?,?,?,?,?)",
                    (event_id, url, domain, action, ",".join(fields)),
                )
                self.conn.commit()

    def log_download(self, url, filename, file_size, mime, state, browser=None):
        if not self.logging_active:
            return
        details = {
            "url": url,
            "filename": filename,
            "file_size": file_size,
            "mime": mime,
            "state": state,
            "browser": browser,
        }
        event_id = self.log_event("download", "extension", details)
        if event_id:
            with self.db_lock:
                self.conn.execute(
                    "INSERT INTO web_downloads(event_id, session_id, ts, browser, url, filename, file_size, mime, state) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (event_id, self.session_id, datetime.datetime.now().isoformat(),
                     browser, url, filename, file_size, mime, state),
                )
                self.conn.commit()

    def log_command(self, pid, ppid, name, cmdline, cwd, user):
        if not self.logging_active:
            return
        details = {
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "cmdline": cmdline,
            "cwd": cwd,
            "user": user,
        }
        event_id = self.log_event("command", "user_command", details)
        if event_id:
            with self.db_lock:
                self.conn.execute(
                    "INSERT INTO commands(session_id, event_id, ts, pid, ppid, name, cmdline, cwd, user) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (self.session_id, event_id, datetime.datetime.now().isoformat(),
                     pid, ppid, name, cmdline, cwd, user),
                )
                self.conn.commit()


    @staticmethod
    def _win_id(w):
        for attr in ("_hWnd", "id", "windowId", "_windowId", "handle"):
            try:
                v = getattr(w, attr, None)
            except Exception:
                continue
            if v is not None:
                return str(v)
        return None

    @staticmethod
    def _safe_app(w):
        try:
            if hasattr(w, "getAppName"):
                return w.getAppName() or ""
        except Exception:
            pass
        return ""

    @staticmethod
    def _safe_title(w):
        try:
            return w.title or ""
        except Exception:
            return ""

    @staticmethod
    def _safe_pid(w):
        try:
            return getattr(w, "pid", None)
        except Exception:
            return None

    def _win_info(self, w, wid):
        info = {
            "window_id": wid or "",
            "title": self._safe_title(w),
            "app": self._safe_app(w),
        }
        pid = self._safe_pid(w)
        if pid is not None:
            info["pid"] = pid
            try:
                proc = psutil.Process(pid)
                info["cmdline"] = " ".join(proc.cmdline()[:4])
            except Exception:
                pass
        try:
            box = w.box
            if box:
                info["box"] = list(box)
        except Exception:
            pass
        return info

    def _win_key(self, info):
        wid = info.get("window_id")
        if wid:
            return ("wid", wid)
        pid = info.get("pid")
        app = (info.get("app") or "").lower()
        if pid is not None:
            return ("pidapp", pid, app)
        return ("apptitle", app, info.get("title") or "")

    def _close_activity_span(self, row_id, end_ts):
        if row_id is None:
            return
        with self.db_lock:
            self.conn.execute(
                "UPDATE window_activity SET end_ts=? WHERE id=? AND end_ts IS NULL",
                (end_ts, row_id),
            )
            self.conn.commit()

    def _write_span(self, info, start_ts):
        with self.db_lock:
            cur = self.conn.execute(
                "INSERT INTO window_activity("
                "session_id, window_id, app, title, pid, start_ts"
                ") VALUES (?,?,?,?,?,?)",
                (self.session_id, info.get("window_id"),
                 info.get("app"), info.get("title"),
                 info.get("pid"), start_ts),
            )
            self.conn.commit()
            return cur.lastrowid

    def _focused_window_dbus(self):
        try:
            out = subprocess.check_output(
                ["gdbus", "call", "--session",
                 "--dest", "org.gnome.Shell",
                 "--object-path",
                 "/org/gnome/shell/extensions/FocusedWindow",
                 "--method",
                 "org.gnome.shell.extensions.FocusedWindow.Get"],
                timeout=2, stderr=subprocess.PIPE,
            ).decode(errors="replace")
        except (OSError, subprocess.SubprocessError) as e:
            error = getattr(e, "stderr", None)
            if isinstance(error, bytes):
                error = error.decode(errors="replace").strip()
            self._window_backend_errors["focused-window-dbus"] = (
                error or repr(e))
            return None

        m = re.search(r"'(\{.*\})'", out, re.DOTALL)
        if not m:
            self._window_backend_errors["focused-window-dbus"] = (
                "The extension returned data that was not a JSON object")
            return None
        try:
            data = json.loads(m.group(1))
        except (TypeError, ValueError) as e:
            self._window_backend_errors["focused-window-dbus"] = (
                f"Could not parse extension response: {e}")
            return None

        title = (data.get("title") or "").strip()
        app = (data.get("wm_class")
               or data.get("wm_class_instance") or "").strip()
        if not (title or app):
            self._window_backend_errors["focused-window-dbus"] = (
                "The extension returned no focused-window title or app")
            return None

        self._window_backend_errors.pop("focused-window-dbus", None)
        info = {
            "window_id": str(data.get("id") or app or title),
            "title": title,
            "app": app,
        }
        if data.get("pid"):
            info["pid"] = int(data["pid"])
        if data.get("width") and data.get("height"):
            info["box"] = [data.get("x", 0), data.get("y", 0),
                           data["width"], data["height"]]
        return info

    def _window_calls_list(self):
        try:
            out = subprocess.check_output(
                ["gdbus", "call", "--session",
                 "--dest", "org.gnome.Shell.Extensions.Windows",
                 "--object-path", "/org/gnome/Shell/Extensions/Windows",
                 "--method", "org.gnome.Shell.Extensions.Windows.List"],
                timeout=3, stderr=subprocess.PIPE,
            ).decode(errors="replace")
        except (OSError, subprocess.SubprocessError) as e:
            error = getattr(e, "stderr", None)
            if isinstance(error, bytes):
                error = error.decode(errors="replace").strip()
            self._window_backend_errors["window-calls"] = error or repr(e)
            return None

        m = re.search(r"\('(\[.*\])',?\)", out, re.DOTALL)
        if not m:
            self._window_backend_errors["window-calls"] = (
                "The extension returned data that was not a JSON list")
            return None
        try:
            items = json.loads(m.group(1))
        except (TypeError, ValueError) as e:
            self._window_backend_errors["window-calls"] = (
                f"Could not parse extension response: {e}")
            return None
        if not isinstance(items, list):
            self._window_backend_errors["window-calls"] = (
                "The extension response is not a list")
            return None

        windows = []
        for item in items:
            if not isinstance(item, dict):
                continue
            wid = item.get("id")
            if wid is None:
                continue
            info = {
                "window_id": str(wid),
                "title": (item.get("title") or "").strip(),
                "app": (item.get("wm_class")
                        or item.get("wm_class_instance") or "").strip(),
            }
            if item.get("pid"):
                info["pid"] = int(item["pid"])
            if item.get("width") and item.get("height"):
                info["box"] = [item.get("x", 0), item.get("y", 0),
                               item["width"], item["height"]]
            windows.append(info)
        self._window_backend_errors.pop("window-calls", None)
        return windows

    def _xdotool_active(self):
        try:
            wid = subprocess.check_output(
                ["xdotool", "getactivewindow"],
                timeout=1, stderr=subprocess.DEVNULL,
            ).decode().strip()
            if not wid:
                return None
            title = subprocess.check_output(
                ["xdotool", "getwindowname", wid],
                timeout=1, stderr=subprocess.DEVNULL,
            ).decode().strip()
            pid = None
            try:
                p = subprocess.check_output(
                    ["xdotool", "getwindowpid", wid],
                    timeout=1, stderr=subprocess.DEVNULL,
                ).decode().strip()
                if p.isdigit():
                    pid = int(p)
            except Exception:
                pass
            app = ""
            if pid is not None:
                try:
                    app = subprocess.check_output(
                        ["ps", "-p", str(pid), "-o", "comm="],
                        timeout=1, stderr=subprocess.DEVNULL,
                    ).decode().strip()
                except Exception:
                    pass
            return {"window_id": wid, "title": title, "app": app, "pid": pid}
        except Exception:
            return None

    def _gnome_active_window(self):
        try:
            out = subprocess.check_output(
                ["gdbus", "call", "--session",
                 "--dest", "org.gnome.Shell",
                 "--object-path", "/org/gnome/Shell/Introspect",
                 "--method", "org.gnome.Shell.Introspect.GetWindows"],
                timeout=2, stderr=subprocess.DEVNULL,
            ).decode(errors="replace")
        except Exception:
            return None

        pattern = re.compile(r"\{uint64 (\d+): \{([^{}]+)\}\}")
        for m in pattern.finditer(out):
            wid, props = m.group(1), m.group(2)
            if "'has-focus': <true>" not in props:
                continue
            def grab(key):
                mm = re.search(r"'" + key + r"': <'((?:[^'\\]|\\.)*)'>", props)
                return mm.group(1) if mm else ""
            title = grab("title")
            app = grab("app-id") or grab("wm-class")
            pid = None
            pm = re.search(r"'pid': <(\d+)>", props)
            if pm:
                pid = int(pm.group(1))
            return {"window_id": wid, "title": title, "app": app, "pid": pid}
        return None

    def _windows_active_window(self):
        if sys.platform != "win32":
            return None
        try:
            import ctypes
            from ctypes import wintypes
            user32 = ctypes.windll.user32
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return None
            length = user32.GetWindowTextLengthW(hwnd)
            buff = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buff, length + 1)
            title = buff.value

            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pid_val = pid.value if pid.value else None
            app = ""
            if pid_val:
                try:
                    p = psutil.Process(pid_val)
                    app = p.name()
                except Exception:
                    pass
            return {"window_id": str(hwnd), "title": title, "app": app, "pid": pid_val}
        except Exception:
            return None

    def _windows_all_windows(self):
        if sys.platform != "win32":
            return None
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            enum_windows_proc = ctypes.WINFUNCTYPE(
                wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
            windows = []

            def collect(hwnd, _):
                if not user32.IsWindowVisible(hwnd):
                    return True
                length = user32.GetWindowTextLengthW(hwnd)
                if length <= 0:
                    return True
                title_buffer = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, title_buffer, length + 1)
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                pid_value = pid.value or None
                app = ""
                if pid_value:
                    try:
                        app = psutil.Process(pid_value).name()
                    except (psutil.Error, OSError):
                        pass
                windows.append({
                    "window_id": str(hwnd),
                    "title": title_buffer.value,
                    "app": app,
                    "pid": pid_value,
                })
                return True

            callback = enum_windows_proc(collect)
            if not user32.EnumWindows(callback, 0):
                return None
            return windows
        except Exception:
            return None

    def _macos_active_window(self):
        if sys.platform != "darwin":
            return None
        script = (
            'tell application "System Events"\n'
            'set frontApp to first application process whose frontmost is true\n'
            'set appName to name of frontApp\n'
            'set appPid to unix id of frontApp\n'
            'set windowTitle to ""\n'
            'try\n'
            'set windowTitle to name of front window of frontApp\n'
            'end try\n'
            'return (appPid as text) & linefeed & appName & linefeed & windowTitle\n'
            'end tell'
        )
        try:
            output = subprocess.check_output(
                ["osascript", "-e", script],
                timeout=3,
                stderr=subprocess.DEVNULL,
            ).decode(errors="replace").splitlines()
            if len(output) < 2:
                return None
            pid = int(output[0]) if output[0].isdigit() else None
            app = output[1].strip()
            title = output[2].strip() if len(output) > 2 else ""
            return {
                "window_id": f"{pid}:{title or app}",
                "title": title,
                "app": app,
                "pid": pid,
            }
        except (OSError, subprocess.SubprocessError, ValueError):
            return None

    def _active_window_info(self):
        if sys.platform == "win32":
            win_info = self._windows_active_window()
            if win_info and (win_info.get("title") or win_info.get("app")):
                return win_info
            try:
                w = pwc.getActiveWindow() if pwc else None
                if w is not None:
                    wid = self._win_id(w)
                    cand = self._win_info(w, wid)
                    if (cand.get("title") or "").strip() or (cand.get("app") or "").strip():
                        return cand
            except Exception:
                pass
            return None

        if sys.platform == "darwin":
            info = self._macos_active_window()
            if info and (info.get("title") or info.get("app")):
                return info
            try:
                w = pwc.getActiveWindow() if pwc else None
                if w is not None:
                    wid = self._win_id(w)
                    cand = self._win_info(w, wid)
                    if (cand.get("title") or "").strip() or \
                       (cand.get("app") or "").strip():
                        return cand
            except Exception:
                pass
            return None

        info = self._focused_window_dbus()
        if info and (info.get("title") or info.get("app")):
            return info
        try:
            w = pwc.getActiveWindow() if pwc else None
            if w is not None:
                wid = self._win_id(w)
                cand = self._win_info(w, wid)
                if (cand.get("title") or "").strip() or \
                   (cand.get("app") or "").strip():
                    return cand
        except Exception:
            pass
        xinfo = self._xdotool_active()
        if xinfo and (xinfo.get("title") or xinfo.get("app")):
            return xinfo
        ginfo = self._gnome_active_window()
        if ginfo and (ginfo.get("title") or ginfo.get("app")):
            return ginfo
        return None

    def _win_self_check(self):
        self._window_backend_errors.clear()
        env = {
            "DISPLAY": os.environ.get("DISPLAY"),
            "WAYLAND_DISPLAY": os.environ.get("WAYLAND_DISPLAY"),
            "XDG_SESSION_TYPE": os.environ.get("XDG_SESSION_TYPE"),
        }

        if sys.platform == "win32":
            info = self._windows_active_window()
            backend = "win32" if info else ("pywinctl" if pwc else None)
            all_wins = self._windows_all_windows()
            all_backend = "win32" if all_wins is not None else None
            if all_wins is None and pwc:
                try:
                    all_wins = pwc.getAllWindows() or []
                    all_backend = "pywinctl"
                except Exception as e:
                    env["all_error"] = repr(e)
                    self._window_backend_errors["pywinctl-window-list"] = repr(e)
                    all_wins = []
            all_count = len(all_wins or [])
            all_ok = all_count > 0
            status = "ok" if backend else "unavailable"
            self.log_event("window_debug", "agent", {
                "status": status,
                "backend": backend,
                "all_backend": all_backend,
                "active_sample": info,
                "all_ok": all_ok,
                "all_count": all_count,
                "env": env,
            })
            if backend is None:
                self.log_error_once("no_backend", {
                    "reason": "Windows foreground-window API is unavailable",
                })
                return False
            return True

        if sys.platform == "darwin":
            info = self._macos_active_window()
            backend = "osascript" if info else None
            if backend is None and pwc:
                try:
                    w = pwc.getActiveWindow()
                    if w is not None:
                        info = self._win_info(w, self._win_id(w))
                        if info.get("title") or info.get("app"):
                            backend = "pywinctl"
                except Exception:
                    pass

            all_ok = False
            all_count = 0
            if pwc:
                try:
                    all_count = len(pwc.getAllWindows() or [])
                    all_ok = all_count > 0
                except Exception as e:
                    env["all_error"] = repr(e)
                    self._window_backend_errors["pywinctl-window-list"] = repr(e)

            self.log_event("window_debug", "agent", {
                "status": "ok" if backend else "unavailable",
                "backend": backend,
                "all_backend": "pywinctl" if all_ok else None,
                "active_sample": info,
                "all_ok": all_ok,
                "all_count": all_count,
                "env": env,
            })
            if backend is None:
                self.log_error_once("no_backend", {
                    "reason": "macOS window tracking needs Accessibility permission",
                    "fix": "Allow the terminal or Python app in System Settings > "
                           "Privacy & Security > Accessibility.",
                })
                return False
            return True

        backend = None
        info = self._focused_window_dbus()
        if info and (info.get("title") or info.get("app")):
            backend = "focused-window-dbus"
        else:
            try:
                w = pwc.getActiveWindow() if pwc else None
                if w is not None:
                    wid = self._win_id(w)
                    cand = self._win_info(w, wid)
                    if (cand.get("title") or "").strip() or \
                       (cand.get("app") or "").strip():
                        info = cand
                        backend = "pywinctl"
            except Exception:
                pass
        if backend is None:
            xinfo = self._xdotool_active()
            if xinfo and (xinfo.get("title") or xinfo.get("app")):
                info = xinfo
                backend = "xdotool"
        if backend is None:
            ginfo = self._gnome_active_window()
            if ginfo and (ginfo.get("title") or ginfo.get("app")):
                info = ginfo
                backend = "gnome-introspect"

        all_ok = False
        all_count = 0
        all_backend = None
        wc = self._window_calls_list()
        if wc is not None:
            all_ok = True
            all_count = len(wc)
            all_backend = "window-calls"
        elif pwc is not None:
            try:
                all_wins = pwc.getAllWindows() or []
                all_count = len(all_wins)
                all_ok = all_count > 0
                if all_ok:
                    all_backend = "pywinctl"
            except Exception as e:
                env["all_error"] = repr(e)
                self._window_backend_errors["pywinctl-window-list"] = repr(e)

        status = "ok" if backend else "unavailable"
        if backend and not all_ok:
            status = "active-only"

        self.log_event("window_debug", "agent", {
            "status": status,
            "backend": backend,
            "all_backend": all_backend,
            "active_sample": info,
            "all_ok": all_ok,
            "all_count": all_count,
            "env": env,
            "backend_errors": dict(self._window_backend_errors),
        })

        if backend is None:
            self.log_error_once("no_backend", {
                "reason": "No window backend returned a focused window",
                "backend_errors": dict(self._window_backend_errors),
                "fix": "On GNOME Wayland, enable the Focused Window D-Bus "
                       "extension for this logged-in desktop session and "
                       "restart GNOME Shell or log out and back in. Verify "
                       "its D-Bus object is available before restarting "
                       "the agent.",
            })
            return False
        return True

    def log_window(self):
        poll = float(self.config.get("window_poll_seconds", 3))
        debug = bool(self.config.get("window_debug", False))
        self._win_self_check()

        active_row_id = None
        last_key = None
        none_streak = 0
        known_windows: dict = {}

        while self.running:
            if not self.logging_active:
                time.sleep(1)
                continue

            now_iso = datetime.datetime.now().isoformat()

            info = self._active_window_info()
            if info is None:
                none_streak += 1
                if none_streak >= 2 and active_row_id is not None:
                    self._close_activity_span(active_row_id, now_iso)
                    active_row_id = None
                    last_key = None
            else:
                none_streak = 0
                self._cache_window(info)
                key = self._win_key(info)
                if debug:
                    self.log_event("window_debug", "poller",
                                   {"key": list(key), "info": info})
                if key != last_key:
                    self._close_activity_span(active_row_id, now_iso)
                    active_row_id = self._write_span(info, now_iso)
                    last_key = key

            current = None
            if sys.platform == "win32":
                wc = self._windows_all_windows()
            elif sys.platform == "darwin":
                wc = None
            else:
                wc = self._window_calls_list()
            if wc is not None:
                current = {self._win_key(i): i for i in wc
                           if i.get("title") or i.get("app")}
            elif pwc is not None:
                try:
                    current = {}
                    for w2 in pwc.getAllWindows():
                        try:
                            wid = self._win_id(w2)
                            info2 = self._win_info(w2, wid)
                            if not (info2.get("title") or info2.get("app")):
                                continue
                            current[self._win_key(info2)] = info2
                        except Exception:
                            continue
                except Exception:
                    current = None

            if current is not None:
                for key, info2 in current.items():
                    if key not in known_windows:
                        self.log_event("window_open", "poller", info2)
                for key, info2 in known_windows.items():
                    if key not in current:
                        self.log_event("window_close", "poller", info2)
                known_windows = current

            time.sleep(poll)

        self._close_activity_span(
            active_row_id, datetime.datetime.now().isoformat())

    # -----------------------------------------------------------------
    # Typing pulse — count-only. Never reads key values.
    # Prefers evdev (works on Wayland + X11). Falls back to pynput (X11).
    # -----------------------------------------------------------------
    def _start_typing_backend(self, state, state_lock):
        """Returns a backend object with .stop(), or None."""

        # ---- evdev (Wayland + X11) ----
        try:
            import evdev
            from evdev import ecodes
        except ImportError:
            evdev = None

        if evdev is not None:
            try:
                devices = []
                for path in evdev.list_devices():
                    try:
                        dev = evdev.InputDevice(path)
                    except Exception:
                        continue
                    try:
                        caps = dev.capabilities()
                    except Exception:
                        continue
                    keys = caps.get(ecodes.EV_KEY, [])
                    # A keyboard has both KEY_A and KEY_ENTER.
                    if ecodes.KEY_A in keys and ecodes.KEY_ENTER in keys:
                        devices.append(dev)
                if not devices:
                    raise RuntimeError("no keyboard devices found")

                stop_flag = {"stop": False}

                def reader_thread():
                    import select as _select
                    while not stop_flag["stop"] and self.running:
                        try:
                            r, _, _ = _select.select(devices, [], [], 1.0)
                        except Exception:
                            time.sleep(0.5)
                            continue
                        for dev in r:
                            try:
                                for ev in dev.read():
                                    if ev.type == ecodes.EV_KEY and \
                                            ev.value == 1:  # key down
                                        with state_lock:
                                            state["count"] += 1
                            except Exception:
                                continue

                threading.Thread(target=reader_thread, daemon=True).start()

                class _EvdevBackend:
                    def __init__(self, devs, flag):
                        self.devs = devs
                        self.flag = flag
                    def stop(self):
                        self.flag["stop"] = True
                        for d in self.devs:
                            try:
                                d.close()
                            except Exception:
                                pass

                self.log_event("typing", "agent", {
                    "backend": "evdev",
                    "devices": [d.name for d in devices],
                    "note": "count-only, no key content captured",
                })
                return _EvdevBackend(devices, stop_flag)
            except PermissionError:
                self.log_error_once("typing_evdev_perm", {
                    "reason": "evdev cannot read /dev/input "
                              "(permission denied)",
                    "fix": "sudo usermod -aG input $USER  "
                           "then log out and back in",
                })
            except Exception as e:
                self.log_error_once("typing_evdev", {
                    "reason": f"evdev backend failed: {e!r}",
                })

        # ---- pynput (X11) ----
        try:
            from pynput import keyboard
        except ImportError:
            self.log_error_once("typing_no_backend", {
                "reason": "no typing backend available",
                "fix": "pip install evdev pynput  and add user to "
                       "'input' group, then log out/in",
            })
            return None

        try:
            def on_press(key):
                with state_lock:
                    state["count"] += 1

            listener = keyboard.Listener(on_press=on_press)
            listener.daemon = True
            listener.start()

            class _PynputBackend:
                def __init__(self, lst):
                    self.listener = lst
                def stop(self):
                    try:
                        self.listener.stop()
                    except Exception:
                        pass

            self.log_event("typing", "agent", {
                "backend": "pynput",
                "note": "count-only, no key content captured",
            })
            return _PynputBackend(listener)
        except Exception as e:
            self.log_error_once("typing_pynput", {
                "reason": f"pynput failed: {e!r}",
                "fix": "On Wayland, use evdev instead and add user "
                       "to the 'input' group",
            })
            return None

    def log_typing_pulse(self):
        interval = float(self.config.get("typing_pulse_seconds", 5.0))
        state = {"count": 0}
        state_lock = threading.Lock()

        backend = self._start_typing_backend(state, state_lock)
        if backend is None:
            return

        try:
            while self.running:
                time.sleep(interval)
                if not self.logging_active:
                    continue
                with state_lock:
                    count = state["count"]
                    state["count"] = 0
                if count > 0:
                    win = self._get_cached_window()
                    self.log_event("typing", "pulse", {
                        "chars": count,
                        "window": win,
                    })
        finally:
            try:
                backend.stop()
            except Exception:
                pass

    def _default_monitor_dirs(self):
        home = Path.home()
        candidates = []

        if sys.platform == "win32":
            try:
                import winreg

                key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                    for name in ("Personal", "Desktop",
                                 "{374DE290-123F-4565-9164-39C4925E467B}"):
                        try:
                            value, _ = winreg.QueryValueEx(key, name)
                            candidates.append(Path(os.path.expandvars(value)))
                        except FileNotFoundError:
                            continue
            except OSError:
                pass
            candidates.extend(home / name for name in
                              ("Documents", "Desktop", "Downloads"))
        elif sys.platform == "darwin":
            candidates.extend(home / name for name in
                              ("Documents", "Desktop", "Downloads"))
        else:
            for directory in ("DOCUMENTS", "DESKTOP", "DOWNLOAD"):
                try:
                    result = subprocess.run(
                        ["xdg-user-dir", directory],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=2,
                    )
                    if result.stdout.strip():
                        candidates.append(Path(result.stdout.strip()).expanduser())
                except (OSError, subprocess.SubprocessError):
                    continue
            candidates.extend(home / name for name in
                              ("Documents", "Desktop", "Downloads"))

        unique = {}
        for path in candidates:
            try:
                resolved = path.expanduser().resolve()
            except OSError:
                continue
            if resolved.is_dir():
                unique[str(resolved)] = resolved
        return list(unique.values())

    def start_file_monitor(self):
        import fnmatch
        from watchdog.observers import Observer
        from watchdog.observers.polling import PollingObserver
        from watchdog.events import FileSystemEventHandler
        agent = self

        IGNORED_PATTERNS = [
            "*.tmp", "*.temp", "*~", ".*.swp", ".*.swo", ".~lock.*", "Thumbs.db",
            "desktop.ini", ".DS_Store", "*.crdownload", "*.part", "*.goutputstream-*",
            "*.pyc", "*.pyo", "*.log",
            "*.git*", "*.vscode*", "*.idea*", "*__pycache__*", "*node_modules*",
            "*audit.db*", "*snapshots*"
        ]

        class FilteredHandler(FileSystemEventHandler):
            def should_ignore(self, path: str) -> bool:
                bname = os.path.basename(path)
                for pat in IGNORED_PATTERNS:
                    if fnmatch.fnmatch(bname, pat) or fnmatch.fnmatch(path, pat):
                        return True
                return False

            def process_event(self, event):
                if event.is_directory and event.event_type == "modified":
                    return

                src = getattr(event, "src_path", None)
                if not src or self.should_ignore(src):
                    return

                key = (src, event.event_type)
                now = time.time()
                with agent._file_debounce_lock:
                    last_time = agent._file_debounce.get(key, 0)
                    if now - last_time < 2.0:
                        return
                    agent._file_debounce[key] = now
                    if len(agent._file_debounce) > 1000:
                        agent._file_debounce = {
                            k: v for k, v in agent._file_debounce.items() if now - v < 5.0
                        }

                dest = getattr(event, "dest_path", None)
                if dest:
                    action = f"moved -> {dest}"
                else:
                    action = event.event_type

                agent.log_file_event(src, action)

            def on_created(self, event):
                self.process_event(event)

            def on_modified(self, event):
                self.process_event(event)

            def on_deleted(self, event):
                self.process_event(event)

            def on_moved(self, event):
                self.process_event(event)

        configured_dirs = self.config.get("monitor_dirs", [])
        directories = []
        for directory in configured_dirs:
            try:
                path = Path(directory).expanduser().resolve()
            except (OSError, TypeError, ValueError) as exc:
                self.log_event("file_monitor_error", "agent", {
                    "path": str(directory),
                    "error": str(exc),
                })
                continue
            if path.is_dir():
                directories.append(path)

        if not directories:
            directories = self._default_monitor_dirs()
            if directories:
                self.log_event("file_monitor", "agent", {
                    "status": "using platform user folders",
                    "configured_dirs": configured_dirs,
                    "directories": [str(path) for path in directories],
                })
        if not directories:
            self.log_event("file_monitor_error", "agent", {
                "reason": "No configured or standard user directories exist",
                "configured_dirs": configured_dirs,
            })
            return

        handler = FilteredHandler()
        observer = Observer()
        scheduled = []
        for path in directories:
            try:
                observer.schedule(handler, str(path), recursive=True)
                scheduled.append(path)
            except (OSError, RuntimeError) as exc:
                self.log_event("file_monitor_error", "agent", {
                    "path": str(path),
                    "error": str(exc),
                })

        if not scheduled:
            self.log_event("file_monitor_error", "agent", {
                "reason": "Could not schedule any configured directories",
                "directories": [str(path) for path in directories],
            })
            return

        try:
            observer.start()
        except (OSError, RuntimeError) as exc:
            observer.stop()
            self.log_event("file_monitor", "agent", {
                "status": "native watcher unavailable; using polling",
                "error": str(exc),
            })
            observer = PollingObserver()
            for path in scheduled:
                observer.schedule(handler, str(path), recursive=True)
            try:
                observer.start()
            except (OSError, RuntimeError) as polling_error:
                self.log_event("file_monitor_error", "agent", {
                    "reason": "Native and polling file monitors failed",
                    "native_error": str(exc),
                    "polling_error": str(polling_error),
                })
                return

        self.observer = observer
        self.log_event("file_monitor", "agent", {
            "status": "started",
            "backend": "polling" if isinstance(observer, PollingObserver) else "native",
            "directories": [str(path) for path in scheduled],
        })

    def start_web_server(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        agent = self

        class Handler(BaseHTTPRequestHandler):
            def send_json(self, status, payload):
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/face-lock":
                    self.send_json(200, {"enabled": agent.face_lock_active})
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self):
                if self.path == "/face-lock":
                    try:
                        length = int(self.headers.get("Content-Length", 0))
                        if not 0 < length <= 1024:
                            raise ValueError("invalid request size")
                        payload = json.loads(self.rfile.read(length))
                        if not isinstance(payload, dict) or \
                                type(payload.get("enabled")) is not bool:
                            raise ValueError("enabled must be a boolean")
                    except (ValueError, json.JSONDecodeError) as exc:
                        self.send_json(400, {"error": str(exc)})
                        return
                    agent.set_face_lock_enabled(payload["enabled"])
                    self.send_json(200, {"enabled": agent.face_lock_active})
                    return
                if self.path != "/visit":
                    self.send_response(404)
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length", 0))
                data = self.rfile.read(length)
                try:
                    payload = json.loads(data)
                except Exception:
                    payload = {}
                kind = payload.get("kind", "visit")
                if kind == "form_submit":
                    agent.log_form_submit(
                        payload.get("url"),
                        payload.get("title"),
                        payload.get("form_action"),
                        payload.get("field_names") or [],
                        payload.get("browser"),
                    )
                elif kind == "download":
                    agent.log_download(
                        payload.get("url"),
                        payload.get("filename"),
                        payload.get("fileSize") or 0,
                        payload.get("mime"),
                        payload.get("state"),
                        payload.get("browser"),
                    )
                else:
                    agent.log_web_visit(
                        payload.get("url"),
                        payload.get("title"),
                        payload.get("browser"),
                    )
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")

            def log_message(self, *args):
                pass

        port = self.config.get("web_server_port", 8765)
        server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.web_server = server

    def _check_screen_locked(self) -> bool:
        if sys.platform == "win32":
            try:
                import ctypes
                user32 = ctypes.windll.user32
                hdesk = user32.OpenInputDesktop(0, False, 0x0001)
                if hdesk == 0:
                    return True
                user32.CloseDesktop(hdesk)
                return False
            except Exception:
                return False
        else:
            try:
                out = subprocess.check_output(
                    ["gdbus", "call", "--session",
                     "--dest", "org.gnome.ScreenSaver",
                     "--object-path", "/org/gnome/ScreenSaver",
                     "--method", "org.gnome.ScreenSaver.GetActive"],
                    timeout=1, stderr=subprocess.DEVNULL
                ).decode()
                if "true" in out.lower():
                    return True
                elif "false" in out.lower():
                    return False
            except Exception:
                pass

            try:
                out = subprocess.check_output(
                    ["loginctl", "show-session", "self", "-p", "LockedHint"],
                    timeout=1, stderr=subprocess.DEVNULL
                ).decode()
                if "LockedHint=yes" in out:
                    return True
                if "LockedHint=no" in out:
                    return False
            except Exception:
                pass
            return False

    def log_lock_monitor(self):
        last_locked = None
        while self.running:
            if not self.logging_active:
                time.sleep(1)
                continue
            try:
                is_locked = self._check_screen_locked()
                if last_locked is None:
                    last_locked = is_locked
                elif is_locked != last_locked:
                    last_locked = is_locked
                    if is_locked:
                        self.log_event("screen_lock", "security", {"state": "locked"})
                    else:
                        self.log_event("screen_unlock", "security", {"state": "unlocked"})
                        if self.config.get("camera_snapshot", False):
                            self.take_snapshot(trigger="screen_unlock")
            except Exception:
                pass
            time.sleep(2.0)

    def log_command_monitor(self):
        seen_pids = set()
        for p in psutil.process_iter(['pid']):
            try:
                seen_pids.add(p.pid)
            except Exception:
                pass

        current_user = getpass.getuser().casefold()
        shell_names = {
            "bash", "zsh", "fish", "sh", "dash", "ksh", "tcsh", "csh",
            "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh",
            "pwsh.exe",
        }

        while self.running:
            if not self.logging_active:
                time.sleep(1)
                continue
            try:
                current_pids = set()
                processes = list(psutil.process_iter(
                    ['pid', 'ppid', 'name', 'cmdline', 'cwd', 'username']))
                shell_pids = set()
                for proc in processes:
                    try:
                        name = (proc.info.get("name") or "").lstrip("-").casefold()
                        user = (proc.info.get("username") or "").casefold()
                        if name in shell_names and (
                                not user or user.rsplit("\\", 1)[-1] == current_user):
                            shell_pids.add(proc.info["pid"])
                    except (psutil.NoSuchProcess, psutil.AccessDenied,
                            psutil.ZombieProcess):
                        continue

                for proc in processes:
                    try:
                        pid = proc.pid
                        current_pids.add(pid)
                        if pid not in seen_pids:
                            seen_pids.add(pid)
                            if proc.info.get("ppid") not in shell_pids:
                                continue
                            user = proc.info.get("username")
                            normalized_user = (user or "").casefold().rsplit("\\", 1)[-1]
                            if normalized_user and normalized_user != current_user:
                                continue
                            cmdline_list = proc.info.get("cmdline") or []
                            if not cmdline_list:
                                continue
                            cmdline_str = " ".join(cmdline_list).strip()
                            if not cmdline_str:
                                continue
                            name = proc.info.get("name")
                            cwd = proc.info.get("cwd")
                            self.log_command(pid, proc.ppid(), name, cmdline_str, cwd, user)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                seen_pids.intersection_update(current_pids)
            except Exception:
                pass
            time.sleep(1.5)

    def take_snapshot(self, trigger="session_start"):
        if not self.config.get("camera_snapshot", False):
            return
        try:
            import cv2
        except ImportError:
            self.log_event("camera", "agent",
                           {"error": "opencv-python not installed", "trigger": trigger})
            return

        cam_index = int(self.config.get("camera_index", 0))
        width     = int(self.config.get("camera_width", 1280))
        height    = int(self.config.get("camera_height", 720))
        warmup    = int(self.config.get("camera_warmup_frames", 15))
        settle_s  = float(self.config.get("camera_settle_seconds", 1.2))
        picks     = int(self.config.get("camera_best_of", 5))

        cap = cv2.VideoCapture(cam_index)
        if not cap.isOpened():
            self.log_event("camera", "agent",
                           {"error": "could not open camera", "trigger": trigger})
            return
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, width)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, height)
        try:
            cap.set(cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc(*"MJPG"))
        except Exception:
            pass

        try:
            for _ in range(max(warmup, 1)):
                cap.grab()
            time.sleep(settle_s)
            candidates = []
            for _ in range(max(picks, 1)):
                ok, frame = cap.read()
                if not ok or frame is None:
                    continue
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                score = cv2.Laplacian(gray, cv2.CV_64F).var()
                candidates.append((score, frame))
                time.sleep(0.08)
            if not candidates:
                self.log_event("camera", "agent",
                               {"error": "no usable frame", "trigger": trigger})
                return
            candidates.sort(key=lambda t: t[0], reverse=True)
            best_score, frame = candidates[0]
        finally:
            cap.release()

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = self.snapshot_dir / f"session_{self.session_id}_{ts}.jpg"
        cv2.imwrite(str(path), frame,
                    [int(cv2.IMWRITE_JPEG_QUALITY), 95])
        self.log_event("camera", "agent", {
            "path": str(path),
            "consent": True,
            "trigger": trigger,
            "sharpness": round(float(best_score), 2),
            "resolution": f"{frame.shape[1]}x{frame.shape[0]}",
        })
        with self.db_lock:
            self.conn.execute(
                "INSERT INTO snapshots(session_id, ts, path, consent) "
                "VALUES (?,?,?,?)",
                (self.session_id, datetime.datetime.now().isoformat(),
                 str(path), 1),
            )
            self.conn.commit()

    def run_tray(self):
        import pystray
        from PIL import Image, ImageDraw

        def create_icon(color):
            img = Image.new("RGB", (64, 64), "black")
            d = ImageDraw.Draw(img)
            d.ellipse((16, 16, 48, 48), fill=color)
            return img

        def on_toggle(icon, item):
            self.logging_active = not self.logging_active
            icon.icon = create_icon("green" if self.logging_active else "red")
            self.log_event("status", "tray",
                           {"logging_active": self.logging_active})

        def on_toggle_face_lock(icon, item):
            self.set_face_lock_enabled(not self.face_lock_active)

        def on_quit(icon, item):
            self.shutdown()
            icon.stop()

        menu = pystray.Menu(
            pystray.MenuItem(
                lambda item: "Pause" if self.logging_active else "Resume",
                on_toggle),
            pystray.MenuItem(
                lambda item: f"Face Presence Lock: {'ON' if self.face_lock_active else 'OFF'}",
                on_toggle_face_lock,
                checked=lambda item: self.face_lock_active),
            pystray.MenuItem("Quit", on_quit),
        )
        icon = pystray.Icon("AuditAgent", create_icon("green"),
                            "Audit Agent", menu)
        self.icon = icon
        icon.run()

    def set_face_lock_enabled(self, enabled: bool):
        enabled = bool(enabled)
        if self.face_lock_active == enabled:
            return

        self.face_lock_active = enabled
        if self.face_watcher:
            self.face_watcher.enabled = enabled
            if not enabled:
                self.face_watcher.consecutive_failures = 0
        self.log_event("status", "tray", {"face_lock_active": enabled})

    def start_face_lock_hotkey(self):
        try:
            from pynput import keyboard
        except ImportError as exc:
            self.log_event("hotkey_error", "agent", {
                "shortcut": "Ctrl+Alt+F",
                "error": str(exc),
                "hint": "Install the pynput dependency to enable global hotkeys.",
            })
            return

        def toggle_face_lock():
            self.set_face_lock_enabled(not self.face_lock_active)
            state = "ON" if self.face_lock_active else "OFF"
            self.log_event("status", "hotkey", {
                "shortcut": "Ctrl+Alt+F",
                "face_lock_active": self.face_lock_active,
            })
            print(f"[FaceLock] {state} (Ctrl+Alt+F)")

        try:
            listener = keyboard.GlobalHotKeys({
                "<ctrl>+<alt>+f": toggle_face_lock,
            })
            listener.start()
            self.face_lock_hotkey_listener = listener
            self.log_event("status", "agent", {
                "global_shortcut": "Ctrl+Alt+F",
                "action": "toggle_face_lock",
            })
        except Exception as exc:
            self.log_event("hotkey_error", "agent", {
                "shortcut": "Ctrl+Alt+F",
                "error": str(exc),
                "hint": "Check desktop permissions and use a supported "
                        "desktop session; global hotkeys may be blocked "
                        "on Wayland.",
            })

    def run_face_lock(self):
        try:
            from face_lock import FaceLockWatcher
            self.face_watcher = FaceLockWatcher(
                config=self.config,
                event_callback=self.log_event,
            )
            self.face_watcher.enabled = self.face_lock_active
            self.face_watcher.run_loop()
        except Exception as e:
            self.log_event("face_lock", "agent", {"error": str(e)})

    def shutdown(self):
        if not self.running:
            return
        self.running = False
        self.log_event("session_end", "agent", {})
        with self.db_lock:
            self.conn.execute(
                "UPDATE sessions SET end_time=? WHERE id=?",
                (datetime.datetime.now().isoformat(), self.session_id),
            )
            self.conn.execute(
                "UPDATE window_activity SET end_ts=? "
                "WHERE session_id=? AND end_ts IS NULL",
                (datetime.datetime.now().isoformat(), self.session_id),
            )
            self.conn.commit()
        if self.observer:
            self.observer.stop()
            self.observer.join()
        if self.face_watcher:
            self.face_watcher.stop()
        if self.face_lock_hotkey_listener:
            self.face_lock_hotkey_listener.stop()
        if self.web_server:
            self.web_server.shutdown()
        self.conn.close()


def run_agent(config_path: str, enable_face_lock: Optional[bool] = None):
    agent = AuditAgent(config_path)
    if enable_face_lock is not None:
        agent.face_lock_active = enable_face_lock
        if agent.face_watcher:
            agent.face_watcher.enabled = enable_face_lock
    agent.take_snapshot(trigger="session_start")
    agent.start_web_server()
    agent.start_face_lock_hotkey()
    threading.Thread(target=agent.log_window, daemon=True).start()
    threading.Thread(target=agent.log_typing_pulse, daemon=True).start()
    threading.Thread(target=agent.log_lock_monitor, daemon=True).start()
    threading.Thread(target=agent.log_command_monitor, daemon=True).start()
    threading.Thread(target=agent.run_face_lock, daemon=True).start()
    agent.start_file_monitor()
    try:
        agent.run_tray()
    except KeyboardInterrupt:
        agent.shutdown()



# ===========================================================================
# PART 2 — TUI
# ===========================================================================

try:
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.widgets import (
        Header, Footer, DataTable, Static, Input, Button,
        TabbedContent, TabPane, Label, RichLog, Select, Tree,
    )
    from textual.binding import Binding
    from textual import work
    from textual.worker import get_current_worker
    from rich.text import Text
except ImportError:
    App = object
    ComposeResult = Horizontal = Vertical = object
    Header = Footer = DataTable = Static = Input = Button = object
    TabbedContent = TabPane = Label = RichLog = Select = Tree = object
    Binding = lambda *args, **kwargs: None
    work = lambda *args, **kwargs: (lambda f: f)
    get_current_worker = lambda: None
    Text = None
    _HAS_TEXTUAL = False
else:
    _HAS_TEXTUAL = True



class DB:
    def __init__(self, path: Path):
        self.path = path
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA query_only = ON")

    def q(self, sql, params=()):
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def sessions(self, limit=500):
        return self.q(
            """
            SELECT id, user, start_time, end_time, ip,
                   CAST((julianday(COALESCE(end_time, datetime('now'))) -
                         julianday(start_time)) * 86400 AS INTEGER) AS duration_s
            FROM sessions ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        )

    def session_counts(self, sid):
        row = self.q(
            """
            SELECT
              (SELECT COUNT(*) FROM events
               WHERE session_id=? AND type='file') AS files,
              (SELECT COUNT(*) FROM events
               WHERE session_id=? AND type='web') AS web,
              (SELECT COUNT(*) FROM window_activity
               WHERE session_id=?) AS window,
              (SELECT COUNT(*) FROM snapshots
               WHERE session_id=?) AS snapshots,
              (SELECT COUNT(*) FROM events
               WHERE session_id=? AND type='typing') AS typing,
              (SELECT COUNT(*) FROM events
               WHERE session_id=? AND type='form_submit') AS forms,
              (SELECT COUNT(*) FROM events
               WHERE session_id=?
                 AND type NOT IN ('file','web','camera','typing',
                                  'form_submit')
                 AND type NOT LIKE 'window%') AS events
            """,
            (sid, sid, sid, sid, sid, sid, sid),
        )[0]
        return {k: (row[k] or 0) for k in
                ("files", "web", "window", "snapshots",
                 "typing", "forms", "events")}

    def session_files(self, sid, limit=1000):
        return self.q(
            """
            SELECT e.ts, f.path AS path, f.action AS action, f.process AS process,
                   f.user AS user, e.details AS details
            FROM file_access f LEFT JOIN events e ON e.id = f.event_id
            WHERE e.session_id = ? ORDER BY e.id ASC LIMIT ?
            """,
            (sid, limit),
        )

    def session_web(self, sid, limit=1000):
        return self.q(
            """
            SELECT e.ts, w.domain AS domain, w.title AS title,
                   w.url AS url, w.browser AS browser, e.details AS details
            FROM web_visits w LEFT JOIN events e ON e.id = w.event_id
            WHERE e.session_id = ? ORDER BY e.id ASC LIMIT ?
            """,
            (sid, limit),
        )

    def session_windows(self, sid, limit=2000):
        return self.q(
            """
            SELECT id, start_ts, end_ts, window_id, app, title, pid
            FROM window_activity
            WHERE session_id = ? ORDER BY id ASC LIMIT ?
            """,
            (sid, limit),
        )

    def session_timeline(self, sid):
        events = self.q(
            """
            SELECT id, ts, type, source, details
            FROM events
            WHERE session_id = ?
            ORDER BY ts ASC, id ASC LIMIT ?
            """,
            (sid, -1),
        )
        windows = self.q(
            """
            SELECT id, start_ts AS ts, start_ts, end_ts, window_id,
                   app, title, pid
            FROM window_activity
            WHERE session_id = ?
            ORDER BY start_ts ASC, id ASC LIMIT ?
            """,
            (sid, -1),
        )
        snapshots = self.q(
            """
            SELECT id, ts, path, consent
            FROM snapshots
            WHERE session_id = ?
            ORDER BY ts ASC, id ASC LIMIT ?
            """,
            (sid, -1),
        )
        return events, windows, snapshots

    def session_snapshots(self, sid, limit=200):
        return self.q(
            """
            SELECT ts, path, consent FROM snapshots
            WHERE session_id = ? ORDER BY id ASC LIMIT ?
            """,
            (sid, limit),
        )

    def session_typing(self, sid, limit=2000):
        return self.q(
            """
            SELECT ts, details FROM events
            WHERE session_id=? AND type='typing'
            ORDER BY id ASC LIMIT ?
            """,
            (sid, limit),
        )

    def session_forms(self, sid, limit=2000):
        return self.q(
            """
            SELECT e.ts, f.url AS url, f.domain AS domain,
                   f.form_action AS form_action, f.field_names AS field_names,
                   e.details AS details
            FROM form_submits f LEFT JOIN events e ON e.id = f.event_id
            WHERE e.session_id = ? ORDER BY e.id ASC LIMIT ?
            """,
            (sid, limit),
        )

    def session_other_events(self, sid, limit=1000):
        return self.q(
            """
            SELECT ts, type, source, details FROM events
            WHERE session_id = ?
              AND type NOT IN ('file','web','camera','typing',
                               'form_submit','command')
              AND type NOT LIKE 'window%'
            ORDER BY id ASC LIMIT ?
            """,
            (sid, limit),
        )

    def session_window_debug(self, sid, limit=200):
        return self.q(
            """
            SELECT ts, type, source, details FROM events
            WHERE session_id=? AND type IN ('window_debug','window_error')
            ORDER BY id ASC LIMIT ?
            """,
            (sid, limit),
        )

    def file_events(self, search=None, limit=500):
        sql = """
            SELECT f.id, f.event_id, e.ts, f.path, f.action, f.process, f.user,
                   e.session_id
            FROM file_access f LEFT JOIN events e ON e.id = f.event_id
            WHERE 1=1
        """
        params = []
        if search:
            sql += " AND f.path LIKE ?"
            params.append(f"%{search}%")
        sql += " ORDER BY f.id DESC LIMIT ?"
        params.append(limit)
        return self.q(sql, params)

    def web_events(self, search=None, limit=500):
        sql = """
            SELECT w.id, w.event_id, e.ts, w.browser, w.domain, w.url, w.title,
                   e.session_id
            FROM web_visits w LEFT JOIN events e ON e.id = w.event_id
            WHERE 1=1
        """
        params = []
        if search:
            sql += " AND (w.url LIKE ? OR w.title LIKE ? OR w.domain LIKE ?)"
            like = f"%{search}%"
            params += [like, like, like]
        sql += " ORDER BY w.id DESC LIMIT ?"
        params.append(limit)
        return self.q(sql, params)

    def session_commands(self, sid, limit=1000):
        return self.q(
            """
            SELECT c.id, c.event_id, c.ts, c.pid, c.ppid, c.name, c.cmdline, c.cwd, c.user
            FROM commands c
            WHERE c.session_id = ?
              AND EXISTS (
                  SELECT 1 FROM events e
                  WHERE e.id = c.event_id AND e.source = 'user_command'
              )
            ORDER BY c.id ASC LIMIT ?
            """,
            (sid, limit),
        )

    def command_events(self, search=None, limit=500):
        sql = """
            SELECT c.id, c.session_id, c.event_id, c.ts, c.pid, c.ppid, c.name, c.cmdline, c.cwd, c.user
            FROM commands c
            WHERE EXISTS (
                SELECT 1 FROM events e
                WHERE e.id = c.event_id AND e.source = 'user_command'
            )
        """
        params = []
        if search:
            sql += " AND (c.cmdline LIKE ? OR c.name LIKE ? OR c.user LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s, s])
        sql += " ORDER BY c.id DESC LIMIT ?"
        params.append(limit)
        return self.q(sql, params)

    def download_events(self, search=None, limit=500):
        sql = """
            SELECT d.id, d.session_id, d.event_id, d.ts, d.browser, d.url, d.filename, d.file_size, d.mime, d.state
            FROM web_downloads d
            WHERE 1=1
        """
        params = []
        if search:
            sql += " AND (d.filename LIKE ? OR d.url LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s])
        sql += " ORDER BY d.id DESC LIMIT ?"
        params.append(limit)
        return self.q(sql, params)

    def advanced_search(self, query=None, event_type=None, sid=None, limit=300):
        sql = """
            SELECT id, session_id, ts, type, source, details
            FROM events
            WHERE (type != 'command' OR source = 'user_command')
        """
        params = []
        if sid is not None:
            sql += " AND session_id = ?"
            params.append(sid)
        if event_type:
            sql += " AND type = ?"
            params.append(event_type)
        if query:
            sql += " AND (details LIKE ? OR type LIKE ? OR source LIKE ?)"
            q = f"%{query}%"
            params.extend([q, q, q])
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return self.q(sql, params)

    def snapshots(self, limit=200):
        return self.q(
            "SELECT id, session_id, ts, path, consent FROM snapshots "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        )

    def counts(self):
        return self.q(
            """
            SELECT
              (SELECT COUNT(*) FROM sessions) AS sessions,
              (SELECT COUNT(*) FROM events) AS events,
              (SELECT COUNT(*) FROM file_access) AS files,
              (SELECT COUNT(*) FROM web_visits) AS web,
              (SELECT COUNT(*) FROM snapshots) AS snaps,
              (SELECT COUNT(*) FROM window_activity) AS wact,
              (SELECT COUNT(*) FROM form_submits) AS forms,
              (SELECT COUNT(*) FROM commands) AS commands,
              (SELECT COUNT(*) FROM web_downloads) AS downloads
            """
        )[0]


def short(s, n=80):
    if s is None:
        return ""
    s = str(s).replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


def fmt_ts(ts):
    if not ts:
        return ""
    try:
        return datetime.datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts


def fmt_ts_short(ts):
    if not ts:
        return ""
    try:
        return datetime.datetime.fromisoformat(ts).strftime("%H:%M:%S")
    except Exception:
        return ts


def span_seconds(start_ts, end_ts):
    if not start_ts:
        return None
    try:
        s = datetime.datetime.fromisoformat(start_ts)
        e = datetime.datetime.fromisoformat(end_ts) if end_ts else datetime.datetime.now()
        return int((e - s).total_seconds())
    except Exception:
        return None


def fmt_dur(sec):
    if sec is None:
        return ""
    sec = int(sec)
    h, r = divmod(sec, 3600)
    m, s = divmod(r, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def open_path(p):
    if sys.platform.startswith("win"):
        subprocess.Popen(["cmd", "/c", "start", "", p], shell=False)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", p])
    else:
        subprocess.Popen(["xdg-open", p])


def details_window(details_json):
    try:
        d = json.loads(details_json) if details_json else {}
    except Exception:
        return {}
    return d.get("window") or {}


PLACEHOLDER = ("placeholder",)


class SessionTreePane(Vertical):
    MAX_ITEMS = 800
    auto_refresh_seconds = 5.0

    BINDINGS = [
        Binding("r", "reload", "Reload"),
        Binding("ctrl+e", "expand_all", "Expand"),
        Binding("ctrl+w", "collapse_all", "Collapse"),
    ]

    def __init__(self):
        super().__init__()
        self._auto_timer = None
        self._last_sig = None

    def compose(self) -> ComposeResult:
        with Horizontal(classes="toolbar"):
            yield Input(placeholder="Filter sessions (user, ip, id)…",
                        id="tree-session-filter")
            yield Input(placeholder="Filter items (path, url, title)…",
                        id="tree-item-filter")
            yield Select(
                options=[
                    ("All categories", "all"),
                    ("📁 Files", "files"),
                    ("🌐 Web", "web"),
                    ("🪟 Windows", "window"),
                    ("📸 Snapshots", "snapshots"),
                    ("⌨ Typing", "typing"),
                    ("📝 Forms", "forms"),
                    ("⚙ Other", "events"),
                    ("🔧 Diagnostics", "wdiag"),
                ],
                value="all", id="tree-cat-filter", allow_blank=False,
            )
            yield Button("Auto ●", id="tree-auto")
            yield Button("Reload", id="tree-reload")
        with Horizontal(id="tree-split"):
            yield Tree("Sessions", id="tree")
            yield RichLog(id="tree-detail", highlight=True, markup=True, wrap=True)

    def on_mount(self):
        tree = self.query_one("#tree", Tree)
        tree.show_root = False
        tree.guide_depth = 4
        self.query_one("#tree-detail", RichLog).write(
            "[dim]Select a session, category, or item to see details.[/dim]")
        self.reload()
        if self.auto_refresh_seconds > 0:
            self._auto_timer = self.set_interval(
                self.auto_refresh_seconds, self._auto_tick)

    def _auto_tick(self):
        if not self.is_mounted:
            return
        tree = self.query_one("#tree", Tree)

        sfilt = self.query_one("#tree-session-filter", Input).value.strip().lower()
        sessions = self.app.db.sessions(limit=500)
        if sfilt:
            sessions = [
                s for s in sessions
                if sfilt in (s["user"] or "").lower()
                or sfilt in (s["ip"] or "").lower()
                or sfilt in str(s["id"])
            ]

        existing = {}
        for node in tree.root.children:
            if node.data and node.data[0] == "session":
                existing[node.data[1]] = node

        wanted_ids = {s["id"] for s in sessions}

        sig_parts = []
        for s in sessions:
            sig_parts.append((
                s["id"], s["end_time"], s["user"], s["ip"],
            ))
            node = existing.get(s["id"])
            if node is not None and node.is_expanded:
                counts = self.app.db.session_counts(s["id"])
                sig_parts.append(tuple(sorted(counts.items())))
        sig = tuple(sig_parts)
        if sig == self._last_sig:
            return
        self._last_sig = sig

        if set(existing.keys()) != wanted_ids:
            self._reload_preserving_state()
            return

        session_by_id = {s["id"]: s for s in sessions}
        for sid, node in existing.items():
            s = session_by_id.get(sid)
            if not s:
                continue
            new_label = self._session_label(s)
            old_plain = getattr(node.label, "plain", str(node.label))
            if old_plain != new_label.plain:
                node.set_label(new_label)
            if node.is_expanded:
                self._refresh_category_counts(node, sid)

        try:
            c = self.app.db.counts()
            bar = self.app.query_one("#status-bar", Static)
            new_text = (
                f"DB: {self.app.db_path}   "
                f"sessions={c['sessions']}  events={c['events']}  "
                f"files={c['files']}  web={c['web']}  "
                f"spans={c['wact']}  forms={c['forms']}  snaps={c['snaps']}"
            )
            if getattr(bar, "_audit_text", None) != new_text:
                bar._audit_text = new_text
                bar.update(new_text)
        except Exception:
            pass

    def _refresh_category_counts(self, session_node, sid):
        counts = self.app.db.session_counts(sid)
        cat_info = {
            "files":     ("📁 Files",          "cyan",        counts["files"]),
            "web":       ("🌐 Websites",       "magenta",     counts["web"]),
            "window":    ("🪟 Windows",        "yellow",      counts["window"]),
            "snapshots": ("📸 Snapshots",      "bright_red",  counts["snapshots"]),
            "typing":    ("⌨ Typing pulses",   "green",       counts["typing"]),
            "forms":     ("📝 Form submits",   "bright_cyan", counts["forms"]),
            "events":    ("⚙ Other events",    "white",       counts["events"]),
        }

        for cat_node in session_node.children:
            if not cat_node.data or cat_node.data == PLACEHOLDER:
                continue
            if cat_node.data[0] != "category":
                continue
            info = cat_info.get(cat_node.data[2])
            if not info:
                continue
            label, color, count = info
            t = Text()
            t.append(f"{label} ", style=color)
            t.append(f"({count})", style="dim")
            old = getattr(cat_node.label, "plain", str(cat_node.label))
            if old != t.plain:
                cat_node.set_label(t)

    def _reload_preserving_state(self):
        tree = self.query_one("#tree", Tree)

        expanded_sessions = set()
        expanded_cats = set()

        def walk(node):
            data = node.data
            if data and data != PLACEHOLDER:
                if data[0] == "session" and node.is_expanded:
                    expanded_sessions.add(data[1])
                elif data[0] == "category" and node.is_expanded:
                    expanded_cats.add((data[1], data[2]))
            for c in node.children:
                walk(c)

        walk(tree.root)
        self.reload()

        for node in tree.root.children:
            if not node.data or node.data[0] != "session":
                continue
            if node.data[1] not in expanded_sessions:
                continue
            node.expand()
            for cat in node.children:
                if not cat.data or cat.data == PLACEHOLDER:
                    continue
                if cat.data[0] != "category":
                    continue
                if (cat.data[1], cat.data[2]) in expanded_cats:
                    cat.expand()

    def reload(self):
        tree = self.query_one("#tree", Tree)
        tree.clear()
        self._last_sig = None
        sfilt = self.query_one("#tree-session-filter", Input).value.strip().lower()
        sessions = self.app.db.sessions(limit=500)
        if sfilt:
            sessions = [
                s for s in sessions
                if sfilt in (s["user"] or "").lower()
                or sfilt in (s["ip"] or "").lower()
                or sfilt in str(s["id"])
            ]
        for s in sessions:
            node = tree.root.add(self._session_label(s),
                                 data=("session", s["id"]))
            node.add_leaf("expand to load…", data=PLACEHOLDER)
        tree.root.expand()
        self.app.refresh_status()

    def _session_label(self, s) -> Text:
        live = not s["end_time"]
        t = Text()
        t.append("● ", style="bold green" if live else "dim")
        t.append(f"Session #{s['id']}", style="bold cyan")
        t.append("   ")
        t.append(f"👤 {s['user'] or '?'}", style="white")
        t.append("   ")
        t.append(f"🕒 {fmt_ts(s['start_time'])}", style="yellow")
        t.append("   ")
        if live:
            t.append("⏱ live", style="bold green")
        else:
            t.append(f"⏱ {fmt_dur(s['duration_s'])}", style="magenta")
        if s["ip"]:
            t.append("   ")
            t.append(f"🌐 {s['ip']}", style="dim")
        return t

    def _is_placeholder(self, node) -> bool:
        return (len(node.children) == 1
                and node.children[0].data == PLACEHOLDER)

    def on_tree_node_expanded(self, event: Tree.NodeExpanded):
        node = event.node
        if not node.data or node.data == PLACEHOLDER:
            return
        kind = node.data[0]
        if kind == "session" and self._is_placeholder(node):
            node.remove_children()
            self._populate_categories(node, node.data[1])
        elif kind == "category" and self._is_placeholder(node):
            node.remove_children()
            self._populate_items(node, node.data[1], node.data[2])

    def _populate_categories(self, session_node, sid):
        counts = self.app.db.session_counts(sid)
        cats = [
            ("files",     "📁 Files",          "cyan",        counts["files"]),
            ("web",       "🌐 Websites",       "magenta",     counts["web"]),
            ("window",    "🪟 Windows",        "yellow",      counts["window"]),
            ("snapshots", "📸 Snapshots",      "bright_red",  counts["snapshots"]),
            ("typing",    "⌨ Typing pulses",   "green",       counts["typing"]),
            ("forms",     "📝 Form submits",   "bright_cyan", counts["forms"]),
            ("events",    "⚙ Other events",    "white",       counts["events"]),
            ("wdiag",     "🔧 Window diagnostics", "dim",      None),
        ]
        cat_filter = self.query_one("#tree-cat-filter", Select).value

        for kind, label, color, count in cats:
            if cat_filter != "all" and cat_filter != kind:
                continue
            if count == 0 and kind not in ("window", "wdiag"):
                continue
            t = Text()
            t.append(f"{label} ", style=color)
            if count is not None:
                t.append(f"({count})", style="dim")
            cat_node = session_node.add(t, data=("category", sid, kind))
            cat_node.add_leaf("expand to load…", data=PLACEHOLDER)

    def _populate_items(self, cat_node, sid, kind):
        efilt = self.query_one("#tree-item-filter", Input).value.strip().lower()
        db = self.app.db

        if kind == "files":
            for r in db.session_files(sid, limit=self.MAX_ITEMS):
                if efilt and efilt not in (r["path"] or "").lower():
                    continue
                win = details_window(r.get("details"))
                t = Text()
                t.append(f"{fmt_ts_short(r['ts'])}  ", style="dim")
                t.append(f"{(r['action'] or '').ljust(10)}", style="cyan")
                t.append(short(r["path"], 120), style="white")
                if win.get("app"):
                    t.append(f"   [{win['app']}]", style="dim yellow")
                cat_node.add_leaf(t, data=("leaf", "file", r))

        elif kind == "web":
            for r in db.session_web(sid, limit=self.MAX_ITEMS):
                blob = f"{r['domain']} {r['title']} {r['url']}".lower()
                if efilt and efilt not in blob:
                    continue
                win = details_window(r.get("details"))
                t = Text()
                t.append(f"{fmt_ts_short(r['ts'])}  ", style="dim")
                t.append(f"{(r['domain'] or '')[:35]:<35}", style="magenta")
                t.append("  ")
                t.append(short(r["title"] or r["url"], 100), style="white")
                if win.get("app"):
                    t.append(f"   [{win['app']}]", style="dim yellow")
                cat_node.add_leaf(t, data=("leaf", "web", r))

        elif kind == "window":
            rows = db.session_windows(sid, limit=self.MAX_ITEMS)
            if not rows:
                cat_node.add_leaf(Text(
                    "(no focus spans yet — see 🔧 Window diagnostics)",
                    style="dim italic"))
            for r in rows:
                blob = f"{r['app']} {r['title']}".lower()
                if efilt and efilt not in blob:
                    continue
                dur = span_seconds(r["start_ts"], r["end_ts"])
                live = not r["end_ts"]
                app_txt = (r["app"] or "").strip() or "<unknown>"
                title_txt = (r["title"] or "").strip() or "<no title>"
                t = Text()
                t.append(f"{fmt_ts_short(r['start_ts'])}", style="dim")
                t.append(" → ", style="dim")
                if live:
                    t.append("live".ljust(8), style="bold green")
                else:
                    t.append(f"{fmt_ts_short(r['end_ts']):<8}", style="dim")
                t.append(f"  {fmt_dur(dur):>7}", style="magenta")
                t.append("  ")
                t.append(f"{app_txt[:18]:<18}", style="yellow")
                t.append("  ")
                t.append(short(title_txt, 100), style="white")
                cat_node.add_leaf(t, data=("leaf", "window", r))

        elif kind == "snapshots":
            for r in db.session_snapshots(sid):
                if efilt and efilt not in (r["path"] or "").lower():
                    continue
                t = Text()
                t.append(f"{fmt_ts_short(r['ts'])}  ", style="dim")
                t.append("📸 ", style="bright_red")
                t.append(short(r["path"], 140), style="white")
                cat_node.add_leaf(t, data=("leaf", "snapshot", r))

        elif kind == "typing":
            for r in db.session_typing(sid, limit=self.MAX_ITEMS):
                try:
                    d = json.loads(r["details"]) if r["details"] else {}
                except Exception:
                    d = {}
                win = d.get("window") or {}
                blob = f"{win.get('app','')} {win.get('title','')}".lower()
                if efilt and efilt not in blob:
                    continue
                t = Text()
                t.append(f"{fmt_ts_short(r['ts'])}  ", style="dim")
                t.append(f"{d.get('chars', 0):>5} chars", style="green")
                t.append("  ")
                t.append(f"{(win.get('app') or '<unknown>')[:20]:<20}",
                         style="yellow")
                t.append("  ")
                t.append(short(win.get("title") or "", 90), style="white")
                cat_node.add_leaf(t, data=("leaf", "typing", {**r, **d}))

        elif kind == "forms":
            for r in db.session_forms(sid, limit=self.MAX_ITEMS):
                blob = f"{r['url']} {r['field_names']}".lower()
                if efilt and efilt not in blob:
                    continue
                try:
                    d = json.loads(r["details"]) if r["details"] else {}
                except Exception:
                    d = {}
                win = d.get("window") or {}
                t = Text()
                t.append(f"{fmt_ts_short(r['ts'])}  ", style="dim")
                t.append(f"{(r['domain'] or '')[:30]:<30}", style="bright_cyan")
                t.append("  fields: ", style="dim")
                t.append(short(r["field_names"] or "", 60), style="white")
                if win.get("app"):
                    t.append(f"   [{win['app']}]", style="dim yellow")
                cat_node.add_leaf(t, data=("leaf", "form", {**r, **d}))

        elif kind == "events":
            for r in db.session_other_events(sid, limit=self.MAX_ITEMS):
                blob = f"{r['type']} {r['source']} {r['details']}".lower()
                if efilt and efilt not in blob:
                    continue
                t = Text()
                t.append(f"{fmt_ts_short(r['ts'])}  ", style="dim")
                t.append(f"{(r['type'] or ''):<16}", style="bold white")
                t.append(f"{(r['source'] or ''):<10}", style="dim")
                t.append(short(r["details"], 120), style="")
                cat_node.add_leaf(t, data=("leaf", "event", r))

        elif kind == "wdiag":
            for r in db.session_window_debug(sid):
                try:
                    d = json.loads(r["details"]) if r["details"] else {}
                except Exception:
                    d = {}
                t = Text()
                t.append(f"{fmt_ts_short(r['ts'])}  ", style="dim")
                t.append(f"{(r['type'] or ''):<14}", style="bold red")
                t.append(short(json.dumps(d, ensure_ascii=False), 150),
                         style="white")
                cat_node.add_leaf(t, data=("leaf", "wdiag", {**r, **d}))

        if not cat_node.children:
            cat_node.add_leaf(Text("(nothing matches filter)",
                                   style="dim italic"))

    def on_tree_node_selected(self, event: Tree.NodeSelected):
        node = event.node
        log = self.query_one("#tree-detail", RichLog)
        log.clear()
        if not node.data or node.data == PLACEHOLDER:
            log.write(Text("No details.", style="dim"))
            return
        kind = node.data[0]
        if kind == "session":
            self._show_session(log, node.data[1])
        elif kind == "category":
            self._show_category_summary(log, node.data[1], node.data[2])
        elif kind == "leaf":
            self._show_leaf(log, node.data[1], node.data[2])

    def _show_session(self, log, sid):
        rows = self.app.db.q("SELECT * FROM sessions WHERE id = ?", (sid,))
        if not rows:
            return
        s = rows[0]
        counts = self.app.db.session_counts(sid)
        log.write(Text(f"Session #{s['id']}", style="bold cyan"))
        log.write("")
        log.write(f"user       : {s['user']}")
        log.write(f"ip         : {s['ip']}")
        log.write(f"started    : {fmt_ts(s['start_time'])}")
        log.write(f"ended      : {fmt_ts(s['end_time']) or '(still running)'}")
        log.write("")
        log.write(Text("Contents", style="bold"))
        for k, v in counts.items():
            log.write(f"  {k:<12} : {v}")
        self._show_session_timeline(log, sid)

    def _show_session_timeline(self, log, sid):
        events, windows, snapshots = self.app.db.session_timeline(sid)
        entries = [
            (row["ts"], 0, row["id"], "event", row)
            for row in events
        ]
        entries.extend(
            (row["ts"], 1, row["id"], "window_start", row)
            for row in windows
        )
        entries.extend(
            (row["end_ts"], 3, row["id"], "window_end", row)
            for row in windows if row["end_ts"]
        )
        entries.extend(
            (row["ts"], 2, row["id"], "snapshot", row)
            for row in snapshots
        )
        entries.sort(key=self._timeline_sort_key)

        log.write("")
        log.write(Text("Timeline (oldest first)", style="bold"))
        log.write(Text(
            "  o = activity; "
            "# = focused-window start/end; S = snapshot",
                       style="dim"))
        if not entries:
            log.write(Text("  (no activity recorded for this session)",
                           style="dim italic"))
            return

        for index, (timeline_ts, _, _, kind, row) in enumerate(entries):
            time_label = fmt_ts(timeline_ts) or "unknown time"
            if kind in ("window_start", "window_end"):
                marker = "#"
                app = (row["app"] or "").strip() or "<unknown app>"
                title = (row["title"] or "").strip()
                action = "Focus ended" if kind == "window_end" else "Focus started"
                label = f"{action}: {app}"
                if title:
                    label += f" — {title}"
                metadata = []
                if row["window_id"]:
                    metadata.append(f"window: {row['window_id']}")
                if row["pid"] is not None:
                    metadata.append(f"pid: {row['pid']}")
                if metadata:
                    label += f" ({', '.join(metadata)})"
                duration = span_seconds(row["start_ts"], row["end_ts"])
                if duration is not None:
                    label += f" — {fmt_dur(duration)}"
            elif kind == "snapshot":
                marker = "S"
                label = f"Camera snapshot: {row['path']}"
                if row["consent"] is not None:
                    label += f" — consent: {'yes' if row['consent'] else 'no'}"
            else:
                marker = "o"
                label = self._timeline_event_label(row)

            log.write(Text(f"{time_label}  {marker}-- {label}", style=""))
            if index + 1 < len(entries):
                log.write(Text("          |", style="dim"))

    @staticmethod
    def _timeline_sort_key(entry):
        ts, priority, row_id, _, _ = entry
        try:
            parsed = datetime.datetime.fromisoformat(
                (ts or "").replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(
                    datetime.timezone.utc).replace(tzinfo=None)
            return 0, parsed, priority, row_id
        except (TypeError, ValueError):
            return 1, str(ts or ""), priority, row_id

    @staticmethod
    def _timeline_event_label(row):
        event_type = row["type"] or "event"
        try:
            details = json.loads(row["details"]) if row["details"] else {}
        except (TypeError, ValueError):
            details = {"info": row["details"]} if row["details"] else {}
        if not isinstance(details, dict):
            details = {"info": details}

        fields = dict(details)
        window = fields.get("window")
        window = window if isinstance(window, dict) else {}
        browser = fields.get("browser")
        browser_label = SessionTreePane._timeline_browser_name(browser)
        url = fields.get("url") or fields.get("form_action") or ""
        domain = urlparse(url).netloc or url

        if event_type == "web":
            label = f"Open {domain or 'website'} : {browser_label}"
            consumed = {"browser"}
        elif event_type == "file":
            action = (fields.get("action") or "access").lower()
            action_labels = {
                "created": "Create",
                "modified": "Modify",
                "deleted": "Delete",
                "moved": "Move",
            }
            label = (
                f"{action_labels.get(action, action.title())} file: "
                f"{fields.get('path') or 'unknown path'}"
            )
            app = window.get("app") or fields.get("process")
            if app:
                label += f" : {app}"
            consumed = {"action", "path", "process"}
        elif event_type == "form_submit":
            label = f"Submit form on {domain or 'website'}"
            if browser:
                label += f" : {browser_label}"
            consumed = {"form_action", "browser"}
        elif event_type == "download":
            filename = fields.get("filename") or url or "file"
            label = f"Download {filename}"
            if browser:
                label += f" : {browser_label}"
            consumed = {"filename", "browser"}
        elif event_type == "command":
            command = fields.get("cmdline") or fields.get("name") or "command"
            label = f"Run {command}"
            if fields.get("cwd"):
                label += f" : {fields['cwd']}"
            consumed = {"cmdline", "name", "cwd"}
        elif event_type == "typing":
            count = fields.get("chars")
            if count is not None:
                label = f"Typing activity: {count} keystrokes"
                if window.get("app"):
                    label += f" : {window['app']}"
            else:
                label = "Typing monitor started"
            consumed = {"chars", "window"}
        elif event_type in ("window_open", "window_close"):
            info = fields
            action = "Open window" if event_type == "window_open" else "Close window"
            label = f"{action}: {info.get('title') or 'untitled'}"
            if info.get("app"):
                label += f" : {info['app']}"
            consumed = {"title", "app"}
        else:
            labels = {
                "session_start": "Session started",
                "session_end": "Session ended",
                "window_debug": "Window tracking status",
                "window_error": "Window capture issue",
                "file_monitor": "File monitoring status",
                "file_monitor_error": "File monitoring issue",
                "screen_lock": "Screen locked",
                "screen_unlock": "Screen unlocked",
                "camera": "Camera event",
                "face_lock": "Face-lock result",
                "hotkey_error": "Shortcut issue",
                "status": "Status changed",
            }
            label = labels.get(
                event_type,
                event_type.replace("_", " ").capitalize(),
            )
            consumed = set()

        remaining = {
            key: value for key, value in fields.items()
            if key not in consumed and value not in ("", None, [], {})
        }
        if isinstance(remaining.get("window"), dict):
            window_fields = dict(remaining["window"])
            app = window_fields.get("app")
            if app and (
                app == window.get("app")
                and (event_type == "file" or str(app).casefold()
                     == str(browser or "").casefold())
            ):
                window_fields.pop("app")
            if window_fields:
                remaining["window"] = window_fields
            else:
                remaining.pop("window")
        if remaining:
            field_order = {
                "status": 0,
                "reason": 1,
                "error": 2,
                "title": 3,
                "url": 4,
                "window": 5,
                "fix": 6,
            }
            label += " — " + "; ".join(
                f"{SessionTreePane._timeline_field_name(key)}: "
                f"{SessionTreePane._timeline_field_value(value)}"
                for key, value in sorted(
                    remaining.items(),
                    key=lambda item: (
                        field_order.get(item[0], 7), item[0]
                    ),
                )
            )
        return label

    @staticmethod
    def _timeline_browser_name(browser):
        if not browser:
            return "Browser"
        names = {
            "brave": "Brave",
            "chrome": "Chrome",
            "chromium": "Chromium",
            "edge": "Microsoft Edge",
            "firefox": "Firefox",
            "msedge": "Microsoft Edge",
            "safari": "Safari",
        }
        return names.get(str(browser).strip().casefold(),
                         str(browser).strip().title())

    @staticmethod
    def _timeline_field_name(name):
        labels = {
            "cmdline": "command",
            "cwd": "folder",
            "file_size": "file size",
            "field_names": "form fields",
            "form_action": "form action",
            "pid": "process ID",
            "ppid": "parent process ID",
            "title": "title",
            "url": "URL",
            "wm_class": "window class",
            "wm_class_instance": "window class",
            "best_similarity": "best match",
            "face_count": "faces detected",
            "global_shortcut": "shortcut",
            "logging_active": "logging",
            "face_lock_active": "face lock",
        }
        return labels.get(name, name.replace("_", " "))

    @staticmethod
    def _timeline_field_value(value):
        if isinstance(value, dict):
            return "; ".join(
                f"{SessionTreePane._timeline_field_name(key)}: "
                f"{SessionTreePane._timeline_field_value(item)}"
                for key, item in value.items()
                if item not in ("", None, [], {})
            )
        if isinstance(value, (list, tuple)):
            return ", ".join(
                SessionTreePane._timeline_field_value(item)
                for item in value
            )
        if isinstance(value, bool):
            return "yes" if value else "no"
        if value is None:
            return ""
        return str(value).replace("\n", " ")

    def _show_category_summary(self, log, sid, kind):
        counts = self.app.db.session_counts(sid)
        log.write(Text(f"{kind}  —  session #{sid}", style="bold cyan"))
        log.write("")
        if kind in counts:
            log.write(f"count: {counts[kind]}")
        log.write("")
        log.write(Text("Expand the category to see individual items.",
                       style="dim"))

    def _show_leaf(self, log, kind, row):
        if kind == "file":
            win = details_window(row.get("details"))
            log.write(Text("File event", style="bold cyan"))
            log.write("")
            log.write(f"time    : {fmt_ts(row.get('ts'))}")
            log.write(f"action  : {row.get('action')}")
            log.write(f"path    : {row.get('path')}")
            if win:
                log.write("")
                log.write(Text("Focused window at time of event", style="bold"))
                log.write(f"  app   : {win.get('app')}")
                log.write(f"  title : {win.get('title')}")
                log.write(f"  pid   : {win.get('pid')}")
        elif kind == "web":
            win = details_window(row.get("details"))
            log.write(Text("Web visit", style="bold magenta"))
            log.write("")
            log.write(f"time    : {fmt_ts(row.get('ts'))}")
            log.write(f"domain  : {row.get('domain')}")
            log.write(f"browser : {row.get('browser')}")
            log.write(f"title   : {row.get('title')}")
            log.write(f"url     : {row.get('url')}")
            if win:
                log.write("")
                log.write(f"focused window : {win.get('app')} — {win.get('title')}")
        elif kind == "window":
            log.write(Text("Window focus span", style="bold yellow"))
            log.write("")
            log.write(f"start     : {fmt_ts(row.get('start_ts'))}")
            log.write(f"end       : {fmt_ts(row.get('end_ts')) or '(live)'}")
            dur = span_seconds(row.get('start_ts'), row.get('end_ts'))
            log.write(f"duration  : {fmt_dur(dur)}")
            log.write(f"window_id : {row.get('window_id')}")
            log.write(f"app       : {row.get('app')}")
            log.write(f"title     : {row.get('title')}")
            if row.get("pid"):
                log.write(f"pid       : {row.get('pid')}")
        elif kind == "snapshot":
            log.write(Text("Snapshot", style="bold bright_red"))
            log.write("")
            log.write(f"time    : {fmt_ts(row.get('ts'))}")
            log.write(f"path    : {row.get('path')}")
        elif kind == "typing":
            win = row.get("window") or {}
            log.write(Text("Typing pulse", style="bold green"))
            log.write("")
            log.write(f"time   : {fmt_ts(row.get('ts'))}")
            log.write(f"chars  : {row.get('chars')}   (count only — no content)")
            log.write("")
            log.write(f"app    : {win.get('app')}")
            log.write(f"title  : {win.get('title')}")
        elif kind == "form":
            win = row.get("window") or {}
            log.write(Text("Form submit", style="bold bright_cyan"))
            log.write("")
            log.write(f"time        : {fmt_ts(row.get('ts'))}")
            log.write(f"domain      : {row.get('domain')}")
            log.write(f"url         : {row.get('url')}")
            log.write(f"form action : {row.get('form_action')}")
            log.write(f"fields      : {row.get('field_names')}")
            log.write("")
            log.write(Text("Field values are never captured.",
                           style="dim italic"))
            if win:
                log.write("")
                log.write(f"focused window : {win.get('app')} — {win.get('title')}")
        elif kind == "wdiag":
            log.write(Text("Window diagnostics", style="bold red"))
            log.write("")
            log.write(f"time   : {fmt_ts(row.get('ts'))}")
            log.write(f"type   : {row.get('type')}")
            log.write("")
            try:
                d = json.loads(row.get("details") or "{}")
                log.write(json.dumps(d, indent=2, ensure_ascii=False))
            except Exception:
                log.write(row.get("details") or "")
        elif kind == "event":
            log.write(Text(f"Event: {row.get('type')}", style="bold white"))
            log.write("")
            log.write(f"time   : {fmt_ts(row.get('ts'))}")
            log.write(f"source : {row.get('source')}")
            try:
                d = json.loads(row.get("details") or "{}")
                log.write("")
                log.write(json.dumps(d, indent=2, ensure_ascii=False))
            except Exception:
                log.write("")
                log.write(row.get("details") or "")

    def action_reload(self):
        self.reload()

    def action_expand_all(self):
        self.query_one("#tree", Tree).root.expand_all()

    def action_collapse_all(self):
        tree = self.query_one("#tree", Tree)
        tree.root.collapse_all()
        tree.root.expand()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "tree-reload":
            self.reload()
        elif event.button.id == "tree-auto":
            if self._auto_timer is not None:
                self._auto_timer.stop()
                self._auto_timer = None
                event.button.label = "Auto ○"
                self.app.notify("Auto-refresh off", timeout=1)
            else:
                self._auto_timer = self.set_interval(
                    self.auto_refresh_seconds, self._auto_tick)
                event.button.label = "Auto ●"
                self.app.notify(
                    f"Auto-refresh every {self.auto_refresh_seconds:.0f}s",
                    timeout=1)

    def on_input_submitted(self, event: Input.Submitted):
        if event.input.id in ("tree-session-filter",):
            self.reload()

    def on_select_changed(self, event: Select.Changed):
        if event.select.id == "tree-cat-filter":
            self.reload()


TYPE_STYLES = {
    "session_start": "bold green",
    "session_end": "bold red",
    "file": "cyan",
    "web": "magenta",
    "window_open": "bold yellow",
    "window_close": "dim yellow",
    "window_debug": "dim cyan",
    "window_error": "bold red",
    "typing": "green",
    "form_submit": "bright_cyan",
    "camera": "bright_red",
    "face_lock": "bright_magenta",
    "status": "dim",
}


class LiveTail(Vertical):
    BINDINGS = [
        Binding("c", "clear", "Clear"),
        Binding("p", "toggle_pause", "Pause/Resume"),
    ]

    def __init__(self, db_path: Path):
        super().__init__()
        self.db_path = db_path
        self._last_id = None
        self.paused = False
        self.filter_type = None
        self.poll_interval = 1.0

    def compose(self) -> ComposeResult:
        with Horizontal(classes="toolbar"):
            yield Static("[b]Live Tail[/b]", classes="title")
            yield Select(
                options=[
                    ("All", "all"), ("Files", "file"), ("Web", "web"),
                    ("Windows", "window"), ("Sessions", "session"),
                    ("Typing", "typing"),
                    ("Forms", "form_submit"), ("Camera", "camera"),
                    ("Face Lock", "face_lock"),
                    ("Window errors", "werr"),
                ],
                value="all", id="tail-filter", allow_blank=False,
            )
            yield Input(placeholder="grep text…", id="tail-grep")
            yield Button("Pause", id="tail-pause")
            yield Button("Clear", id="tail-clear")
            yield Static("", id="tail-status", classes="hint")
        yield RichLog(id="tail-log", highlight=True, markup=True, wrap=True)

    def on_mount(self):
        conn = sqlite3.connect(str(self.db_path))
        try:
            row = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()
            self._last_id = row[0] if row else 0
        finally:
            conn.close()
        self.query_one("#tail-log", RichLog).write(
            Text(f"[tail] following from event id > {self._last_id}", style="dim"))
        self._update_status()
        self.poll_events()

    @work(exclusive=True, thread=True)
    def poll_events(self):
        worker = get_current_worker()
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")
        try:
            while not worker.is_cancelled:
                if not self.paused:
                    try:
                        rows = conn.execute(
                            "SELECT id, session_id, ts, type, source, details "
                            "FROM events WHERE id > ? ORDER BY id ASC LIMIT 200",
                            (self._last_id,),
                        ).fetchall()
                    except sqlite3.OperationalError:
                        rows = []
                    batch = []
                    for r in rows:
                        r = dict(r)
                        self._last_id = r["id"]
                        if self.filter_type and self.filter_type != "all":
                            if self.filter_type == "session":
                                if r["type"] not in ("session_start",
                                                     "session_end", "status"):
                                    continue
                            elif self.filter_type == "window":
                                if not r["type"].startswith("window"):
                                    continue
                            elif self.filter_type == "werr":
                                if r["type"] != "window_error":
                                    continue
                            elif r["type"] != self.filter_type:
                                continue
                        grep = self._grep_text()
                        if grep and grep not in (r["details"] or "").lower() \
                                and grep not in (r["type"] or "").lower() \
                                and grep not in (r["source"] or "").lower():
                            continue
                        batch.append(r)
                    if batch:
                        self.app.call_from_thread(self._append_batch, batch)
                time.sleep(self.poll_interval)
        finally:
            conn.close()

    def _grep_text(self):
        try:
            return self.query_one("#tail-grep", Input).value.strip().lower()
        except Exception:
            return ""

    def _append_batch(self, rows):
        if not rows:
            return
        log = self.query_one("#tail-log", RichLog)

        try:
            at_bottom = (log.max_scroll_y - log.scroll_offset.y) <= 2
        except Exception:
            at_bottom = True

        lines = []
        for r in rows:
            style = TYPE_STYLES.get(r["type"], "white")
            ts = fmt_ts_short(r["ts"])
            lines.append(
                f"[dim]{ts}[/dim] "
                f"[dim]#{r['id']:<5}[/dim] "
                f"[dim]s{r['session_id']:<3}[/dim] "
                f"[{style}]{r['type']:<14}[/{style}] "
                f"[dim]{r['source']:<10}[/dim]"
            )
            detail = self._format_detail(r["type"], r["details"])
            if detail:
                lines.append(f"    {detail}")

        log.write("\n".join(lines))

        if at_bottom:
            try:
                log.scroll_end(animate=False)
            except Exception:
                pass

    def _format_detail(self, type_, raw):
        try:
            d = json.loads(raw) if raw else {}
        except Exception:
            return raw or ""
        if type_ == "file":
            win = d.get("window") or {}
            s = f"{d.get('action','')}  {d.get('path','')}"
            if win.get("app"):
                s += f"   [{win['app']}]"
            return s
        if type_ == "web":
            win = d.get("window") or {}
            s = f"{d.get('domain','')}  {d.get('title','')}"
            if win.get("app"):
                s += f"   [{win['app']}]"
            return s
        if type_ == "typing":
            win = d.get("window") or {}
            return (f"{d.get('chars',0)} chars  "
                    f"[{win.get('app','?')}]  {win.get('title','')[:60]}")
        if type_ == "form_submit":
            return (f"{d.get('domain','')}  fields={d.get('field_names',[])}  "
                    f"action={d.get('form_action','')}")
        if type_.startswith("window"):
            if type_ == "window_debug":
                return short(json.dumps(d, ensure_ascii=False), 140)
            if type_ == "window_error":
                return f"{d.get('reason','')}  fix={d.get('fix','')}"
            return (f"{d.get('app','')}  {d.get('title','')}  "
                    f"[{d.get('window_id','')}]")
        if type_ == "session_start":
            return (f"user={d.get('user','')}  ip={d.get('ip','')}  "
                    f"boot={d.get('boot_id','')}")
        if type_ == "camera":
            return f"snapshot: {d.get('path','')}"
        if type_ == "face_lock":
            action = d.get("action", "")
            reason = d.get("reason", "")
            sim = d.get("similarity", "")
            if sim != "":
                return f"[{action.upper()}] {reason} (sim={sim})"
            return f"[{action.upper()}] {reason}"
        return json.dumps(d, ensure_ascii=False)

    def _update_status(self):
        try:
            status = self.query_one("#tail-status", Static)
        except Exception:
            return
        state = "PAUSED" if self.paused else "LIVE"
        color = "red" if self.paused else "green"
        flt = self.filter_type or "all"
        status.update(f"[{color}]{state}[/{color}]  filter={flt}  "
                      f"last_id={self._last_id}")

    def action_clear(self):
        self.query_one("#tail-log", RichLog).clear()
        self.notify("Cleared", timeout=1)

    def action_toggle_pause(self):
        self.paused = not self.paused
        self.query_one("#tail-pause", Button).label = (
            "Resume" if self.paused else "Pause")
        self._update_status()

    def on_select_changed(self, event: Select.Changed):
        if event.select.id == "tail-filter":
            self.filter_type = None if event.value == "all" else event.value
            self._update_status()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "tail-pause":
            self.action_toggle_pause()
        elif event.button.id == "tail-clear":
            self.action_clear()

    def on_input_changed(self, event: Input.Changed):
        if event.input.id == "tail-grep":
            self._update_status()


class FilesPane(Vertical):
    def compose(self) -> ComposeResult:
        with Horizontal(classes="toolbar"):
            yield Input(placeholder="Filter path…", id="files-search")
            yield Button("Refresh", id="files-refresh")
        yield DataTable(id="files-table", zebra_stripes=True, cursor_type="row")

    def on_mount(self):
        t = self.query_one("#files-table", DataTable)
        t.add_columns("ID", "Sess", "Time", "Action", "Path", "Process", "User")
        if getattr(self.app, "db", None) is not None:
            self.reload()

    def reload(self):
        if getattr(self.app, "db", None) is None:
            return
        search = self.query_one("#files-search", Input).value.strip() or None
        rows = self.app.db.file_events(search=search)
        t = self.query_one("#files-table", DataTable)
        t.clear()
        for r in rows:
            t.add_row(
                str(r["id"]), str(r["session_id"] or ""),
                fmt_ts(r["ts"]), r["action"] or "",
                short(r["path"], 70), r["process"] or "", r["user"] or "",
                key=str(r["id"]),
            )

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "files-refresh":
            self.reload()

    def on_input_submitted(self, event: Input.Submitted):
        self.reload()


class WebPane(Vertical):
    def compose(self) -> ComposeResult:
        with Horizontal(classes="toolbar"):
            yield Input(placeholder="Filter url / title / domain…", id="web-search")
            yield Button("Refresh", id="web-refresh")
        yield DataTable(id="web-table", zebra_stripes=True, cursor_type="row")

    def on_mount(self):
        t = self.query_one("#web-table", DataTable)
        t.add_columns("ID", "Sess", "Time", "Domain", "Title", "Browser")
        if getattr(self.app, "db", None) is not None:
            self.reload()

    def reload(self):
        if getattr(self.app, "db", None) is None:
            return
        search = self.query_one("#web-search", Input).value.strip() or None
        rows = self.app.db.web_events(search=search)
        t = self.query_one("#web-table", DataTable)
        t.clear()
        for r in rows:
            t.add_row(
                str(r["id"]), str(r["session_id"] or ""),
                fmt_ts(r["ts"]), r["domain"] or "",
                short(r["title"], 60), r["browser"] or "",
                key=str(r["id"]),
            )

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "web-refresh":
            self.reload()

    def on_input_submitted(self, event: Input.Submitted):
        self.reload()


class SnapshotsPane(Vertical):
    BINDINGS = [Binding("o", "open_snapshot", "Open")]

    def compose(self) -> ComposeResult:
        with Horizontal(classes="toolbar"):
            yield Button("Refresh", id="snaps-refresh")
            yield Button("Open", id="snaps-open")
            yield Label("(o to open selected)", classes="hint")
        yield DataTable(id="snaps-table", zebra_stripes=True, cursor_type="row")

    def on_mount(self):
        t = self.query_one("#snaps-table", DataTable)
        t.add_columns("ID", "Session", "Time", "Consent", "Path")
        if getattr(self.app, "db", None) is not None:
            self.reload()

    def reload(self):
        if getattr(self.app, "db", None) is None:
            return
        rows = self.app.db.snapshots()
        t = self.query_one("#snaps-table", DataTable)
        t.clear()
        for r in rows:
            t.add_row(
                str(r["id"]), str(r["session_id"]),
                fmt_ts(r["ts"]), "yes" if r["consent"] else "no",
                r["path"] or "", key=str(r["id"]),
            )

    def _selected_path(self):
        t = self.query_one("#snaps-table", DataTable)
        if t.cursor_row is None:
            return None
        try:
            return t.get_row_at(t.cursor_row)[-1]
        except Exception:
            return None

    def action_open_snapshot(self):
        p = self._selected_path()
        if p and os.path.exists(p):
            open_path(p)
        else:
            self.app.notify("File not found", severity="warning", timeout=2)

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "snaps-refresh":
            self.reload()
        elif event.button.id == "snaps-open":
            self.action_open_snapshot()


class CommandsPane(Vertical):
    def compose(self) -> ComposeResult:
        with Horizontal(classes="toolbar"):
            yield Input(placeholder="Filter commands / process / user…", id="cmds-search")
            yield Button("Refresh", id="cmds-refresh")
        yield DataTable(id="cmds-table", zebra_stripes=True, cursor_type="row")

    def on_mount(self):
        t = self.query_one("#cmds-table", DataTable)
        t.add_columns("ID", "Sess", "Time", "PID", "PPID", "Name", "Command Line", "User")
        if getattr(self.app, "db", None) is not None:
            self.reload()

    def reload(self):
        if getattr(self.app, "db", None) is None:
            return
        search = self.query_one("#cmds-search", Input).value.strip() or None
        rows = self.app.db.command_events(search=search)
        t = self.query_one("#cmds-table", DataTable)
        t.clear()
        for r in rows:
            t.add_row(
                str(r["id"]), str(r["session_id"] or ""),
                fmt_ts(r["ts"]), str(r["pid"] or ""), str(r["ppid"] or ""),
                r["name"] or "", short(r["cmdline"], 80), r["user"] or "",
                key=str(r["id"]),
            )

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "cmds-refresh":
            self.reload()

    def on_input_submitted(self, event: Input.Submitted):
        self.reload()


class SearchPane(Vertical):
    def compose(self) -> ComposeResult:
        with Horizontal(classes="toolbar"):
            yield Input(placeholder="Search all events (type, source, details)…", id="search-query")
            yield Button("Search", id="search-btn")
        yield DataTable(id="search-table", zebra_stripes=True, cursor_type="row")

    def on_mount(self):
        t = self.query_one("#search-table", DataTable)
        t.add_columns("ID", "Sess", "Time", "Type", "Source", "Details")
        if getattr(self.app, "db", None) is not None:
            self.reload()

    def reload(self):
        if getattr(self.app, "db", None) is None:
            return
        query = self.query_one("#search-query", Input).value.strip() or None
        rows = self.app.db.advanced_search(query=query)
        t = self.query_one("#search-table", DataTable)
        t.clear()
        for r in rows:
            t.add_row(
                str(r["id"]), str(r["session_id"] or ""),
                fmt_ts(r["ts"]), r["type"] or "", r["source"] or "",
                short(r["details"], 90),
                key=str(r["id"]),
            )

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "search-btn":
            self.reload()

    def on_input_submitted(self, event: Input.Submitted):
        self.reload()


class AuditTUI(App):
    CSS = """
    Screen { layout: vertical; }
    .toolbar { height: 3; padding: 0 1; }
    .toolbar Input { width: 1fr; }
    .toolbar Button { width: 12; margin-left: 1; }
    .toolbar Select { width: 22; margin-left: 1; }
    #face-lock-toggle { width: 24; }
    #face-lock-status { width: 1fr; }
    .title { width: auto; padding: 0 1; }
    .hint { padding: 1; color: $text-muted; width: auto; }
    DataTable { height: 1fr; }
    #tree-split { height: 1fr; }
    #tree { width: 62%; border-right: solid $primary; }
    #tree-detail { width: 38%; padding: 0 1; }
    #tail-log { height: 1fr; padding: 0 1; }
    #tail-status { width: auto; padding: 0 1; }
    #status-bar { height: 1; background: $boost; padding: 0 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("1", "tab_tree", "Sessions"),
        Binding("2", "tab_live", "Live"),
        Binding("3", "tab_files", "Files"),
        Binding("4", "tab_web", "Web"),
        Binding("5", "tab_snaps", "Snaps"),
        Binding("6", "tab_cmds", "Commands"),
        Binding("7", "tab_search", "Search"),
        Binding("ctrl+p", "toggle_dark", "Theme"),
    ]

    def __init__(self, db_path: Path, config_path: Path = Path("config.json")):
        super().__init__()
        self.db_path = db_path
        self.db: DB = DB(db_path)
        self.web_server_port = 8765
        self.face_lock_enabled = False
        try:
            cfg_path = Path(config_path)
            if cfg_path.exists():
                cfg = json.loads(cfg_path.read_text())
                self.web_server_port = int(cfg.get("web_server_port", 8765))
                self.face_lock_enabled = bool(
                    cfg.get("face_lock", {}).get("enabled", False))
                SessionTreePane.auto_refresh_seconds = float(
                    cfg.get("tui_auto_refresh_seconds", 5.0))
        except Exception:
            pass

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(classes="toolbar"):
            yield Button("Toggle Face Lock", id="face-lock-toggle", variant="primary")
            yield Static("Face Lock: checking agent…", id="face-lock-status")
        with TabbedContent(initial="tab-tree"):
            with TabPane("Sessions", id="tab-tree"):
                yield SessionTreePane()
            with TabPane("Live", id="tab-live"):
                yield LiveTail(self.db_path)
            with TabPane("Files", id="tab-files"):
                yield FilesPane()
            with TabPane("Web", id="tab-web"):
                yield WebPane()
            with TabPane("Snapshots", id="tab-snaps"):
                yield SnapshotsPane()
            with TabPane("Commands", id="tab-cmds"):
                yield CommandsPane()
            with TabPane("Search", id="tab-search"):
                yield SearchPane()
        yield Static(id="status-bar")
        yield Footer()

    def on_mount(self):
        self.title = "Audit Agent — Viewer"
        self.sub_title = str(self.db_path)
        self.refresh_status()
        self.sync_face_lock()
        for pane_cls in (FilesPane, WebPane, SnapshotsPane, CommandsPane, SearchPane):
            for pane in self.query(pane_cls):
                try:
                    pane.reload()
                except Exception:
                    pass

    @work(exclusive=True, thread=True)
    def sync_face_lock(self, enabled=None):
        from urllib.request import Request, urlopen

        url = f"http://127.0.0.1:{self.web_server_port}/face-lock"
        request = Request(url, method="GET")
        data = None
        if enabled is not None:
            data = json.dumps({"enabled": bool(enabled)}).encode("utf-8")
            request = Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

        try:
            with urlopen(request, timeout=2) as response:
                payload = json.loads(response.read().decode("utf-8"))
            state = payload.get("enabled")
            if type(state) is not bool:
                raise ValueError("Agent returned an invalid face-lock status")
        except Exception as exc:
            self.app.call_from_thread(self._update_face_lock_status, None, str(exc))
            return
        self.app.call_from_thread(self._update_face_lock_status, state, None)

    def _update_face_lock_status(self, enabled, error):
        button = self.query_one("#face-lock-toggle", Button)
        if error:
            self.query_one("#face-lock-status", Static).update(
                "Face Lock: agent unavailable")
            button.label = f"Turn Face Lock {'OFF' if self.face_lock_enabled else 'ON'}"
            button.disabled = False
            self.notify(
                f"Could not contact the running agent: {error}",
                severity="warning",
                timeout=4,
            )
            return

        self.face_lock_enabled = enabled
        self.query_one("#face-lock-status", Static).update(
            f"Face Lock: {'ON' if enabled else 'OFF'}")
        button.label = f"Turn Face Lock {'OFF' if enabled else 'ON'}"
        button.disabled = False

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "face-lock-toggle":
            event.button.disabled = True
            self.sync_face_lock(not self.face_lock_enabled)

    def refresh_status(self):
        try:
            c = self.db.counts()
        except sqlite3.OperationalError as e:
            self.query_one("#status-bar", Static).update(
                f"DB: {self.db_path}   [error: {e}]")
            return
        bar = self.query_one("#status-bar", Static)
        bar._audit_text = (
            f"DB: {self.db_path}   "
            f"sessions={c['sessions']}  events={c['events']}  "
            f"files={c['files']}  web={c['web']}  "
            f"commands={c.get('commands', 0)}  downloads={c.get('downloads', 0)}  "
            f"spans={c['wact']}  forms={c['forms']}  snaps={c['snaps']}"
        )
        bar.update(bar._audit_text)

    def action_refresh(self):
        for pane_cls in (SessionTreePane, FilesPane, WebPane, SnapshotsPane, CommandsPane, SearchPane):
            for pane in self.query(pane_cls):
                try:
                    pane.reload()
                except Exception:
                    pass
        self.refresh_status()
        self.notify("Refreshed", timeout=1)

    def action_tab_tree(self):
        self.query_one(TabbedContent).active = "tab-tree"
    def action_tab_live(self):
        self.query_one(TabbedContent).active = "tab-live"
    def action_tab_files(self):
        self.query_one(TabbedContent).active = "tab-files"
    def action_tab_web(self):
        self.query_one(TabbedContent).active = "tab-web"
    def action_tab_snaps(self):
        self.query_one(TabbedContent).active = "tab-snaps"
    def action_tab_cmds(self):
        self.query_one(TabbedContent).active = "tab-cmds"
    def action_tab_search(self):
        self.query_one(TabbedContent).active = "tab-search"

    def action_toggle_dark(self):
        self.dark = not self.dark


def run_tui(db_path: Path, config_path: Path = Path("config.json")):
    if not _HAS_TEXTUAL:
        raise SystemExit(
            "Textual is not installed in the current environment.\n"
            "To launch the TUI viewer, install it with:\n"
            "    pip install textual rich\n")
    if not db_path.exists():
        raise SystemExit(
            f"Database not found: {db_path}\n"
            f"Run the agent first:  python main.py agent")
    c = sqlite3.connect(str(db_path))
    try:
        c.execute("SELECT 1 FROM sessions LIMIT 1")
    except sqlite3.OperationalError as e:
        raise SystemExit(
            f"{db_path} exists but has no audit tables.\n"
            f"Underlying error: {e}")
    finally:
        c.close()
    AuditTUI(db_path, config_path).run()


# ===========================================================================
# PART 3 — CLI
# ===========================================================================

DEFAULT_CONFIG = {
    "db_path": "audit.db",
    "snapshot_dir": "snapshots",
    "monitor_dirs": ["~/Documents", "~/Desktop"],
    "window_poll_seconds": 3,
    "window_debug": False,
    "camera_snapshot": False,
    "camera_index": 0,
    "camera_width": 1280,
    "camera_height": 720,
    "camera_warmup_frames": 15,
    "camera_settle_seconds": 1.2,
    "camera_best_of": 5,
    "typing_pulse_seconds": 5.0,
    "tui_auto_refresh_seconds": 5.0,
    "retention_days": 30,
    "web_server_port": 8765,
    "face_lock": {
        "enabled": False,
        "interval_seconds": 15,
        "similarity_threshold": 0.363,
        "consecutive_failures_to_lock": 1,
        "lock_on_no_face": True,
        "lock_on_multiple_faces": True,
        "lock_on_unauthorized": True,
        "faces_dir": "faces",
        "models_dir": "models",
        "notify_on_lock": True,
        "camera_index": 0,
        "camera_warmup_frames": 3,
    },
}


def write_default_config(path: Path):
    if not path.exists():
        path.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
        print(f"Wrote default config: {path}")


def cli_search(db_path: Path, query=None, event_type=None, sid=None, limit=50):
    if not db_path.exists():
        raise SystemExit(f"Database not found: {db_path}")
    db = DB(db_path)
    results = db.advanced_search(query=query, event_type=event_type, sid=sid, limit=limit)
    print(f"Found {len(results)} matching events in {db_path}:")
    print("-" * 80)
    for r in results:
        ts = fmt_ts(r["ts"])
        etype = (r["type"] or "").ljust(12)
        source = (r["source"] or "").ljust(12)
        det = short(r["details"], 50)
        print(f"[{ts}] ID={r['id']} Sess={r['session_id']} {etype} {source} {det}")


def cli_export(db_path: Path, out_path=None, fmt="json"):
    if not db_path.exists():
        raise SystemExit(f"Database not found: {db_path}")
    db = DB(db_path)
    events = db.q(
        "SELECT * FROM events WHERE type != 'command' OR source = 'user_command' "
        "ORDER BY id ASC")
    commands = db.command_events(limit=1000000)
    files = db.q("SELECT * FROM file_access ORDER BY id ASC")
    web = db.q("SELECT * FROM web_visits ORDER BY id ASC")
    downloads = db.q("SELECT * FROM web_downloads ORDER BY id ASC")

    data = {
        "exported_at": datetime.datetime.now().isoformat(),
        "database": str(db_path),
        "events": events,
        "commands": commands,
        "file_access": files,
        "web_visits": web,
        "web_downloads": downloads,
    }

    if not out_path:
        out_path = f"audit_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"

    out_file = Path(out_path)
    if fmt == "json":
        out_file.write_text(json.dumps(data, indent=2))
    elif fmt == "csv":
        import csv
        with open(out_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["id", "session_id", "ts", "type", "source", "details"])
            for r in events:
                writer.writerow([r.get("id"), r.get("session_id"), r.get("ts"),
                                 r.get("type"), r.get("source"), r.get("details")])
    print(f"Exported {len(events)} events to {out_file.resolve()}")


def main():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Transparent audit agent + TUI viewer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_agent = sub.add_parser("agent", help="Run the background logger")
    p_agent.add_argument("--config", default="config.json")
    p_agent.add_argument(
        "--face-lock",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Override the config and turn webcam face lock on or off",
    )

    p_tui = sub.add_parser("tui", help="Run the TUI viewer")
    p_tui.add_argument("--db", default="audit.db")
    p_tui.add_argument("--config", default="config.json")

    sub.add_parser("init", help="Write a default config.json")

    p_enroll = sub.add_parser("enroll-face", help="Enroll authorized face for webcam auto-lock")
    p_enroll.add_argument("--camera", type=int, default=0, help="Webcam index (default 0)")
    p_enroll.add_argument("--samples", type=int, default=4, help="Number of face samples")
    p_enroll.add_argument(
        "--image", action="append",
        help="Import face(s) from an image; repeat for multiple images",
    )

    p_facelock = sub.add_parser("face-lock", help="Webcam face presence lock controls")
    p_facelock.add_argument("action", choices=["run", "test", "enroll", "lock-test"],
                            default="test", nargs="?", help="Action to perform")
    p_facelock.add_argument("--interval", type=float, default=15.0, help="Webcam check interval (seconds)")
    p_facelock.add_argument("--camera", type=int, default=0, help="Camera index")
    p_facelock.add_argument("--threshold", type=float, default=0.363, help="Cosine similarity threshold")
    p_facelock.add_argument("--no-dry-run", action="store_true", help="Lock workstation on test failure")
    p_facelock.add_argument("--samples", type=int, default=4, help="Enrollment samples per webcam user")
    p_facelock.add_argument(
        "--image", action="append",
        help="Import face(s) from an image; repeat for multiple images",
    )

    p_search = sub.add_parser("search", help="Search audit events")
    p_search.add_argument("--query", "-q", help="Search text query")
    p_search.add_argument("--type", "-t", help="Event type filter")
    p_search.add_argument("--session", "-s", type=int, help="Session ID filter")
    p_search.add_argument("--limit", "-n", type=int, default=50, help="Max items")
    p_search.add_argument("--db", default="audit.db", help="Audit database path")

    p_export = sub.add_parser("export", help="Export audit records")
    p_export.add_argument("--format", choices=["json", "csv"], default="json")
    p_export.add_argument("--out", "-o", help="Output file destination")
    p_export.add_argument("--db", default="audit.db", help="Audit database path")

    args = parser.parse_args()

    if args.cmd == "agent":
        cfg = Path(args.config)
        if not cfg.exists():
            write_default_config(cfg)
        run_agent(str(cfg), enable_face_lock=args.face_lock)
    elif args.cmd == "enroll-face":
        from face_lock import interactive_enrollment, enroll_from_image_file
        if args.image:
            for image_path in args.image:
                enroll_from_image_file(image_path)
        else:
            interactive_enrollment(camera_index=args.camera, samples_needed=args.samples)
    elif args.cmd == "face-lock":
        from face_lock import (
            interactive_enrollment,
            enroll_from_image_file,
            run_standalone_test,
            FaceLockWatcher,
            lock_workstation,
        )
        if args.action == "enroll":
            if args.image:
                for image_path in args.image:
                    enroll_from_image_file(image_path)
            else:
                interactive_enrollment(
                    camera_index=args.camera, samples_needed=args.samples)
        elif args.action == "lock-test":
            print("Testing workstation lock in 3 seconds...")
            time.sleep(3)
            ok, method = lock_workstation()
            print(f"Lock result: success={ok}, method={method}")
        elif args.action == "test":
            run_standalone_test(
                camera_index=args.camera,
                interval=args.interval,
                dry_run=not args.no_dry_run,
            )
        elif args.action == "run":
            watcher = FaceLockWatcher(
                config={
                    "face_lock": {
                        "enabled": True,
                        "interval_seconds": args.interval,
                        "camera_index": args.camera,
                        "similarity_threshold": args.threshold,
                    }
                }
            )
            try:
                watcher.run_loop()
            except KeyboardInterrupt:
                watcher.stop()
                print("\nStopped Face-Lock.")
    elif args.cmd == "tui":
        run_tui(
            Path(args.db).expanduser().resolve(),
            Path(args.config).expanduser().resolve(),
        )
    elif args.cmd == "init":
        write_default_config(Path("config.json"))
    elif args.cmd == "search":
        cli_search(Path(args.db).expanduser().resolve(),
                   query=args.query, event_type=args.type,
                   sid=args.session, limit=args.limit)
    elif args.cmd == "export":
        cli_export(Path(args.db).expanduser().resolve(),
                   out_path=args.out, fmt=args.format)


if __name__ == "__main__":
    main()
