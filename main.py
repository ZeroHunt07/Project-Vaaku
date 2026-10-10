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
        self._logged_errors = set()

        self._last_window = None
        self._last_window_lock = threading.Lock()

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
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
        CREATE INDEX IF NOT EXISTS idx_events_sid ON events(session_id);
        CREATE INDEX IF NOT EXISTS idx_files_path ON file_access(path);
        CREATE INDEX IF NOT EXISTS idx_web_domain ON web_visits(domain);
        CREATE INDEX IF NOT EXISTS idx_wact_sid ON window_activity(session_id);
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
                timeout=2, stderr=subprocess.DEVNULL,
            ).decode(errors="replace")
        except Exception:
            return None

        m = re.search(r"'(\{.*\})'", out, re.DOTALL)
        if not m:
            return None
        try:
            data = json.loads(m.group(1))
        except Exception:
            return None

        title = (data.get("title") or "").strip()
        app = (data.get("wm_class")
               or data.get("wm_class_instance") or "").strip()
        if not (title or app):
            return None

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
                timeout=3, stderr=subprocess.DEVNULL,
            ).decode(errors="replace")
        except Exception:
            return None

        m = re.search(r"\('(\[.*\])',?\)", out, re.DOTALL)
        if not m:
            return None
        try:
            items = json.loads(m.group(1))
        except Exception:
            return None
        if not isinstance(items, list):
            return None

        windows = []
        for item in items:
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

    def _active_window_info(self):
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
        env = {
            "DISPLAY": os.environ.get("DISPLAY"),
            "WAYLAND_DISPLAY": os.environ.get("WAYLAND_DISPLAY"),
            "XDG_SESSION_TYPE": os.environ.get("XDG_SESSION_TYPE"),
        }

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
        })

        if backend is None:
            self.log_error_once("no_backend", {
                "reason": "No window tracking backend available",
                "fix": "Install GNOME 'Focused Window D-Bus' extension "
                       "or xdotool+wmctrl.",
            })
            return False
        return True

    def log_window(self):
        if not self._win_self_check():
            return

        poll = float(self.config.get("window_poll_seconds", 3))
        debug = bool(self.config.get("window_debug", False))

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

    def start_file_monitor(self):
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
        agent = self

        class Handler(FileSystemEventHandler):
            def on_any_event(self, event):
                if event.is_directory:
                    return
                agent.log_file_event(event.src_path, event.event_type)

        observer = Observer()
        handler = Handler()
        for d in self.config.get("monitor_dirs", []):
            p = Path(d).expanduser()
            if p.exists():
                observer.schedule(handler, str(p), recursive=True)
        observer.start()
        self.observer = observer

    def start_web_server(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        agent = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
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

    def take_snapshot(self):
        if not self.config.get("camera_snapshot", False):
            return
        try:
            import cv2
        except ImportError:
            self.log_event("camera", "agent",
                           {"error": "opencv-python not installed"})
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
                           {"error": "could not open camera"})
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
                               {"error": "no usable frame"})
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

        def on_quit(icon, item):
            self.shutdown()
            icon.stop()

        menu = pystray.Menu(
            pystray.MenuItem(
                lambda item: "Pause" if self.logging_active else "Resume",
                on_toggle),
            pystray.MenuItem("Quit", on_quit),
        )
        icon = pystray.Icon("AuditAgent", create_icon("green"),
                            "Audit Agent", menu)
        self.icon = icon
        icon.run()

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
        if self.web_server:
            self.web_server.shutdown()
        self.conn.close()


def run_agent(config_path: str):
    agent = AuditAgent(config_path)
    agent.take_snapshot()
    agent.start_web_server()
    threading.Thread(target=agent.log_window, daemon=True).start()
    threading.Thread(target=agent.log_typing_pulse, daemon=True).start()
    agent.start_file_monitor()
    try:
        agent.run_tray()
    except KeyboardInterrupt:
        agent.shutdown()


# ===========================================================================
# PART 2 — TUI
# ===========================================================================

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
                               'form_submit')
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
              (SELECT COUNT(*) FROM form_submits) AS forms
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


class AuditTUI(App):
    CSS = """
    Screen { layout: vertical; }
    .toolbar { height: 3; padding: 0 1; }
    .toolbar Input { width: 1fr; }
    .toolbar Button { width: 12; margin-left: 1; }
    .toolbar Select { width: 22; margin-left: 1; }
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
        Binding("ctrl+p", "toggle_dark", "Theme"),
    ]

    def __init__(self, db_path: Path):
        super().__init__()
        self.db_path = db_path
        self.db: DB = DB(db_path)
        try:
            cfg_path = Path("config.json")
            if cfg_path.exists():
                cfg = json.loads(cfg_path.read_text())
                SessionTreePane.auto_refresh_seconds = float(
                    cfg.get("tui_auto_refresh_seconds", 5.0))
        except Exception:
            pass

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
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
        yield Static(id="status-bar")
        yield Footer()

    def on_mount(self):
        self.title = "Audit Agent — Viewer"
        self.sub_title = str(self.db_path)
        self.refresh_status()
        for pane_cls in (FilesPane, WebPane, SnapshotsPane):
            for pane in self.query(pane_cls):
                try:
                    pane.reload()
                except Exception:
                    pass

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
            f"spans={c['wact']}  forms={c['forms']}  snaps={c['snaps']}"
        )
        bar.update(bar._audit_text)

    def action_refresh(self):
        for pane_cls in (SessionTreePane, FilesPane, WebPane, SnapshotsPane):
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

    def action_toggle_dark(self):
        self.dark = not self.dark


def run_tui(db_path: Path):
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
    AuditTUI(db_path).run()


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
}


def write_default_config(path: Path):
    if not path.exists():
        path.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
        print(f"Wrote default config: {path}")


def main():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Transparent audit agent + TUI viewer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_agent = sub.add_parser("agent", help="Run the background logger")
    p_agent.add_argument("--config", default="config.json")

    p_tui = sub.add_parser("tui", help="Run the TUI viewer")
    p_tui.add_argument("--db", default="audit.db")

    sub.add_parser("init", help="Write a default config.json")

    args = parser.parse_args()

    if args.cmd == "agent":
        cfg = Path(args.config)
        if not cfg.exists():
            write_default_config(cfg)
        run_agent(str(cfg))
    elif args.cmd == "tui":
        run_tui(Path(args.db).expanduser().resolve())
    elif args.cmd == "init":
        write_default_config(Path("config.json"))


if __name__ == "__main__":
    main()
