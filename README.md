# SecOPS Audit Agent

A transparent, consent-based endpoint activity audit tool for Linux, with cross-platform stubs for Windows and macOS. It records selected endpoint activity in a local SQLite database and provides a terminal UI for reviewing the audit trail.

> [!IMPORTANT]
> **Consent and lawful use:** Use this tool only on computers you own or where every affected user has given documented, informed consent. Monitoring laws vary by jurisdiction. This README is not legal advice; consult qualified counsel before deploying it in a workplace or on a shared device.

## Privacy and safety by design

- Does **not** record typed characters; the typing feature is intended to count key events only.
- Does **not** store clipboard contents.
- Does **not** silently capture webcam images; camera capture is optional and should require visible consent.
- Does **not** hide itself from the operating system or process listings.
- Does **not** send audit data off-device; the database is stored locally.

Activity records can still reveal sensitive personal information. Enable only the collectors you need, tell users what is collected, restrict access to the database, and establish a short retention period.

## Table of contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [GNOME Wayland setup](#gnome-wayland-setup)
6. [Browser extension](#browser-extension)
7. [Configuration](#configuration)
8. [Run the agent and TUI](#run-the-agent-and-tui)
9. [Auto-start](#auto-start)
10. [Database](#database)
11. [How collectors work](#how-collectors-work)
12. [Permissions](#permissions)
13. [Troubleshooting](#troubleshooting)
14. [FAQ](#faq)
15. [Security and privacy](#security-and-privacy)
16. [Uninstall](#uninstall)
17. [License](#license)

## Features

| Feature | What it records | Storage | Default |
|---|---|---|---|
| Sessions | Agent session, user, boot time, IP, start/end | `sessions`, `events` | On |
| Window focus | Continuous focus spans | `window_activity` | On |
| Window open/close | Top-level window changes | `events` | On |
| File events | Create, modify, delete, move in configured directories | `file_access`, `events` | On |
| Web visits | URL, domain, title, browser | `web_visits`, `events` | On |
| Form submissions | Form action and field names only | `form_submits`, `events` | On |
| Typing pulse | Number of key-down events per interval; no characters | `events` | On |
| Camera snapshot | Optional JPEG snapshot | `snapshots`, `snapshots/` | Off |
| TUI viewer | Read-only views and live tail | — | Available |
| Live tail | New events as they are logged | — | Available |

**Important:** URLs, window titles, filenames, and form field names can themselves contain sensitive information. Review the data policy with all users before enabling collection.

## Architecture

```text
┌──────────────────────────── Audit Agent ────────────────────────────┐
│                                                                      │
│  Window focus collector     Typing pulse collector   File monitor    │
│  D-Bus / pywinctl / xdotool  evdev / pynput           watchdog       │
│              │                      │                     │          │
│              └──────────────────────┴─────────────────────┘          │
│                                     │                                │
│                       Local HTTP server (127.0.0.1:8765)             │
│                                     │                                │
│                       Browser extension (optional)                   │
│                                                                      │
│                       SQLite database (WAL mode)                     │
└──────────────────────────────────────┬───────────────────────────────┘
                                       │
                             Read-only terminal UI
```

The agent uses worker threads for window focus, typing pulses, file monitoring, and the local web server. The TUI opens the database in read-only/query-only mode so it can inspect data while the agent is running.

## Requirements

| Component | Minimum | Recommended |
|---|---|---|
| OS | Linux; Windows/macOS support is partial | Kali 2024+, Ubuntu 22.04+, Debian 12+ |
| Python | 3.10 | 3.11 or 3.12 |
| RAM | About 200 MB | About 500 MB |
| Disk | About 500 MB | 5 GB available |
| Desktop | X11 or Wayland desktop for window tracking | GNOME 42+ on Wayland or X11 |

### Optional system packages

On Kali, Debian, or Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv sqlite3 xdotool wmctrl git curl
```

If Python packages need native compilation:

```bash
sudo apt install -y python3-dev build-essential
```

`xdotool` and `wmctrl` mainly help with X11/XWayland window tracking. GNOME Wayland may require the extensions described below.

## Installation

### 1. Create a project directory

```bash
mkdir -p ~/Desktop/Software/SecOPS
cd ~/Desktop/Software/SecOPS
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv myenv
source myenv/bin/activate
```

### 3. Install Python dependencies

```bash
python -m pip install --upgrade pip
pip install "pywinctl[linux]" pystray Pillow watchdog psutil opencv-python textual pynput evdev
```

### 4. Add the application file

Place `main.py` in the project directory:

```text
~/Desktop/Software/SecOPS/main.py
```

### 5. Create the configuration

```bash
python main.py init
```

This creates `config.json` if the application implements the `init` command.

### 6. Verify imports

```bash
python -c "import textual, watchdog, psutil, cv2; print('Dependencies OK')"
python -c "import pywinctl; print('pywinctl OK')"
python -c "import evdev; print([evdev.InputDevice(p).name for p in evdev.list_devices()])"
```

If `evdev` cannot access input devices, do not run the agent as root to work around it. Review the permissions section and decide whether typing counts are necessary; you can omit that collector if they are not.

### 7. Start the agent and viewer

Terminal 1:

```bash
cd ~/Desktop/Software/SecOPS
source myenv/bin/activate
python main.py agent
```

Terminal 2:

```bash
cd ~/Desktop/Software/SecOPS
source myenv/bin/activate
python main.py tui --db audit.db
```

> **Implementation note:** These commands assume your `main.py` implements the CLI and features described here. This README documents the intended interface; verify it against the actual source before publishing.

## GNOME Wayland setup

Wayland limits one application’s ability to inspect other applications’ windows. On GNOME, optional extensions may expose focused-window details or window lists. Review the extension source and permissions before installing third-party extensions.

- Focused Window D-Bus: <https://extensions.gnome.org/extension/5592/focused-window-d-bus/>
- Window Calls: <https://extensions.gnome.org/extension/4724/window-calls/>

Example D-Bus check for the focused-window extension:

```bash
gdbus call --session \
  --dest org.gnome.Shell \
  --object-path /org/gnome/shell/extensions/FocusedWindow \
  --method org.gnome.shell.extensions.FocusedWindow.Get
```

Example window-list check:

```bash
gdbus call --session \
  --dest org.gnome.Shell.Extensions.Windows \
  --object-path /org/gnome/Shell/Extensions/Windows \
  --method org.gnome.shell.extensions.Windows.List
```

If you prefer not to use extensions, an X11 session may provide better compatibility with traditional window enumeration tools.

## Browser extension

The optional browser extension reports visits and form metadata to the local agent. The proposed directory structure is:

```text
browser-extension/
├── manifest.json
├── background.js
└── content.js
```

### Manifest V3 example

```json
{
  "manifest_version": 3,
  "name": "SecOPS Audit Agent Web Logger",
  "version": "1.2.0",
  "permissions": ["tabs", "activeTab", "scripting"],
  "host_permissions": ["http://127.0.0.1:8765/*", "https://*/*", "http://*/*"],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["http://*/*", "https://*/*"],
      "js": ["content.js"],
      "run_at": "document_idle",
      "all_frames": false
    }
  ]
}
```

The broad site access above is powerful. Prefer limiting site access to the domains needed, and make collection status visible to users. Do not collect passwords, field values, page contents, or authentication data.

### Load in Chromium-based browsers

1. Open `chrome://extensions` (or the equivalent page in Edge/Brave).
2. Enable **Developer mode**.
3. Choose **Load unpacked** and select `browser-extension/`.
4. Review the extension's site-access permissions and keep them as narrow as practical.

The extension and agent must agree on the local endpoint and payload format. Ensure the local HTTP server accepts only expected request types and validates input; loopback binding alone is not a complete security boundary.

## Configuration

`config.json` is expected to be next to `main.py`.

```json
{
  "db_path": "audit.db",
  "snapshot_dir": "snapshots",
  "monitor_dirs": ["~/Documents", "~/Desktop"],
  "window_poll_seconds": 3,
  "window_debug": false,
  "camera_snapshot": false,
  "camera_index": 0,
  "camera_width": 1280,
  "camera_height": 720,
  "camera_warmup_frames": 15,
  "camera_settle_seconds": 1.2,
  "camera_best_of": 5,
  "typing_pulse_seconds": 5.0,
  "tui_auto_refresh_seconds": 5.0,
  "retention_days": 30,
  "web_server_port": 8765
}
```

| Key | Type | Default | Purpose |
|---|---|---:|---|
| `db_path` | string | `audit.db` | SQLite database path |
| `snapshot_dir` | string | `snapshots` | Directory for optional JPEG snapshots |
| `monitor_dirs` | list | Documents, Desktop | Directories watched recursively |
| `window_poll_seconds` | number | `3` | Window focus polling interval |
| `window_debug` | boolean | `false` | Additional window diagnostics |
| `camera_snapshot` | boolean | `false` | Enables optional snapshot capture |
| `camera_index` | integer | `0` | Camera device index |
| `camera_width` / `camera_height` | integer | `1280` / `720` | Requested image dimensions |
| `camera_warmup_frames` | integer | `15` | Frames discarded during warm-up |
| `camera_settle_seconds` | number | `1.2` | Delay after warm-up |
| `camera_best_of` | integer | `5` | Frames compared for sharpness |
| `typing_pulse_seconds` | number | `5.0` | Key-event count interval |
| `tui_auto_refresh_seconds` | number | `5.0` | TUI refresh interval; `0` disables |
| `retention_days` | integer | `30` | Intended data retention period |
| `web_server_port` | integer | `8765` | Local HTTP server port |

Restart the agent after changing configuration. The implementation should validate paths, enforce retention consistently, and fail safely when optional collectors are unavailable.

## Run the agent and TUI

Start the agent:

```bash
source myenv/bin/activate
python main.py agent
```

Start the read-only terminal UI in another terminal:

```bash
source myenv/bin/activate
python main.py tui --db audit.db
```

### TUI screens

| Screen | Purpose |
|---|---|
| Sessions | Sessions and grouped events |
| Live | Streaming event view |
| Files | Searchable file-event table |
| Web | Searchable web-visit table |
| Snapshots | Snapshot metadata and optional image opening |

### Keybindings

| Key | Action |
|---|---|
| `1`–`5` | Switch screens |
| `q` | Quit |
| `r` | Refresh |
| `Ctrl+E` | Expand sessions |
| `Ctrl+W` | Collapse sessions |
| `Ctrl+P` | Toggle theme |
| `c` / `p` in Live | Clear / pause |
| `o` in Snapshots | Open selected image |

Keybindings may vary with the implementation; keep this table synchronized with `main.py`.

## Auto-start

Auto-start is optional. Prefer a visible, user-session startup entry and clearly disclose it to all users of the device. Do not configure hidden or privileged persistence.

### Linux desktop autostart

Create `~/.config/autostart/audit-agent.desktop` and replace `YOUR_USER` with the actual home-directory path:

```ini
[Desktop Entry]
Type=Application
Name=SecOPS Audit Agent
Comment=Consent-based endpoint activity audit
Exec=/home/YOUR_USER/Desktop/Software/SecOPS/myenv/bin/python /home/YOUR_USER/Desktop/Software/SecOPS/main.py agent --config /home/YOUR_USER/Desktop/Software/SecOPS/config.json
Path=/home/YOUR_USER/Desktop/Software/SecOPS
Terminal=false
X-GNOME-Autostart-enabled=true
```

Use only one startup method. If you enable auto-start, provide an obvious way to pause and quit the agent and tell users how to disable it.

Windows Task Scheduler and macOS LaunchAgents may be used for a user-visible login launch, but support depends on the actual implementation and platform permissions. Do not grant Full Disk Access or other broad permissions unless a documented feature genuinely needs them.

## Database

The default database is `audit.db`, using SQLite. Inspect it with:

```bash
sqlite3 audit.db
```

Useful commands:

```sql
.tables
.schema sessions
SELECT * FROM sessions ORDER BY id DESC LIMIT 5;
```

### Expected tables

| Table | Purpose |
|---|---|
| `sessions` | One row per agent run |
| `events` | General event log |
| `file_access` | File-operation details |
| `web_visits` | Web-visit metadata |
| `snapshots` | Snapshot metadata |
| `window_activity` | Window focus spans |
| `form_submits` | Form action and field-name metadata |

### Example queries

**Latest events**

```sql
SELECT ts, type, source, substr(details, 1, 80)
FROM events
ORDER BY id DESC
LIMIT 10;
```

**Focus time per app for a session**

```sql
SELECT app,
       SUM((julianday(COALESCE(end_ts, datetime('now'))) -
            julianday(start_ts)) * 86400) AS seconds
FROM window_activity
WHERE session_id = 1
GROUP BY app
ORDER BY seconds DESC;
```

**Web visits by domain**

```sql
SELECT domain, COUNT(*)
FROM web_visits
GROUP BY domain
ORDER BY COUNT(*) DESC
LIMIT 20;
```

**Typing-count events from the last hour**

```sql
SELECT ts, details
FROM events
WHERE type = 'typing'
  AND ts > datetime('now', '-1 hour')
ORDER BY id DESC;
```

### Backup

Use SQLite’s backup command:

```bash
sqlite3 audit.db ".backup 'audit-$(date +%F).db'"
```

Treat backups as sensitive audit data and protect or delete them according to the same retention policy.

## How collectors work

### Sessions

Records an agent session with boot information, current user, IP address, and timestamps. A clean shutdown should update the session end time.

### Window focus

Polls the active window at the configured interval. Potential backends include the GNOME focused-window D-Bus extension, `pywinctl`, and `xdotool`. Availability depends on desktop session and permissions.

### Window open/close

Compares window lists over time when the desktop backend supports enumeration.

### File events

`watchdog` monitors configured directories recursively for create, modify, delete, and move events. Avoid monitoring sensitive folders unless there is a clear need and explicit consent.

### Web visits

The browser extension sends visit metadata to the local HTTP endpoint. Consider recording only the domain or minimizing URL details to reduce collection of sensitive information.

### Form submissions

The intended design records form action and field **names** only, never values. Field names and form actions may still disclose sensitive context.

### Typing pulse

The intended design counts key-down events over fixed time intervals without storing characters. Access to raw input devices is highly sensitive; leave this feature disabled unless it is necessary, disclosed, and explicitly approved. Do not run as root to bypass input permissions.

### Camera snapshot

Camera capture is disabled by default. If implemented, it should show a clear, interactive consent prompt immediately before capture and must not run in headless mode where that prompt cannot be shown.

### Retention

The `retention_days` setting is intended to limit stored history. Verify that every related table and associated image file is cleaned up, and test retention before real deployment.

## Permissions

| Permission | Purpose |
|---|---|
| Read configured folders | File-change monitoring |
| Input-device access (optional) | Key-event counts |
| Session D-Bus access | GNOME window extensions |
| Bind to `127.0.0.1` | Local browser-to-agent communication |
| Camera access (optional) | Explicitly consented snapshot |
| Write to project/database directory | Store audit records |

The agent should run as the normal logged-in user. Avoid root privileges and broad access grants. If a feature cannot operate with least privilege, disable that feature rather than weakening system security.

## Troubleshooting

### Missing Python module

Activate the virtual environment before starting the program:

```bash
source myenv/bin/activate
python -m pip install -r requirements.txt
```

If no `requirements.txt` exists yet, create one that matches the packages actually imported by `main.py`.

### Port 8765 is already in use

Check which process owns the port:

```bash
ss -tlnp | grep 8765
```

Stop only the process you recognize and intend to stop. Avoid broad `pkill` commands that may terminate unrelated processes.

### Window list is empty

- Check whether the session is X11 or Wayland.
- Verify the required desktop backend or GNOME extension is installed and enabled.
- Remember that Wayland intentionally restricts cross-application window inspection.

### Typing counts do not appear

- Confirm the optional collector is enabled and dependencies are installed.
- Check device permissions without granting root access.
- If permissions are not appropriate, disable the feature.

### Web visits do not appear

1. Confirm the agent is running.
2. Confirm the browser extension is enabled.
3. Verify that its configured local endpoint and port match the agent.
4. Inspect agent logs for rejected or malformed requests.

### Camera feature fails

- Confirm `camera_snapshot` is enabled only when intended.
- Check that a camera is connected and available.
- Ensure an interactive consent prompt is supported.
- Otherwise leave the feature disabled.

### TUI flickers

Increase `tui_auto_refresh_seconds` or disable automatic refresh by setting it to `0`, if supported by the implementation.

## FAQ

**Does this require administrator privileges?**

It should run as the logged-in user. Some optional features may require additional user-level permissions. Do not use root as a workaround for a collector.

**Does it record what I type?**

The intended typing-pulse design records counts only, not characters. Confirm this against the implementation before deployment.

**Does it read clipboard contents?**

No clipboard collector is documented in this design.

**Where is the data stored?**

In the local SQLite database and, if explicitly enabled, the configured snapshots directory.

**Can I open the database on another machine?**

You can inspect a copy with SQLite or the TUI if the relevant dependencies are installed. Treat copied databases as sensitive data.

**Does it support Windows and macOS?**

The design describes partial support, but collector availability differs by platform. Test each platform before relying on it.

**How can I stop it?**

Use the application's visible Quit control or stop the foreground process with `Ctrl+C`. Disable any configured auto-start entry if you no longer want it to launch.

## Security and privacy

- **Data minimization:** Collect only what is necessary; consider disabling typing counts, form metadata, full URLs, and snapshots.
- **Transparency:** Tell every affected user what is collected, why, how long it is kept, and who can access it.
- **Access controls:** Restrict project and database permissions. Example:

  ```bash
  chmod 700 ~/Desktop/Software/SecOPS
  chmod 600 ~/Desktop/Software/SecOPS/audit.db
  ```

- **Retention:** Use the shortest practical retention period and test deletion across all tables and image files.
- **Local endpoint:** Bind only to loopback, validate request size and fields, and reject unexpected origins and payloads. Loopback binding alone does not prevent every local abuse case.
- **No stealth:** Keep the process visible, provide pause/quit controls, and do not disguise or conceal the agent.
- **Review before deployment:** Audit the source code, browser permissions, and desktop extensions before collecting real activity.

This project description is not a legal opinion. Monitoring may be subject to privacy, employment, interception, and data-protection laws. Obtain informed consent and qualified legal advice where appropriate.

## Uninstall

First stop the agent using its visible Quit control or `Ctrl+C` in the terminal where it is running.

Disable whichever startup mechanism you configured:

- Desktop autostart: remove `~/.config/autostart/audit-agent.desktop`.
- User systemd service: disable and remove the service you created.
- Windows Task Scheduler: disable and remove the task you created.
- macOS LaunchAgent: unload and remove the plist you created.

Then remove the browser extension through the browser's extensions page. Remove any optional GNOME extensions through the Extensions app if you no longer need them.

To delete locally stored data, verify the directory first and then remove only the files you intend to erase:

```bash
cd ~/Desktop/Software/SecOPS
rm -i audit.db audit.db-wal audit.db-shm
```

If you enabled snapshots, review and remove the contents of `snapshots/` separately. Finally, delete the project directory only after confirming that you have no data you need to retain.

## License

MIT License. Add a `LICENSE` file containing the full MIT license text and the correct copyright holder before publishing. Use and redistribution remain subject to applicable laws and the project's actual license file.

---

**Status:** Documentation draft. Verify every command, configuration key, feature, permission, and keybinding against the actual source code before release.
