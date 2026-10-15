# SecOPS Audit Agent

A transparent, consent-based endpoint activity audit tool for Linux, with cross-platform stubs for Windows and macOS. It records selected endpoint activity in a local SQLite database and provides a terminal UI for reviewing the audit trail.

> [!IMPORTANT]
> **Consent and lawful use:** Use this tool only on computers you own or where every affected user has given documented, informed consent. Monitoring laws vary by jurisdiction. This README is not legal advice; consult qualified counsel before deploying it in a workplace or on a shared device.

## Privacy and safety by design

- Does **not** record typed characters; the typing feature is intended to count key events only.
- Does **not** store clipboard contents.
- Does **not** silently capture webcam snapshots; optional snapshots are separate from face lock, which periodically checks the camera when enabled.
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
| User commands | New processes launched directly from the logged-in user's shell; excludes GUI/background application processes | `commands`, `events` | On |
| Camera snapshot | Optional JPEG snapshot | `snapshots`, `snapshots/` | Off |
| Face presence lock | Periodically checks for the enrolled face and locks the workstation if verification fails | `events` | Configurable |
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
│                 Optional webcam face-presence lock                  │
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

The agent uses worker threads for window focus, typing pulses, file monitoring, face lock, and the local web server. Face lock is separately configurable and can be switched on or off from the agent's system-tray menu. The TUI opens the database in read-only/query-only mode so it can inspect data while the agent is running.

## Requirements

| Component | Minimum | Recommended |
|---|---|---|
| OS | Linux, Windows 10+, macOS 12+; desktop integrations require platform permissions | Ubuntu 22.04+, Debian 12+, current Windows/macOS |
| Python | 3.10 | 3.11 or 3.12 |
| RAM | About 200 MB | About 500 MB |
| Disk | About 500 MB | 5 GB available |
| Desktop | Interactive desktop session for window tracking, tray controls, and locking | X11; GNOME on Wayland with its window extension |

File monitoring, SQLite logging, the TUI, and Chromium browser-extension integration are cross-platform. Window titles and the tray require an interactive desktop session. macOS may prompt for Accessibility permission; GNOME Wayland restricts global window inspection unless its documented extension is installed. Global typing counts are optional and depend on OS permissions; they are not available through `pynput` on many Wayland sessions.

### Optional system packages

On Kali, Debian, or Ubuntu (desktop integration packages):

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv sqlite3 xdotool wmctrl git curl xdg-user-dirs
```

If Python packages need native compilation:

```bash
sudo apt install -y python3-dev build-essential
```

`xdotool` and `wmctrl` mainly help with X11/XWayland window tracking. GNOME Wayland may require the extensions described below.

## Installation

### 1. Get the project

```bash
git clone https://github.com/ZeroHunt07/Project-Vaaku.git
cd Project-Vaaku
```

### 2. Create and activate a virtual environment

Linux and macOS:

```bash
python3 -m venv myenv
source myenv/bin/activate
```

Windows PowerShell:

```powershell
py -m venv myenv
.\myenv\Scripts\Activate.ps1
```

### 3. Install Python dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r req.txt
```

### 4. Create the configuration if needed

```bash
python main.py init
```

This writes a default `config.json` only when one does not already exist. The included `config.json` enables face lock; a newly generated default config leaves it disabled.

### 5. Enroll the authorized face (optional)

```bash
python main.py enroll-face --samples 4
```

Enrollment uses the selected camera and adds samples to the existing profile rather than replacing it. Enroll authorized people one at a time; one camera sample must contain exactly one person. To import multiple authorized users from images, repeat `--image` (every detected face in each selected image is enrolled):

```bash
python main.py enroll-face --image alice.jpg --image bob.jpg
```

At runtime, every detected face is checked against the enrolled profiles. The
check passes only when all detected faces are recognized; a single
unrecognized face triggers the lock warning. Multiple recognized people may
be in view together. Store enrollment data securely under `faces/`.

### 6. Start the agent and viewer

Terminal 1:

```bash
cd Project-Vaaku
source myenv/bin/activate
python main.py agent
```

Terminal 2:

```bash
cd Project-Vaaku
source myenv/bin/activate
python main.py tui --db audit.db
```

The `agent` command shows a system-tray icon. Use its menu to pause/resume audit logging, switch **Face Presence Lock** on or off, or quit the agent. The face-lock menu item is a checkbox and reflects the current runtime state.

The TUI also has a **Face Lock** switch at the top of every screen. It controls the running agent immediately over the loopback connection; start the agent before using the switch. The TUI shows **agent unavailable** if it cannot reach the configured local web-server port.

### Face-lock switch and command-line controls

Face lock is independent of the agent's other collectors. Use the TUI's top-of-screen switch or the agent's tray checkbox to turn it on or off. Turning it off stops future checks and clears any accumulated failed-check count; it does not unlock a workstation that has already been locked. Runtime switches apply for the current run. To choose the startup state, edit `face_lock.enabled` in `config.json`, or use a command-line override:

You can also press **Ctrl+Alt+F** at any time while the agent is running to toggle face lock; the TUI does not need to be open. The agent prints the new state and records it in the event log. Global shortcut support depends on the desktop: it works where `pynput` can monitor keyboard shortcuts, may require Accessibility/Input Monitoring permission on macOS, and is generally blocked by Wayland compositors. If unavailable, use the tray menu or TUI switch.

```bash
python main.py agent --face-lock       # Force on for this run
python main.py agent --no-face-lock    # Force off for this run
```

If enabled, the agent uses the camera every `interval_seconds`. Before locking after a failed check, it shows a large full-screen warning and retries face verification; recognizing an enrolled face during the warning cancels the lock. The warning delay adapts to the result: a clear unauthorized-face match gets a shorter delay, while a near-match, missing face, or camera hiccup gets more time. These warning delays are at most 12 seconds. If a full-screen window is unavailable, the agent logs the issue, sends a desktop notification when supported, and still performs the grace-period checks. The 15-second `interval_seconds` setting remains the interval between routine checks; it is not the warning countdown. Use `python main.py face-lock test` to test recognition without locking. Face lock depends on a working camera, model files in `models/`, and a supported desktop lock command. Keep the system tray visible and tell all affected users when this camera-based feature is enabled.

### User command logging

The Commands screen records only newly started processes whose direct parent is an interactive shell owned by the current user. This omits applications and background services that start their own child processes. Commands that finish between process scans may not be captured; use shell history or OS auditing when complete command history is required. Older process-monitor records from previous runs are filtered from the Commands screen and exports.

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

An extension being installed is not enough: it must be enabled in the same
logged-in GNOME session as the agent and expose the D-Bus object shown above.
If the focused-window check reports that the object does not exist, enable the
extension and check again. The agent keeps polling after an initial failure,
so a newly available backend can start recording focus spans.

If you prefer not to use extensions, an X11 session may provide better compatibility with traditional window enumeration tools.

## Browser extension

The optional browser extension reports visits and form metadata to the local agent. Its files are at the repository root:

```text
manifest.json
background.js
content.js
```

### Current Manifest V3 permissions

```json
{
  "manifest_version": 3,
  "name": "Audit Agent Web Logger",
  "version": "1.2",
  "permissions": ["tabs", "activeTab", "scripting", "downloads"],
  "host_permissions": ["<all_urls>"],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_idle",
      "all_frames": true
    }
  ]
}
```

The extension has broad site access and observes forms in all frames. Review and narrow its site access in the browser's extension settings when possible; make collection status visible to users. Do not collect passwords, field values, page contents, or authentication data.

### Load in Chromium-based browsers

1. Open `chrome://extensions` (or the equivalent page in Edge/Brave).
2. Enable **Developer mode**.
3. Choose **Load unpacked** and select the repository directory containing `manifest.json`.
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
  "web_server_port": 8765,
  "face_lock": {
    "enabled": false,
    "interval_seconds": 15,
    "similarity_threshold": 0.363,
    "consecutive_failures_to_lock": 1,
    "faces_dir": "faces",
    "models_dir": "models",
    "notify_on_lock": true,
    "camera_index": 0,
    "camera_warmup_frames": 3
  }
}
```

| Key | Type | Default | Purpose |
|---|---|---:|---|
| `db_path` | string | `audit.db` | SQLite database path |
| `snapshot_dir` | string | `snapshots` | Directory for optional JPEG snapshots |
| `monitor_dirs` | list | Documents, Desktop | Directories watched recursively; if none exist, the agent discovers existing Documents/Desktop/Downloads folders for the OS |
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
| `face_lock.enabled` | boolean | `false` in generated defaults | Enable periodic face verification and workstation locking |
| `face_lock.interval_seconds` | number | `15` | Seconds between face checks |
| `face_lock.similarity_threshold` | number | `0.363` | Face-recognition similarity threshold |
| `face_lock.consecutive_failures_to_lock` | integer | `1` | Failed checks before locking |
| `face_lock.faces_dir` / `models_dir` | path | `faces` / `models` | Enrollment data and YuNet/SFace model directories |
| `face_lock.notify_on_lock` | boolean | `true` | Show a desktop notification when face lock attempts to lock |
| `face_lock.camera_index` | integer | `0` | Camera device used for face checks |
| `face_lock.camera_warmup_frames` | integer | `3` | Frames discarded before each check |

Restart the agent after changing configuration. The checked-in `config.json` enables face lock; the default written by `python main.py init` leaves it disabled.

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

In **Sessions**, select a session to see its activity as a scrollable,
chronological ASCII timeline. It shows every recorded event as a readable
activity heading—for example, `Open example.com : Chrome`—along with useful
event details, focused-window spans, and snapshot records. If window capture
cannot start, its diagnostic event includes the backend errors and setup
guidance. The collector continues polling, so a backend enabled after startup
can begin recording without restarting the agent.

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
python -m pip install -r req.txt
```

### Port 8765 is already in use

Check which process owns the port:

```bash
ss -tlnp | grep 8765
```

Stop only the process you recognize and intend to stop. Avoid broad `pkill` commands that may terminate unrelated processes.

### Window list is empty

- Check the `window_debug` and `window_error` events in the database for the selected backend and failure details.
- On Linux X11, install `pywinctl`; `xdotool` can provide another active-window backend.
- On GNOME Wayland, install and enable the Focused Window D-Bus extension. Wayland deliberately restricts global window inspection, so this cannot work on every Wayland compositor.
- On macOS, grant Accessibility access to the terminal or Python executable under **System Settings → Privacy & Security → Accessibility**, then restart the agent.
- On Windows, run from the signed-in desktop session rather than a service/session 0.

### File events do not appear

- Check `file_monitor` and `file_monitor_error` events to see which folders and watcher backend are active.
- The configured `monitor_dirs` must exist and be readable. When none of them exists, the agent tries the OS Documents, Desktop, and Downloads folders (including XDG user directories on Linux).
- Add absolute paths for other locations to `monitor_dirs`; avoid protected/system folders. A polling watcher is used if the native filesystem watcher cannot start.
- Temporary files, logs, caches, and generated audit database/snapshot files are intentionally filtered.

### Typing counts do not appear

- Confirm `pynput` is installed and inspect `window_error` events for the selected typing backend.
- On Linux Wayland, install the optional `evdev` dependency and grant the logged-in user access to input devices only if typing counts are necessary and consented to. On macOS, grant Input Monitoring permission; on Windows, use the interactive desktop session.
- Global input monitoring may be blocked by the OS. If the required permission is unavailable, disable/omit this feature rather than running the agent as root.

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

### Face lock does not start or keeps locking

- Check `face_lock.enabled` in `config.json` and the current **Face Presence Lock** checkbox in the system-tray menu.
- Enroll an authorized face with `python main.py enroll-face` and verify the YuNet/SFace model files are present in `models/`.
- Check camera access and `face_lock.camera_index`; a camera read failure counts as a failed check.
- To prevent face lock from starting for one run, use `python main.py agent --no-face-lock`. The tray toggle controls the running agent, not a workstation that was already locked.

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

**How do I turn face lock off while the agent is running?**

Open the agent's system-tray menu and uncheck **Face Presence Lock**. This only disables future face checks; unlock the workstation normally if it has already been locked.

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
