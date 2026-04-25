"""
NexoraGuard Remote Agent v2.0
==============================
Professional Windows monitoring agent.
- First run: shows setup wizard
- Normal run: runs silently in system tray
- Auto-starts on Windows boot
- Reports to NexoraGuard central server every 15s
"""
import os
import sys
import json
import time
import socket
import platform
import threading
import logging
import winreg
import tkinter as tk
from tkinter import font as tkfont

import psutil
import requests
from PIL import Image, ImageDraw
import pystray

# ── Paths ──────────────────────────────────────────────────────────────────────
_APPDATA       = os.environ.get("APPDATA", os.path.expanduser("~"))
CONFIG_DIR     = os.path.join(_APPDATA, "NexoraGuard")
CONFIG_FILE    = os.path.join(CONFIG_DIR, "agent_config.json")
LOG_FILE       = os.path.join(CONFIG_DIR, "agent.log")
AUTORUN_KEY    = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTORUN_NAME   = "NexoraGuardAgent"

# ── Defaults ───────────────────────────────────────────────────────────────────
AGENT_SECRET    = "nexora-agent-key-2024"
AGENT_VERSION   = "2.0"
REPORT_INTERVAL = 15

# ── Logging ────────────────────────────────────────────────────────────────────
os.makedirs(CONFIG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AGENT] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger(__name__)

# ── Suspicious indicators ──────────────────────────────────────────────────────
_SUSPICIOUS_PROCS = {
    "mimikatz","lazagne","pwdump","fgdump","wce","netcat","nc.exe","ncat",
    "meterpreter","empire","cobalt","beacon","psexec","wmiexec","smbexec",
    "procdump","gsecdump","xmrig","minerd","cryptominer",
}
_SUSPICIOUS_PORTS = {4444, 1337, 31337, 9001, 9002, 8888, 6666, 5555}


# ══════════════════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════════════════
def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        try:
            return json.loads(open(CONFIG_FILE, encoding="utf-8").read())
        except Exception:
            pass
    return {}

def save_config(cfg: dict):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    open(CONFIG_FILE, "w", encoding="utf-8").write(json.dumps(cfg, indent=2))

def is_configured() -> bool:
    cfg = load_config()
    return bool(cfg.get("server_url") and cfg.get("agent_name"))


# ══════════════════════════════════════════════════════════════════════════════
# WINDOWS AUTO-START
# ══════════════════════════════════════════════════════════════════════════════
def _get_exe_path() -> str:
    return sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)

def enable_autostart():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTORUN_KEY, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, AUTORUN_NAME, 0, winreg.REG_SZ, f'"{_get_exe_path()}"')
        winreg.CloseKey(key)
        log.info("Auto-start enabled in registry")
    except Exception as e:
        log.warning(f"Auto-start setup failed: {e}")

def disable_autostart():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTORUN_KEY, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, AUTORUN_NAME)
        winreg.CloseKey(key)
    except Exception:
        pass

def is_autostart_enabled() -> bool:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTORUN_KEY, 0, winreg.KEY_READ)
        winreg.QueryValueEx(key, AUTORUN_NAME)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# SETUP WIZARD — shown on first run
# ══════════════════════════════════════════════════════════════════════════════
class SetupWizard:
    # Dark theme colors matching NexoraGuard dashboard
    BG      = "#030813"
    SURFACE = "#0c1426"
    BORDER  = "#1a2d4a"
    ACCENT  = "#0ea5e9"
    TEXT    = "#f1f5f9"
    TEXT2   = "#94a3b8"
    TEXT3   = "#475569"
    GREEN   = "#22c55e"
    RED     = "#ef4444"

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("NexoraGuard Agent Setup")
        self.root.geometry("480x580")
        self.root.resizable(False, False)
        self.root.configure(bg=self.BG)
        self.root.eval("tk::PlaceWindow . center")

        # Try to set icon
        try:
            icon_path = os.path.join(os.path.dirname(_get_exe_path()), "logo.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass

        self._build_ui()
        self.result = False

    def _lbl(self, parent, text, size=12, color=None, bold=False, **kw):
        f = tkfont.Font(family="Segoe UI", size=size, weight="bold" if bold else "normal")
        return tk.Label(parent, text=text, font=f,
                        fg=color or self.TEXT, bg=kw.pop("bg", self.BG), **kw)

    def _entry(self, parent, placeholder="", show=""):
        frame = tk.Frame(parent, bg=self.SURFACE, highlightbackground=self.BORDER,
                         highlightthickness=1, bd=0)
        e = tk.Entry(frame, bg=self.SURFACE, fg=self.TEXT, insertbackground=self.TEXT,
                     font=("Segoe UI", 11), bd=0, show=show,
                     relief="flat", highlightthickness=0)
        e.pack(fill="x", padx=12, pady=10)

        # Placeholder logic
        if placeholder:
            e.insert(0, placeholder)
            e.config(fg=self.TEXT3)
            def on_focus_in(ev):
                if e.get() == placeholder:
                    e.delete(0, "end")
                    e.config(fg=self.TEXT)
            def on_focus_out(ev):
                if not e.get():
                    e.insert(0, placeholder)
                    e.config(fg=self.TEXT3)
            e.bind("<FocusIn>",  on_focus_in)
            e.bind("<FocusOut>", on_focus_out)

        def on_enter(ev): frame.config(highlightbackground=self.ACCENT)
        def on_leave(ev): frame.config(highlightbackground=self.BORDER)
        frame.bind("<Enter>", on_enter)
        frame.bind("<Leave>", on_leave)
        e.bind("<FocusIn>",  lambda ev: frame.config(highlightbackground=self.ACCENT))
        e.bind("<FocusOut>", lambda ev: frame.config(highlightbackground=self.BORDER))

        return frame, e

    def _build_ui(self):
        root = self.root

        # Header
        hdr = tk.Frame(root, bg=self.SURFACE, height=80)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        logo_frame = tk.Frame(hdr, bg="#0ea5e9", width=40, height=40)
        logo_frame.place(x=20, rely=0.5, anchor="w")
        tk.Label(logo_frame, text="🛡", font=("Segoe UI", 18),
                 bg="#0ea5e9", fg="white").place(relx=.5, rely=.5, anchor="center")

        tk.Label(hdr, text="NexoraGuard", font=("Segoe UI", 15, "bold"),
                 fg=self.TEXT, bg=self.SURFACE).place(x=72, y=16)
        tk.Label(hdr, text="Remote Agent Setup", font=("Segoe UI", 10),
                 fg=self.TEXT3, bg=self.SURFACE).place(x=72, y=42)

        sep = tk.Frame(root, bg=self.BORDER, height=1)
        sep.pack(fill="x")

        # Content
        content = tk.Frame(root, bg=self.BG)
        content.pack(fill="both", expand=True, padx=30, pady=24)

        self._lbl(content, "Connect to NexoraGuard Server", size=14, bold=True).pack(anchor="w", pady=(0, 4))
        self._lbl(content, "Enter your server details to start monitoring this machine.",
                  size=10, color=self.TEXT2).pack(anchor="w", pady=(0, 20))

        # Server URL
        self._lbl(content, "SERVER URL", size=9, color=self.TEXT3).pack(anchor="w", pady=(0, 5))
        self._url_frame, self.url_entry = self._entry(content, "http://192.168.1.X:8080")
        self._url_frame.pack(fill="x", pady=(0, 4))
        self._lbl(content, "Your NexoraGuard server IP address and port",
                  size=9, color=self.TEXT3).pack(anchor="w", pady=(0, 16))

        # Machine Name
        self._lbl(content, "MACHINE NAME", size=9, color=self.TEXT3).pack(anchor="w", pady=(0, 5))
        default_name = socket.gethostname()
        self._name_frame, self.name_entry = self._entry(content, default_name)
        self.name_entry.delete(0, "end")
        self.name_entry.insert(0, default_name)
        self.name_entry.config(fg=self.TEXT)
        self._name_frame.pack(fill="x", pady=(0, 4))
        self._lbl(content, "How this machine will appear in the dashboard",
                  size=9, color=self.TEXT3).pack(anchor="w", pady=(0, 16))

        # Auto-start
        self.autostart_var = tk.BooleanVar(value=True)
        cb_frame = tk.Frame(content, bg=self.BG)
        cb_frame.pack(anchor="w", pady=(0, 20))
        tk.Checkbutton(cb_frame, variable=self.autostart_var, bg=self.BG,
                       fg=self.TEXT, selectcolor=self.SURFACE,
                       activebackground=self.BG, activeforeground=self.TEXT,
                       font=("Segoe UI", 10)).pack(side="left")
        self._lbl(cb_frame, "Start agent automatically when Windows boots",
                  size=10, bg=self.BG).pack(side="left", padx=(4, 0))

        # Status label
        self.status_lbl = self._lbl(content, "", size=10, color=self.TEXT2)
        self.status_lbl.pack(anchor="w", pady=(0, 12))

        # Buttons
        btn_frame = tk.Frame(content, bg=self.BG)
        btn_frame.pack(fill="x")

        # Test button
        test_btn = tk.Button(btn_frame, text="Test Connection",
                             font=("Segoe UI", 10), fg=self.TEXT2, bg=self.SURFACE,
                             activeforeground=self.ACCENT, activebackground=self.SURFACE,
                             relief="flat", bd=0, cursor="hand2",
                             padx=16, pady=10,
                             command=self._test_connection)
        test_btn.pack(side="left", padx=(0, 10))

        # Install button
        self.install_btn = tk.Button(btn_frame, text="Install & Start Agent",
                                     font=("Segoe UI", 11, "bold"),
                                     fg="white", bg=self.ACCENT,
                                     activeforeground="white", activebackground="#0284c7",
                                     relief="flat", bd=0, cursor="hand2",
                                     padx=20, pady=10,
                                     command=self._install)
        self.install_btn.pack(side="right")

        # Footer
        footer = tk.Frame(root, bg=self.SURFACE, height=40)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)
        self._lbl(footer, f"NexoraGuard Agent v{AGENT_VERSION}  •  Nexora Cyber Tech",
                  size=9, color=self.TEXT3, bg=self.SURFACE).place(relx=.5, rely=.5, anchor="center")

    def _get_url(self) -> str:
        url = self.url_entry.get().strip()
        if url in ("http://192.168.1.X:8080", ""):
            return ""
        if not url.startswith("http"):
            url = "http://" + url
        return url.rstrip("/")

    def _get_name(self) -> str:
        name = self.name_entry.get().strip()
        return name if name else socket.gethostname()

    def _set_status(self, msg: str, color: str = None):
        self.status_lbl.config(text=msg, fg=color or self.TEXT2)
        self.root.update_idletasks()

    def _test_connection(self):
        url = self._get_url()
        if not url:
            self._set_status("⚠  Please enter server URL", self.RED)
            return
        self._set_status("Testing connection...", self.ACCENT)
        try:
            r = requests.get(f"{url}/status", timeout=5)
            if r.status_code == 200:
                self._set_status("✓  Connected successfully!", self.GREEN)
            else:
                self._set_status(f"⚠  Server responded with {r.status_code}", self.RED)
        except Exception as e:
            self._set_status(f"✗  Cannot reach server: {e}", self.RED)

    def _install(self):
        url  = self._get_url()
        name = self._get_name()
        if not url:
            self._set_status("⚠  Server URL is required", self.RED)
            return

        self._set_status("Installing...", self.ACCENT)
        self.install_btn.config(state="disabled")

        cfg = {
            "server_url":  url,
            "agent_name":  name,
            "agent_secret": AGENT_SECRET,
            "autostart":   self.autostart_var.get(),
        }
        save_config(cfg)

        if self.autostart_var.get():
            enable_autostart()

        self._set_status("✓  Agent installed successfully!", self.GREEN)
        self.result = True
        self.root.after(1200, self.root.destroy)

    def run(self) -> bool:
        self.root.mainloop()
        return self.result


# ══════════════════════════════════════════════════════════════════════════════
# DATA COLLECTION
# ══════════════════════════════════════════════════════════════════════════════
def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return "127.0.0.1"

def _collect_processes() -> list:
    procs = []
    try:
        for p in psutil.process_iter(["pid","name","cpu_percent","memory_info","status"]):
            try:
                i = p.info
                procs.append({"pid":i["pid"],"name":i["name"] or "","cpu":round(i["cpu_percent"] or 0,1),
                               "ram_mb":round((i["memory_info"].rss if i["memory_info"] else 0)/1e6,1),"status":i["status"]})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception: pass
    return sorted(procs, key=lambda x: x["cpu"], reverse=True)[:30]

def _collect_connections() -> list:
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == "ESTABLISHED" and c.raddr:
                conns.append({"local_port":c.laddr.port if c.laddr else 0,
                               "remote_ip":c.raddr.ip,"remote_port":c.raddr.port,"pid":c.pid})
    except Exception: pass
    return conns[:50]

def _detect_threats(procs, conns) -> list:
    alerts = []
    for p in procs:
        if p["name"].lower().replace(".exe","") in _SUSPICIOUS_PROCS:
            alerts.append({"type":"SUSPICIOUS_PROCESS","severity":"HIGH",
                           "detail":f"Suspicious process: {p['name']} (PID {p['pid']})","process":p["name"]})
    for p in procs:
        if p["cpu"] > 80:
            alerts.append({"type":"HIGH_CPU_PROCESS","severity":"MEDIUM",
                           "detail":f"{p['name']} using {p['cpu']}% CPU — possible miner"})
    for c in conns:
        if c["remote_port"] in _SUSPICIOUS_PORTS:
            alerts.append({"type":"SUSPICIOUS_CONNECTION","severity":"HIGH",
                           "detail":f"Connection to suspicious port {c['remote_port']} at {c['remote_ip']}"})
    return alerts

def collect_snapshot(agent_name: str) -> dict:
    procs   = _collect_processes()
    conns   = _collect_connections()
    alerts  = _detect_threats(procs, conns)
    ram     = psutil.virtual_memory()
    disk    = psutil.disk_usage("/")
    return {
        "hostname":      agent_name,
        "ip":            _get_local_ip(),
        "os":            f"{platform.system()} {platform.release()}",
        "cpu":           psutil.cpu_percent(interval=1),
        "ram":           round(ram.percent, 1),
        "disk":          round(disk.percent, 1),
        "processes":     procs,
        "connections":   conns,
        "alerts":        alerts,
        "agent_version": AGENT_VERSION,
    }

def send_report(cfg: dict, snapshot: dict) -> bool:
    agent_id = cfg["agent_name"].replace(" ","_").lower()
    try:
        r = requests.post(
            f"{cfg['server_url']}/endpoints/report",
            json=snapshot,
            headers={"X-Agent-Key": cfg.get("agent_secret", AGENT_SECRET),
                     "X-Agent-ID":  agent_id},
            timeout=8,
        )
        return r.status_code == 200
    except requests.exceptions.ConnectionError:
        return False
    except Exception as e:
        log.error(f"Send error: {e}"); return False


# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM TRAY
# ══════════════════════════════════════════════════════════════════════════════
_tray_icon = None
_connected = False
_stop_event = threading.Event()

def _make_icon(color=(14, 165, 233)) -> Image.Image:
    """Create shield-shaped tray icon."""
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d   = ImageDraw.Draw(img)
    cx  = size // 2
    # Simple shield polygon
    pts = [(cx,4),(58,14),(58,36),(cx,60),(6,36),(6,14)]
    d.polygon(pts, fill=(*color, 230))
    d.polygon(pts, outline=(255,255,255,120), width=2)
    return img

def _icon_green(): return _make_icon((34, 197, 94))
def _icon_red():   return _make_icon((239, 68, 68))
def _icon_blue():  return _make_icon((14, 165, 233))

def _open_dashboard(icon, item):
    cfg = load_config()
    url = cfg.get("server_url", "http://127.0.0.1:8080")
    import webbrowser
    webbrowser.open(f"{url}/dashboard")

def _show_status(icon, item):
    cfg  = load_config()
    status = "Connected" if _connected else "Disconnected"
    msg = (f"Status: {status}\n"
           f"Server: {cfg.get('server_url','?')}\n"
           f"Machine: {cfg.get('agent_name','?')}\n"
           f"Log: {LOG_FILE}")
    import ctypes
    ctypes.windll.user32.MessageBoxW(0, msg, "NexoraGuard Agent", 0x40)

def _toggle_autostart(icon, item):
    if is_autostart_enabled():
        disable_autostart()
        cfg = load_config(); cfg["autostart"] = False; save_config(cfg)
    else:
        enable_autostart()
        cfg = load_config(); cfg["autostart"] = True; save_config(cfg)
    icon.update_menu()

def _exit_agent(icon, item):
    _stop_event.set()
    icon.stop()

def _make_menu():
    return pystray.Menu(
        pystray.MenuItem("NexoraGuard Agent", None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Open Dashboard",    _open_dashboard),
        pystray.MenuItem("Status",            _show_status),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(
            lambda item: "Disable Auto-start" if is_autostart_enabled() else "Enable Auto-start",
            _toggle_autostart
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Exit",              _exit_agent),
    )


# ══════════════════════════════════════════════════════════════════════════════
# BACKGROUND REPORTER
# ══════════════════════════════════════════════════════════════════════════════
def _reporter_loop(icon: pystray.Icon):
    global _connected
    cfg  = load_config()
    name = cfg.get("agent_name", socket.gethostname())
    fail = 0

    log.info(f"Reporter started | Server: {cfg.get('server_url')} | Machine: {name}")

    while not _stop_event.is_set():
        try:
            snap = collect_snapshot(name)
            ok   = send_report(cfg, snap)
            if ok:
                _connected = True
                fail = 0
                icon.icon  = _icon_green()
                icon.title = f"NexoraGuard — Connected | Alerts: {len(snap['alerts'])}"
                log.info(f"Report sent | CPU:{snap['cpu']}% Alerts:{len(snap['alerts'])}")
            else:
                _connected = False
                fail += 1
                icon.icon  = _icon_red()
                icon.title = f"NexoraGuard — Server unreachable"
                if fail == 3:
                    log.warning(f"Cannot reach {cfg.get('server_url')} — retrying...")
        except Exception as e:
            log.error(f"Reporter error: {e}")

        _stop_event.wait(REPORT_INTERVAL)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    # First run: show setup wizard
    if not is_configured():
        log.info("First run — launching setup wizard")
        wizard = SetupWizard()
        ok = wizard.run()
        if not ok:
            log.info("Setup cancelled — exiting")
            sys.exit(0)
        log.info("Setup complete — starting agent")

    # Create tray icon
    icon = pystray.Icon(
        name  = "NexoraGuard Agent",
        icon  = _icon_blue(),
        title = "NexoraGuard Agent — Starting...",
        menu  = _make_menu(),
    )

    # Start reporter in background thread
    t = threading.Thread(target=_reporter_loop, args=(icon,), daemon=True)
    t.start()

    # Run tray (blocks until exit)
    icon.run()
    log.info("Agent stopped.")


if __name__ == "__main__":
    main()
