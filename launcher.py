"""
NexoraGuard Launcher — DEBUG MODE
console=True, uac_admin=False, no webview, verbose prints.
Goal: see the Traceback. Run EXE as Admin manually if needed.
"""
print("DEBUG: Step 1 — launcher.py top-level reached", flush=True)

import sys
print("DEBUG: Step 2 — sys imported", flush=True)

import os
print("DEBUG: Step 3 — os imported", flush=True)

import socket
import time
import threading
import traceback
import logging
from datetime import datetime
print("DEBUG: Step 4 — all stdlib imports done", flush=True)

# ── DO NOT redirect stdout/stderr — we want to see everything ─────────────────
# (removed the frozen-mode /dev/null redirect that was hiding all errors)

APP_NAME        = "NexoraGuard"
APP_VERSION     = "2.0.0"
BIND_HOST       = "127.0.0.1"   # loopback only for debug
CONNECT_HOST    = "127.0.0.1"
PREFERRED_PORTS = list(range(8080, 8090))

_FROZEN   = getattr(sys, "frozen", False)
_SELF_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))

print(f"DEBUG: Step 5 — FROZEN={_FROZEN}, SELF_DIR={_SELF_DIR}", flush=True)

# ── AppData log directory ─────────────────────────────────────────────────────
_APPDATA  = os.environ.get("APPDATA") or os.path.expanduser("~")
_LOG_DIR  = os.path.abspath(os.path.join(_APPDATA, "NexoraCyberTech", "NexoraGuard"))
os.makedirs(_LOG_DIR, exist_ok=True)
_LOG_FILE = os.path.join(_LOG_DIR, "nexoraguard.log")

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(_LOG_FILE, encoding="utf-8"),
    ],
)
logger = logging.getLogger("launcher")
print(f"DEBUG: Step 6 — logging set up, log file: {_LOG_FILE}", flush=True)


# ── Path helpers ──────────────────────────────────────────────────────────────

def get_backend_path() -> str:
    if _FROZEN:
        return os.path.abspath(os.path.join(sys._MEIPASS, "backend"))
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "backend"))


def get_dashboard_path() -> str:
    if _FROZEN:
        return os.path.abspath(os.path.join(sys._MEIPASS, "dashboard"))
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "dashboard"))


# ── Port binding ──────────────────────────────────────────────────────────────

def find_and_bind() -> tuple:
    print("DEBUG: Step 8 — find_and_bind() called", flush=True)
    for port in PREFERRED_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((BIND_HOST, port))
            print(f"DEBUG: Step 9 — port {port} bound successfully", flush=True)
            return s, port
        except OSError as e:
            print(f"DEBUG: port {port} busy ({e}), trying next", flush=True)
            s.close()

    # OS fallback
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((BIND_HOST, 0))
    port = s.getsockname()[1]
    print(f"DEBUG: Step 9 — OS assigned port {port}", flush=True)
    return s, port


# ── Backend server ────────────────────────────────────────────────────────────

_server_crash: str = ""


def start_server(sock: socket.socket, port: int) -> None:
    global _server_crash
    print(f"DEBUG: Step 11 — start_server() thread started on port {port}", flush=True)

    backend = get_backend_path()
    print(f"DEBUG: Step 12 — backend path = {backend}", flush=True)
    print(f"DEBUG: Step 12b — backend exists = {os.path.exists(backend)}", flush=True)

    if backend not in sys.path:
        sys.path.insert(0, backend)

    os.chdir(backend)
    print(f"DEBUG: Step 13 — chdir to backend done, cwd = {os.getcwd()}", flush=True)

    try:
        print("DEBUG: Step 14 — importing uvicorn...", flush=True)
        import uvicorn
        print("DEBUG: Step 15 — uvicorn imported OK", flush=True)

        config = uvicorn.Config(
            "main:app",
            host=BIND_HOST,
            port=port,
            log_level="debug",
            log_config=None,
            access_log=True,
        )
        print("DEBUG: Step 16 — uvicorn.Config created", flush=True)

        server = uvicorn.Server(config)
        print("DEBUG: Step 17 — uvicorn.Server created, calling server.run()...", flush=True)
        server.run(sockets=[sock])
        print("DEBUG: Step 17b — server.run() returned (server stopped)", flush=True)

    except Exception as e:
        _server_crash = str(e)
        print(f"DEBUG: ERROR in start_server: {type(e).__name__}: {e}", flush=True)
        traceback.print_exc()
        logger.error(f"uvicorn crashed: {e}")


def wait_for_server(port: int, timeout: int = 60) -> bool:
    print(f"DEBUG: Step 18 — waiting for server on port {port} (timeout={timeout}s)...", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _server_crash:
            print(f"DEBUG: Step 18b — server crashed: {_server_crash}", flush=True)
            return False
        try:
            conn = socket.create_connection((CONNECT_HOST, port), timeout=1)
            conn.close()
            print(f"DEBUG: Step 19 — server is UP on port {port}!", flush=True)
            return True
        except OSError:
            time.sleep(0.5)
    print("DEBUG: Step 18c — server wait TIMEOUT (server may still be starting)", flush=True)
    return False


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("DEBUG: Step 7 — main() entered", flush=True)

    sock, port = find_and_bind()
    url = f"http://{CONNECT_HOST}:{port}/dashboard/index.html"
    print(f"DEBUG: Step 10 — URL will be: {url}", flush=True)

    # Write config.js for dashboard
    dashboard   = get_dashboard_path()
    config_path = os.path.join(dashboard, "config.js")
    try:
        os.makedirs(dashboard, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(f"// Auto-generated\nwindow.NEXORA_PORT = {port};\n")
        print(f"DEBUG: Step 10b — config.js written to {config_path}", flush=True)
    except Exception as e:
        print(f"DEBUG: WARNING — could not write config.js: {e}", flush=True)

    # Start backend in daemon thread
    server_thread = threading.Thread(
        target=start_server, args=(sock, port), daemon=True, name="uvicorn"
    )
    server_thread.start()
    print("DEBUG: Step 11b — uvicorn thread started", flush=True)

    if not wait_for_server(port):
        if _server_crash:
            print(f"\n{'='*60}", flush=True)
            print(f"STARTUP FAILURE: {_server_crash}", flush=True)
            print(f"{'='*60}\n", flush=True)
            return
        # Timeout but no crash — server is likely still starting, keep alive
        print(f"\n{'='*60}", flush=True)
        print(f"WARNING: TCP check timed out but server thread is still running.", flush=True)
        print(f"Try opening the dashboard manually: {url}", flush=True)
        print(f"{'='*60}\n", flush=True)

    print(f"DEBUG: Step 20 — backend is RUNNING at {url}", flush=True)
    print("DEBUG: Step 21 — WebView is DISABLED for this debug build.", flush=True)
    print("       Open your browser and go to:", flush=True)
    print(f"       {url}", flush=True)
    print("DEBUG: Step 22 — keeping process alive (Ctrl+C to stop)...", flush=True)

    # ── webview.create_window DISABLED for debug — uncomment to re-enable ─────
    # import webview
    # _webview_window = webview.create_window(
    #     title=APP_NAME, url=url, width=1280, height=780, min_size=(900, 600)
    # )
    # webview.start(debug=True)

    # Keep process alive so uvicorn stays running
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\nDEBUG: Ctrl+C received — shutting down.", flush=True)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("DEBUG: Step 0 — __main__ block entered", flush=True)
    try:
        main()
    except Exception as exc:
        print(f"\n{'='*60}", flush=True)
        print(f"FATAL CRASH: {type(exc).__name__}: {exc}", flush=True)
        print(f"{'='*60}", flush=True)
        traceback.print_exc()
        print(f"\nLog file: {_LOG_FILE}", flush=True)
        input("\nPress ENTER to close...")  # pause so window doesn't vanish
        sys.exit(1)
