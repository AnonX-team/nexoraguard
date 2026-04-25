"""
NexoraGuard Windows Service
Installs the backend as a proper Windows Service that:
  - Auto-starts on boot
  - Runs in background (no console needed)
  - Managed via services.msc or CLI

Usage:
  python windows_service.py install    — install service
  python windows_service.py start      — start service
  python windows_service.py stop       — stop service
  python windows_service.py remove     — uninstall service
  python windows_service.py status     — check status
"""
import sys
import os
import time
import threading
import logging

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

SERVICE_NAME    = "NexoraGuard"
SERVICE_DISPLAY = "NexoraGuard Security Agent"
SERVICE_DESC    = "AI-powered real-time security monitoring — NexoraGuard v2.0"
HOST            = "0.0.0.0"   # bind all interfaces so Android/remote can reach it
PORT            = 8000         # matches main.py / start.bat default

# Service-specific log file — safe path resolution for both dev and frozen EXE.
# Wrapped in try/except so an import of this module never crashes the app.
try:
    _svc_log_dir = os.path.join(
        os.environ.get("APPDATA") or os.path.expanduser("~"),
        "NexoraCyberTech", "NexoraGuard"
    )
    os.makedirs(_svc_log_dir, exist_ok=True)
    _svc_log_file = os.path.join(_svc_log_dir, "service.log")
    _svc_handler = logging.FileHandler(_svc_log_file, encoding="utf-8")
    _svc_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    _svc_logger = logging.getLogger("NexoraGuard-Service")
    if not _svc_logger.handlers:
        _svc_logger.addHandler(_svc_handler)
    _svc_logger.setLevel(logging.INFO)
except Exception:
    pass   # service logging is non-critical — never crash the app over it
logger = logging.getLogger("NexoraGuard-Service")


class NexoraGuardService(win32serviceutil.ServiceFramework if HAS_WIN32 else object):
    _svc_name_         = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY
    _svc_description_  = SERVICE_DESC

    def __init__(self, args):
        if HAS_WIN32:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
        self._running = False

    def SvcStop(self):
        logger.info("Service stop requested")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self._stop_event)
        self._running = False

    def SvcDoRun(self):
        logger.info("NexoraGuard Service starting...")
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, "")
        )
        self._running = True
        self._run_server()

    def _run_server(self):
        """Start FastAPI server in a daemon thread."""
        backend_dir = os.path.dirname(os.path.abspath(__file__))
        if backend_dir not in sys.path:
            sys.path.insert(0, backend_dir)
        os.chdir(backend_dir)

        # Resolve log path so uvicorn writes to AppData (not CWD)
        log_file = os.path.join(
            os.environ.get("APPDATA") or os.path.expanduser("~"),
            "NexoraCyberTech", "NexoraGuard", "uvicorn.log"
        )

        def run():
            try:
                import uvicorn
                uvicorn.run(
                    "main:app",
                    host=HOST,
                    port=PORT,
                    log_level="warning",
                    access_log=False,
                    # Write uvicorn logs to file (no console when running as service)
                    log_config={
                        "version": 1,
                        "disable_existing_loggers": False,
                        "handlers": {
                            "file": {
                                "class": "logging.FileHandler",
                                "filename": log_file,
                                "encoding": "utf-8",
                                "formatter": "default",
                            }
                        },
                        "formatters": {
                            "default": {
                                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
                            }
                        },
                        "loggers": {
                            "uvicorn":        {"handlers": ["file"], "level": "WARNING"},
                            "uvicorn.error":  {"handlers": ["file"], "level": "WARNING"},
                            "uvicorn.access": {"handlers": ["file"], "level": "WARNING"},
                        },
                    }
                )
            except Exception as e:
                logger.error(f"Server crashed: {e}")

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        logger.info(f"Server thread started on {HOST}:{PORT}")

        # Keep service alive until stop is requested
        while self._running:
            if HAS_WIN32:
                result = win32event.WaitForSingleObject(self._stop_event, 5000)
                if result == win32event.WAIT_OBJECT_0:
                    break
            else:
                time.sleep(5)

        logger.info("NexoraGuard Service stopped.")


# ── CLI Commands ──────────────────────────────────────────────────────────────
def install_service():
    if not HAS_WIN32:
        print("[!] pywin32 not installed. Run: pip install pywin32"); return
    print(f"[*] Installing '{SERVICE_DISPLAY}' as Windows Service...")

    # When running from frozen EXE use the EXE itself; in dev use Python
    if getattr(sys, "frozen", False):
        exe  = sys.executable
        args = ""
    else:
        exe  = sys.executable
        args = f'"{os.path.abspath(__file__)}"'

    win32serviceutil.InstallService(
        pythonClassString=f"{__name__}.NexoraGuardService",
        serviceName=SERVICE_NAME,
        displayName=SERVICE_DISPLAY,
        description=SERVICE_DESC,
        startType=win32service.SERVICE_AUTO_START,
        exeName=exe,
        exeArgs=args,
    )
    print(f"[✓] Service installed!")
    print(f"    Name   : {SERVICE_NAME}")
    print(f"    Display: {SERVICE_DISPLAY}")
    print(f"    Start  : Automatic (starts on Windows boot)")
    print(f"    Port   : {PORT}")
    print(f"\n    To start now : python windows_service.py start")
    print(f"    Dashboard    : http://localhost:{PORT}/dashboard/index.html")


def remove_service():
    print(f"[*] Removing service '{SERVICE_NAME}'...")
    try:
        win32serviceutil.StopService(SERVICE_NAME)
        time.sleep(2)
    except Exception:
        pass
    win32serviceutil.RemoveService(SERVICE_NAME)
    print(f"[✓] Service removed.")


def start_service():
    print(f"[*] Starting service '{SERVICE_NAME}'...")
    win32serviceutil.StartService(SERVICE_NAME)
    print(f"[✓] Service started — NexoraGuard is now monitoring in background")
    print(f"    Dashboard: http://{HOST}:{PORT}/dashboard/index.html")


def stop_service():
    print(f"[*] Stopping service '{SERVICE_NAME}'...")
    win32serviceutil.StopService(SERVICE_NAME)
    print(f"[✓] Service stopped.")


def check_status():
    try:
        status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        states = {
            1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING",
            4: "RUNNING", 5: "CONTINUE_PENDING", 6: "PAUSE_PENDING", 7: "PAUSED"
        }
        state = states.get(status[1], "UNKNOWN")
        print(f"[*] Service '{SERVICE_NAME}': {state}")
        return state
    except Exception as e:
        print(f"[!] Service not found or error: {e}")
        return "NOT_INSTALLED"


def get_service_state() -> dict:
    """Return service state as dict — for use by the API endpoint."""
    if not HAS_WIN32:
        return {"installed": False, "state": "NOT_AVAILABLE", "message": "pywin32 not installed"}
    try:
        status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        states = {
            1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING",
            4: "RUNNING", 5: "CONTINUE_PENDING", 6: "PAUSE_PENDING", 7: "PAUSED"
        }
        state = states.get(status[1], "UNKNOWN")
        return {
            "installed": True,
            "state": state,
            "running": state == "RUNNING",
            "name": SERVICE_NAME,
            "display": SERVICE_DISPLAY,
            "port": PORT,
        }
    except Exception:
        return {"installed": False, "state": "NOT_INSTALLED", "running": False}


if __name__ == "__main__":
    if not HAS_WIN32:
        print("[!] pywin32 required. Run: pip install pywin32")
        sys.exit(1)

    commands = {
        "install": install_service,
        "remove":  remove_service,
        "uninstall": remove_service,
        "start":   start_service,
        "stop":    stop_service,
        "status":  check_status,
    }

    if len(sys.argv) < 2 or sys.argv[1] not in commands:
        print(f"""
NexoraGuard Windows Service Manager
====================================
Usage: python windows_service.py <command>

Commands:
  install    Install as Windows Service (auto-start on boot)
  start      Start the service
  stop       Stop the service
  status     Check service status
  remove     Uninstall the service
        """)
    elif sys.argv[1] in ("install", "remove", "uninstall", "start", "stop", "status"):
        commands[sys.argv[1]]()
    else:
        # Called by Windows SCM
        win32serviceutil.HandleCommandLine(NexoraGuardService)
