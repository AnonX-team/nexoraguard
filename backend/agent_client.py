"""
NexoraGuard — Remote Agent Client
====================================
Copy this file to any Windows machine you want to monitor.
It will send system data to your central NexoraGuard server.

SETUP:
  1. Change SERVER_URL to your server's IP
  2. Run: python agent_client.py
  3. Machine will appear in Dashboard -> Endpoints

Requirements: pip install requests psutil
"""
import os
import sys
import time
import socket
import platform
import logging

import psutil
import requests

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION — Change SERVER_URL to your NexoraGuard server IP
# ══════════════════════════════════════════════════════════════════════════════
SERVER_URL      = "http://127.0.0.1:8080"   # Change to your server IP e.g. http://192.168.1.5:8080
AGENT_SECRET    = "nexora-agent-key-2024"   # Must match server config
REPORT_INTERVAL = 15                         # seconds between reports
AGENT_VERSION   = "1.0"
# ══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AGENT] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)

# ── Suspicious process names (basic EDR) ──────────────────────────────────────
_SUSPICIOUS = {
    "mimikatz", "lazagne", "pwdump", "fgdump", "wce",
    "netcat", "nc.exe", "ncat", "socat",
    "meterpreter", "empire", "cobalt", "beacon",
    "psexec", "wmiexec", "smbexec", "dcsync",
    "procdump", "lsass", "gsecdump",
    "cryptominer", "xmrig", "minerd",
}

# ── Suspicious ports ──────────────────────────────────────────────────────────
_SUSPICIOUS_PORTS = {4444, 1337, 31337, 9001, 9002, 8888, 6666, 5555}


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def collect_processes() -> list:
    procs = []
    try:
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "status"]):
            try:
                info = p.info
                procs.append({
                    "pid":    info["pid"],
                    "name":   info["name"] or "",
                    "cpu":    round(info["cpu_percent"] or 0, 1),
                    "ram_mb": round((info["memory_info"].rss if info["memory_info"] else 0) / 1e6, 1),
                    "status": info["status"],
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception as e:
        log.warning(f"Process collection error: {e}")
    return sorted(procs, key=lambda x: x["cpu"], reverse=True)[:30]


def collect_connections() -> list:
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == "ESTABLISHED" and c.raddr:
                conns.append({
                    "local_port":  c.laddr.port if c.laddr else 0,
                    "remote_ip":   c.raddr.ip if c.raddr else "",
                    "remote_port": c.raddr.port if c.raddr else 0,
                    "status":      c.status,
                    "pid":         c.pid,
                })
    except Exception:
        pass
    return conns[:50]


def detect_threats(processes: list, connections: list) -> list:
    """Basic local threat detection before sending to server."""
    alerts = []

    # Suspicious process names
    for p in processes:
        name_lower = p["name"].lower().replace(".exe", "")
        if name_lower in _SUSPICIOUS:
            alerts.append({
                "type":     "SUSPICIOUS_PROCESS",
                "severity": "HIGH",
                "detail":   f"Suspicious process detected: {p['name']} (PID {p['pid']})",
                "pid":      p["pid"],
                "process":  p["name"],
            })

    # High CPU single process (possible miner)
    for p in processes:
        if p["cpu"] > 80:
            alerts.append({
                "type":     "HIGH_CPU_PROCESS",
                "severity": "MEDIUM",
                "detail":   f"{p['name']} using {p['cpu']}% CPU — possible cryptominer",
                "pid":      p["pid"],
                "process":  p["name"],
            })

    # Suspicious outbound ports
    for c in connections:
        if c["remote_port"] in _SUSPICIOUS_PORTS:
            alerts.append({
                "type":     "SUSPICIOUS_CONNECTION",
                "severity": "HIGH",
                "detail":   f"Connection to suspicious port {c['remote_port']} at {c['remote_ip']}",
                "remote":   f"{c['remote_ip']}:{c['remote_port']}",
            })

    # Too many outbound connections (possible C2 beacon)
    if len(connections) > 80:
        alerts.append({
            "type":     "HIGH_CONNECTION_COUNT",
            "severity": "MEDIUM",
            "detail":   f"Unusually high connection count: {len(connections)}",
        })

    return alerts


def collect_snapshot() -> dict:
    """Collect full system snapshot."""
    procs   = collect_processes()
    conns   = collect_connections()
    alerts  = detect_threats(procs, conns)

    cpu_percent = psutil.cpu_percent(interval=1)
    ram         = psutil.virtual_memory()
    disk        = psutil.disk_usage("/")

    return {
        "hostname":      socket.gethostname(),
        "ip":            get_local_ip(),
        "os":            f"{platform.system()} {platform.release()}",
        "cpu":           cpu_percent,
        "ram":           round(ram.percent, 1),
        "ram_total_gb":  round(ram.total / 1e9, 1),
        "disk":          round(disk.percent, 1),
        "disk_total_gb": round(disk.total / 1e9, 1),
        "processes":     procs,
        "connections":   conns,
        "alerts":        alerts,
        "agent_version": AGENT_VERSION,
    }


def send_report(snapshot: dict) -> bool:
    """POST snapshot to central server."""
    endpoint_id = snapshot["hostname"].replace(" ", "_").lower()
    try:
        r = requests.post(
            f"{SERVER_URL}/endpoints/report",
            json=snapshot,
            headers={
                "X-Agent-Key": AGENT_SECRET,
                "X-Agent-ID":  endpoint_id,
            },
            timeout=10,
        )
        if r.status_code == 200:
            return True
        log.warning(f"Server returned {r.status_code}: {r.text[:100]}")
        return False
    except requests.exceptions.ConnectionError:
        log.warning(f"Cannot reach server at {SERVER_URL} — will retry...")
        return False
    except Exception as e:
        log.error(f"Send error: {e}")
        return False


def main():
    log.info("=" * 50)
    log.info("  NexoraGuard Remote Agent v1.0")
    log.info(f"  Server: {SERVER_URL}")
    log.info(f"  Hostname: {socket.gethostname()}")
    log.info(f"  IP: {get_local_ip()}")
    log.info("=" * 50)
    log.info("Starting — press Ctrl+C to stop")

    consecutive_failures = 0

    while True:
        try:
            snapshot = collect_snapshot()
            ok = send_report(snapshot)

            if ok:
                consecutive_failures = 0
                alert_count = len(snapshot["alerts"])
                log.info(
                    f"Report sent | CPU:{snapshot['cpu']}% RAM:{snapshot['ram']}% "
                    f"Procs:{len(snapshot['processes'])} Alerts:{alert_count}"
                )
            else:
                consecutive_failures += 1
                if consecutive_failures == 3:
                    log.warning("3 failed attempts — check SERVER_URL and network")

        except KeyboardInterrupt:
            log.info("Agent stopped.")
            sys.exit(0)
        except Exception as e:
            log.error(f"Unexpected error: {e}")

        time.sleep(REPORT_INTERVAL)


if __name__ == "__main__":
    main()
