"""
Real-time System Monitor
CPU, Memory, Disk, Processes, Network using psutil.
Full IPv4 + IPv6 support with protocol tagging.
"""
import psutil
import socket
from datetime import datetime


SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz", "meterpreter", "nc.exe", "ncat", "netcat",
    "pwdump", "fgdump", "procdump", "lazagne", "wce",
    "bloodhound", "sharphound", "rubeus", "cobaltstrike",
    "psexec", "wmiexec", "smbexec", "empire", "covenant",
    "havoc", "sliver", "brute-ratel", "cobalt", "metasploit",
}

SUSPICIOUS_PORTS = {4444, 1337, 31337, 9999, 6666, 8888, 4445, 5555, 1234, 54321}


def get_system_stats() -> dict:
    """Get CPU, RAM, Disk usage."""
    disk = psutil.disk_usage("C:\\")
    return {
        "cpu_percent":    psutil.cpu_percent(interval=1),
        "ram_percent":    psutil.virtual_memory().percent,
        "ram_used_gb":    round(psutil.virtual_memory().used  / (1024 ** 3), 2),
        "ram_total_gb":   round(psutil.virtual_memory().total / (1024 ** 3), 2),
        "disk_percent":   disk.percent,
        "disk_free_gb":   round(disk.free / (1024 ** 3), 2),
        "disk_total_gb":  round(disk.total / (1024 ** 3), 2),
    }


def get_running_processes() -> list[dict]:
    """List all running processes with PID, name, CPU, memory, and parent (process tree)."""
    processes = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status", "ppid", "cmdline"]):
        try:
            info = proc.info
            # Resolve parent name
            parent_name = ""
            parent_pid  = info.get("ppid") or 0
            if parent_pid:
                try:
                    parent_name = psutil.Process(parent_pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    parent_name = ""

            # Command line (first 120 chars)
            cmdline = ""
            try:
                raw = info.get("cmdline") or []
                cmdline = " ".join(raw)[:120]
            except Exception:
                pass

            processes.append({
                "pid":         info["pid"],
                "name":        info["name"],
                "cpu":         round(info["cpu_percent"] or 0, 2),
                "memory":      round(info["memory_percent"] or 0, 2),
                "status":      info["status"],
                "parent_pid":  parent_pid,
                "parent_name": parent_name,
                "cmdline":     cmdline,
                "suspicious":  info["name"].lower() in SUSPICIOUS_PROCESS_NAMES
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes


def get_suspicious_processes() -> list[dict]:
    """Filter only suspicious processes."""
    return [p for p in get_running_processes() if p["suspicious"]]


# ── Network (IPv4 + IPv6) ─────────────────────────────────────────────────────

def _is_ipv6(ip: str) -> bool:
    """Return True if address string is IPv6."""
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except (socket.error, OSError):
        return False


def _format_addr(ip: str, port: int) -> str:
    """Format address:port, wrapping IPv6 in brackets."""
    if _is_ipv6(ip):
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def _is_suspicious_port(port: int) -> bool:
    return port in SUSPICIOUS_PORTS


def get_network_connections() -> list[dict]:
    """
    Get all active network connections — IPv4 and IPv6.
    Each entry includes: protocol (IPv4/IPv6), addresses, port, status, suspicious flags.
    """
    connections = []
    try:
        # kind="inet" covers both inet4 and inet6 in psutil
        for conn in psutil.net_connections(kind="inet"):
            local_ip   = conn.laddr.ip   if conn.laddr else ""
            local_port = conn.laddr.port if conn.laddr else 0
            remote_ip  = conn.raddr.ip   if conn.raddr else ""
            remote_port = conn.raddr.port if conn.raddr else 0

            protocol = "IPv6" if _is_ipv6(local_ip) else "IPv4"

            local_addr  = _format_addr(local_ip, local_port)  if conn.laddr else ""
            remote_addr = _format_addr(remote_ip, remote_port) if conn.raddr else ""

            suspicious_local  = _is_suspicious_port(local_port)
            suspicious_remote = _is_suspicious_port(remote_port)

            entry = {
                "pid":              conn.pid,
                "status":           conn.status,
                "protocol":         protocol,
                "local_addr":       local_addr,
                "local_ip":         local_ip,
                "local_port":       local_port,
                "remote_addr":      remote_addr,
                "remote_ip":        remote_ip,
                "remote_port":      remote_port,
                "suspicious_port":  suspicious_local or suspicious_remote,
                "suspicious_local_port":  suspicious_local,
                "suspicious_remote_port": suspicious_remote,
                "is_ipv6":          protocol == "IPv6",
            }
            connections.append(entry)

    except (psutil.AccessDenied, PermissionError):
        pass
    return connections


def get_suspicious_connections() -> list[dict]:
    """Filter connections on suspicious ports (IPv4 + IPv6)."""
    return [c for c in get_network_connections() if c["suspicious_port"]]


def get_network_stats() -> dict:
    """Get bytes sent/received and per-interface breakdown."""
    net = psutil.net_io_counters()
    stats = {
        "bytes_sent_mb":  round(net.bytes_sent   / (1024 ** 2), 2),
        "bytes_recv_mb":  round(net.bytes_recv   / (1024 ** 2), 2),
        "packets_sent":   net.packets_sent,
        "packets_recv":   net.packets_recv,
        "errin":          net.errin,
        "errout":         net.errout,
        "dropin":         net.dropin,
        "dropout":        net.dropout,
    }

    # Per-interface breakdown
    try:
        per_iface = psutil.net_io_counters(pernic=True)
        ifaces = {}
        for name, counters in per_iface.items():
            if counters.bytes_sent > 0 or counters.bytes_recv > 0:
                ifaces[name] = {
                    "bytes_sent_mb": round(counters.bytes_sent / (1024 ** 2), 2),
                    "bytes_recv_mb": round(counters.bytes_recv / (1024 ** 2), 2),
                }
        stats["interfaces"] = ifaces
    except Exception:
        stats["interfaces"] = {}

    return stats


def get_network_summary() -> dict:
    """Quick summary: IPv4 vs IPv6 connection counts + suspicious breakdown."""
    conns = get_network_connections()
    ipv4  = [c for c in conns if not c["is_ipv6"]]
    ipv6  = [c for c in conns if c["is_ipv6"]]
    susp  = [c for c in conns if c["suspicious_port"]]
    active = [c for c in conns if c.get("remote_addr")]
    return {
        "total":           len(conns),
        "active":          len(active),
        "ipv4_count":      len(ipv4),
        "ipv6_count":      len(ipv6),
        "suspicious_count": len(susp),
        "listening_count": len([c for c in conns if c["status"] == "LISTEN"]),
        "established_count": len([c for c in conns if c["status"] == "ESTABLISHED"]),
    }


def get_full_snapshot() -> dict:
    """Full system snapshot for AI analysis."""
    suspicious_procs  = get_suspicious_processes()
    suspicious_conns  = get_suspicious_connections()
    net_summary       = get_network_summary()

    return {
        "timestamp":            datetime.now().isoformat(),
        "hostname":             socket.gethostname(),
        "system_stats":         get_system_stats(),
        "network_stats":        get_network_stats(),
        "network_summary":      net_summary,
        "suspicious_processes": suspicious_procs,
        "suspicious_connections": suspicious_conns,
        "total_processes":      len(list(psutil.process_iter())),
        "total_connections":    net_summary["total"],
        "ipv4_connections":     net_summary["ipv4_count"],
        "ipv6_connections":     net_summary["ipv6_count"],
    }


def kill_process(pid: int) -> dict:
    """Kill a process by PID (requires admin for system processes)."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.kill()
        return {"success": True, "message": f"Process {name} (PID {pid}) killed"}
    except psutil.NoSuchProcess:
        return {"success": False, "message": f"Process PID {pid} not found"}
    except psutil.AccessDenied:
        return {"success": False, "message": f"Access denied to kill PID {pid}"}
