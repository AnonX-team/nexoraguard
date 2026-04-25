"""
DDoS / Flood Attack Detector — NexoraGuard (Ethreon-Enhanced)
Real-time host-based detection using psutil network telemetry.

Detection coverage — 15 attack protocols (adapted from Ethreon cloud architecture):
  1.  TCP Connection Flood    — many connections from single IP in short window
  2.  SYN Flood              — half-open SYN_SENT/SYN_RECV accumulation
  3.  Port Scan              — one IP hitting many different local ports
  4.  Bandwidth Spike        — bytes_recv delta vs rolling baseline (3σ rule)
  5.  Entropy Flood          — low source-IP Shannon entropy + high volume
  6.  UDP Flood              — many UDP sockets + high UDP bandwidth
  7.  DNS Amplification      — outbound UDP 53 (179× amplification factor)
  8.  NTP Amplification      — outbound UDP 123 (556× — monlist abuse)
  9.  SSDP Amplification     — outbound UDP 1900 (30× — UPnP reflection)
 10.  Memcached Reflection    — UDP 11211 (51,200× — highest of any protocol)
 11.  LDAP/CLDAP Reflection   — UDP 389 (70× — anonymous bind abuse)
 12.  HTTP GET/POST Flood     — high request rate to local web ports
 13.  Slowloris              — persistent half-connections to HTTP ports
 14.  Carpet Bombing         — /24 subnet-distributed flood (evades per-IP limits)
 15.  IoT Botnet (Mirai)     — many unique sources, each contributing few connections

Feature extraction (Ethreon-inspired 20+ features):
  src_ip_entropy, dst_port_entropy, SYN/ACK ratio, amplification_ratio,
  established_ratio, carpet_bombing_risk, unique_src_ips, subnet_diversity, etc.

MITRE ATT&CK:
  T1498.001 — Network DoS: Direct Network Flood
  T1498.002 — Network DoS: Reflection Amplification
  T1499.004 — Endpoint DoS: Application or System Exploitation
  T1046    — Network Service Discovery
"""
import math
import time
import logging
import psutil
from collections import defaultdict, deque
from datetime import datetime

logger = logging.getLogger(__name__)


# ── Rolling baseline ───────────────────────────────────────────────────────────

_net_history: deque = deque(maxlen=30)


def _update_net_baseline(stats: dict, total_conns: int) -> None:
    _net_history.append({
        "bytes_recv": stats.get("bytes_recv_mb", 0),
        "total_conns": total_conns,
        "ts": time.time(),
    })


def _net_baseline_stats() -> dict:
    if len(_net_history) < 5:
        return {}
    entries = list(_net_history)
    recv_vals = [e["bytes_recv"] for e in entries]
    conn_vals = [e["total_conns"] for e in entries]
    avg_r = sum(recv_vals) / len(recv_vals)
    avg_c = sum(conn_vals) / len(conn_vals)
    std_r = math.sqrt(sum((x - avg_r) ** 2 for x in recv_vals) / len(recv_vals)) or 1
    std_c = math.sqrt(sum((x - avg_c) ** 2 for x in conn_vals) / len(conn_vals)) or 1
    return {
        "avg_recv": avg_r, "std_recv": std_r,
        "avg_conn": avg_c, "std_conn": std_c,
    }


# ── IP connection rate tracking ────────────────────────────────────────────────

_ip_window: dict = defaultdict(list)
_ip_ports:  dict = defaultdict(set)
RATE_WINDOW     = 60
FLOOD_THRESHOLD = 40
SCAN_THRESHOLD  = 15


def _update_ip_tracking(connections: list) -> None:
    now    = time.time()
    cutoff = now - RATE_WINDOW
    for conn in connections:
        ip   = conn.get("remote_ip", "")
        port = conn.get("local_port", 0)
        if not ip or ip in ("", "127.0.0.1", "::1"):
            continue
        _ip_window[ip].append(now)
        if port:
            _ip_ports[ip].add(port)
    for ip in list(_ip_window.keys()):
        _ip_window[ip] = [t for t in _ip_window[ip] if t > cutoff]
        if not _ip_window[ip]:
            del _ip_window[ip]
            _ip_ports.pop(ip, None)


# ── Shannon entropy helpers ────────────────────────────────────────────────────

def _shannon(counts: dict) -> float:
    total = sum(counts.values())
    if total == 0:
        return 4.0
    H = 0.0
    for c in counts.values():
        p = c / total
        if p > 0:
            H -= p * math.log2(p)
    return round(H, 3)


def _source_entropy(connections: list) -> float:
    ip_counts: dict = defaultdict(int)
    for c in connections:
        ip = c.get("remote_ip", "")
        if ip:
            ip_counts[ip] += 1
    return _shannon(ip_counts)


def _dst_port_entropy(connections: list) -> float:
    port_counts: dict = defaultdict(int)
    for c in connections:
        p = c.get("local_port", 0)
        if p:
            port_counts[p] += 1
    return _shannon(port_counts)


# ── /24 subnet helper ──────────────────────────────────────────────────────────

def _subnet24(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3])
    return ip


# ── Slowloris persistent connection tracker ────────────────────────────────────

_http_conn_age: dict = {}          # (remote_ip, local_port) → first_seen_ts
_SLOWLORIS_PORTS = {80, 443, 8080, 8443}
_SLOWLORIS_AGE   = 120             # seconds ESTABLISHED before flagging


def _update_slowloris_tracker(connections: list) -> None:
    now  = time.time()
    seen = set()
    for c in connections:
        ip   = c.get("remote_ip", "")
        port = c.get("local_port", 0)
        if ip and port in _SLOWLORIS_PORTS and c.get("status") == "ESTABLISHED":
            key = (ip, port)
            seen.add(key)
            if key not in _http_conn_age:
                _http_conn_age[key] = now
    for key in list(_http_conn_age.keys()):
        if key not in seen:
            del _http_conn_age[key]


# ── Detection checks ───────────────────────────────────────────────────────────

def check_connection_flood(connections: list) -> list:
    alerts = []
    ip_counts: dict = defaultdict(int)
    for c in connections:
        ip = c.get("remote_ip", "")
        if ip and ip not in ("127.0.0.1", "::1", ""):
            ip_counts[ip] += 1
    for ip, count in ip_counts.items():
        if count >= FLOOD_THRESHOLD:
            alerts.append({
                "type": "CONNECTION_FLOOD", "severity": "CRITICAL",
                "source_ip": ip, "count": count,
                "detail": f"Connection flood: {ip} has {count} active connections (threshold: {FLOOD_THRESHOLD})",
                "mitre": "T1498.001", "auto_block": True,
                "protocol": "TCP",
            })
        elif count >= FLOOD_THRESHOLD // 2:
            alerts.append({
                "type": "CONNECTION_SURGE", "severity": "HIGH",
                "source_ip": ip, "count": count,
                "detail": f"Connection surge: {ip} has {count} connections — approaching flood threshold",
                "mitre": "T1498.001", "auto_block": False,
                "protocol": "TCP",
            })
    return alerts


def check_syn_flood(connections: list) -> list:
    alerts = []
    syn_states = [c for c in connections if c.get("status") in ("SYN_SENT", "SYN_RECV")]
    time_wait  = [c for c in connections if c.get("status") == "TIME_WAIT"]
    if len(syn_states) >= 20:
        alerts.append({
            "type": "SYN_FLOOD", "severity": "CRITICAL", "source_ip": None,
            "count": len(syn_states),
            "detail": f"SYN flood: {len(syn_states)} half-open connections (SYN_SENT/SYN_RECV) — TCP stack under attack",
            "mitre": "T1498.001", "auto_block": False,
            "protocol": "TCP/SYN",
        })
    elif len(syn_states) >= 10:
        alerts.append({
            "type": "SYN_SURGE", "severity": "HIGH", "source_ip": None,
            "count": len(syn_states),
            "detail": f"SYN surge: {len(syn_states)} half-open connections — possible early SYN flood",
            "mitre": "T1498.001", "auto_block": False,
            "protocol": "TCP/SYN",
        })
    if len(time_wait) >= 100:
        alerts.append({
            "type": "TIME_WAIT_FLOOD", "severity": "MEDIUM", "source_ip": None,
            "count": len(time_wait),
            "detail": f"High TIME_WAIT count ({len(time_wait)}) — post-flood socket accumulation",
            "mitre": "T1499", "auto_block": False,
            "protocol": "TCP",
        })
    return alerts


def check_port_scan(connections: list) -> list:
    alerts = []
    ip_ports: dict = defaultdict(set)
    for c in connections:
        ip   = c.get("remote_ip", "")
        port = c.get("local_port", 0)
        if ip and ip not in ("127.0.0.1", "::1", "") and port:
            ip_ports[ip].add(port)
    for ip, ports in ip_ports.items():
        if len(ports) >= SCAN_THRESHOLD:
            alerts.append({
                "type": "PORT_SCAN", "severity": "HIGH",
                "source_ip": ip, "count": len(ports),
                "ports_hit": sorted(list(ports))[:20],
                "detail": f"Port scan: {ip} connected to {len(ports)} different local ports",
                "mitre": "T1046",
                "auto_block": len(ports) >= SCAN_THRESHOLD * 2,
                "protocol": "TCP",
            })
    return alerts


def check_bandwidth_spike(current_stats: dict) -> list:
    alerts = []
    baseline = _net_baseline_stats()
    if not baseline:
        return []
    current_recv = current_stats.get("bytes_recv_mb", 0)
    avg_r, std_r = baseline["avg_recv"], baseline["std_recv"]
    spike_mb     = current_recv - avg_r
    if spike_mb > avg_r * 0.5 and spike_mb > 50 and spike_mb > (3 * std_r):
        alerts.append({
            "type": "BANDWIDTH_SPIKE", "severity": "HIGH", "source_ip": None,
            "count": int(spike_mb),
            "detail": (
                f"Bandwidth spike: {current_recv:.0f}MB recv "
                f"(baseline avg {avg_r:.0f}MB, +{spike_mb:.0f}MB — 3σ exceeded) — possible volumetric attack"
            ),
            "mitre": "T1498.001", "auto_block": False,
            "protocol": "Multi-vector",
        })
    return alerts


def check_entropy_flood(connections: list) -> list:
    alerts = []
    active = [c for c in connections if c.get("remote_ip")]
    if len(active) < 20:
        return []
    entropy = _source_entropy(active)
    if entropy < 1.0 and len(active) >= 50:
        alerts.append({
            "type": "ENTROPY_FLOOD", "severity": "CRITICAL", "source_ip": None,
            "count": len(active),
            "detail": (
                f"Volumetric flood: {len(active)} connections, "
                f"src-IP entropy {entropy} (normal >2.0) — traffic concentrated from few sources"
            ),
            "mitre": "T1498.001", "auto_block": False,
            "protocol": "Multi-vector",
        })
    elif entropy < 1.5 and len(active) >= 30:
        alerts.append({
            "type": "ENTROPY_LOW", "severity": "MEDIUM", "source_ip": None,
            "count": len(active),
            "detail": f"Abnormal traffic distribution: entropy {entropy} with {len(active)} connections",
            "mitre": "T1498.001", "auto_block": False,
            "protocol": "Multi-vector",
        })
    return alerts


def check_udp_flood(connections: list, net_stats: dict) -> list:
    """UDP flood — many UDP sockets + high UDP bandwidth usage."""
    alerts = []
    try:
        raw_udp    = psutil.net_connections(kind="udp")
        udp_count  = len(raw_udp)
        udp_src: dict = defaultdict(int)
        for c in raw_udp:
            raddr = c.raddr
            if raddr and raddr.ip and raddr.ip not in ("0.0.0.0", "::", "127.0.0.1", "::1"):
                udp_src[raddr.ip] += 1

        if udp_count > 200:
            alerts.append({
                "type": "UDP_FLOOD", "severity": "CRITICAL", "source_ip": None,
                "count": udp_count,
                "detail": f"UDP flood: {udp_count} active UDP sockets (threshold: 200)",
                "mitre": "T1498.001", "auto_block": False,
                "protocol": "UDP",
            })
        elif udp_count > 100:
            alerts.append({
                "type": "UDP_SURGE", "severity": "HIGH", "source_ip": None,
                "count": udp_count,
                "detail": f"UDP surge: {udp_count} active UDP sockets",
                "mitre": "T1498.001", "auto_block": False,
                "protocol": "UDP",
            })

        for ip, cnt in udp_src.items():
            if cnt >= 20:
                alerts.append({
                    "type": "UDP_SOURCE_FLOOD", "severity": "HIGH",
                    "source_ip": ip, "count": cnt,
                    "detail": f"UDP flood from {ip}: {cnt} UDP datagrams",
                    "mitre": "T1498.001", "auto_block": cnt >= 50,
                    "protocol": "UDP",
                })
    except Exception as e:
        logger.debug(f"UDP check skipped: {e}")
    return alerts


# Amplification protocol definitions: port → (name, mitre, amp_factor, severity)
_AMP_PORTS = {
    53:    ("DNS",        "T1498.002", 179,    "CRITICAL"),
    123:   ("NTP",        "T1498.002", 556,    "CRITICAL"),
    1900:  ("SSDP",       "T1498.002", 30,     "HIGH"),
    11211: ("Memcached",  "T1498.002", 51200,  "CRITICAL"),
    389:   ("LDAP",       "T1498.002", 70,     "HIGH"),
    19:    ("Chargen",    "T1498.002", 370,    "CRITICAL"),
    111:   ("Portmapper", "T1498.002", 7,      "MEDIUM"),
}


def check_amplification_attacks(connections: list) -> list:
    """
    Detect reflection/amplification attack indicators.
    Outbound UDP connections to well-known amplifier ports signal either:
    - This host is being used as a reflector (misconfigured service), or
    - High-volume outbound to amp ports = attacker is using this host to amplify.
    """
    alerts = []
    amp_counts: dict = defaultdict(int)
    amp_ips:    dict = defaultdict(list)
    for c in connections:
        rport = c.get("remote_port", 0)
        rip   = c.get("remote_ip", "")
        if rport in _AMP_PORTS and rip and rip not in ("127.0.0.1", "::1"):
            amp_counts[rport] += 1
            amp_ips[rport].append(rip)
    for port, count in amp_counts.items():
        if count >= 5:
            proto, mitre, amp_factor, severity = _AMP_PORTS[port]
            unique_srv = len(set(amp_ips[port]))
            alerts.append({
                "type":       f"{proto}_AMPLIFICATION",
                "severity":   severity,
                "source_ip":  None,
                "count":      count,
                "detail": (
                    f"{proto} amplification: {count} connections to UDP/{port} "
                    f"({unique_srv} unique servers) — {amp_factor}× amplification factor. "
                    f"Possible reflection attack or open service abuse."
                ),
                "mitre":      mitre,
                "auto_block": False,
                "protocol":   proto,
                "amp_factor": amp_factor,
                "port":       port,
            })
    return alerts


_HTTP_PORTS      = {80, 443, 8080, 8443, 8000, 3000}
HTTP_FLOOD_THOLD = 30


def check_http_flood(connections: list) -> list:
    """HTTP GET/POST flood — many connections to web ports from same IP."""
    alerts = []
    ip_http: dict = defaultdict(int)
    for c in connections:
        lport = c.get("local_port", 0)
        rip   = c.get("remote_ip", "")
        if lport in _HTTP_PORTS and rip and rip not in ("127.0.0.1", "::1"):
            ip_http[rip] += 1
    for ip, cnt in ip_http.items():
        if cnt >= HTTP_FLOOD_THOLD:
            alerts.append({
                "type": "HTTP_FLOOD", "severity": "CRITICAL",
                "source_ip": ip, "count": cnt,
                "detail": f"HTTP flood: {ip} has {cnt} connections to web ports — L7 GET/POST flood",
                "mitre": "T1499.004", "auto_block": True,
                "protocol": "HTTP",
            })
        elif cnt >= HTTP_FLOOD_THOLD // 2:
            alerts.append({
                "type": "HTTP_FLOOD_SURGE", "severity": "HIGH",
                "source_ip": ip, "count": cnt,
                "detail": f"HTTP flood surge: {ip} has {cnt} web connections",
                "mitre": "T1499.004", "auto_block": False,
                "protocol": "HTTP",
            })
    return alerts


def check_slowloris(connections: list) -> list:
    """
    Slowloris — attacker sends partial HTTP headers, holds connections open to
    exhaust the web server's connection pool without completing requests.
    Detection: ESTABLISHED HTTP connections held open for >{_SLOWLORIS_AGE}s.
    """
    now = time.time()
    _update_slowloris_tracker(connections)
    aged = [(k, age) for k, age in _http_conn_age.items() if now - age >= _SLOWLORIS_AGE]
    if not aged:
        return []
    ip_aged: dict = defaultdict(int)
    for (ip, _port), _first in aged:
        ip_aged[ip] += 1
    alerts = []
    for ip, cnt in ip_aged.items():
        if cnt >= 5:
            alerts.append({
                "type": "SLOWLORIS", "severity": "HIGH",
                "source_ip": ip, "count": cnt,
                "detail": (
                    f"Slowloris detected: {ip} has {cnt} HTTP connections "
                    f"held open for >{_SLOWLORIS_AGE}s — slow connection hold attack"
                ),
                "mitre": "T1499.004", "auto_block": cnt >= 10,
                "protocol": "HTTP/Slowloris",
            })
    return alerts


SUBNET_FLOOD_THOLD = 20


def check_carpet_bombing(connections: list) -> list:
    """
    Carpet bombing — attack distributed across /24 subnet to evade per-IP thresholds.
    Characteristic of nation-state and advanced botnets.
    """
    alerts = []
    subnet_ips:   dict = defaultdict(set)
    subnet_conns: dict = defaultdict(int)
    for c in connections:
        ip = c.get("remote_ip", "")
        if ip and ip not in ("127.0.0.1", "::1", ""):
            s = _subnet24(ip)
            subnet_ips[s].add(ip)
            subnet_conns[s] += 1
    for subnet, ips in subnet_ips.items():
        if len(ips) >= SUBNET_FLOOD_THOLD:
            total = subnet_conns[subnet]
            alerts.append({
                "type": "CARPET_BOMBING", "severity": "HIGH",
                "source_ip": f"{subnet}.0/24", "count": total,
                "detail": (
                    f"Carpet bombing from {subnet}.0/24: {len(ips)} unique IPs, "
                    f"{total} total connections — distributed flood evading per-IP thresholds"
                ),
                "mitre": "T1498.001", "auto_block": False,
                "protocol": "Multi-vector",
                "unique_ips": len(ips),
                "subnet": f"{subnet}.0/24",
            })
    return alerts


IOT_MIN_SOURCES = 30
IOT_MAX_PER_IP  = 3


def check_iot_botnet(connections: list) -> list:
    """
    Mirai-style IoT botnet detection.
    Signature: many unique source IPs each contributing very few connections.
    Contrast with centralized flood (few IPs × many connections each).
    """
    ip_counts: dict = defaultdict(int)
    for c in connections:
        ip = c.get("remote_ip", "")
        if ip and ip not in ("127.0.0.1", "::1", ""):
            ip_counts[ip] += 1
    if not ip_counts:
        return []
    total_ips   = len(ip_counts)
    total_conns = sum(ip_counts.values())
    avg_per_ip  = total_conns / total_ips
    low_cnt_ips = sum(1 for v in ip_counts.values() if v <= IOT_MAX_PER_IP)
    if (total_ips >= IOT_MIN_SOURCES and
            avg_per_ip <= IOT_MAX_PER_IP and
            low_cnt_ips / total_ips >= 0.8):
        return [{
            "type": "IOT_BOTNET", "severity": "HIGH",
            "source_ip": None, "count": total_conns,
            "detail": (
                f"IoT botnet pattern: {total_ips} unique sources, "
                f"avg {avg_per_ip:.1f} conns/IP — Mirai-style distributed flood"
            ),
            "mitre": "T1498.001", "auto_block": False,
            "protocol": "Botnet/Mirai",
            "unique_sources": total_ips,
        }]
    return []


# ── Feature extraction (Ethreon-inspired 20+ features) ────────────────────────

def extract_features(connections: list, net_stats: dict,
                     prev_recv_mb: float = 0.0) -> dict:
    """
    Extract 20+ traffic features mirroring Ethreon's ML pipeline.
    Used for confidence scoring and trend analysis.
    """
    if not connections:
        return {"feature_error": "no_connections"}

    total = len(connections)

    ip_counts: dict   = defaultdict(int)
    port_counts: dict = defaultdict(int)
    state_counts: dict = defaultdict(int)

    for c in connections:
        ip = c.get("remote_ip", "")
        if ip:
            ip_counts[ip] += 1
        p = c.get("local_port", 0)
        if p:
            port_counts[p] += 1
        st = c.get("status") or "NONE"
        state_counts[st] += 1

    established = state_counts.get("ESTABLISHED", 0)
    syn_states  = state_counts.get("SYN_SENT", 0) + state_counts.get("SYN_RECV", 0)
    time_wait   = state_counts.get("TIME_WAIT", 0)
    close_wait  = state_counts.get("CLOSE_WAIT", 0)

    recv_mb     = net_stats.get("bytes_recv_mb", 0)
    sent_mb     = net_stats.get("bytes_sent_mb", 0)
    delta_recv  = max(recv_mb - prev_recv_mb, 0)

    subnets = set(
        _subnet24(c.get("remote_ip", ""))
        for c in connections if c.get("remote_ip")
    )

    amp_ratio    = (recv_mb / sent_mb) if sent_mb > 0.001 else 1.0
    syn_ack_ratio = syn_states / max(established, 1)
    unique_ips   = len(ip_counts)

    return {
        # Volume
        "total_connections":   total,
        "unique_src_ips":      unique_ips,
        "unique_dst_ports":    len(port_counts),
        "unique_subnets":      len(subnets),
        # Entropy
        "src_ip_entropy":      _source_entropy(connections),
        "dst_port_entropy":    _dst_port_entropy(connections),
        # TCP state ratios
        "established_ratio":   round(established / max(total, 1), 3),
        "syn_ratio":           round(syn_states  / max(total, 1), 3),
        "time_wait_ratio":     round(time_wait   / max(total, 1), 3),
        "close_wait_ratio":    round(close_wait  / max(total, 1), 3),
        "syn_ack_ratio":       round(syn_ack_ratio, 3),
        # Bandwidth
        "recv_mb":             round(recv_mb, 3),
        "sent_mb":             round(sent_mb, 3),
        "recv_delta_mb":       round(delta_recv, 3),
        "amplification_ratio": round(amp_ratio, 3),
        # Distribution
        "avg_conns_per_ip":    round(total / max(unique_ips, 1), 3),
        "max_conns_single_ip": max(ip_counts.values()) if ip_counts else 0,
        # Derived risk flags
        "carpet_bombing_risk": len(subnets) >= SUBNET_FLOOD_THOLD,
        "iot_botnet_risk":     (unique_ips >= IOT_MIN_SOURCES and
                                total / max(unique_ips, 1) <= IOT_MAX_PER_IP),
        "high_entropy_ok":     _source_entropy(connections) >= 2.0,
    }


# ── Auto-response ──────────────────────────────────────────────────────────────

_auto_blocked_this_run: set = set()


def auto_respond(alerts: list, dry_run: bool = False) -> list:
    actions = []
    for alert in alerts:
        ip = alert.get("source_ip")
        if not ip or not alert.get("auto_block"):
            continue
        if ip in _auto_blocked_this_run:
            continue
        action = {
            "action": "BLOCK_IP",
            "ip":     ip,
            "reason": f"DDoS auto-block: {alert['type']} ({alert['count']} connections)",
            "ts":     datetime.now().isoformat(),
        }
        if not dry_run:
            try:
                from bruteforce_guard import block_ip
                result = block_ip(ip, f"DDoS: {alert['type']}")
                action["success"] = result.get("success", False)
                action["message"] = result.get("message", "")
                if result.get("success"):
                    _auto_blocked_this_run.add(ip)
            except Exception as e:
                action["success"] = False
                action["message"] = str(e)
        else:
            action["success"] = True
            action["message"] = "dry_run"
        actions.append(action)
    return actions


# ── Main entry point ───────────────────────────────────────────────────────────

_last_ddos_auto_reset: float = 0
_last_recv_mb:         float = 0


def detect_ddos(snapshot: dict, auto_block: bool = True) -> dict:
    """
    Full DDoS detection pipeline — 15 attack protocols (Ethreon-enhanced).
    Adapts Ethreon's cloud detection architecture to local psutil telemetry.
    Returns structured result compatible with detection_engine rule_alerts format.
    """
    global _last_ddos_auto_reset, _last_recv_mb

    connections = snapshot.get("all_connections") or []
    net_stats   = snapshot.get("network_stats", {})
    total_conns = len(connections)

    _update_net_baseline(net_stats, total_conns)
    _update_ip_tracking(connections)

    now = time.time()
    if now - _last_ddos_auto_reset > 3600:
        _auto_blocked_this_run.clear()
        _last_ddos_auto_reset = now

    # Run all 15 protocol detectors
    alerts: list = []
    alerts.extend(check_connection_flood(connections))
    alerts.extend(check_syn_flood(connections))
    alerts.extend(check_port_scan(connections))
    alerts.extend(check_bandwidth_spike(net_stats))
    alerts.extend(check_entropy_flood(connections))
    alerts.extend(check_udp_flood(connections, net_stats))
    alerts.extend(check_amplification_attacks(connections))
    alerts.extend(check_http_flood(connections))
    alerts.extend(check_slowloris(connections))
    alerts.extend(check_carpet_bombing(connections))
    alerts.extend(check_iot_botnet(connections))

    # Extract Ethreon-style 20+ features
    features = extract_features(connections, net_stats, _last_recv_mb)
    _last_recv_mb = net_stats.get("bytes_recv_mb", 0)

    # Deduplicate by (type, source_ip)
    seen_keys: set = set()
    unique: list  = []
    for a in alerts:
        key = (a["type"], a.get("source_ip"))
        if key not in seen_keys:
            seen_keys.add(key)
            unique.append(a)
    alerts = unique

    # Risk scoring
    sev_score = {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10}
    total_score = sum(sev_score.get(a["severity"], 0) for a in alerts)
    risk = ("CRITICAL" if total_score >= 60 else
            "HIGH"     if total_score >= 30 else
            "MEDIUM"   if total_score >= 10 else
            "LOW"      if total_score >  0  else "SAFE")

    # Auto-response
    response_actions: list = []
    if auto_block and alerts:
        response_actions = auto_respond(alerts)

    # Rule alerts for detection_engine integration
    rule_alerts: list = []
    if alerts:
        top = max(alerts, key=lambda a: {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}.get(a["severity"], 0))
        flood_count = sum(1 for a in alerts if any(
            x in a["type"] for x in ("FLOOD", "SURGE", "BOTNET", "BOMBING")))
        scan_count  = sum(1 for a in alerts if a["type"] == "PORT_SCAN")
        amp_count   = sum(1 for a in alerts if "AMPLIFICATION" in a["type"])

        if flood_count > 0:
            rule_alerts.append({
                "rule":      "DDOS_ATTACK",
                "severity":  top["severity"],
                "message":   f"DDoS/Flood detected — {len(alerts)} indicator(s), risk {risk}",
                "count":     len(alerts),
                "timestamp": datetime.now().isoformat(),
                "detail":    top["detail"],
            })
        if scan_count > 0:
            rule_alerts.append({
                "rule":      "PORT_SCAN",
                "severity":  "HIGH",
                "message":   "Port scan detected — attacker mapping open services",
                "timestamp": datetime.now().isoformat(),
            })
        if amp_count > 0:
            rule_alerts.append({
                "rule":      "AMPLIFICATION_ATTACK",
                "severity":  "CRITICAL",
                "message":   f"Reflection/amplification attack — {amp_count} protocol(s) detected",
                "timestamp": datetime.now().isoformat(),
            })

    # Prevention recommendations
    prevention = []
    if alerts:
        try:
            from prevention_module import get_recommendations_for_alerts
            prevention = get_recommendations_for_alerts(alerts)
        except Exception:
            pass

    return {
        "checked_at":       datetime.now().isoformat(),
        "alert_count":      len(alerts),
        "risk":             risk,
        "risk_score":       min(total_score, 100),
        "alerts":           alerts,
        "auto_blocked":     [a["ip"] for a in response_actions if a.get("success")],
        "response_actions": response_actions,
        "rule_alerts":      rule_alerts,
        "features":         features,
        "prevention":       prevention,
        "stats": {
            "total_connections":  total_conns,
            "source_entropy":     _source_entropy(connections),
            "dst_port_entropy":   _dst_port_entropy(connections),
            "baseline_ready":     len(_net_history) >= 5,
            "baseline_samples":   len(_net_history),
        },
        "protocol_coverage": {
            "total_protocols": 15,
            "active_detections": list({
                a.get("protocol", a["type"]) for a in alerts
            }),
        },
    }
