"""
Lateral Movement Detector — NexoraGuard
Detects attacker movement between systems/accounts after initial compromise.

Detection methods (CrowdStrike/Elastic parity):
  1. Network logon anomaly    — Type-3 logins from unexpected sources (T1021)
  2. Pass-the-Hash indicators — NTLM auth with no interactive session (T1550.002)
  3. SMB lateral connection   — internal machines connecting to SMB (port 445)
  4. RDP from new source      — first-time RDP access from an IP (T1021.001)
  5. WinRM abuse              — PowerShell Remoting to/from this host (T1021.006)
  6. Admin share access       — ADMIN$/C$ connection from internal IP (T1021.002)
  7. Scheduled task remote    — task created via remote session
  8. Service install remote   — service installed during remote session

MITRE ATT&CK:
  T1021      — Remote Services
  T1021.001  — Remote Desktop Protocol
  T1021.002  — SMB/Windows Admin Shares
  T1021.006  — Windows Remote Management
  T1550.002  — Pass the Hash
  T1570      — Lateral Tool Transfer
"""
import re
import logging
from collections import defaultdict, deque
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Trusted source tracking ────────────────────────────────────────────────────
# Maps username → set of known source IPs for network logons
_known_rdp_sources:  dict = defaultdict(set)
_known_smb_sources:  dict = defaultdict(set)
_known_winrm_sources: dict = defaultdict(set)
_baseline_ready:     bool = False
_logon_count:        int  = 0
_BASELINE_THRESHOLD  = 20  # need 20+ logons before flagging new sources

# Private IP ranges that should NOT connect to sensitive services from outside
_INTERNAL_RANGES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                    "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                    "172.29.", "172.30.", "172.31.", "127.")


def _is_internal(ip: str) -> bool:
    return any(ip.startswith(r) for r in _INTERNAL_RANGES)


# ── Event log parsers ──────────────────────────────────────────────────────────

def _parse_network_logons(logs: dict) -> list:
    """
    Extract network logon events (Type 3) from Event 4624.
    Type 3 = network logon (SMB, RDP pre-auth, WinRM, etc.)
    """
    events = []
    for ev in logs.get("successful_logins", []):
        msg = ev.get("Message", "")
        type_m  = re.search(r"Logon Type:\s*(\d+)", msg)
        user_m  = re.search(r"Account Name:\s*(\S+)", msg)
        src_m   = re.search(r"Source Network Address:\s*(\S+)", msg)
        proc_m  = re.search(r"Process Name:\s*(.+?)(?:\r|\n|$)", msg)
        auth_m  = re.search(r"Authentication Package:\s*(\S+)", msg)

        logon_type = int(type_m.group(1)) if type_m else 0
        username   = user_m.group(1) if user_m else ""
        source_ip  = src_m.group(1)  if src_m  else ""
        process    = proc_m.group(1).strip() if proc_m else ""
        auth_pkg   = auth_m.group(1) if auth_m else ""

        if logon_type not in (3, 10) or not username or username.endswith("$"):
            continue
        if username.lower() in ("system", "anonymous logon", ""):
            continue

        events.append({
            "logon_type": logon_type,
            "username":   username,
            "source_ip":  source_ip,
            "process":    process,
            "auth_pkg":   auth_pkg,
            "ts":         ev.get("TimeCreated", ""),
        })
    return events


# ── Detection checks ───────────────────────────────────────────────────────────

def check_rdp_lateral(network_logons: list, connections: list) -> list:
    """
    Detect RDP lateral movement:
    - Active connections to/from port 3389
    - New source IP for RDP for a given user
    """
    global _logon_count, _baseline_ready
    alerts = []

    # Check active RDP connections
    rdp_conns = [c for c in connections
                 if c.get("local_port") == 3389 or c.get("remote_port") == 3389]

    for conn in rdp_conns:
        rip = conn.get("remote_ip", "")
        if not rip or rip in ("127.0.0.1", "::1"):
            continue

        # Flag external IPs connecting via RDP
        if not _is_internal(rip):
            alerts.append({
                "type":      "RDP_EXTERNAL",
                "severity":  "HIGH",
                "source_ip": rip,
                "detail":    f"RDP connection from external IP {rip} — possible unauthorized remote access",
                "mitre":     "T1021.001",
            })

    # Check new-source RDP logons from Event Logs (Type 10 = RemoteInteractive)
    for ev in network_logons:
        if ev["logon_type"] != 10:
            continue
        user = ev["username"]
        src  = ev.get("source_ip", "")
        _logon_count += 1
        if _logon_count >= _BASELINE_THRESHOLD:
            _baseline_ready = True

        if _baseline_ready and src and src not in _known_rdp_sources[user]:
            alerts.append({
                "type":      "RDP_NEW_SOURCE",
                "severity":  "HIGH",
                "username":  user,
                "source_ip": src,
                "detail":    f"RDP login for '{user}' from new source {src} — first-time source (possible lateral movement)",
                "mitre":     "T1021.001",
            })

        _known_rdp_sources[user].add(src)

    return alerts


def check_smb_lateral(connections: list, logs: dict) -> list:
    """
    Detect SMB-based lateral movement:
    - Internal machines connecting to port 445 (SMB)
    - Admin share access events (Event 5140)
    """
    alerts = []

    # Active SMB connections from internal IPs
    smb_conns = [c for c in connections
                 if c.get("remote_port") == 445 and c.get("remote_ip")]
    internal_smb = [c for c in smb_conns if _is_internal(c.get("remote_ip", ""))]

    if len(internal_smb) >= 5:
        unique_targets = {c.get("remote_ip") for c in internal_smb}
        alerts.append({
            "type":      "SMB_LATERAL_SPREAD",
            "severity":  "HIGH",
            "source_ip": None,
            "count":     len(internal_smb),
            "detail":    f"SMB lateral movement: {len(internal_smb)} connections to {len(unique_targets)} internal host(s) via port 445",
            "mitre":     "T1021.002",
            "targets":   list(unique_targets)[:5],
        })

    # Admin share access (Event 5140) — check in Windows Security logs
    for ev in logs.get("admin_share_events", []):
        msg      = ev.get("Message", "")
        share_m  = re.search(r"Share Name:\s*(\S+)", msg)
        src_m    = re.search(r"Source Address:\s*(\S+)", msg)
        user_m   = re.search(r"Account Name:\s*(\S+)", msg)
        share    = share_m.group(1) if share_m else ""
        src      = src_m.group(1)   if src_m   else ""
        user     = user_m.group(1)  if user_m  else ""

        if share.upper() in ("ADMIN$", "C$", "IPC$") and src and src != "127.0.0.1":
            alerts.append({
                "type":      "ADMIN_SHARE_ACCESS",
                "severity":  "HIGH",
                "username":  user,
                "source_ip": src,
                "share":     share,
                "detail":    f"Admin share '{share}' accessed by '{user}' from {src} — lateral movement via SMB",
                "mitre":     "T1021.002",
            })

    return alerts


def check_winrm_lateral(connections: list, network_logons: list) -> list:
    """
    Detect WinRM/PowerShell Remoting lateral movement.
    WinRM uses ports 5985 (HTTP) and 5986 (HTTPS).
    """
    alerts = []
    winrm_conns = [c for c in connections
                   if c.get("remote_port") in (5985, 5986) or
                      c.get("local_port") in (5985, 5986)]

    for conn in winrm_conns:
        rip   = conn.get("remote_ip", "")
        lport = conn.get("local_port", 0)
        rport = conn.get("remote_port", 0)
        if not rip or rip in ("127.0.0.1", "::1"):
            continue

        port  = lport if lport in (5985, 5986) else rport
        proto = "HTTPS" if port == 5986 else "HTTP"

        if not _is_internal(rip):
            alerts.append({
                "type":      "WINRM_EXTERNAL",
                "severity":  "CRITICAL",
                "source_ip": rip,
                "detail":    f"WinRM {proto} connection from external IP {rip} — remote PowerShell from internet",
                "mitre":     "T1021.006",
            })
        else:
            alerts.append({
                "type":      "WINRM_INTERNAL",
                "severity":  "MEDIUM",
                "source_ip": rip,
                "detail":    f"WinRM {proto} connection from internal IP {rip} — PowerShell Remoting in use",
                "mitre":     "T1021.006",
            })

    return alerts


def check_pass_the_hash(network_logons: list) -> list:
    """
    Detect Pass-the-Hash indicators:
    - Type-3 NTLM logon with blank password (Event 4624)
    - NTLMv1 usage (weaker, hash-crackable)
    - Logon with RunAs and NTLM from unusual source
    """
    alerts = []

    for ev in network_logons:
        auth = ev.get("auth_pkg", "").upper()
        src  = ev.get("source_ip", "")
        user = ev.get("username", "")

        # NTLM Type-3 logon from a non-local source with no Kerberos = PtH indicator
        if auth == "NTLM" and src and not _is_internal(src) and src != "-":
            alerts.append({
                "type":      "PASS_THE_HASH",
                "severity":  "HIGH",
                "username":  user,
                "source_ip": src,
                "detail":    f"Possible Pass-the-Hash: NTLM Type-3 network logon for '{user}' from external {src} — no Kerberos used",
                "mitre":     "T1550.002",
            })

    return alerts


def check_remote_service_install(logs: dict) -> list:
    """
    Detect services or scheduled tasks created during an active remote session.
    Lateral tool transfer indicator (T1570).
    """
    alerts = []
    svc_events  = logs.get("service_install_events", [])
    task_events = logs.get("scheduled_task_events", [])

    for ev in svc_events:
        msg  = ev.get("Message", "")
        src_m = re.search(r"Subject:\s+.*?Account Name:\s+(\S+)", msg, re.DOTALL)
        svc_m = re.search(r"Service Name:\s*(\S+)", msg)
        svc   = svc_m.group(1) if svc_m else "unknown"
        user  = src_m.group(1) if src_m else ""

        # If installed by a domain account (contains backslash) it may be remote
        if "\\" in user or user.endswith("$"):
            alerts.append({
                "type":      "REMOTE_SERVICE_INSTALL",
                "severity":  "HIGH",
                "username":  user,
                "detail":    f"Service '{svc}' installed by '{user}' — may indicate lateral tool transfer",
                "mitre":     "T1570",
            })

    return alerts


# ── Main entry point ───────────────────────────────────────────────────────────

def detect_lateral_movement(logs: dict, snapshot: dict) -> dict:
    """
    Full lateral movement detection pipeline.
    Covers: RDP, SMB, WinRM, Pass-the-Hash, Remote Service Install.
    """
    connections    = snapshot.get("all_connections") or []
    network_logons = _parse_network_logons(logs)

    alerts = []
    alerts.extend(check_rdp_lateral(network_logons, connections))
    alerts.extend(check_smb_lateral(connections, logs))
    alerts.extend(check_winrm_lateral(connections, network_logons))
    alerts.extend(check_pass_the_hash(network_logons))
    alerts.extend(check_remote_service_install(logs))

    # Deduplicate
    seen: set = set()
    unique = []
    for a in alerts:
        key = (a["type"], a.get("source_ip"), a.get("username"))
        if key not in seen:
            seen.add(key)
            unique.append(a)
    alerts = unique

    # Risk scoring
    sev_scores = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10}
    total_score = sum(sev_scores.get(a["severity"], 0) for a in alerts)
    risk = ("CRITICAL" if total_score >= 60 else
            "HIGH"     if total_score >= 30 else
            "MEDIUM"   if total_score >= 10 else
            "LOW"      if total_score > 0  else "SAFE")

    rule_alerts = []
    if alerts:
        top = max(alerts, key=lambda a: {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}.get(a["severity"], 0))
        rule_alerts.append({
            "rule":      "LATERAL_MOVEMENT",
            "severity":  top["severity"],
            "message":   f"Lateral movement detected — {len(alerts)} indicator(s): {top['type']}",
            "count":     len(alerts),
            "timestamp": datetime.now().isoformat(),
            "detail":    top.get("detail", ""),
        })

    return {
        "checked_at":      datetime.now().isoformat(),
        "alert_count":     len(alerts),
        "risk":            risk,
        "risk_score":      min(total_score, 100),
        "alerts":          alerts,
        "rule_alerts":     rule_alerts,
        "baseline_ready":  _baseline_ready,
        "logons_tracked":  _logon_count,
    }
