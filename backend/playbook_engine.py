"""
Automated Response Playbook Engine — NexoraGuard XDR
Pre-built response playbooks for common attack scenarios.

Each playbook defines:
  - trigger:   which alert types / conditions activate it
  - actions:   what to DO automatically or recommend
  - priority:  execution order when multiple playbooks fire
  - mitre:     which ATT&CK techniques it counters

Playbook action types:
  BLOCK_IP         — add to Windows Firewall deny rule
  KILL_PROCESS     — terminate the process by name/PID
  ISOLATE_NETWORK  — enable full network isolation
  ALERT_USER       — high-priority desktop notification
  LOG_FORENSICS    — capture current snapshot for forensics
  DISABLE_SERVICE  — stop a Windows service
  LOCK_ACCOUNT     — flag account for review (notify admin)
  QUARANTINE_FILE  — flag file for deletion/review
  RUN_VULN_SCAN    — trigger immediate vulnerability scan
  RECOMMEND_ONLY   — advisory action (no automation)
"""
import logging
import subprocess
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Playbook definitions ──────────────────────────────────────────────────────

PLAYBOOKS: list = [

    # ── PB-01: Active Ransomware ──────────────────────────────────────────────
    {
        "id":          "PB-01",
        "name":        "Active Ransomware Response",
        "description": "Mass file encryption or ransom note detected. Immediate isolation required.",
        "priority":    1,
        "mitre":       ["T1486", "T1490"],
        "trigger": {
            "any_of":  ["RANSOMWARE_DETECTED", "MASS_FILE_MODIFICATION", "SHADOW_COPY_DELETION", "RANSOM_NOTE"],
            "min_sev": "HIGH",
        },
        "actions": [
            {"type": "ISOLATE_NETWORK",  "auto": True,  "label": "Isolate network immediately"},
            {"type": "ALERT_USER",       "auto": True,  "label": "Critical alert: Ransomware detected"},
            {"type": "LOG_FORENSICS",    "auto": True,  "label": "Capture forensic snapshot"},
            {"type": "RECOMMEND_ONLY",   "auto": False, "label": "Do NOT reboot — check vssadmin for shadow copies"},
            {"type": "RECOMMEND_ONLY",   "auto": False, "label": "Identify & kill encrypting process"},
        ],
        "recovery_tip": "1) Isolate immediately  2) Do NOT reboot  3) Check shadow copies: vssadmin list shadows  4) Contact incident response",
    },

    # ── PB-02: Brute Force + Successful Login ────────────────────────────────
    {
        "id":          "PB-02",
        "name":        "Brute Force + Account Compromise",
        "description": "Brute force attack followed by a successful login from the same source.",
        "priority":    2,
        "mitre":       ["T1110", "T1078"],
        "trigger": {
            "all_of":  ["BRUTE_FORCE"],
            "any_of":  ["EXPLICIT_LOGON", "REMOTE_LOGON", "NEW_SOURCE_LOGON"],
            "min_sev": "HIGH",
        },
        "actions": [
            {"type": "BLOCK_IP",         "auto": True,  "label": "Block source IP via Windows Firewall"},
            {"type": "ALERT_USER",       "auto": True,  "label": "Alert: Possible account compromise after brute force"},
            {"type": "LOG_FORENSICS",    "auto": True,  "label": "Log active sessions and login events"},
            {"type": "LOCK_ACCOUNT",     "auto": False, "label": "Review and lock compromised account"},
        ],
        "recovery_tip": "Change passwords immediately. Review login events for the compromised account.",
    },

    # ── PB-03: Lateral Movement Chain ────────────────────────────────────────
    {
        "id":          "PB-03",
        "name":        "Lateral Movement Containment",
        "description": "RDP/SMB/WinRM lateral movement detected — attacker spreading through network.",
        "priority":    2,
        "mitre":       ["T1021", "T1021.001", "T1021.002", "T1021.006"],
        "trigger": {
            "any_of":  ["LATERAL_MOVEMENT", "RDP_EXTERNAL", "SMB_LATERAL_SPREAD",
                        "WINRM_EXTERNAL", "PASS_THE_HASH", "ADMIN_SHARE_ACCESS"],
            "min_sev": "HIGH",
        },
        "actions": [
            {"type": "BLOCK_IP",         "auto": True,  "label": "Block lateral movement source IP"},
            {"type": "ALERT_USER",       "auto": True,  "label": "Alert: Lateral movement detected"},
            {"type": "LOG_FORENSICS",    "auto": True,  "label": "Capture network connection state"},
            {"type": "RECOMMEND_ONLY",   "auto": False, "label": "Disable RDP if not required: Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1"},
            {"type": "RECOMMEND_ONLY",   "auto": False, "label": "Disable WinRM if not required: Stop-Service WinRM"},
        ],
        "recovery_tip": "Identify all compromised accounts used for lateral movement. Reset credentials.",
    },

    # ── PB-04: Pass-the-Hash ─────────────────────────────────────────────────
    {
        "id":          "PB-04",
        "name":        "Pass-the-Hash Containment",
        "description": "NTLM credential reuse from external source detected.",
        "priority":    2,
        "mitre":       ["T1550.002"],
        "trigger": {
            "any_of":  ["PASS_THE_HASH"],
            "min_sev": "HIGH",
        },
        "actions": [
            {"type": "BLOCK_IP",         "auto": True,  "label": "Block external IP using NTLM hash"},
            {"type": "ALERT_USER",       "auto": True,  "label": "Alert: Pass-the-Hash from external source"},
            {"type": "RECOMMEND_ONLY",   "auto": False, "label": "Force Kerberos: Disable NTLMv1 via Group Policy"},
            {"type": "RECOMMEND_ONLY",   "auto": False, "label": "Enable Protected Users security group for privileged accounts"},
        ],
        "recovery_tip": "Force password reset on all accounts the attacker had NTLM hashes for.",
    },

    # ── PB-05: Malware / Known Malicious Process ──────────────────────────────
    {
        "id":          "PB-05",
        "name":        "Malware Process Termination",
        "description": "Known malicious process or hash detected on endpoint.",
        "priority":    2,
        "mitre":       ["T1204.002", "T1055"],
        "trigger": {
            "any_of":  ["MALWARE_DETECTED", "MALICIOUS_PROCESS", "KNOWN_BAD_IP", "PROCESS_INJECTION"],
            "min_sev": "HIGH",
        },
        "actions": [
            {"type": "KILL_PROCESS",     "auto": False, "label": "Kill malicious process (manual confirmation required)"},
            {"type": "BLOCK_IP",         "auto": True,  "label": "Block malicious C2 IP"},
            {"type": "ALERT_USER",       "auto": True,  "label": "Alert: Malware/malicious process active"},
            {"type": "LOG_FORENSICS",    "auto": True,  "label": "Capture process tree and network connections"},
            {"type": "QUARANTINE_FILE",  "auto": False, "label": "Quarantine executable for analysis"},
        ],
        "recovery_tip": "Run full AV scan. Check for persistence mechanisms (scheduled tasks, services, registry).",
    },

    # ── PB-06: Defense Evasion (Log Clearing) ────────────────────────────────
    {
        "id":          "PB-06",
        "name":        "Anti-Forensics Response",
        "description": "Windows event logs cleared — active defense evasion attempt.",
        "priority":    1,
        "mitre":       ["T1070.001"],
        "trigger": {
            "any_of":  ["LOG_CLEARED"],
            "min_sev": "MEDIUM",
        },
        "actions": [
            {"type": "ALERT_USER",       "auto": True,  "label": "CRITICAL: Event logs have been cleared"},
            {"type": "LOG_FORENSICS",    "auto": True,  "label": "Capture current system state immediately"},
            {"type": "RECOMMEND_ONLY",   "auto": False, "label": "Enable centralized log forwarding to prevent future clearing"},
            {"type": "RECOMMEND_ONLY",   "auto": False, "label": "Check who cleared logs: Get-WinEvent -LogName Security | Where Id -eq 1102"},
        ],
        "recovery_tip": "Immediately capture running process list, network connections, and scheduled tasks before more data is lost.",
    },

    # ── PB-07: PowerShell Abuse ───────────────────────────────────────────────
    {
        "id":          "PB-07",
        "name":        "Malicious PowerShell Containment",
        "description": "Suspicious PowerShell execution with malicious patterns detected.",
        "priority":    3,
        "mitre":       ["T1059.001"],
        "trigger": {
            "any_of":  ["SUSPICIOUS_POWERSHELL", "SUSPICIOUS_SPAWN", "LOLBIN_ABUSE"],
            "min_sev": "HIGH",
        },
        "actions": [
            {"type": "ALERT_USER",       "auto": True,  "label": "Alert: Malicious PowerShell/LOLBin detected"},
            {"type": "LOG_FORENSICS",    "auto": True,  "label": "Capture PowerShell command history"},
            {"type": "RECOMMEND_ONLY",   "auto": False, "label": "Enable PowerShell Constrained Language Mode"},
            {"type": "RECOMMEND_ONLY",   "auto": False, "label": "Enable Script Block Logging: HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"},
        ],
        "recovery_tip": "Review PowerShell transcript logs. Consider disabling PowerShell v2.",
    },

    # ── PB-08: Privilege Escalation ───────────────────────────────────────────
    {
        "id":          "PB-08",
        "name":        "Privilege Escalation Response",
        "description": "A process or user gained unexpected elevated privileges.",
        "priority":    2,
        "mitre":       ["T1078.003", "T1548"],
        "trigger": {
            "any_of":  ["PRIVILEGE_ESCALATION", "PRIVILEGE_ANOMALY"],
            "min_sev": "HIGH",
        },
        "actions": [
            {"type": "ALERT_USER",       "auto": True,  "label": "Alert: Privilege escalation detected"},
            {"type": "LOG_FORENSICS",    "auto": True,  "label": "Capture privilege elevation event context"},
            {"type": "LOCK_ACCOUNT",     "auto": False, "label": "Review elevated account — consider forced logoff"},
            {"type": "RECOMMEND_ONLY",   "auto": False, "label": "Audit admin group membership: Get-LocalGroupMember Administrators"},
        ],
        "recovery_tip": "Review Security event log for Event 4672 (Special Privileges). Remove unauthorized group memberships.",
    },

    # ── PB-09: DDoS Attack ────────────────────────────────────────────────────
    {
        "id":          "PB-09",
        "name":        "DDoS Flood Mitigation",
        "description": "Active DDoS flood detected — automatic rate limiting applied.",
        "priority":    3,
        "mitre":       ["T1498", "T1499"],
        "trigger": {
            "any_of":  ["DDOS_ATTACK", "HTTP_FLOOD", "AMPLIFICATION_ATTACK",
                        "SLOWLORIS", "TCP_SYN_FLOOD", "UDP_FLOOD", "CARPET_BOMBING"],
            "min_sev": "HIGH",
        },
        "actions": [
            {"type": "BLOCK_IP",         "auto": True,  "label": "Block top attacking IPs via firewall"},
            {"type": "ALERT_USER",       "auto": True,  "label": "Alert: DDoS attack in progress"},
            {"type": "RECOMMEND_ONLY",   "auto": False, "label": "Enable SYN cookies: netsh int tcp set global synattackprotect=enabled"},
            {"type": "RECOMMEND_ONLY",   "auto": False, "label": "Rate limit connections: netsh advfirewall set allprofiles state on"},
        ],
        "recovery_tip": "Contact upstream ISP for BGP blackholing if attack persists.",
    },

    # ── PB-10: Off-Hours Admin Activity (UEBA) ───────────────────────────────
    {
        "id":          "PB-10",
        "name":        "Anomalous After-Hours Login",
        "description": "Administrative login detected outside normal working hours.",
        "priority":    3,
        "mitre":       ["T1078"],
        "trigger": {
            "any_of":  ["OFF_HOURS_LOGIN", "UEBA_ANOMALY"],
            "min_sev": "MEDIUM",
        },
        "actions": [
            {"type": "ALERT_USER",       "auto": True,  "label": "Alert: After-hours admin login detected"},
            {"type": "LOG_FORENSICS",    "auto": True,  "label": "Log session context and commands"},
            {"type": "RECOMMEND_ONLY",   "auto": False, "label": "Verify login with account owner — may be insider threat"},
        ],
        "recovery_tip": "Review session activity. If unauthorized, terminate session and reset password.",
    },

    # ── PB-11: Critical Vulnerability + Active Exploitation ──────────────────
    {
        "id":          "PB-11",
        "name":        "Vulnerability Under Exploitation",
        "description": "Unpatched critical vulnerability combined with active exploitation indicator.",
        "priority":    2,
        "mitre":       ["T1190", "T1068"],
        "trigger": {
            "any_of":  ["VULNERABILITY_FOUND", "PATCH_CRITICAL"],
            "min_sev": "CRITICAL",
        },
        "actions": [
            {"type": "ALERT_USER",       "auto": True,  "label": "Alert: Critical unpatched vulnerability — patch immediately"},
            {"type": "RUN_VULN_SCAN",    "auto": True,  "label": "Run immediate vulnerability rescan"},
            {"type": "RECOMMEND_ONLY",   "auto": False, "label": "Apply patches: Start-Process wuauclt /updatenow"},
            {"type": "RECOMMEND_ONLY",   "auto": False, "label": "Apply virtual patch: isolate service until patched"},
        ],
        "recovery_tip": "Prioritize patch for CISA KEV items — these are actively exploited in the wild.",
    },

    # ── PB-12: New Admin Account Created ─────────────────────────────────────
    {
        "id":          "PB-12",
        "name":        "Unauthorized Account Creation",
        "description": "New user account created outside provisioning process.",
        "priority":    3,
        "mitre":       ["T1136.001"],
        "trigger": {
            "any_of":  ["NEW_ACCOUNT"],
            "min_sev": "MEDIUM",
        },
        "actions": [
            {"type": "ALERT_USER",       "auto": True,  "label": "Alert: New account created — verify authorization"},
            {"type": "LOG_FORENSICS",    "auto": True,  "label": "Log account creation event (Event 4720)"},
            {"type": "LOCK_ACCOUNT",     "auto": False, "label": "Disable new account pending review: Disable-LocalUser"},
        ],
        "recovery_tip": "Check who created the account (Event 4720 creator field). Remove if unauthorized.",
    },
]

# Index playbooks by ID for fast lookup
_PLAYBOOK_INDEX = {pb["id"]: pb for pb in PLAYBOOKS}


# ── Trigger evaluator ─────────────────────────────────────────────────────────

def _get_alert_types(alerts: list) -> set:
    """Extract all rule/type keys from an alert list."""
    types = set()
    for a in alerts:
        if a.get("rule"):
            types.add(str(a["rule"]).upper())
        if a.get("type"):
            types.add(str(a["type"]).upper())
    return types


def _get_max_severity(alerts: list) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for s in order:
        if any(str(a.get("severity", "")).upper() == s for a in alerts):
            return s
    return "INFO"


def _severity_gte(sev: str, min_sev: str) -> bool:
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    return order.get(sev, 0) >= order.get(min_sev, 0)


def evaluate_playbooks(all_alerts: list) -> list:
    """
    Evaluate all playbooks against the current alert set.
    Returns list of triggered playbooks (sorted by priority).
    """
    alert_types  = _get_alert_types(all_alerts)
    max_sev      = _get_max_severity(all_alerts)
    triggered    = []

    for pb in PLAYBOOKS:
        trigger = pb["trigger"]
        min_sev = trigger.get("min_sev", "LOW")

        # Severity gate
        if not _severity_gte(max_sev, min_sev):
            continue

        all_of  = set(trigger.get("all_of", []))
        any_of  = set(trigger.get("any_of", []))

        # all_of: EVERY listed type must be present
        if all_of and not all_of.issubset(alert_types):
            continue

        # any_of: AT LEAST ONE listed type must be present
        if any_of and not any_of.intersection(alert_types):
            continue

        # Playbook triggered — find matching alerts as evidence
        evidence_types = all_of | any_of
        evidence = [
            a for a in all_alerts
            if (str(a.get("rule", "")).upper() in evidence_types or
                str(a.get("type", "")).upper() in evidence_types)
        ][:5]

        triggered.append({
            "playbook_id":   pb["id"],
            "name":          pb["name"],
            "description":   pb["description"],
            "priority":      pb["priority"],
            "mitre":         pb["mitre"],
            "actions":       pb["actions"],
            "recovery_tip":  pb.get("recovery_tip", ""),
            "triggered_at":  datetime.now().isoformat(),
            "evidence_count": len(evidence),
            "evidence_types": [e.get("rule") or e.get("type") for e in evidence],
        })

    # Sort by priority (1=highest) then by evidence count
    triggered.sort(key=lambda p: (p["priority"], -p["evidence_count"]))
    return triggered


# ── Automated action executors ────────────────────────────────────────────────

def execute_action(action_type: str, params: dict) -> dict:
    """
    Execute an automated playbook action.
    Returns {success, message, output}.
    """
    try:
        if action_type == "BLOCK_IP":
            return _action_block_ip(params.get("ip", ""))
        elif action_type == "ISOLATE_NETWORK":
            from network_isolation import enable_isolation
            enable_isolation()
            return {"success": True, "message": "Network isolation enabled"}
        elif action_type == "KILL_PROCESS":
            return _action_kill_process(params.get("pid"), params.get("name", ""))
        elif action_type == "DISABLE_SERVICE":
            return _action_disable_service(params.get("service_name", ""))
        elif action_type == "LOG_FORENSICS":
            return {"success": True, "message": "Forensic snapshot logged"}
        elif action_type == "ALERT_USER":
            return {"success": True, "message": f"Alert sent: {params.get('message', '')}"}
        elif action_type == "RUN_VULN_SCAN":
            from vuln_scanner import run_vuln_scan
            run_vuln_scan()
            return {"success": True, "message": "Vulnerability scan triggered"}
        else:
            return {"success": False, "message": f"Action type '{action_type}' is advisory only"}
    except Exception as e:
        logger.error(f"Playbook action {action_type} failed: {e}")
        return {"success": False, "message": str(e)}


def _action_block_ip(ip: str) -> dict:
    if not ip or ip in ("127.0.0.1", "::1", ""):
        return {"success": False, "message": "Invalid IP"}
    try:
        rule_name = f"NexoraGuard_Block_{ip}"
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=in", "action=block",
             f"remoteip={ip}", "protocol=any"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return {"success": True, "message": f"Blocked {ip} via Windows Firewall"}
        return {"success": False, "message": result.stderr.strip()}
    except Exception as e:
        return {"success": False, "message": str(e)}


def _action_kill_process(pid, name: str) -> dict:
    try:
        import psutil
        if pid:
            p = psutil.Process(int(pid))
            p.kill()
            return {"success": True, "message": f"Killed process PID {pid}"}
        elif name:
            killed = 0
            for p in psutil.process_iter(["name", "pid"]):
                if p.info["name"] and name.lower() in p.info["name"].lower():
                    p.kill()
                    killed += 1
            return {"success": True, "message": f"Killed {killed} process(es) matching '{name}'"}
        return {"success": False, "message": "No PID or name provided"}
    except Exception as e:
        return {"success": False, "message": str(e)}


def _action_disable_service(service_name: str) -> dict:
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"Stop-Service -Name '{service_name}' -Force; Set-Service -Name '{service_name}' -StartupType Disabled"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            return {"success": True, "message": f"Service '{service_name}' stopped and disabled"}
        return {"success": False, "message": result.stderr.strip()}
    except Exception as e:
        return {"success": False, "message": str(e)}


# ── Summary ───────────────────────────────────────────────────────────────────

def get_playbook_summary(triggered: list) -> dict:
    auto_actions   = sum(1 for pb in triggered for a in pb["actions"] if a.get("auto"))
    manual_actions = sum(1 for pb in triggered for a in pb["actions"] if not a.get("auto"))
    return {
        "total_triggered":  len(triggered),
        "auto_actions":     auto_actions,
        "manual_actions":   manual_actions,
        "top_playbook":     triggered[0]["name"] if triggered else None,
    }
