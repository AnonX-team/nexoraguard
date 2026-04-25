"""
Kill Chain Tracker — NexoraGuard XDR
Tracks attacker progression through MITRE ATT&CK kill chain stages
and predicts the attacker's NEXT likely moves.

Kill Chain stages (ATT&CK Enterprise order):
  TA0001  Initial Access
  TA0002  Execution
  TA0003  Persistence
  TA0004  Privilege Escalation
  TA0005  Defense Evasion
  TA0006  Credential Access
  TA0007  Discovery
  TA0008  Lateral Movement
  TA0009  Collection
  TA0011  Command and Control
  TA0010  Exfiltration
  TA0040  Impact

For each active stage the tracker outputs:
  - evidence alerts
  - dwell_time (seconds since first detection)
  - next_likely_tactics  (ordered by probability)
  - predicted_techniques (specific T-numbers to watch)
  - attacker_objective   (human-readable goal)
"""
import logging
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)

# ── Kill Chain definition ─────────────────────────────────────────────────────
KILL_CHAIN_STAGES = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

STAGE_IDS = {
    "Initial Access":       "TA0001",
    "Execution":            "TA0002",
    "Persistence":          "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion":      "TA0005",
    "Credential Access":    "TA0006",
    "Discovery":            "TA0007",
    "Lateral Movement":     "TA0008",
    "Collection":           "TA0009",
    "Command and Control":  "TA0011",
    "Exfiltration":         "TA0010",
    "Impact":               "TA0040",
}

# Attacker objective per stage (what they are trying to achieve)
STAGE_OBJECTIVES = {
    "Initial Access":       "Gain foothold on the network or endpoint",
    "Execution":            "Run malicious code on the system",
    "Persistence":          "Maintain access across reboots and sessions",
    "Privilege Escalation": "Gain higher-level permissions (SYSTEM/Admin)",
    "Defense Evasion":      "Avoid detection and disable security tools",
    "Credential Access":    "Steal credentials to expand access",
    "Discovery":            "Map the environment — users, hosts, shares",
    "Lateral Movement":     "Move to other systems inside the network",
    "Collection":           "Gather sensitive data for exfiltration",
    "Command and Control":  "Establish persistent C2 channel",
    "Exfiltration":         "Transfer stolen data to attacker infrastructure",
    "Impact":               "Destroy, encrypt, or disrupt operations",
}

# Threat level per stage
STAGE_SEVERITY = {
    "Initial Access":       "MEDIUM",
    "Execution":            "HIGH",
    "Persistence":          "HIGH",
    "Privilege Escalation": "HIGH",
    "Defense Evasion":      "HIGH",
    "Credential Access":    "HIGH",
    "Discovery":            "MEDIUM",
    "Lateral Movement":     "CRITICAL",
    "Collection":           "CRITICAL",
    "Command and Control":  "CRITICAL",
    "Exfiltration":         "CRITICAL",
    "Impact":               "CRITICAL",
}

# ATT&CK techniques to WATCH for each predicted next stage
# These are the specific TTPs we predict the attacker will use NEXT
PREDICTED_TECHNIQUES = {
    "Initial Access": {
        "next": ["Execution", "Persistence"],
        "watch": ["T1059 (PowerShell/cmd launch)", "T1547 (Registry Run Keys)", "T1053 (Scheduled Tasks)"],
        "indicator": "Attacker is inside — watch for script execution and persistence attempts",
    },
    "Execution": {
        "next": ["Persistence", "Privilege Escalation", "Defense Evasion"],
        "watch": ["T1112 (Registry Modification)", "T1055 (Process Injection)", "T1070 (Log Clearing)"],
        "indicator": "Code is running — watch for persistence and evasion activity",
    },
    "Persistence": {
        "next": ["Privilege Escalation", "Credential Access"],
        "watch": ["T1078 (Valid Accounts)", "T1548 (Abuse Elevation Control)", "T1003 (Credential Dumping)"],
        "indicator": "Attacker has footing — will try to escalate or steal credentials next",
    },
    "Privilege Escalation": {
        "next": ["Defense Evasion", "Credential Access"],
        "watch": ["T1070 (Log Clearing)", "T1562 (Impair Defenses)", "T1003 (LSASS Dump)", "T1110 (Brute Force)"],
        "indicator": "Admin rights obtained — expect security tool tampering or credential harvesting",
    },
    "Defense Evasion": {
        "next": ["Credential Access", "Discovery"],
        "watch": ["T1003 (Credential Dumping)", "T1087 (Account Discovery)", "T1135 (Network Share Discovery)"],
        "indicator": "Defenses bypassed — credential theft and reconnaissance imminent",
    },
    "Credential Access": {
        "next": ["Discovery", "Lateral Movement"],
        "watch": ["T1018 (Remote System Discovery)", "T1021 (Remote Services)", "T1550 (Pass-the-Hash)"],
        "indicator": "Credentials stolen — attacker will move to other systems shortly",
    },
    "Discovery": {
        "next": ["Lateral Movement", "Collection"],
        "watch": ["T1021.001 (RDP)", "T1021.002 (SMB)", "T1021.006 (WinRM)", "T1560 (Archive Collected Data)"],
        "indicator": "Network mapped — lateral movement or data collection expected next",
    },
    "Lateral Movement": {
        "next": ["Collection", "Command and Control"],
        "watch": ["T1560 (Data Archive)", "T1071 (Application Protocol C2)", "T1219 (Remote Access Software)"],
        "indicator": "Attacker is spreading — data collection and C2 channel expected",
    },
    "Collection": {
        "next": ["Command and Control", "Exfiltration"],
        "watch": ["T1048 (Exfiltration over Alternative Protocol)", "T1041 (Exfiltration over C2)", "T1567 (Exfil to Cloud)"],
        "indicator": "Data gathered — exfiltration attempt imminent (DNS/HTTPS/cloud)",
    },
    "Command and Control": {
        "next": ["Exfiltration", "Impact"],
        "watch": ["T1048 (Exfiltration)", "T1486 (Data Encrypted for Impact)", "T1490 (Shadow Copy Delete)"],
        "indicator": "C2 active — attacker may exfiltrate data or deploy ransomware",
    },
    "Exfiltration": {
        "next": ["Impact"],
        "watch": ["T1486 (Ransomware)", "T1490 (Inhibit System Recovery)", "T1491 (Defacement)", "T1531 (Account Removal)"],
        "indicator": "Data stolen — destructive payload (ransomware/wiper) may follow",
    },
    "Impact": {
        "next": [],
        "watch": [],
        "indicator": "Terminal stage — immediate incident response required",
    },
}

# Map alert rule names → ATT&CK tactic
RULE_TO_TACTIC = {
    # Initial Access
    "USB_DEVICE":              "Initial Access",
    "UEBA_ANOMALY":            "Initial Access",
    "VULNERABILITY_FOUND":     "Initial Access",
    # Execution
    "SUSPICIOUS_POWERSHELL":   "Execution",
    "SUSPICIOUS_SPAWN":        "Execution",
    "MALWARE_DETECTED":        "Execution",
    # Persistence
    "NEW_ACCOUNT":             "Persistence",
    "SCHEDULED_TASK":          "Persistence",
    "SERVICE_INSTALL":         "Persistence",
    # Privilege Escalation
    "PRIVILEGE_ESCALATION":    "Privilege Escalation",
    # Defense Evasion
    "LOG_CLEARED":             "Defense Evasion",
    "FILE_MODIFIED":           "Defense Evasion",
    "ZERO_DAY_ANOMALY":        "Defense Evasion",
    "PROCESS_INJECTION":       "Defense Evasion",
    "LOLBIN_ABUSE":            "Defense Evasion",
    # Credential Access
    "BRUTE_FORCE":             "Credential Access",
    # Discovery
    "HIGH_CPU":                "Discovery",
    "PORT_SCAN":               "Discovery",
    # Lateral Movement
    "EXPLICIT_LOGON":          "Lateral Movement",
    "REMOTE_LOGON":            "Lateral Movement",
    "LATERAL_MOVEMENT":        "Lateral Movement",
    # C2
    "MALICIOUS_PROCESS":       "Command and Control",
    "SUSPICIOUS_PORT":         "Command and Control",
    "KNOWN_BAD_IP":            "Command and Control",
    # Impact
    "ACCOUNT_LOCKOUT":         "Impact",
    "RANSOMWARE_DETECTED":     "Impact",
    "DDOS_ATTACK":             "Impact",
    "AMPLIFICATION_ATTACK":    "Impact",
    "HTTP_FLOOD":              "Impact",
    "SLOWLORIS":               "Impact",
}

# Sub-detector type → tactic (for UEBA/Ransomware/Lateral alerts that have "type" not "rule")
TYPE_TO_TACTIC = {
    "OFF_HOURS_LOGIN":         "Initial Access",
    "NEW_SOURCE_LOGON":        "Initial Access",
    "CREDENTIAL_STUFFING":     "Credential Access",
    "PASSWORD_SPRAY":          "Credential Access",
    "ACCOUNT_ENUMERATION":     "Discovery",
    "PRIVILEGE_ANOMALY":       "Privilege Escalation",
    "RARE_PROCESS":            "Execution",
    "MASS_FILE_MODIFICATION":  "Impact",
    "RANSOM_EXTENSION":        "Impact",
    "RANSOM_NOTE":             "Impact",
    "HIGH_ENTROPY_WRITE":      "Impact",
    "SHADOW_COPY_DELETION":    "Impact",
    "RDP_EXTERNAL":            "Lateral Movement",
    "RDP_NEW_SOURCE":          "Lateral Movement",
    "SMB_LATERAL_SPREAD":      "Lateral Movement",
    "ADMIN_SHARE_ACCESS":      "Lateral Movement",
    "WINRM_EXTERNAL":          "Lateral Movement",
    "WINRM_INTERNAL":          "Lateral Movement",
    "PASS_THE_HASH":           "Credential Access",
    "REMOTE_SERVICE_INSTALL":  "Persistence",
    "EOL_SOFTWARE":            "Initial Access",
    "PATCH_CRITICAL":          "Initial Access",
    "PATCH_OVERDUE":           "Initial Access",
    "TCP_SYN_FLOOD":           "Impact",
    "UDP_FLOOD":               "Impact",
    "DNS_AMPLIFICATION":       "Impact",
    "NTP_AMPLIFICATION":       "Impact",
    "HTTP_FLOOD":              "Impact",
    "SLOWLORIS":               "Impact",
    "CARPET_BOMBING":          "Impact",
    "IOT_BOTNET":              "Impact",
}

# ── State tracking ─────────────────────────────────────────────────────────────
_stage_first_seen: dict = {}   # tactic → first detection timestamp
_stage_alert_count: dict = {}  # tactic → alert count


def _extract_tactic(alert: dict) -> str | None:
    """Extract ATT&CK tactic from an alert dict (rule, type, or mitre field)."""
    # 1. From enriched mitre data
    mitre = alert.get("mitre")
    if isinstance(mitre, dict) and mitre.get("tactic"):
        return mitre["tactic"]
    # 2. From rule field
    rule = str(alert.get("rule", "")).upper()
    if rule in RULE_TO_TACTIC:
        return RULE_TO_TACTIC[rule]
    # 3. From type field (sub-detector alerts)
    atype = str(alert.get("type", "")).upper()
    if atype in TYPE_TO_TACTIC:
        return TYPE_TO_TACTIC[atype]
    return None


def track_kill_chain(all_alerts: list) -> dict:
    """
    Main entry point. Takes all current alerts from every detector,
    maps them to kill chain stages, and predicts next attacker moves.

    Returns full kill chain state dict ready for the dashboard.
    """
    global _stage_first_seen, _stage_alert_count

    now = datetime.now()

    # Group alerts by tactic
    tactic_alerts: dict = defaultdict(list)
    for alert in all_alerts:
        tactic = _extract_tactic(alert)
        if tactic:
            tactic_alerts[tactic].append(alert)

    # Update state
    for tactic, alerts in tactic_alerts.items():
        if tactic not in _stage_first_seen:
            _stage_first_seen[tactic] = now.isoformat()
        _stage_alert_count[tactic] = _stage_alert_count.get(tactic, 0) + len(alerts)

    # Determine active stages
    active_stages = set(tactic_alerts.keys())

    # Find the highest (most advanced) stage
    highest_stage = None
    highest_index = -1
    for tactic in active_stages:
        if tactic in KILL_CHAIN_STAGES:
            idx = KILL_CHAIN_STAGES.index(tactic)
            if idx > highest_index:
                highest_index = idx
                highest_stage = tactic

    # Compute dwell times
    stage_details = []
    for stage in KILL_CHAIN_STAGES:
        is_active = stage in active_stages
        alerts_for_stage = tactic_alerts.get(stage, [])
        first_seen = _stage_first_seen.get(stage)
        dwell_seconds = 0
        if first_seen:
            try:
                dwell_seconds = int((now - datetime.fromisoformat(first_seen)).total_seconds())
            except Exception:
                dwell_seconds = 0

        prediction = PREDICTED_TECHNIQUES.get(stage, {})
        stage_details.append({
            "stage":          stage,
            "tactic_id":      STAGE_IDS.get(stage, ""),
            "is_active":      is_active,
            "is_highest":     stage == highest_stage,
            "alert_count":    len(alerts_for_stage),
            "total_seen":     _stage_alert_count.get(stage, 0),
            "first_seen":     first_seen,
            "dwell_seconds":  dwell_seconds,
            "severity":       STAGE_SEVERITY.get(stage, "LOW"),
            "objective":      STAGE_OBJECTIVES.get(stage, ""),
            "evidence":       [
                a.get("message") or a.get("detail") or a.get("type", "")
                for a in alerts_for_stage[:3]
            ],
        })

    # Predict next stages
    predicted_next = []
    if highest_stage and highest_stage in PREDICTED_TECHNIQUES:
        pred = PREDICTED_TECHNIQUES[highest_stage]
        for next_stage in pred.get("next", []):
            if next_stage not in active_stages:  # not already detected
                predicted_next.append({
                    "stage":     next_stage,
                    "tactic_id": STAGE_IDS.get(next_stage, ""),
                    "severity":  STAGE_SEVERITY.get(next_stage, "MEDIUM"),
                    "objective": STAGE_OBJECTIVES.get(next_stage, ""),
                    "watch_for": PREDICTED_TECHNIQUES.get(next_stage, {}).get("watch", []),
                    "probability": "HIGH" if next_stage == pred["next"][0] else "MEDIUM",
                })

    # Overall kill chain risk
    if highest_stage in ("Impact", "Exfiltration", "Command and Control", "Lateral Movement"):
        chain_risk = "CRITICAL"
    elif highest_stage in ("Collection", "Defense Evasion", "Credential Access"):
        chain_risk = "HIGH"
    elif highest_stage in ("Persistence", "Privilege Escalation", "Discovery", "Execution"):
        chain_risk = "MEDIUM"
    elif highest_stage in ("Initial Access",):
        chain_risk = "LOW"
    else:
        chain_risk = "SAFE"

    # Attacker profile inference
    attacker_profile = _infer_attacker_profile(active_stages)

    # Current indicator message
    current_indicator = ""
    if highest_stage:
        current_indicator = PREDICTED_TECHNIQUES.get(highest_stage, {}).get("indicator", "")

    return {
        "checked_at":        now.isoformat(),
        "chain_risk":        chain_risk,
        "active_stages":     list(active_stages),
        "active_count":      len(active_stages),
        "highest_stage":     highest_stage,
        "highest_stage_idx": highest_index,
        "predicted_next":    predicted_next,
        "stages":            stage_details,
        "attacker_profile":  attacker_profile,
        "current_indicator": current_indicator,
        "total_alerts_seen": sum(len(v) for v in tactic_alerts.values()),
    }


def _infer_attacker_profile(active_stages: set) -> dict:
    """
    Infer attacker profile/type based on which stages are active.
    Returns profile dict with type, sophistication, likely_goal.
    """
    has_lateral   = "Lateral Movement" in active_stages
    has_c2        = "Command and Control" in active_stages
    has_impact    = "Impact" in active_stages
    has_evasion   = "Defense Evasion" in active_stages
    has_cred      = "Credential Access" in active_stages
    has_persist   = "Persistence" in active_stages
    has_exfil     = "Exfiltration" in active_stages
    stage_count   = len(active_stages)

    if has_impact and ("RANSOMWARE_DETECTED" in [s for s in active_stages]):
        profile_type = "Ransomware Operator"
        goal         = "Encrypt files and demand ransom"
        sophistication = "MEDIUM"
    elif has_lateral and has_c2 and has_evasion:
        profile_type = "APT / Nation-State Actor"
        goal         = "Long-term persistence and intelligence gathering"
        sophistication = "HIGH"
    elif has_c2 and has_exfil:
        profile_type = "Data Theft Actor"
        goal         = "Exfiltrate sensitive data"
        sophistication = "HIGH"
    elif has_lateral and has_cred:
        profile_type = "Internal Threat / Lateral Mover"
        goal         = "Expand access across network"
        sophistication = "MEDIUM"
    elif has_impact and not has_lateral:
        profile_type = "Script Kiddie / DDoS Actor"
        goal         = "Disrupt services"
        sophistication = "LOW"
    elif stage_count >= 4 and has_persist and has_evasion:
        profile_type = "Targeted Attacker"
        goal         = "Maintain access and move through kill chain"
        sophistication = "HIGH"
    elif stage_count >= 2:
        profile_type = "Opportunistic Attacker"
        goal         = "Exploit discovered vulnerabilities"
        sophistication = "LOW"
    else:
        profile_type = "Unknown / Unconfirmed"
        goal         = "Activity not yet profiled"
        sophistication = "UNKNOWN"

    return {
        "type":            profile_type,
        "goal":            goal,
        "sophistication":  sophistication,
        "stages_active":   stage_count,
    }


def reset_kill_chain():
    """Reset tracked state (call after incident closure)."""
    global _stage_first_seen, _stage_alert_count
    _stage_first_seen  = {}
    _stage_alert_count = {}
