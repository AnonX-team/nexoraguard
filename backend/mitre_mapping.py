"""
MITRE ATT&CK Mapping for NexoraGuard
Maps internal rule names to ATT&CK Tactics, Techniques, and Sub-techniques.
Reference: https://attack.mitre.org/

Every alert fired by NexoraGuard now carries:
  - tactic:     ATT&CK tactic (e.g. "Credential Access")
  - technique:  Technique ID  (e.g. "T1110")
  - sub_tech:   Sub-technique (e.g. "T1110.001") or None
  - tech_name:  Human name    (e.g. "Brute Force")
  - url:        MITRE link
"""

# ── Mapping table ─────────────────────────────────────────────────────────────
# rule_name → { tactic, technique, sub_tech, tech_name }

RULE_TO_MITRE: dict[str, dict] = {

    # ── Credential Access ────────────────────────────────────────────────────
    "BRUTE_FORCE": {
        "tactic":    "Credential Access",
        "tactic_id": "TA0006",
        "technique": "T1110",
        "sub_tech":  "T1110.001",
        "tech_name": "Brute Force: Password Guessing",
        "url":       "https://attack.mitre.org/techniques/T1110/001/",
        "severity_boost": 0,  # extra severity points for ATT&CK context
    },

    # ── Privilege Escalation ─────────────────────────────────────────────────
    "PRIVILEGE_ESCALATION": {
        "tactic":    "Privilege Escalation",
        "tactic_id": "TA0004",
        "technique": "T1078",
        "sub_tech":  "T1078.003",
        "tech_name": "Valid Accounts: Local Accounts",
        "url":       "https://attack.mitre.org/techniques/T1078/003/",
        "severity_boost": 5,
    },

    # ── Execution (PowerShell) ───────────────────────────────────────────────
    "SUSPICIOUS_POWERSHELL": {
        "tactic":    "Execution",
        "tactic_id": "TA0002",
        "technique": "T1059",
        "sub_tech":  "T1059.001",
        "tech_name": "Command & Scripting: PowerShell",
        "url":       "https://attack.mitre.org/techniques/T1059/001/",
        "severity_boost": 10,
    },

    # ── Persistence ──────────────────────────────────────────────────────────
    "NEW_ACCOUNT": {
        "tactic":    "Persistence",
        "tactic_id": "TA0003",
        "technique": "T1136",
        "sub_tech":  "T1136.001",
        "tech_name": "Create Account: Local Account",
        "url":       "https://attack.mitre.org/techniques/T1136/001/",
        "severity_boost": 0,
    },

    "SCHEDULED_TASK": {
        "tactic":    "Persistence",
        "tactic_id": "TA0003",
        "technique": "T1053",
        "sub_tech":  "T1053.005",
        "tech_name": "Scheduled Task/Job: Scheduled Task",
        "url":       "https://attack.mitre.org/techniques/T1053/005/",
        "severity_boost": 5,
    },

    "SERVICE_INSTALL": {
        "tactic":    "Persistence",
        "tactic_id": "TA0003",
        "technique": "T1543",
        "sub_tech":  "T1543.003",
        "tech_name": "Create or Modify System Process: Windows Service",
        "url":       "https://attack.mitre.org/techniques/T1543/003/",
        "severity_boost": 10,
    },

    # ── Defense Evasion ──────────────────────────────────────────────────────
    "LOG_CLEARED": {
        "tactic":    "Defense Evasion",
        "tactic_id": "TA0005",
        "technique": "T1070",
        "sub_tech":  "T1070.001",
        "tech_name": "Indicator Removal: Clear Windows Event Logs",
        "url":       "https://attack.mitre.org/techniques/T1070/001/",
        "severity_boost": 20,   # extremely suspicious — always boost
    },

    "FILE_MODIFIED": {
        "tactic":    "Defense Evasion",
        "tactic_id": "TA0005",
        "technique": "T1565",
        "sub_tech":  "T1565.001",
        "tech_name": "Data Manipulation: Stored Data Manipulation",
        "url":       "https://attack.mitre.org/techniques/T1565/001/",
        "severity_boost": 5,
    },

    # ── Discovery ────────────────────────────────────────────────────────────
    "HIGH_CPU": {
        "tactic":    "Discovery",
        "tactic_id": "TA0007",
        "technique": "T1057",
        "sub_tech":  None,
        "tech_name": "Process Discovery",
        "url":       "https://attack.mitre.org/techniques/T1057/",
        "severity_boost": 0,
    },

    # ── Lateral Movement ─────────────────────────────────────────────────────
    "EXPLICIT_LOGON": {
        "tactic":    "Lateral Movement",
        "tactic_id": "TA0008",
        "technique": "T1021",
        "sub_tech":  None,
        "tech_name": "Remote Services",
        "url":       "https://attack.mitre.org/techniques/T1021/",
        "severity_boost": 5,
    },

    "REMOTE_LOGON": {
        "tactic":    "Lateral Movement",
        "tactic_id": "TA0008",
        "technique": "T1021",
        "sub_tech":  "T1021.001",
        "tech_name": "Remote Services: Remote Desktop Protocol",
        "url":       "https://attack.mitre.org/techniques/T1021/001/",
        "severity_boost": 5,
    },

    # ── Command & Control ────────────────────────────────────────────────────
    "MALICIOUS_PROCESS": {
        "tactic":    "Command and Control",
        "tactic_id": "TA0011",
        "technique": "T1219",
        "sub_tech":  None,
        "tech_name": "Remote Access Software",
        "url":       "https://attack.mitre.org/techniques/T1219/",
        "severity_boost": 15,
    },

    "SUSPICIOUS_PORT": {
        "tactic":    "Command and Control",
        "tactic_id": "TA0011",
        "technique": "T1571",
        "sub_tech":  None,
        "tech_name": "Non-Standard Port",
        "url":       "https://attack.mitre.org/techniques/T1571/",
        "severity_boost": 10,
    },

    # ── Impact ───────────────────────────────────────────────────────────────
    "ACCOUNT_LOCKOUT": {
        "tactic":    "Impact",
        "tactic_id": "TA0040",
        "technique": "T1531",
        "sub_tech":  None,
        "tech_name": "Account Access Removal",
        "url":       "https://attack.mitre.org/techniques/T1531/",
        "severity_boost": 5,
    },

    # ── Initial Access ───────────────────────────────────────────────────────
    "USB_DEVICE": {
        "tactic":    "Initial Access",
        "tactic_id": "TA0001",
        "technique": "T1091",
        "sub_tech":  None,
        "tech_name": "Replication Through Removable Media",
        "url":       "https://attack.mitre.org/techniques/T1091/",
        "severity_boost": 0,
    },

    # ── Zero-Day / Behavioral Anomaly ────────────────────────────────────────
    "ZERO_DAY_ANOMALY": {
        "tactic":    "Defense Evasion",
        "tactic_id": "TA0005",
        "technique": "T1036",
        "sub_tech":  "T1036.005",
        "tech_name": "Masquerading: Match Legitimate Name or Location",
        "url":       "https://attack.mitre.org/techniques/T1036/005/",
        "severity_boost": 25,
    },

    "PROCESS_INJECTION": {
        "tactic":    "Defense Evasion",
        "tactic_id": "TA0005",
        "technique": "T1055",
        "sub_tech":  None,
        "tech_name": "Process Injection",
        "url":       "https://attack.mitre.org/techniques/T1055/",
        "severity_boost": 30,
    },

    "LOLBIN_ABUSE": {
        "tactic":    "Defense Evasion",
        "tactic_id": "TA0005",
        "technique": "T1218",
        "sub_tech":  None,
        "tech_name": "System Binary Proxy Execution",
        "url":       "https://attack.mitre.org/techniques/T1218/",
        "severity_boost": 20,
    },

    "SUSPICIOUS_SPAWN": {
        "tactic":    "Execution",
        "tactic_id": "TA0002",
        "technique": "T1059",
        "sub_tech":  "T1059.001",
        "tech_name": "Command and Scripting Interpreter: PowerShell",
        "url":       "https://attack.mitre.org/techniques/T1059/001/",
        "severity_boost": 20,
    },

    # ── DDoS / Flood ─────────────────────────────────────────────────────────
    "DDOS_ATTACK": {
        "tactic":    "Impact",
        "tactic_id": "TA0040",
        "technique": "T1498",
        "sub_tech":  "T1498.001",
        "tech_name": "Network Denial of Service: Direct Network Flood",
        "url":       "https://attack.mitre.org/techniques/T1498/001/",
        "severity_boost": 25,
    },

    "PORT_SCAN": {
        "tactic":    "Discovery",
        "tactic_id": "TA0007",
        "technique": "T1046",
        "sub_tech":  None,
        "tech_name": "Network Service Discovery",
        "url":       "https://attack.mitre.org/techniques/T1046/",
        "severity_boost": 10,
    },

    # ── Reflection / Amplification ────────────────────────────────────────────
    "AMPLIFICATION_ATTACK": {
        "tactic":    "Impact",
        "tactic_id": "TA0040",
        "technique": "T1498",
        "sub_tech":  "T1498.002",
        "tech_name": "Network Denial of Service: Reflection Amplification",
        "url":       "https://attack.mitre.org/techniques/T1498/002/",
        "severity_boost": 30,
    },

    # ── L7 / Application DoS ──────────────────────────────────────────────────
    "HTTP_FLOOD": {
        "tactic":    "Impact",
        "tactic_id": "TA0040",
        "technique": "T1499",
        "sub_tech":  "T1499.004",
        "tech_name": "Endpoint Denial of Service: Application or System Exploitation",
        "url":       "https://attack.mitre.org/techniques/T1499/004/",
        "severity_boost": 25,
    },

    "SLOWLORIS": {
        "tactic":    "Impact",
        "tactic_id": "TA0040",
        "technique": "T1499",
        "sub_tech":  "T1499.004",
        "tech_name": "Endpoint Denial of Service: Application or System Exploitation",
        "url":       "https://attack.mitre.org/techniques/T1499/004/",
        "severity_boost": 20,
    },

    # ── UEBA — Behavioral Anomalies ───────────────────────────────────────────
    "UEBA_ANOMALY": {
        "tactic":    "Initial Access",
        "tactic_id": "TA0001",
        "technique": "T1078",
        "sub_tech":  None,
        "tech_name": "Valid Accounts",
        "url":       "https://attack.mitre.org/techniques/T1078/",
        "severity_boost": 20,
    },

    # ── Ransomware ────────────────────────────────────────────────────────────
    "RANSOMWARE_DETECTED": {
        "tactic":    "Impact",
        "tactic_id": "TA0040",
        "technique": "T1486",
        "sub_tech":  None,
        "tech_name": "Data Encrypted for Impact",
        "url":       "https://attack.mitre.org/techniques/T1486/",
        "severity_boost": 40,
    },

    # ── Threat Intel — Known malware ──────────────────────────────────────────
    "MALWARE_DETECTED": {
        "tactic":    "Execution",
        "tactic_id": "TA0002",
        "technique": "T1204",
        "sub_tech":  "T1204.002",
        "tech_name": "User Execution: Malicious File",
        "url":       "https://attack.mitre.org/techniques/T1204/002/",
        "severity_boost": 35,
    },

    "KNOWN_BAD_IP": {
        "tactic":    "Command and Control",
        "tactic_id": "TA0011",
        "technique": "T1071",
        "sub_tech":  None,
        "tech_name": "Application Layer Protocol",
        "url":       "https://attack.mitre.org/techniques/T1071/",
        "severity_boost": 25,
    },

    # ── Lateral Movement ──────────────────────────────────────────────────────
    "LATERAL_MOVEMENT": {
        "tactic":    "Lateral Movement",
        "tactic_id": "TA0008",
        "technique": "T1021",
        "sub_tech":  None,
        "tech_name": "Remote Services",
        "url":       "https://attack.mitre.org/techniques/T1021/",
        "severity_boost": 30,
    },

    # ── Vulnerability ─────────────────────────────────────────────────────────
    "VULNERABILITY_FOUND": {
        "tactic":    "Initial Access",
        "tactic_id": "TA0001",
        "technique": "T1190",
        "sub_tech":  None,
        "tech_name": "Exploit Public-Facing Application",
        "url":       "https://attack.mitre.org/techniques/T1190/",
        "severity_boost": 15,
    },
}

# Tactic color coding for UI
TACTIC_COLORS: dict[str, str] = {
    "Initial Access":        "#f97316",
    "Execution":             "#ef4444",
    "Persistence":           "#8b5cf6",
    "Privilege Escalation":  "#ec4899",
    "Defense Evasion":       "#6366f1",
    "Credential Access":     "#0ea5e9",
    "Discovery":             "#22c55e",
    "Lateral Movement":      "#eab308",
    "Collection":            "#14b8a6",
    "Command and Control":   "#ef4444",
    "Exfiltration":          "#f97316",
    "Impact":                "#dc2626",
}


def enrich_alert_with_mitre(alert: dict) -> dict:
    """
    Add MITRE ATT&CK fields to an alert dict in-place.
    Returns the same dict with added 'mitre' key.
    """
    rule = alert.get("rule", "").upper()
    mapping = RULE_TO_MITRE.get(rule)

    if mapping:
        alert["mitre"] = {
            "tactic":    mapping["tactic"],
            "tactic_id": mapping["tactic_id"],
            "technique": mapping["technique"],
            "sub_tech":  mapping.get("sub_tech"),
            "tech_name": mapping["tech_name"],
            "url":       mapping["url"],
            "color":     TACTIC_COLORS.get(mapping["tactic"], "#475569"),
        }
    else:
        alert["mitre"] = None

    return alert


def enrich_alerts(alerts: list[dict]) -> list[dict]:
    """Enrich a list of rule alerts with MITRE ATT&CK data."""
    return [enrich_alert_with_mitre(a) for a in alerts]


def get_mitre_summary(alerts: list[dict]) -> dict:
    """
    Summarize ATT&CK coverage from a list of enriched alerts.
    Returns: tactic counts, unique techniques, kill chain stage.
    """
    tactic_counts: dict[str, int] = {}
    techniques: set[str] = set()
    tactics_seen: set[str] = set()

    for a in alerts:
        m = a.get("mitre")
        if not m:
            continue
        tactic = m["tactic"]
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        techniques.add(m["technique"])
        tactics_seen.add(tactic)

    # Kill chain ordering (ATT&CK enterprise matrix order)
    KILL_CHAIN = [
        "Initial Access", "Execution", "Persistence",
        "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection",
        "Command and Control", "Exfiltration", "Impact",
    ]
    stage = None
    for t in reversed(KILL_CHAIN):  # highest stage seen
        if t in tactics_seen:
            stage = t
            break

    return {
        "tactic_counts":    tactic_counts,
        "unique_techniques": list(techniques),
        "technique_count":  len(techniques),
        "tactic_count":     len(tactics_seen),
        "kill_chain_stage": stage,
        "tactics_seen":     list(tactics_seen),
    }
