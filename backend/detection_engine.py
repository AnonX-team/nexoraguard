"""
Detection Engine — Rule-Based + Dual-Mode AI
Phase 1 cost-optimised design:

  80% of cases → handled entirely by local rule logic (zero API cost)
  20% of cases → AI called only when HIGH/CRITICAL risk is confirmed by rules

AI key priority:
  1. User's own key (Settings → API Key) — used for all AI calls
  2. Fallback hardcoded key — ONLY for CRITICAL alerts (company cost)
  3. No key → local summary + "AI in standby" message
"""
import re
import json
import logging
from datetime import datetime
import groq as groq_module
from groq import Groq
from config import GROQ_API_KEY, FAILED_LOGIN_THRESHOLD

logger = logging.getLogger(__name__)


# ── Key resolver ──────────────────────────────────────────────────────────────

def get_effective_api_key(risk_level: str = "SAFE") -> str:
    """
    Return the API key to use for AI calls.

    Priority:
      1. User-provided key (Settings) — always preferred
      2. Hardcoded fallback key — ONLY when risk_level is CRITICAL
      3. Empty string — no AI call (local logic handles it)
    """
    try:
        from user_config import get_api_key
        user_key = get_api_key()
        if user_key:
            return user_key
    except Exception:
        pass

    if risk_level == "CRITICAL" and GROQ_API_KEY:
        logger.info("Using fallback key for CRITICAL alert")
        return GROQ_API_KEY

    return ""


def _groq_client(api_key: str) -> Groq:
    return Groq(api_key=api_key)


def call_ai(prompt: str, api_key: str) -> str:
    """
    Call Groq API with the given key.
    Raises descriptive exceptions that callers can log/display.
    """
    try:
        resp = _groq_client(api_key).chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=512,
            temperature=0.1
        )
        return resp.choices[0].message.content
    except groq_module.AuthenticationError as e:
        err = f"[401 Unauthorized] Invalid API key: {api_key[:8]}... — {e}"
        print(err)
        logger.error(err)
        raise
    except groq_module.RateLimitError as e:
        err = f"[429 Rate Limit] Groq daily quota exhausted — {e}"
        print(err)
        logger.error(err)
        raise
    except groq_module.APIStatusError as e:
        err = f"[HTTP {e.status_code}] Groq API error — {e.message}"
        print(err)
        logger.error(err)
        raise
    except groq_module.APIConnectionError as e:
        err = f"[Connection Error] Could not reach api.groq.com — {e}"
        print(err)
        logger.error(err)
        raise


# ── Rule-based detection ──────────────────────────────────────────────────────

def rule_failed_logins(logs: dict) -> list[dict]:
    alerts = []
    count = len(logs.get("failed_logins", []))
    if count >= FAILED_LOGIN_THRESHOLD:
        alerts.append({
            "rule": "BRUTE_FORCE", "severity": "HIGH",
            "message": f"{count} failed login attempts detected",
            "count": count, "timestamp": datetime.now().isoformat()
        })
    return alerts


def rule_new_accounts(logs: dict) -> list[dict]:
    alerts = []
    for event in logs.get("new_accounts", []):
        msg = event.get("Message", "")
        match = re.search(r"Account Name:\s+(\S+)", msg)
        username = match.group(1) if match else "unknown"
        alerts.append({
            "rule": "NEW_ACCOUNT", "severity": "MEDIUM",
            "message": f"New user account created: {username}",
            "timestamp": event.get("TimeCreated", datetime.now().isoformat())
        })
    return alerts


def rule_privilege_escalation(logs: dict) -> list[dict]:
    alerts = []
    escalations = logs.get("privilege_escalations", [])
    if len(escalations) > 3:
        alerts.append({
            "rule": "PRIVILEGE_ESCALATION", "severity": "CRITICAL",
            "message": f"{len(escalations)} privilege escalation events detected",
            "count": len(escalations), "timestamp": datetime.now().isoformat()
        })
    return alerts


def rule_suspicious_powershell(logs: dict) -> list[dict]:
    alerts = []
    KEYWORDS = [
        "invoke-expression", "iex", "downloadstring", "bypass",
        "encodedcommand", "hidden", "base64", "mimikatz",
        "invoke-mimikatz", "shellcode", "meterpreter"
    ]
    for event in logs.get("powershell_events", []):
        msg = event.get("Message", "").lower()
        for kw in KEYWORDS:
            if kw in msg:
                alerts.append({
                    "rule": "SUSPICIOUS_POWERSHELL", "severity": "CRITICAL",
                    "message": f"Suspicious PowerShell keyword: '{kw}'",
                    "timestamp": event.get("TimeCreated", datetime.now().isoformat())
                })
                break
    return alerts


def rule_suspicious_processes(snapshot: dict) -> list[dict]:
    return [
        {
            "rule": "MALICIOUS_PROCESS", "severity": "CRITICAL",
            "message": f"Suspicious process: {p['name']} (PID {p['pid']})",
            "pid": p["pid"], "timestamp": datetime.now().isoformat()
        }
        for p in snapshot.get("suspicious_processes", [])
    ]


def rule_suspicious_ports(snapshot: dict) -> list[dict]:
    return [
        {
            "rule": "SUSPICIOUS_PORT", "severity": "HIGH",
            "message": f"Connection on suspicious port: {c['local_addr']} -> {c['remote_addr']}",
            "timestamp": datetime.now().isoformat()
        }
        for c in snapshot.get("suspicious_connections", [])
    ]


def rule_high_cpu(snapshot: dict) -> list[dict]:
    alerts = []
    cpu = snapshot.get("system_stats", {}).get("cpu_percent", 0)
    if cpu > 95:
        alerts.append({
            "rule": "HIGH_CPU", "severity": "MEDIUM",
            "message": f"CPU critically high: {cpu}%",
            "timestamp": datetime.now().isoformat()
        })
    return alerts


def rule_scheduled_tasks(logs: dict) -> list[dict]:
    alerts = []
    for event in logs.get("scheduled_task_events", []):
        msg = event.get("Message", "")
        eid = str(event.get("Id", ""))
        action = "created" if eid == "4698" else "modified"
        alerts.append({
            "rule": "SCHEDULED_TASK", "severity": "HIGH",
            "message": f"Scheduled task {action}: check Task Scheduler for unauthorized entries",
            "timestamp": event.get("TimeCreated", datetime.now().isoformat())
        })
    return alerts[:3]   # cap to avoid alert flood


def rule_service_install(logs: dict) -> list[dict]:
    alerts = []
    for event in logs.get("service_install_events", []):
        msg = event.get("Message", "")
        match = re.search(r"Service Name:\s*(\S+)", msg)
        svc_name = match.group(1) if match else "unknown"
        alerts.append({
            "rule": "SERVICE_INSTALL", "severity": "HIGH",
            "message": f"New service installed: {svc_name}",
            "timestamp": event.get("TimeCreated", datetime.now().isoformat())
        })
    return alerts[:3]


def rule_log_cleared(logs: dict) -> list[dict]:
    alerts = []
    for event in logs.get("log_cleared_events", []):
        alerts.append({
            "rule": "LOG_CLEARED", "severity": "CRITICAL",
            "message": "Windows Event Log was cleared — possible attack cover-up",
            "timestamp": event.get("TimeCreated", datetime.now().isoformat())
        })
    return alerts[:2]


def rule_account_lockout(logs: dict) -> list[dict]:
    alerts = []
    lockouts = logs.get("account_lockout_events", [])
    if lockouts:
        alerts.append({
            "rule": "ACCOUNT_LOCKOUT", "severity": "HIGH",
            "message": f"{len(lockouts)} account lockout(s) detected — likely brute force",
            "count": len(lockouts),
            "timestamp": datetime.now().isoformat()
        })
    return alerts


def rule_zero_day(snapshot: dict, api_key: str = "") -> list:
    """Behavioral anomaly / zero-day detection."""
    try:
        from zero_day_detector import detect_zero_day
        result = detect_zero_day(snapshot, api_key)
        return result.get("rule_alerts", [])
    except Exception as e:
        logger.error(f"Zero-day detector error: {e}")
        return []


def rule_ddos(snapshot: dict) -> list:
    """DDoS / flood detection — 15 protocols."""
    try:
        from ddos_detector import detect_ddos
        result = detect_ddos(snapshot, auto_block=True)
        return result.get("rule_alerts", [])
    except Exception as e:
        logger.error(f"DDoS detector error: {e}")
        return []


def rule_ueba(logs: dict, snapshot: dict) -> list:
    """User & Entity Behavior Analytics."""
    try:
        from ueba import analyze_ueba
        result = analyze_ueba(logs, snapshot)
        return result.get("rule_alerts", [])
    except Exception as e:
        logger.error(f"UEBA error: {e}")
        return []


def rule_ransomware(logs: dict, snapshot: dict) -> list:
    """Ransomware behavioral detection."""
    try:
        from ransomware_detector import detect_ransomware
        result = detect_ransomware(logs, snapshot)
        return result.get("rule_alerts", [])
    except Exception as e:
        logger.error(f"Ransomware detector error: {e}")
        return []


def rule_lateral_movement(logs: dict, snapshot: dict) -> list:
    """Lateral movement detection."""
    try:
        from lateral_movement import detect_lateral_movement
        result = detect_lateral_movement(logs, snapshot)
        return result.get("rule_alerts", [])
    except Exception as e:
        logger.error(f"Lateral movement detector error: {e}")
        return []


def rule_threat_intel(snapshot: dict, api_key: str = "") -> list:
    """Threat intelligence feed — hash + IP reputation checks."""
    try:
        from threat_intel_feed import run_threat_intel_scan
        # Only use VirusTotal if user provided their own key (cost control)
        vt_key = api_key if api_key else ""
        result = run_threat_intel_scan(snapshot, vt_key)
        return result.get("rule_alerts", [])
    except Exception as e:
        logger.error(f"Threat intel feed error: {e}")
        return []


def run_all_rules(logs: dict, snapshot: dict, api_key: str = "") -> list:
    from mitre_mapping import enrich_alerts
    alerts = []
    alerts.extend(rule_failed_logins(logs))
    alerts.extend(rule_new_accounts(logs))
    alerts.extend(rule_privilege_escalation(logs))
    alerts.extend(rule_suspicious_powershell(logs))
    alerts.extend(rule_suspicious_processes(snapshot))
    alerts.extend(rule_suspicious_ports(snapshot))
    alerts.extend(rule_high_cpu(snapshot))
    # New rules from Phase A log collector
    alerts.extend(rule_scheduled_tasks(logs))
    alerts.extend(rule_service_install(logs))
    alerts.extend(rule_log_cleared(logs))
    alerts.extend(rule_account_lockout(logs))
    # AI-powered behavioral detection
    alerts.extend(rule_zero_day(snapshot, api_key))
    alerts.extend(rule_ddos(snapshot))
    # New: market-parity detectors
    alerts.extend(rule_ueba(logs, snapshot))
    alerts.extend(rule_ransomware(logs, snapshot))
    alerts.extend(rule_lateral_movement(logs, snapshot))
    alerts.extend(rule_threat_intel(snapshot, api_key))
    # Enrich all alerts with MITRE ATT&CK mapping
    return enrich_alerts(alerts)


# ── Local smart scoring (no API cost) ────────────────────────────────────────

def _local_risk_score(rule_alerts: list[dict]) -> tuple[str, int, bool]:
    """
    Compute risk level, score, and is_attack flag purely from rule alerts.
    Handles ~80% of all scan cases without any API call.
    """
    if not rule_alerts:
        return "SAFE", 0, False

    severities   = {a["severity"] for a in rule_alerts}
    count        = len(rule_alerts)
    has_critical = "CRITICAL" in severities
    has_high     = "HIGH" in severities

    if has_critical:
        score = min(85 + count * 2, 100)
        return "CRITICAL", score, True
    if has_high:
        score = min(55 + count * 5, 84)
        return "HIGH", score, count >= 3
    if count > 3:
        return "MEDIUM", 40 + count, False
    return "LOW", 10 + count * 6, False


_RULE_TIPS = {
    "BRUTE_FORCE":          "Block attacking IPs via the Brute Force tab.",
    "MALICIOUS_PROCESS":    "Terminate suspicious processes in the Processes tab.",
    "SUSPICIOUS_PORT":      "Investigate suspicious connections in the Network tab.",
    "PRIVILEGE_ESCALATION": "Review privilege escalation events in Windows Event Viewer.",
    "SUSPICIOUS_POWERSHELL":"Investigate PowerShell execution in Windows Security logs.",
    "NEW_ACCOUNT":          "Verify the newly created user account is authorized.",
    "HIGH_CPU":             "Identify CPU-heavy processes in the Processes tab.",
}


def _local_analysis_result(rule_alerts: list[dict], risk: str, score: int,
                            is_attack: bool, has_key: bool) -> dict:
    """Build an analysis result dict using only local data — zero API cost."""
    if not rule_alerts:
        return {
            "risk_level": "SAFE", "risk_score": 0,
            "is_attack": False, "attack_type": None,
            "summary": "System is clean. No threats detected.",
            "recommendations": ["Continue monitoring.", "Keep Windows Defender updated."],
            "ai_used": False
        }

    rules_fired   = list({a["rule"] for a in rule_alerts})
    rule_str      = ", ".join(rules_fired[:3])
    standby_note  = (" AI is in standby — enter your API key in Settings for deep analysis."
                     if not has_key else "")

    summary = (
        f"Rule engine detected {len(rule_alerts)} alert(s) "
        f"({rule_str}).{standby_note}"
    )

    # De-duplicate recommendations
    seen = set()
    recommendations = []
    for alert in rule_alerts:
        tip = _RULE_TIPS.get(alert["rule"])
        if tip and tip not in seen:
            recommendations.append(tip)
            seen.add(tip)

    return {
        "risk_level": risk, "risk_score": score,
        "is_attack": is_attack, "attack_type": None,
        "summary": summary,
        "recommendations": recommendations[:4],
        "ai_used": False
    }


def _local_remediation(rule_alerts: list[dict]) -> dict:
    """Generate remediation steps from rules alone — no AI."""
    steps = []
    step_num = 1
    for alert in rule_alerts[:5]:
        action_type = "investigate"
        target      = None
        if alert["rule"] == "MALICIOUS_PROCESS" and alert.get("pid"):
            action_type = "kill_process"
            target      = str(alert["pid"])
        elif alert["rule"] == "BRUTE_FORCE":
            action_type = "investigate"
        desc = _RULE_TIPS.get(alert["rule"], f"Investigate {alert['rule']} alert.")
        steps.append({
            "step": step_num, "action_type": action_type,
            "target": target, "description": desc,
            "priority": alert["severity"]
        })
        step_num += 1
    return {
        "threat_verdict": f"{len(rule_alerts)} rule alert(s) detected",
        "threat_level": rule_alerts[0]["severity"] if rule_alerts else "LOW",
        "remediation_steps": steps
    }


# ── AI analysis (called only for HIGH / CRITICAL) ────────────────────────────

def summarize_for_ai(logs: dict, snapshot: dict, rule_alerts: list[dict]) -> str:
    lines = ["=== SYSTEM SNAPSHOT ==="]
    stats = snapshot.get("system_stats", {})
    lines.append(f"CPU: {stats.get('cpu_percent')}%  RAM: {stats.get('ram_percent')}%")
    lines.append(f"Processes: {snapshot.get('total_processes')}  "
                 f"Connections: {snapshot.get('total_connections')}")
    lines.append(f"\n=== LOG SUMMARY ===")
    lines.append(f"Failed Logins: {len(logs.get('failed_logins', []))}")
    lines.append(f"Privilege Escalations: {len(logs.get('privilege_escalations', []))}")
    lines.append(f"PowerShell Events: {len(logs.get('powershell_events', []))}")
    if rule_alerts:
        lines.append(f"\n=== RULE ALERTS ===")
        for a in rule_alerts:
            lines.append(f"  [{a['severity']}] {a['rule']}: {a['message']}")
    return "\n".join(lines)


def analyze_with_ai(logs: dict, snapshot: dict, rule_alerts: list[dict],
                    api_key: str) -> dict:
    summary = summarize_for_ai(logs, snapshot, rule_alerts)
    prompt = f"""You are a senior cybersecurity analyst reviewing a Windows system.

{summary}

Respond ONLY in this exact JSON (no extra text):
{{
  "risk_level": "SAFE|LOW|MEDIUM|HIGH|CRITICAL",
  "risk_score": <0-100>,
  "is_attack": <true|false>,
  "attack_type": "<name or null>",
  "summary": "<2-3 sentence analysis>",
  "recommendations": ["<action 1>", "<action 2>", "<action 3>"]
}}"""
    try:
        text = call_ai(prompt, api_key).strip()
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        result = json.loads(text)
        result["ai_used"] = True
        return result
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return None   # caller will fall back to local result


def get_ai_remediation(rule_alerts: list[dict], snapshot: dict, api_key: str) -> dict:
    if not rule_alerts:
        return {"threat_verdict": "System Clean", "remediation_steps": []}

    alert_lines = [f"[{a['severity']}] {a['rule']}: {a['message']}" for a in rule_alerts[:8]]
    sus_procs   = snapshot.get("suspicious_processes", [])
    context     = "\n".join(alert_lines)
    if sus_procs:
        context += "\nSuspicious processes:\n" + "\n".join(
            f"PID {p['pid']}: {p['name']}" for p in sus_procs[:5])

    prompt = f"""You are an expert incident responder.

ALERTS:
{context}

Respond ONLY in this exact JSON:
{{
  "threat_verdict": "<one line verdict>",
  "threat_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "remediation_steps": [
    {{
      "step": 1,
      "action_type": "kill_process|block_ip|manual|investigate",
      "target": "<PID, IP, or null>",
      "description": "<clear action>",
      "priority": "HIGH|MEDIUM|LOW"
    }}
  ]
}}
Max 5 steps. Be specific."""
    try:
        text = call_ai(prompt, api_key).strip()
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text)
    except Exception as e:
        logger.error(f"Remediation AI failed: {e}")
        return _local_remediation(rule_alerts)


# ── Main entry point ──────────────────────────────────────────────────────────

def full_analysis(logs: dict, snapshot: dict) -> dict:
    """
    Full detection pipeline.

    Decision tree:
      1. Run all rules (free, always)
      2. Compute local risk score (free, always)
      3. If risk < HIGH OR no API key → return local result (zero cost, ~80% of scans)
      4. If risk >= HIGH AND key available → call AI for deep analysis
    """
    # Step 1 & 2 — rules + local scoring (always free)
    api_key_for_rules = get_effective_api_key("HIGH")   # pass key for zero-day AI scoring
    rule_alerts  = run_all_rules(logs, snapshot, api_key_for_rules)
    local_risk, local_score, local_is_attack = _local_risk_score(rule_alerts)

    # Step 3 — decide whether to use AI
    api_key = get_effective_api_key(local_risk)
    use_ai  = bool(api_key) and local_risk in ("HIGH", "CRITICAL")

    if use_ai:
        # Deep analysis via LLM
        ai_result = analyze_with_ai(logs, snapshot, rule_alerts, api_key)
        if ai_result is None:
            # AI failed — fall back to local
            ai_result = _local_analysis_result(rule_alerts, local_risk,
                                                local_score, local_is_attack,
                                                has_key=bool(api_key))
        remediation = get_ai_remediation(rule_alerts, snapshot, api_key) if rule_alerts else {}
    else:
        # Local-only result (no API cost)
        ai_result   = _local_analysis_result(rule_alerts, local_risk,
                                              local_score, local_is_attack,
                                              has_key=bool(api_key))
        remediation = _local_remediation(rule_alerts) if rule_alerts else {}

    from mitre_mapping import get_mitre_summary
    mitre_summary = get_mitre_summary(rule_alerts)

    return {
        "timestamp":        datetime.now().isoformat(),
        "rule_alerts":      rule_alerts,
        "rule_alert_count": len(rule_alerts),
        "ai_analysis":      ai_result,
        "remediation":      remediation,
        "overall_risk":     ai_result.get("risk_level", local_risk),
        "risk_score":       ai_result.get("risk_score", local_score),
        "is_attack":        ai_result.get("is_attack", local_is_attack),
        "ai_used":          ai_result.get("ai_used", False),
        "mitre":            mitre_summary,
    }
