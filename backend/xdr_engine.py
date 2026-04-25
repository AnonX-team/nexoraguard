"""
XDR Correlation Engine — NexoraGuard
Unifies EDR (endpoint) + NDR (network) alerts into correlated security incidents.

How it works:
  1. Collects alerts from ALL detectors (rules, UEBA, ransomware, lateral, DDoS, vulns, intel)
  2. Normalizes them to a standard alert format
  3. Groups into INCIDENTS by shared entity (source IP / username) within a 5-min window
  4. Scores each incident by severity, sensor coverage, and kill chain stage
  5. Returns ranked incident list ready for dashboard and playbook engine

Incident structure:
  {
    incident_id, title, risk, score,
    source_ip, username,
    first_seen, last_seen, duration_s,
    alert_count, sensors_triggered,
    alerts[],  stages[], highest_stage,
    edr_count, ndr_count,         ← EDR vs NDR split
    confidence, status
  }
"""
import hashlib
import logging
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
CORRELATION_WINDOW_S = 300      # 5 minutes — alerts within this window get correlated
MAX_INCIDENTS        = 100      # keep last N incidents in memory
MIN_ALERTS_INCIDENT  = 2        # need at least 2 alerts to form a multi-sensor incident

# ── In-memory incident store ──────────────────────────────────────────────────
_incidents: list = []
_incident_seq: int = 0

# Severity weights for scoring
_SEV = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 5, "INFO": 1}

# Which rules/types come from EDR vs NDR
_EDR_SOURCES = {
    "SUSPICIOUS_POWERSHELL", "SUSPICIOUS_SPAWN", "MALICIOUS_PROCESS",
    "NEW_ACCOUNT", "SCHEDULED_TASK", "SERVICE_INSTALL", "LOG_CLEARED",
    "FILE_MODIFIED", "HIGH_CPU", "PRIVILEGE_ESCALATION", "BRUTE_FORCE",
    "ACCOUNT_LOCKOUT", "ZERO_DAY_ANOMALY", "PROCESS_INJECTION", "LOLBIN_ABUSE",
    "USB_DEVICE", "EXPLICIT_LOGON", "REMOTE_LOGON",
    # UEBA types
    "OFF_HOURS_LOGIN", "NEW_SOURCE_LOGON", "CREDENTIAL_STUFFING",
    "PASSWORD_SPRAY", "ACCOUNT_ENUMERATION", "PRIVILEGE_ANOMALY", "RARE_PROCESS",
    # Ransomware types
    "MASS_FILE_MODIFICATION", "RANSOM_EXTENSION", "RANSOM_NOTE",
    "HIGH_ENTROPY_WRITE", "SHADOW_COPY_DELETION",
    # Lateral movement types
    "RDP_EXTERNAL", "RDP_NEW_SOURCE", "SMB_LATERAL_SPREAD", "ADMIN_SHARE_ACCESS",
    "WINRM_EXTERNAL", "WINRM_INTERNAL", "PASS_THE_HASH", "REMOTE_SERVICE_INSTALL",
    # Vulnerability types
    "EOL_SOFTWARE", "PATCH_CRITICAL", "PATCH_OVERDUE", "WEAK_CONFIG",
    "ADMIN_SHARE_EXPOSED", "REMOTE_REGISTRY", "WINRM_ENABLED",
}

_NDR_SOURCES = {
    "DDOS_ATTACK", "AMPLIFICATION_ATTACK", "HTTP_FLOOD", "SLOWLORIS",
    "PORT_SCAN", "SUSPICIOUS_PORT", "KNOWN_BAD_IP",
    "TCP_SYN_FLOOD", "UDP_FLOOD", "DNS_AMPLIFICATION", "NTP_AMPLIFICATION",
    "SSDP_AMPLIFICATION", "MEMCACHED_AMP", "CARPET_BOMBING", "IOT_BOTNET",
    "BANDWIDTH_SPIKE", "ENTROPY_FLOOD",
}

# Tactic → stage index (for kill chain ordering)
_TACTIC_INDEX = {
    "Initial Access": 0, "Execution": 1, "Persistence": 2,
    "Privilege Escalation": 3, "Defense Evasion": 4, "Credential Access": 5,
    "Discovery": 6, "Lateral Movement": 7, "Collection": 8,
    "Command and Control": 9, "Exfiltration": 10, "Impact": 11,
}

from kill_chain_tracker import RULE_TO_TACTIC, TYPE_TO_TACTIC


# ── Alert normalizer ──────────────────────────────────────────────────────────

def _normalize(alert: dict, source_tag: str = "rule") -> dict:
    """
    Normalize any alert (rule alert, UEBA alert, DDoS alert, etc.)
    to a standard dict used by the correlation engine.
    """
    rule    = str(alert.get("rule",    "")).upper()
    atype   = str(alert.get("type",    "")).upper()
    key     = rule or atype or "UNKNOWN"

    # Tactic from MITRE enrichment or fallback lookup
    mitre   = alert.get("mitre") or {}
    tactic  = (mitre.get("tactic") if isinstance(mitre, dict) else None) or \
               RULE_TO_TACTIC.get(rule) or \
               TYPE_TO_TACTIC.get(atype) or "Unknown"

    technique = (mitre.get("technique") if isinstance(mitre, dict) else None) or \
                 alert.get("mitre", "—") if isinstance(alert.get("mitre"), str) else "—"

    sev      = str(alert.get("severity", "LOW")).upper()
    src_ip   = alert.get("source_ip") or alert.get("src_ip") or ""
    username = alert.get("username") or alert.get("user") or ""
    detail   = alert.get("detail") or alert.get("message") or alert.get("desc") or ""
    ts       = alert.get("timestamp") or alert.get("checked_at") or datetime.now().isoformat()

    # Classify as EDR or NDR
    sensor_type = "NDR" if key in _NDR_SOURCES else "EDR"

    return {
        "key":         key,
        "rule":        rule or atype,
        "tactic":      tactic,
        "technique":   technique,
        "severity":    sev,
        "score":       _SEV.get(sev, 5),
        "source_ip":   src_ip,
        "username":    username,
        "detail":      detail[:200],
        "timestamp":   ts,
        "sensor_type": sensor_type,
        "source_tag":  source_tag,
    }


# ── Correlation logic ─────────────────────────────────────────────────────────

def _entity_key(alert: dict) -> list:
    """
    Return list of entity keys for grouping.
    An alert can match by source_ip OR by username.
    """
    keys = []
    if alert.get("source_ip"):
        keys.append("ip:" + alert["source_ip"])
    if alert.get("username"):
        keys.append("user:" + alert["username"].lower())
    if not keys:
        keys.append("unknown")
    return keys


def _incident_id(alerts: list) -> str:
    """Stable short ID based on alert keys and first timestamp."""
    raw = "|".join(sorted(a["key"] for a in alerts)) + (alerts[0]["timestamp"] if alerts else "")
    return "INC-" + hashlib.md5(raw.encode()).hexdigest()[:8].upper()


def correlate_alerts(all_alerts_raw: list) -> list:
    """
    Main correlation function.
    Takes raw alert dicts from any source, returns correlated incident list.
    """
    global _incidents, _incident_seq

    if not all_alerts_raw:
        return []

    # Normalize all alerts
    normalized = [_normalize(a) for a in all_alerts_raw]

    # Group by entity within time window
    entity_groups: dict = defaultdict(list)
    for alert in normalized:
        for ek in _entity_key(alert):
            entity_groups[ek].append(alert)

    # Merge overlapping entity groups → incident candidates
    # (alerts that share ANY entity get merged into one incident)
    merged_groups = _merge_entity_groups(entity_groups, normalized)

    # Build incident objects
    new_incidents = []
    for group in merged_groups:
        if not group:
            continue

        # Sort by time
        group_sorted = sorted(group, key=lambda a: a["timestamp"])
        first_ts = group_sorted[0]["timestamp"]
        last_ts  = group_sorted[-1]["timestamp"]

        # Duration
        try:
            dt_first = datetime.fromisoformat(first_ts)
            dt_last  = datetime.fromisoformat(last_ts)
            duration_s = int((dt_last - dt_first).total_seconds())
        except Exception:
            duration_s = 0

        # Source entities
        source_ips = list({a["source_ip"] for a in group if a["source_ip"]})
        usernames  = list({a["username"]  for a in group if a["username"]})

        # EDR vs NDR split
        edr_alerts = [a for a in group if a["sensor_type"] == "EDR"]
        ndr_alerts = [a for a in group if a["sensor_type"] == "NDR"]

        # Tactics seen
        tactics = list({a["tactic"] for a in group if a["tactic"] != "Unknown"})
        tactic_indices = [_TACTIC_INDEX.get(t, -1) for t in tactics]
        highest_idx = max(tactic_indices) if tactic_indices else -1
        highest_stage = next(
            (t for t, i in _TACTIC_INDEX.items() if i == highest_idx), None
        )

        # Score
        total_score = sum(a["score"] for a in group)
        sensor_bonus = 20 if (edr_alerts and ndr_alerts) else 0  # cross-sensor bonus
        total_score += sensor_bonus

        risk = ("CRITICAL" if total_score >= 60 else
                "HIGH"     if total_score >= 30 else
                "MEDIUM"   if total_score >= 15 else
                "LOW"      if total_score > 0  else "INFO")

        # Confidence: more sensors + more alerts = higher confidence
        sensors_triggered = len({a["source_tag"] for a in group})
        unique_rules = len({a["rule"] for a in group})
        if unique_rules >= 5 or (edr_alerts and ndr_alerts and unique_rules >= 3):
            confidence = "HIGH"
        elif unique_rules >= 3 or sensors_triggered >= 2:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        # Title
        title = _generate_title(group, highest_stage, edr_alerts, ndr_alerts)

        _incident_seq += 1
        incident = {
            "incident_id":       _incident_id(group_sorted),
            "seq":               _incident_seq,
            "title":             title,
            "risk":              risk,
            "score":             min(total_score, 100),
            "confidence":        confidence,
            "status":            "ACTIVE",
            "source_ips":        source_ips[:5],
            "primary_ip":        source_ips[0] if source_ips else None,
            "usernames":         usernames[:3],
            "first_seen":        first_ts,
            "last_seen":         last_ts,
            "duration_s":        duration_s,
            "alert_count":       len(group),
            "edr_count":         len(edr_alerts),
            "ndr_count":         len(ndr_alerts),
            "sensors_triggered": sensors_triggered,
            "unique_rules":      unique_rules,
            "stages":            tactics,
            "highest_stage":     highest_stage,
            "alerts":            group_sorted[:20],
            "is_cross_sensor":   bool(edr_alerts and ndr_alerts),
        }
        new_incidents.append(incident)

    # Sort by score (highest first)
    new_incidents.sort(key=lambda i: i["score"], reverse=True)

    # Merge with stored incidents (replace by incident_id)
    stored_ids = {i["incident_id"] for i in _incidents}
    for inc in new_incidents:
        if inc["incident_id"] not in stored_ids:
            _incidents.append(inc)
        else:
            # Update existing
            for j, existing in enumerate(_incidents):
                if existing["incident_id"] == inc["incident_id"]:
                    _incidents[j] = inc
                    break

    # Trim to MAX_INCIDENTS
    _incidents = sorted(_incidents, key=lambda i: i["score"], reverse=True)[:MAX_INCIDENTS]

    return _incidents


def _merge_entity_groups(entity_groups: dict, all_alerts: list) -> list:
    """
    Merge entity groups that share alerts (union-find style).
    Returns list of alert-lists (each = one incident candidate).
    """
    # Build a mapping: alert index → entity keys
    alert_to_entities: dict = defaultdict(set)
    entity_to_alerts: dict = defaultdict(set)

    for i, alert in enumerate(all_alerts):
        for ek in _entity_key(alert):
            alert_to_entities[i].add(ek)
            entity_to_alerts[ek].add(i)

    # Union-find to merge alerts that share an entity
    parent = list(range(len(all_alerts)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        px, py = find(x), find(y)
        if px != py:
            parent[px] = py

    for ek, indices in entity_to_alerts.items():
        idxs = list(indices)
        for j in range(1, len(idxs)):
            union(idxs[0], idxs[j])

    # Group by root
    groups: dict = defaultdict(list)
    for i, alert in enumerate(all_alerts):
        groups[find(i)].append(alert)

    return list(groups.values())


def _generate_title(alerts: list, highest_stage: str | None,
                    edr_alerts: list, ndr_alerts: list) -> str:
    """Generate a human-readable incident title."""
    rule_counts: dict = defaultdict(int)
    for a in alerts:
        rule_counts[a["rule"]] += 1

    top_rule = max(rule_counts, key=rule_counts.get) if rule_counts else "UNKNOWN"

    if edr_alerts and ndr_alerts:
        prefix = "Cross-Domain"
    elif edr_alerts:
        prefix = "Endpoint"
    else:
        prefix = "Network"

    stage_label = f" — {highest_stage}" if highest_stage else ""

    rule_label = top_rule.replace("_", " ").title()
    return f"{prefix} Attack{stage_label}: {rule_label} + {len(alerts)} indicator(s)"


# ── Public API ────────────────────────────────────────────────────────────────

def get_xdr_summary() -> dict:
    """Return summary stats for the XDR overview KPI cards."""
    active  = [i for i in _incidents if i["status"] == "ACTIVE"]
    cross   = [i for i in active if i["is_cross_sensor"]]
    crit    = [i for i in active if i["risk"] == "CRITICAL"]
    return {
        "total_incidents":        len(_incidents),
        "active_incidents":       len(active),
        "cross_sensor_incidents": len(cross),
        "critical_incidents":     len(crit),
    }


def close_incident(incident_id: str) -> bool:
    """Mark an incident as closed."""
    for i, inc in enumerate(_incidents):
        if inc["incident_id"] == incident_id:
            _incidents[i]["status"] = "CLOSED"
            return True
    return False


def get_incidents(status: str = "ALL") -> list:
    """Return incidents filtered by status."""
    if status == "ALL":
        return _incidents
    return [i for i in _incidents if i["status"] == status]
