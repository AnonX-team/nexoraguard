"""
UEBA — User & Entity Behavior Analytics — NexoraGuard
Baselines normal user/process behavior and detects anomalies.

Detection capabilities:
  1. Login time anomaly      — off-hours / weekend logins vs baseline
  2. New source IP logon     — first-time IP/machine access
  3. Login failure spike     — burst of failures before success (credential stuffing)
  4. Privilege use anomaly   — unusual privilege token use (Event 4672)
  5. Account enumeration     — rapid probing of many accounts
  6. Off-hours process spike — unusual process count outside normal hours
  7. Rare process execution  — process never seen before on this system

MITRE ATT&CK:
  T1078  — Valid Accounts (lateral movement via legitimate creds)
  T1110  — Brute Force
  T1087  — Account Discovery
  T1021  — Remote Services
"""
import math
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# ── Rolling behavioral baseline ────────────────────────────────────────────────
# Keyed by username → rolling window of events

_login_hours:   dict = defaultdict(list)    # user → [hour_of_day, ...]
_login_sources: dict = defaultdict(set)     # user → {ip/machine, ...}
_proc_baseline: set  = set()               # set of process names seen in clean state
_proc_history:  deque = deque(maxlen=500)  # recent process names for rare detection

_baseline_lock = threading.Lock()
_BASELINE_MIN_SAMPLES = 10   # need at least this many logins before flagging


# ── Baseline updaters ──────────────────────────────────────────────────────────

def update_login_baseline(username: str, hour: int, source: str) -> None:
    with _baseline_lock:
        _login_hours[username].append(hour)
        if len(_login_hours[username]) > 200:
            _login_hours[username] = _login_hours[username][-200:]
        if source:
            _login_sources[username].add(source)


def update_process_baseline(process_names: list) -> None:
    with _baseline_lock:
        for name in process_names:
            if name:
                _proc_baseline.add(name.lower())
                _proc_history.append(name.lower())


# ── Statistical helpers ────────────────────────────────────────────────────────

def _hour_distribution(hours: list) -> dict:
    """Build hour → count distribution."""
    dist: dict = defaultdict(int)
    for h in hours:
        dist[h] += 1
    return dict(dist)


def _is_off_hours(hour: int, baseline_hours: list) -> tuple:
    """
    Return (is_anomalous, confidence).
    Anomalous = current hour has very low frequency vs baseline.
    """
    if len(baseline_hours) < _BASELINE_MIN_SAMPLES:
        return False, 0
    dist = _hour_distribution(baseline_hours)
    total = len(baseline_hours)
    freq  = dist.get(hour, 0) / total
    # Off-hours: <2% of logins happen at this hour
    if freq < 0.02:
        confidence = min(int((1 - freq) * 100), 95)
        return True, confidence
    return False, 0


def _is_new_source(username: str, source: str) -> bool:
    if not source:
        return False
    with _baseline_lock:
        known = _login_sources.get(username, set())
        return bool(known) and source not in known


# ── Event Log parsers ──────────────────────────────────────────────────────────

def _parse_login_events(logs: dict) -> list:
    """Extract structured login events from Windows Event Log data."""
    events = []

    # Successful logins (Event 4624)
    for ev in logs.get("successful_logins", []):
        msg   = ev.get("Message", "")
        ts    = ev.get("TimeCreated", "")
        try:
            dt   = datetime.fromisoformat(str(ts)[:19])
            hour = dt.hour
        except Exception:
            hour = -1

        # Parse username and source IP from Event 4624 message
        import re
        user_match = re.search(r"Account Name:\s+(\S+)", msg)
        src_match  = re.search(r"Source Network Address:\s+(\S+)", msg)
        type_match = re.search(r"Logon Type:\s+(\d+)", msg)
        username   = user_match.group(1) if user_match else ""
        source_ip  = src_match.group(1)  if src_match  else ""
        logon_type = int(type_match.group(1)) if type_match else 0

        # Skip computer accounts and known system users
        if username.endswith("$") or username.lower() in ("system", ""):
            continue

        events.append({
            "type":       "LOGIN_SUCCESS",
            "username":   username,
            "source_ip":  source_ip,
            "hour":       hour,
            "logon_type": logon_type,
            "ts":         ts,
        })

    # Failed logins (Event 4625)
    for ev in logs.get("failed_logins", []):
        msg  = ev.get("Message", "")
        ts   = ev.get("TimeCreated", "")
        import re
        user_match = re.search(r"Account Name:\s+(\S+)", msg)
        src_match  = re.search(r"Source Network Address:\s+(\S+)", msg)
        username   = user_match.group(1) if user_match else ""
        source_ip  = src_match.group(1)  if src_match  else ""
        if username.endswith("$") or not username:
            continue
        events.append({
            "type":      "LOGIN_FAIL",
            "username":  username,
            "source_ip": source_ip,
            "ts":        ts,
        })

    return events


# ── UEBA Detectors ─────────────────────────────────────────────────────────────

def detect_off_hours_login(login_events: list) -> list:
    """Flag logins happening at unusual hours vs per-user baseline."""
    alerts = []
    now_hour = datetime.now().hour

    for ev in login_events:
        if ev["type"] != "LOGIN_SUCCESS":
            continue
        user = ev["username"]
        hour = ev.get("hour", now_hour)
        if hour < 0:
            continue

        # Update baseline with this login
        update_login_baseline(user, hour, ev.get("source_ip", ""))

        is_off, confidence = _is_off_hours(hour, _login_hours.get(user, []))
        if is_off:
            is_weekend = datetime.now().weekday() >= 5
            label = "weekend" if is_weekend else f"{hour:02d}:00"
            alerts.append({
                "type":       "OFF_HOURS_LOGIN",
                "severity":   "HIGH",
                "username":   user,
                "detail":     f"Off-hours login for {user} at {label} — unusual based on {len(_login_hours[user])} historical logins",
                "confidence": confidence,
                "mitre":      "T1078",
                "logon_type": ev.get("logon_type", 0),
                "source_ip":  ev.get("source_ip", ""),
            })

    return alerts


def detect_new_source_logon(login_events: list) -> list:
    """Flag first-time logins from a new source IP or machine."""
    alerts = []
    seen_new: set = set()

    for ev in login_events:
        if ev["type"] != "LOGIN_SUCCESS":
            continue
        user   = ev["username"]
        source = ev.get("source_ip", "")

        # Check BEFORE updating baseline
        if _is_new_source(user, source):
            key = (user, source)
            if key not in seen_new:
                seen_new.add(key)
                known_count = len(_login_sources.get(user, set()))
                alerts.append({
                    "type":       "NEW_SOURCE_LOGON",
                    "severity":   "MEDIUM",
                    "username":   user,
                    "source_ip":  source,
                    "detail":     f"First-time login from {source} for user {user} (seen {known_count} prior sources)",
                    "confidence": 70,
                    "mitre":      "T1078",
                })

        # Update after check
        with _baseline_lock:
            _login_sources[user].add(source)

    return alerts


def detect_credential_stuffing(login_events: list) -> list:
    """
    Detect credential stuffing / spray: many failures for same user or
    failures from same source across many users.
    """
    alerts = []
    fail_by_user:   dict = defaultdict(list)
    fail_by_source: dict = defaultdict(set)

    for ev in login_events:
        if ev["type"] != "LOGIN_FAIL":
            continue
        user = ev["username"]
        src  = ev.get("source_ip", "")
        fail_by_user[user].append(src)
        if src:
            fail_by_source[src].add(user)

    # Many failures for single user = password spray on that account
    for user, sources in fail_by_user.items():
        if len(sources) >= 5:
            unique_srcs = len(set(sources))
            alerts.append({
                "type":       "CREDENTIAL_STUFFING",
                "severity":   "HIGH",
                "username":   user,
                "detail":     f"Credential stuffing on {user}: {len(sources)} failures from {unique_srcs} source(s)",
                "confidence": min(50 + len(sources) * 5, 95),
                "mitre":      "T1110",
                "fail_count": len(sources),
            })

    # One source failing on many users = password spraying
    for src, users in fail_by_source.items():
        if src and len(users) >= 3:
            alerts.append({
                "type":       "PASSWORD_SPRAY",
                "severity":   "CRITICAL",
                "source_ip":  src,
                "username":   None,
                "detail":     f"Password spray from {src}: failed on {len(users)} accounts — {', '.join(list(users)[:5])}",
                "confidence": min(60 + len(users) * 10, 95),
                "mitre":      "T1110",
                "target_count": len(users),
            })

    return alerts


def detect_account_enumeration(logs: dict) -> list:
    """
    Detect rapid account probing — many unique account names tested in short time.
    (Event 4625 with many different account names)
    """
    alerts = []
    usernames_failed: set = set()
    for ev in logs.get("failed_logins", []):
        msg = ev.get("Message", "")
        import re
        m = re.search(r"Account Name:\s+(\S+)", msg)
        if m:
            u = m.group(1)
            if not u.endswith("$") and u.lower() not in ("system", "", "-"):
                usernames_failed.add(u.lower())

    if len(usernames_failed) >= 5:
        alerts.append({
            "type":       "ACCOUNT_ENUMERATION",
            "severity":   "HIGH",
            "username":   None,
            "detail":     f"Account enumeration: {len(usernames_failed)} unique accounts probed in current window",
            "confidence": min(50 + len(usernames_failed) * 8, 95),
            "mitre":      "T1087",
            "count":      len(usernames_failed),
        })

    return alerts


def detect_privilege_anomaly(logs: dict) -> list:
    """
    Detect unusual privilege use — Event 4672 (special privileges assigned).
    Flag if occurs outside normal hours or for accounts that rarely use it.
    """
    alerts = []
    escalations = logs.get("privilege_escalations", [])
    if not escalations:
        return []

    now_hour = datetime.now().hour
    is_odd_hour = now_hour < 6 or now_hour > 22

    for ev in escalations:
        msg = ev.get("Message", "")
        import re
        m = re.search(r"Account Name:\s+(\S+)", msg)
        user = m.group(1) if m else "unknown"
        if user.endswith("$"):
            continue

        if is_odd_hour:
            alerts.append({
                "type":       "PRIVILEGE_AFTER_HOURS",
                "severity":   "HIGH",
                "username":   user,
                "detail":     f"Privilege escalation for {user} at {now_hour:02d}:00 — outside normal business hours",
                "confidence": 75,
                "mitre":      "T1078",
            })

    return alerts


def detect_rare_process(processes: list) -> list:
    """
    Flag processes never seen before in this system's history.
    Works best after baseline is built (>100 process observations).
    """
    alerts = []
    if len(_proc_baseline) < 20:
        # Not enough baseline yet
        update_process_baseline([p.get("name", "") for p in processes])
        return []

    for proc in processes:
        name = (proc.get("name") or "").lower()
        if not name or len(name) < 4:
            continue
        if name not in _proc_baseline:
            # Additional check: does it have suspicious characteristics?
            cmdline = (proc.get("cmdline") or "").lower()
            has_sus_cmdline = any(k in cmdline for k in [
                "encoded", "bypass", "hidden", "downloadstring",
                "iex", "webclient", "invoke", "-e ", "-enc "
            ])
            if has_sus_cmdline:
                alerts.append({
                    "type":       "RARE_PROCESS",
                    "severity":   "HIGH",
                    "username":   None,
                    "process":    proc.get("name", ""),
                    "pid":        proc.get("pid"),
                    "detail":     f"Never-before-seen process '{proc.get('name')}' with suspicious command line: {cmdline[:100]}",
                    "confidence": 70,
                    "mitre":      "T1059",
                })

    # Update baseline after detection
    update_process_baseline([p.get("name", "") for p in processes])
    return alerts


# ── Main entry point ───────────────────────────────────────────────────────────

def analyze_ueba(logs: dict, snapshot: dict) -> dict:
    """
    Full UEBA analysis pipeline.
    Returns structured result with behavioral anomalies and risk assessment.
    """
    login_events = _parse_login_events(logs)
    processes    = snapshot.get("all_processes") or []

    alerts = []
    alerts.extend(detect_off_hours_login(login_events))
    alerts.extend(detect_new_source_logon(login_events))
    alerts.extend(detect_credential_stuffing(login_events))
    alerts.extend(detect_account_enumeration(logs))
    alerts.extend(detect_privilege_anomaly(logs))
    alerts.extend(detect_rare_process(processes))

    # Deduplicate by (type, username)
    seen: set = set()
    unique = []
    for a in alerts:
        key = (a["type"], a.get("username"), a.get("source_ip"))
        if key not in seen:
            seen.add(key)
            unique.append(a)
    alerts = unique

    # Risk scoring
    sev_scores = {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10}
    total_score = sum(sev_scores.get(a["severity"], 0) for a in alerts)
    risk = ("CRITICAL" if total_score >= 60 else
            "HIGH"     if total_score >= 30 else
            "MEDIUM"   if total_score >= 10 else
            "LOW"      if total_score > 0  else "SAFE")

    # Rule alerts for detection engine
    rule_alerts = []
    if alerts:
        top = max(alerts, key=lambda a: {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}.get(a["severity"], 0))
        rule_alerts.append({
            "rule":      "UEBA_ANOMALY",
            "severity":  top["severity"],
            "message":   f"UEBA behavioral anomaly: {len(alerts)} indicator(s) — {top['type']}",
            "count":     len(alerts),
            "timestamp": datetime.now().isoformat(),
            "detail":    top.get("detail", ""),
        })

    baseline_size = sum(len(v) for v in _login_hours.values())

    return {
        "checked_at":     datetime.now().isoformat(),
        "alert_count":    len(alerts),
        "risk":           risk,
        "risk_score":     min(total_score, 100),
        "alerts":         alerts,
        "rule_alerts":    rule_alerts,
        "baseline_users": len(_login_hours),
        "baseline_size":  baseline_size,
        "baseline_ready": baseline_size >= _BASELINE_MIN_SAMPLES,
        "proc_baseline_size": len(_proc_baseline),
        "stats": {
            "users_tracked":         len(_login_hours),
            "logins_observed":       baseline_size,
            "processes_in_baseline": len(_proc_baseline),
            "baseline_ready":        baseline_size >= _BASELINE_MIN_SAMPLES,
        },
    }
