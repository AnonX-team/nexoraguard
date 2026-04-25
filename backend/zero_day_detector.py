"""
Zero-Day / Unknown Threat Detector — NexoraGuard
Uses behavioral anomaly analysis (no signatures, pure heuristics + AI).

Detection pillars:
  1. Process name entropy   — random-looking names = malware-generated (T1036)
  2. Suspicious parent-child — Office/browser spawning cmd/powershell (T1059)
  3. Living-off-the-land     — LOLBins used with suspicious cmdlines (T1218)
  4. Process hollowing hints — process with no cmdline or mismatched image (T1055)
  5. Memory anomaly          — high RAM + near-zero CPU = possible injected code
  6. Baseline deviation      — process/connection count spike vs rolling average
  7. AI scoring              — Groq LLM classifies the anomaly bundle when found

MITRE ATT&CK:
  T1036  — Masquerading
  T1055  — Process Injection
  T1059  — Command and Scripting Interpreter
  T1218  — System Binary Proxy Execution (LOLBins)
  T1106  — Native API
"""
import math
import re
import json
import time
import logging
from datetime import datetime
from collections import deque

logger = logging.getLogger(__name__)


# ── Baseline tracker ──────────────────────────────────────────────────────────
# Rolling window of the last 20 snapshots to compute "normal" baselines

_baseline_window: deque = deque(maxlen=20)   # each entry: {proc_count, conn_count, timestamp}
_baseline_lock_flag = False


def update_baseline(snapshot: dict) -> None:
    """Add current snapshot metrics to the rolling baseline window."""
    _baseline_window.append({
        "proc_count": snapshot.get("total_processes", 0),
        "conn_count":  snapshot.get("total_connections", 0),
        "cpu":         snapshot.get("system_stats", {}).get("cpu_percent", 0),
        "ram":         snapshot.get("system_stats", {}).get("ram_percent", 0),
        "ts":          time.time(),
    })


def _get_baseline_averages() -> dict:
    if len(_baseline_window) < 3:
        return {}   # not enough data yet
    entries = list(_baseline_window)
    return {
        "avg_proc": sum(e["proc_count"] for e in entries) / len(entries),
        "avg_conn": sum(e["conn_count"]  for e in entries) / len(entries),
        "avg_cpu":  sum(e["cpu"]         for e in entries) / len(entries),
        "avg_ram":  sum(e["ram"]         for e in entries) / len(entries),
    }


# ── Suspicious parent-child relationships ─────────────────────────────────────

# parent → set of children that are suspicious when spawned by that parent
SUSPICIOUS_SPAWN: dict[str, set] = {
    "winword.exe":    {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
                       "mshta.exe", "certutil.exe", "regsvr32.exe", "rundll32.exe"},
    "excel.exe":      {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
                       "mshta.exe", "certutil.exe", "regsvr32.exe", "rundll32.exe"},
    "powerpnt.exe":   {"cmd.exe", "powershell.exe", "wscript.exe", "certutil.exe"},
    "outlook.exe":    {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"},
    "chrome.exe":     {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"},
    "firefox.exe":    {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"},
    "msedge.exe":     {"cmd.exe", "powershell.exe", "wscript.exe"},
    "explorer.exe":   {"powershell.exe"},  # only flag PS from Explorer (common malware tactic)
    "svchost.exe":    {"cmd.exe", "powershell.exe"},
    "lsass.exe":      {"cmd.exe", "powershell.exe", "wscript.exe"},
    "msiexec.exe":    {"cmd.exe", "powershell.exe"},
    "mspaint.exe":    {"cmd.exe", "powershell.exe"},
    "notepad.exe":    {"cmd.exe", "powershell.exe"},
}

# LOLBins — Windows built-in tools abused for malicious purposes
LOLBINS = {
    "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "msiexec.exe",  "wmic.exe",  "cscript.exe",  "wscript.exe",
    "bitsadmin.exe","forfiles.exe","odbcconf.exe","pcalua.exe",
    "msbuild.exe",  "installutil.exe", "regasm.exe", "regsvcs.exe",
    "cmstp.exe",    "xwizard.exe", "appsyncpublishingserver.exe",
    "syncappvpublishingserver.exe", "presentationhost.exe",
}

# LOLBin trigger keywords — only flag if cmdline contains these
LOLBIN_TRIGGERS = {
    "certutil.exe":   ["urlcache", "decode", "encode", "-f ", "http", "ftp"],
    "mshta.exe":      ["http", "vbscript", "javascript", ".hta"],
    "regsvr32.exe":   ["scrobj", "/s ", "http", "/u ", "/i:"],
    "rundll32.exe":   ["javascript", "shell32", "url.dll", "advpack"],
    "msiexec.exe":    ["/q ", "http", "ftp", "/i "],
    "wmic.exe":       ["process call create", "shadowcopy delete", "os get"],
    "bitsadmin.exe":  ["/transfer", "http", "ftp"],
    "cscript.exe":    [".vbs", ".js", "http", "wscript.shell"],
    "wscript.exe":    [".vbs", ".js", "http", "wscript.shell"],
}


def _shannon_entropy(name: str) -> float:
    """Calculate Shannon entropy of a string. High entropy → random-looking."""
    if not name:
        return 0.0
    freq = {}
    for c in name:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(name)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def _is_high_entropy_name(name: str) -> bool:
    """
    Names like 'svchost.exe' have entropy ~3.1.
    Malware names like 'xkqjpvmr.exe' have entropy > 3.8.
    Only flag processes > 8 chars (exclude short legit names).
    """
    base = name.lower().replace(".exe", "").replace(".dll", "")
    if len(base) < 8:
        return False
    # Skip known good names
    KNOWN_GOOD_PREFIXES = {"service", "svchost", "system", "runtime", "windows",
                            "microsoft", "chrome", "firefox", "msedge", "update"}
    if any(base.startswith(p) for p in KNOWN_GOOD_PREFIXES):
        return False
    return _shannon_entropy(base) > 3.8


# ── Individual anomaly checkers ───────────────────────────────────────────────

def check_process_entropy(processes: list[dict]) -> list[dict]:
    """Detect processes with high-entropy names — likely malware-generated."""
    anomalies = []
    for p in processes:
        name = p.get("name", "")
        if _is_high_entropy_name(name):
            anomalies.append({
                "type":      "HIGH_ENTROPY_PROCESS",
                "severity":  "HIGH",
                "confidence": 70,
                "process":   name,
                "pid":       p.get("pid"),
                "detail":    f"Process name '{name}' has unusually high entropy ({_shannon_entropy(name.replace('.exe',''))}) — typical of malware-generated random names",
                "mitre":     "T1036",
            })
    return anomalies


def check_suspicious_spawn(processes: list[dict]) -> list[dict]:
    """Detect suspicious parent-child process relationships."""
    anomalies = []
    # Build pid→name map
    pid_name = {p["pid"]: p["name"].lower() for p in processes if p.get("pid") and p.get("name")}

    for p in processes:
        child_name  = p.get("name", "").lower()
        parent_pid  = p.get("parent_pid", 0)
        parent_name = p.get("parent_name", "").lower() or pid_name.get(parent_pid, "")

        if not parent_name:
            continue

        # Check if this child is suspicious when spawned by this parent
        suspicious_children = SUSPICIOUS_SPAWN.get(parent_name, set())
        if child_name in suspicious_children:
            anomalies.append({
                "type":       "SUSPICIOUS_SPAWN",
                "severity":   "CRITICAL",
                "confidence": 85,
                "process":    p.get("name"),
                "pid":        p.get("pid"),
                "detail":     f"Suspicious spawn: {parent_name} → {child_name} (PID {p.get('pid')}) — common macro/malware delivery pattern",
                "mitre":      "T1059",
            })
    return anomalies


def check_lolbin_abuse(processes: list[dict]) -> list[dict]:
    """Detect Living-off-the-Land Binary (LOLBin) abuse."""
    anomalies = []
    for p in processes:
        name    = p.get("name", "").lower()
        cmdline = (p.get("cmdline") or "").lower()
        if not cmdline or name not in LOLBINS:
            continue
        triggers = LOLBIN_TRIGGERS.get(name, [])
        for trigger in triggers:
            if trigger in cmdline:
                anomalies.append({
                    "type":       "LOLBIN_ABUSE",
                    "severity":   "CRITICAL",
                    "confidence": 80,
                    "process":    p.get("name"),
                    "pid":        p.get("pid"),
                    "cmdline":    cmdline[:120],
                    "detail":     f"LOLBin abuse: {p.get('name')} used with suspicious parameter '{trigger}'",
                    "mitre":      "T1218",
                })
                break
    return anomalies


def check_process_hollowing_hints(processes: list[dict]) -> list[dict]:
    """
    Heuristic detection of process hollowing:
    - Legitimate system process names with very high memory but no cmdline
    - Multiple processes with same name at unusual paths
    """
    anomalies = []
    HOLLOW_TARGETS = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
                       "explorer.exe", "spoolsv.exe", "taskhost.exe"}

    for p in processes:
        name    = p.get("name", "").lower()
        cmdline = p.get("cmdline") or ""
        mem     = p.get("memory", 0)
        cpu     = p.get("cpu", 0)

        # Suspicious: legitimate system process with no cmdline AND high memory
        if name in HOLLOW_TARGETS and not cmdline and mem > 5.0:
            anomalies.append({
                "type":       "HOLLOW_HINT",
                "severity":   "HIGH",
                "confidence": 60,
                "process":    p.get("name"),
                "pid":        p.get("pid"),
                "detail":     f"Process hollowing hint: {p.get('name')} (PID {p.get('pid')}) — no cmdline + high memory ({mem:.1f}%) — possible injected code",
                "mitre":      "T1055",
            })
    return anomalies


def check_baseline_deviation(snapshot: dict) -> list[dict]:
    """Detect sudden spikes in process/connection counts vs rolling baseline."""
    anomalies = []
    baselines = _get_baseline_averages()
    if not baselines:
        return []   # not enough history

    proc_count = snapshot.get("total_processes", 0)
    conn_count = snapshot.get("total_connections", 0)
    cpu        = snapshot.get("system_stats", {}).get("cpu_percent", 0)

    avg_proc = baselines["avg_proc"]
    avg_conn = baselines["avg_conn"]

    # Spike threshold: >40% above average (and at least 20 extra processes)
    if avg_proc > 0 and proc_count > avg_proc * 1.4 and (proc_count - avg_proc) > 20:
        anomalies.append({
            "type":       "PROCESS_SPIKE",
            "severity":   "HIGH",
            "confidence": 65,
            "process":    None,
            "pid":        None,
            "detail":     f"Process count spike: {proc_count} processes (baseline avg {avg_proc:.0f}) — {int((proc_count/avg_proc-1)*100)}% above normal",
            "mitre":      "T1106",
        })

    if avg_conn > 0 and conn_count > avg_conn * 2.0 and (conn_count - avg_conn) > 30:
        anomalies.append({
            "type":       "CONNECTION_SPIKE",
            "severity":   "HIGH",
            "confidence": 70,
            "process":    None,
            "pid":        None,
            "detail":     f"Connection spike: {conn_count} connections (baseline avg {avg_conn:.0f}) — may indicate C2 or DDoS",
            "mitre":      "T1071",
        })

    return anomalies


def check_memory_anomaly(processes: list[dict]) -> list[dict]:
    """Detect processes with high memory but near-zero CPU — injection marker."""
    anomalies = []
    for p in processes:
        mem = p.get("memory", 0)
        cpu = p.get("cpu", 0)
        name = p.get("name", "")
        # Skip known heavy apps
        EXCLUDE = {"chrome.exe", "firefox.exe", "msedge.exe", "explorer.exe",
                   "code.exe", "devenv.exe", "idea64.exe", "slack.exe", "teams.exe",
                   "outlook.exe", "excel.exe", "winword.exe", "photoshop.exe"}
        if name.lower() in EXCLUDE:
            continue
        # High mem (>8%) + nearly zero CPU (<0.1%) in a background process
        if mem > 8.0 and cpu < 0.1 and name.lower() not in {"system", "smss.exe"}:
            anomalies.append({
                "type":       "MEMORY_ANOMALY",
                "severity":   "MEDIUM",
                "confidence": 55,
                "process":    name,
                "pid":        p.get("pid"),
                "detail":     f"Memory anomaly: {name} (PID {p.get('pid')}) uses {mem:.1f}% RAM but {cpu}% CPU — may indicate injected/dormant code",
                "mitre":      "T1055",
            })
    return anomalies[:3]   # cap to avoid noise


# ── AI scoring ────────────────────────────────────────────────────────────────

def ai_score_anomalies(anomalies: list[dict], api_key: str) -> dict | None:
    """
    Ask Groq LLM to classify the behavioral anomaly bundle.
    Only called when anomalies are found (cost control).
    """
    if not api_key or not anomalies:
        return None
    try:
        from detection_engine import call_ai
        anomaly_text = "\n".join(
            f"- [{a['severity']}] {a['type']}: {a['detail']}" for a in anomalies[:6]
        )
        prompt = f"""You are an expert malware analyst.
Behavioral anomalies detected on a Windows system:

{anomaly_text}

Assess if this looks like a zero-day attack, APT, or benign false positive.
Respond ONLY in this exact JSON (no extra text):
{{
  "verdict": "ZERO_DAY|SUSPICIOUS|LIKELY_FALSE_POSITIVE",
  "confidence": <0-100>,
  "attack_family": "<malware type or null>",
  "summary": "<2 sentence analysis>",
  "immediate_action": "<single most important action>"
}}"""
        text = call_ai(prompt, api_key).strip()
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"): text = text[4:]
        return json.loads(text)
    except Exception as e:
        logger.error(f"Zero-day AI scoring failed: {e}")
        return None


# ── Main entry point ──────────────────────────────────────────────────────────

_last_zd_check: float = 0
_zd_cooldown: float   = 60   # minimum seconds between full checks


def detect_zero_day(snapshot: dict, api_key: str = "") -> dict:
    """
    Full zero-day behavioral analysis.
    Returns a structured result dict with anomalies + AI verdict.
    """
    global _last_zd_check

    processes = snapshot.get("suspicious_processes", [])
    # For richer analysis, use all processes if available
    all_procs = snapshot.get("all_processes") or processes

    # Update baseline for drift detection
    update_baseline(snapshot)

    anomalies = []
    anomalies.extend(check_process_entropy(all_procs))
    anomalies.extend(check_suspicious_spawn(all_procs))
    anomalies.extend(check_lolbin_abuse(all_procs))
    anomalies.extend(check_process_hollowing_hints(all_procs))
    anomalies.extend(check_baseline_deviation(snapshot))
    anomalies.extend(check_memory_anomaly(all_procs))

    # Deduplicate by (type, pid)
    seen_keys = set()
    unique = []
    for a in anomalies:
        key = (a["type"], a.get("pid"))
        if key not in seen_keys:
            seen_keys.add(key)
            unique.append(a)
    anomalies = unique

    # Severity score
    sev_score = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    total_score = sum(sev_score.get(a["severity"], 0) for a in anomalies)
    risk = ("CRITICAL" if total_score >= 60 else
            "HIGH"     if total_score >= 30 else
            "MEDIUM"   if total_score >= 10 else
            "LOW"      if total_score > 0  else "SAFE")

    # AI scoring — only when anomalies found and enough time since last check
    ai_verdict = None
    now = time.time()
    if anomalies and api_key and (now - _last_zd_check) > _zd_cooldown:
        ai_verdict = ai_score_anomalies(anomalies, api_key)
        _last_zd_check = now

    # Final zero-day alert for rule engine integration
    rule_alerts = []
    if anomalies:
        top = max(anomalies, key=lambda a: {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}.get(a["severity"],0))
        rule_alerts.append({
            "rule":      "ZERO_DAY_ANOMALY",
            "severity":  top["severity"],
            "message":   f"{len(anomalies)} behavioral anomaly(ies) detected — possible zero-day activity",
            "count":     len(anomalies),
            "timestamp": datetime.now().isoformat(),
            "detail":    top["detail"],
            "mitre_id":  top.get("mitre", "T1036"),
        })
        if any(a["type"] == "SUSPICIOUS_SPAWN" for a in anomalies):
            rule_alerts.append({
                "rule":      "PROCESS_INJECTION",
                "severity":  "CRITICAL",
                "message":   "Suspicious process spawn pattern — possible macro or fileless attack",
                "timestamp": datetime.now().isoformat(),
                "mitre_id":  "T1059",
            })

    return {
        "checked_at":    datetime.now().isoformat(),
        "anomaly_count": len(anomalies),
        "risk":          risk,
        "risk_score":    min(total_score, 100),
        "anomalies":     anomalies,
        "ai_verdict":    ai_verdict,
        "rule_alerts":   rule_alerts,
        "baseline_ready": len(_baseline_window) >= 3,
        "baseline_samples": len(_baseline_window),
    }
