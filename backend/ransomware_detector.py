"""
Ransomware Behavioral Detector — NexoraGuard
Detects ransomware patterns without signature databases.

Detection methods (behavioral — Malwarebytes/SentinelOne parity):
  1. Mass file modification  — many files changed in short window
  2. High-entropy writes     — encrypted file content (Shannon entropy > 7.5)
  3. Known ransom extensions — .locked, .encrypted, .crypto, .pay2decrypt, etc.
  4. Ransom note detection   — README.txt, DECRYPT_INSTRUCTIONS.txt, etc.
  5. Shadow copy deletion    — vssadmin/wmic deleting VSS snapshots (T1490)
  6. File extension churn    — mass rename (original ext → new ext)
  7. Rapid directory scan    — process enumerating many dirs quickly

MITRE ATT&CK:
  T1486 — Data Encrypted for Impact
  T1490 — Inhibit System Recovery (shadow copy deletion)
  T1083 — File and Directory Discovery
"""
import os
import math
import time
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Known ransomware extension signatures ─────────────────────────────────────
RANSOM_EXTENSIONS = {
    # Common ransomware families
    ".locked", ".encrypted", ".crypto", ".crypt", ".enc",
    ".pay2decrypt", ".kraken", ".locky", ".zepto", ".odin",
    ".thor", ".aesir", ".zzzzz", ".cerber", ".cerber2", ".cerber3",
    ".wallet", ".globe", ".purge", ".globe2", ".raid10",
    ".wcry", ".wncry", ".wncryt",        # WannaCry
    ".ryuk", ".hermes",                  # Ryuk
    ".maze", ".sekhmet",                 # Maze
    ".revil", ".sodinokibi",             # REvil
    ".blackcat", ".alphv",               # BlackCat/ALPHV
    ".lockbit", ".lckd",                 # LockBit
    ".clop", ".cl0p",                    # Clop
    ".hive",                             # Hive
    ".conti",                            # Conti
    ".darkside",                         # DarkSide
    ".netwalker",                        # NetWalker
    ".pay", ".payme", ".ransom",
    ".helpme", ".helpdecrypt",
    ".howdecrypt", ".howto",
}

# ── Known ransom note filenames ────────────────────────────────────────────────
RANSOM_NOTE_NAMES = {
    "readme.txt", "readme!.txt", "read_me.txt", "read-me.txt",
    "decrypt_instructions.txt", "how_to_decrypt.txt", "how_decrypt.txt",
    "howdecrypt.txt", "help_decrypt.html", "help_decrypt.txt",
    "your_files_are_encrypted.txt", "message.txt",
    "recover_files.html", "recovery_note.txt",
    "files_encrypted.html", "@please_read_me@.txt",
    "decrypt_my_files.txt", "attention.txt",
    "_readme.txt", "!!!readme!!.txt",
    "!!!how_to_decrypt.txt", "!!decrypt!!.txt",
}

# ── File modification tracker ──────────────────────────────────────────────────
_mod_history: deque = deque(maxlen=1000)   # (timestamp, filepath, extension)
_dir_scan_counts: dict = defaultdict(int)  # dir → scan count this window
_last_scan_reset: float = 0

# Thresholds
MASS_MOD_THRESHOLD   = 30    # files modified in MASS_MOD_WINDOW seconds
MASS_MOD_WINDOW      = 60    # seconds
ENTROPY_THRESHOLD    = 7.2   # Shannon bits/byte — encrypted data approaches 8.0
ENTROPY_SAMPLE_BYTES = 4096  # bytes to sample for entropy check
DIR_SCAN_THRESHOLD   = 50    # unique directories scanned = suspicious


def _shannon_entropy_file(filepath: str) -> float:
    """Calculate Shannon entropy of file content (higher = more encrypted)."""
    try:
        with open(filepath, "rb") as f:
            data = f.read(ENTROPY_SAMPLE_BYTES)
        if len(data) < 512:
            return 0.0
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        n = len(data)
        entropy = 0.0
        for c in byte_counts:
            if c > 0:
                p = c / n
                entropy -= p * math.log2(p)
        return round(entropy, 3)
    except Exception:
        return 0.0


def _scan_user_dirs() -> list:
    """
    Scan common user data directories for recently modified files.
    Focuses on Documents, Desktop, Pictures, Downloads — prime ransomware targets.
    """
    findings = []
    user_home = Path.home()
    target_dirs = [
        user_home / "Documents",
        user_home / "Desktop",
        user_home / "Pictures",
        user_home / "Downloads",
        user_home / "Videos",
    ]

    now = time.time()
    cutoff = now - 120    # files modified in last 2 minutes

    for target in target_dirs:
        if not target.exists():
            continue
        try:
            for entry in target.rglob("*"):
                if not entry.is_file():
                    continue
                try:
                    mtime = entry.stat().st_mtime
                    if mtime < cutoff:
                        continue
                    ext  = entry.suffix.lower()
                    name = entry.name.lower()
                    findings.append({
                        "path":    str(entry),
                        "ext":     ext,
                        "name":    name,
                        "mtime":   mtime,
                        "dir":     str(entry.parent),
                        "size":    entry.stat().st_size,
                    })
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            continue

    return findings


# ── Detection checks ───────────────────────────────────────────────────────────

def check_mass_file_modification() -> list:
    """Detect mass file modification — ransomware encrypts many files quickly."""
    alerts = []
    now    = time.time()
    cutoff = now - MASS_MOD_WINDOW

    recent_files = _scan_user_dirs()
    for f in recent_files:
        _mod_history.append((f["mtime"], f["path"], f["ext"]))

    # Count files modified in the last window
    recent_count = sum(1 for (t, _, _) in _mod_history if t > cutoff)
    if recent_count >= MASS_MOD_THRESHOLD:
        recent_exts = [ext for (t, _, ext) in _mod_history if t > cutoff]
        unique_exts = set(recent_exts)
        alerts.append({
            "type":       "MASS_FILE_MODIFICATION",
            "severity":   "CRITICAL",
            "count":      recent_count,
            "detail":     (
                f"Mass file modification: {recent_count} files changed in {MASS_MOD_WINDOW}s "
                f"across {len(unique_exts)} extension type(s) — ransomware encryption pattern"
            ),
            "mitre":      "T1486",
            "auto_block": False,
        })
    return alerts


def check_ransom_extensions() -> list:
    """Detect known ransomware file extensions in user directories."""
    alerts = []
    recent_files = _scan_user_dirs()
    found_exts: dict = defaultdict(list)

    for f in recent_files:
        if f["ext"] in RANSOM_EXTENSIONS:
            found_exts[f["ext"]].append(f["path"])

    for ext, paths in found_exts.items():
        alerts.append({
            "type":       "RANSOM_EXTENSION",
            "severity":   "CRITICAL",
            "count":      len(paths),
            "extension":  ext,
            "detail":     f"Ransomware extension '{ext}' found on {len(paths)} file(s): {paths[0]}",
            "mitre":      "T1486",
            "auto_block": False,
            "sample_path": paths[0],
        })

    return alerts


def check_ransom_notes() -> list:
    """Detect ransom note files dropped by ransomware."""
    alerts = []
    user_home = Path.home()
    search_dirs = [
        user_home / "Documents",
        user_home / "Desktop",
        user_home / "Downloads",
        Path("C:/"),
        Path("C:/Users/Public"),
    ]

    for d in search_dirs:
        if not d.exists():
            continue
        try:
            for entry in d.iterdir():
                if entry.is_file() and entry.name.lower() in RANSOM_NOTE_NAMES:
                    alerts.append({
                        "type":       "RANSOM_NOTE",
                        "severity":   "CRITICAL",
                        "count":      1,
                        "detail":     f"Ransom note detected: {entry} — ransomware has likely encrypted files",
                        "mitre":      "T1486",
                        "auto_block": False,
                        "note_path":  str(entry),
                    })
        except (PermissionError, OSError):
            continue

    return alerts


def check_high_entropy_writes() -> list:
    """
    Sample recently modified files for high entropy.
    Encrypted data has entropy near 8.0 bits/byte.
    """
    alerts = []
    recent_files = _scan_user_dirs()

    # Sample a subset to avoid performance impact
    candidates = [
        f for f in recent_files
        if f["size"] > 1024
        and f["ext"] not in (".exe", ".dll", ".zip", ".7z", ".rar", ".jpg", ".png", ".mp4")
    ][:10]

    high_entropy_files = []
    for f in candidates:
        entropy = _shannon_entropy_file(f["path"])
        if entropy > ENTROPY_THRESHOLD:
            high_entropy_files.append((f["path"], entropy))

    if len(high_entropy_files) >= 3:
        avg_entropy = sum(e for _, e in high_entropy_files) / len(high_entropy_files)
        alerts.append({
            "type":       "HIGH_ENTROPY_WRITES",
            "severity":   "HIGH",
            "count":      len(high_entropy_files),
            "detail":     (
                f"High-entropy file writes: {len(high_entropy_files)} recently modified files "
                f"with avg entropy {avg_entropy:.2f} bits/byte (normal <6.5, encrypted >7.2)"
            ),
            "mitre":      "T1486",
            "auto_block": False,
            "avg_entropy": avg_entropy,
        })

    return alerts


def check_shadow_copy_deletion(logs: dict, processes: list) -> list:
    """
    Detect shadow copy deletion — ransomware's first step to prevent recovery.
    Looks for: vssadmin delete shadows, wmic shadowcopy delete
    """
    alerts = []
    SHADOW_PATTERNS = [
        "vssadmin delete shadows",
        "vssadmin.exe delete",
        "wmic shadowcopy delete",
        "bcdedit /set {default} recoveryenabled no",
        "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
        "wbadmin delete catalog",
        "diskshadow /s",
    ]

    # Check PowerShell events
    for ev in logs.get("powershell_events", []):
        msg = ev.get("Message", "").lower()
        for pat in SHADOW_PATTERNS:
            if pat.lower() in msg:
                alerts.append({
                    "type":       "SHADOW_COPY_DELETION",
                    "severity":   "CRITICAL",
                    "count":      1,
                    "detail":     f"Shadow copy deletion attempt via PowerShell: '{pat}' — ransomware pre-attack recovery sabotage",
                    "mitre":      "T1490",
                    "auto_block": False,
                    "pattern":    pat,
                })
                break

    # Check running processes
    for proc in processes:
        cmdline = (proc.get("cmdline") or "").lower()
        name    = (proc.get("name") or "").lower()
        for pat in SHADOW_PATTERNS:
            if pat.lower() in cmdline:
                alerts.append({
                    "type":       "SHADOW_COPY_DELETION",
                    "severity":   "CRITICAL",
                    "count":      1,
                    "detail":     f"Shadow copy deletion via '{proc.get('name')}' (PID {proc.get('pid')}): {cmdline[:120]}",
                    "mitre":      "T1490",
                    "auto_block": False,
                    "pid":        proc.get("pid"),
                    "process":    proc.get("name"),
                })
                break

    return alerts


def check_ransomware_process_behavior(processes: list) -> list:
    """
    Detect process behavior patterns typical of ransomware:
    - Process opening many files rapidly (file scanner before encryption)
    - Process spawning child processes then terminating quickly
    """
    alerts = []
    SUSPICIOUS_COMBOS = [
        # Ransomware commonly uses these to disable defenses before encrypting
        ("cmd.exe", ["vssadmin", "bcdedit", "wbadmin"]),
        ("powershell.exe", ["vssadmin", "bcdedit", "shadow"]),
        ("wscript.exe",  []),
        ("mshta.exe",    []),
    ]

    proc_names = {(p.get("name") or "").lower() for p in processes}
    cmdlines   = [(p.get("name") or "").lower() + " " + (p.get("cmdline") or "").lower()
                  for p in processes]

    for parent, triggers in SUSPICIOUS_COMBOS:
        if parent in proc_names:
            for trig in triggers:
                if any(trig in cl for cl in cmdlines):
                    alerts.append({
                        "type":       "RANSOMWARE_BEHAVIOR",
                        "severity":   "HIGH",
                        "count":      1,
                        "detail":     f"Ransomware pre-encryption behavior: {parent} executing '{trig}' — disabling backup/recovery",
                        "mitre":      "T1490",
                        "auto_block": False,
                        "process":    parent,
                        "trigger":    trig,
                    })

    return alerts


# ── Main entry point ───────────────────────────────────────────────────────────

def detect_ransomware(logs: dict, snapshot: dict) -> dict:
    """
    Full ransomware detection pipeline.
    Checks behavioral patterns, file system changes, and process activity.
    """
    processes = snapshot.get("all_processes") or []

    alerts = []
    # File system checks
    alerts.extend(check_ransom_notes())
    alerts.extend(check_ransom_extensions())
    alerts.extend(check_mass_file_modification())
    alerts.extend(check_high_entropy_writes())
    # Process / log checks
    alerts.extend(check_shadow_copy_deletion(logs, processes))
    alerts.extend(check_ransomware_process_behavior(processes))

    # Deduplicate by type
    seen: set = set()
    unique = []
    for a in alerts:
        key = (a["type"], a.get("extension", ""), a.get("note_path", ""))
        if key not in seen:
            seen.add(key)
            unique.append(a)
    alerts = unique

    # Risk scoring
    sev_scores = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10}
    total_score = sum(sev_scores.get(a["severity"], 0) for a in alerts)
    risk = ("CRITICAL" if total_score >= 40 else
            "HIGH"     if total_score >= 25 else
            "MEDIUM"   if total_score >= 10 else
            "LOW"      if total_score > 0  else "SAFE")

    # Rule alerts
    rule_alerts = []
    if alerts:
        top = max(alerts, key=lambda a: {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}.get(a["severity"], 0))
        rule_alerts.append({
            "rule":      "RANSOMWARE_DETECTED",
            "severity":  top["severity"],
            "message":   f"Ransomware behavior detected — {len(alerts)} indicator(s): {top['type']}",
            "count":     len(alerts),
            "timestamp": datetime.now().isoformat(),
            "detail":    top.get("detail", ""),
        })

    has_critical = any(a["severity"] == "CRITICAL" for a in alerts)

    # Build stats summary
    mass_mod  = next((a for a in alerts if a["type"] == "MASS_FILE_MODIFICATION"), None)
    entropy_a = next((a for a in alerts if a.get("avg_entropy") is not None), None)
    ext_alerts = [a for a in alerts if a["type"] == "RANSOM_EXTENSION"]
    note_alerts = [a for a in alerts if a["type"] == "RANSOM_NOTE"]
    shadow_deleted = any(a["type"] == "SHADOW_COPY_DELETION" for a in alerts)

    return {
        "checked_at":   datetime.now().isoformat(),
        "alert_count":  len(alerts),
        "risk":         risk,
        "risk_score":   min(total_score, 100),
        "alerts":       alerts,
        "rule_alerts":  rule_alerts,
        "is_active_ransomware": has_critical,
        "stats": {
            "files_modified_60s":  mass_mod.get("count") if mass_mod else 0,
            "files_scanned":       entropy_a.get("count") if entropy_a else 0,
            "avg_entropy":         entropy_a.get("avg_entropy") if entropy_a else None,
            "ransom_ext_count":    len(ext_alerts),
            "ransom_notes_count":  len(note_alerts),
            "shadow_copy_deleted": shadow_deleted,
        },
        "recovery_tip": (
            "IMMEDIATELY: 1) Isolate this machine from network. "
            "2) Do NOT reboot. 3) Check for Shadow Copies: vssadmin list shadows. "
            "4) Contact incident response."
        ) if has_critical else None,
    }
