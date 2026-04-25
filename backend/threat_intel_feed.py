"""
Threat Intelligence Feed — NexoraGuard
Multi-source threat intel integration (free/community tiers).

Sources:
  1. VirusTotal (file hash reputation)    — 4 lookups/min free tier
  2. GreyNoise   (IP noise/threat context) — community free API
  3. Abuse.ch MalwareBazaar (hash lookup)  — fully free
  4. Abuse.ch URLhaus (IP/domain lookup)   — fully free
  5. AbuseIPDB   (IP abuse score)          — already in threat_intel.py

All results are cached to avoid rate limit exhaustion.
Cache TTL: 1 hour for IPs, 24 hours for file hashes.

MITRE ATT&CK:
  T1105 — Ingress Tool Transfer (malware downloads)
  T1071 — Application Layer Protocol (C2 comms)
"""
import time
import logging
import hashlib
import threading
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Response cache ─────────────────────────────────────────────────────────────
_cache: dict = {}
_cache_lock  = threading.Lock()
IP_TTL_SEC   = 3600     # 1 hour
HASH_TTL_SEC = 86400    # 24 hours


def _cache_get(key: str):
    with _cache_lock:
        entry = _cache.get(key)
        if entry and time.time() < entry["expires"]:
            return entry["data"]
        return None


def _cache_set(key: str, data, ttl: int = IP_TTL_SEC):
    with _cache_lock:
        _cache[key] = {"data": data, "expires": time.time() + ttl}


# ── VirusTotal ─────────────────────────────────────────────────────────────────

def check_hash_virustotal(file_hash: str, api_key: str = "") -> dict:
    """
    Check file hash reputation via VirusTotal API v3.
    Free tier: 4 lookups/min, 500/day.
    hash can be MD5, SHA1, or SHA256.
    """
    if not api_key:
        return {"source": "virustotal", "error": "no_api_key"}

    cache_key = f"vt:{file_hash}"
    cached = _cache_get(cache_key)
    if cached:
        return {**cached, "cached": True}

    try:
        import urllib.request
        import json
        url     = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        req     = urllib.request.Request(url, headers={"x-apikey": api_key})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        attrs   = data.get("data", {}).get("attributes", {})
        stats   = attrs.get("last_analysis_stats", {})
        malicious   = stats.get("malicious", 0)
        suspicious  = stats.get("suspicious", 0)
        total       = sum(stats.values())
        name        = attrs.get("meaningful_name", file_hash[:16])

        result = {
            "source":       "virustotal",
            "hash":         file_hash,
            "name":         name,
            "malicious":    malicious,
            "suspicious":   suspicious,
            "total":        total,
            "detection_pct": round(malicious / max(total, 1) * 100, 1),
            "is_malicious": malicious >= 3,
            "verdict":      "MALICIOUS" if malicious >= 3 else ("SUSPICIOUS" if suspicious >= 2 else "CLEAN"),
            "checked_at":   datetime.now().isoformat(),
        }
        _cache_set(cache_key, result, HASH_TTL_SEC)
        return result

    except Exception as e:
        logger.debug(f"VirusTotal hash check failed for {file_hash[:16]}: {e}")
        return {"source": "virustotal", "hash": file_hash, "error": str(e)}


# ── GreyNoise ──────────────────────────────────────────────────────────────────

def check_ip_greynoise(ip: str) -> dict:
    """
    Check IP context via GreyNoise Community API (free, no key needed).
    Returns: classification (malicious/benign/unknown), name, tags.
    """
    cache_key = f"gn:{ip}"
    cached = _cache_get(cache_key)
    if cached:
        return {**cached, "cached": True}

    try:
        import urllib.request
        import json
        url  = f"https://api.greynoise.io/v3/community/{ip}"
        req  = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())

        result = {
            "source":         "greynoise",
            "ip":             ip,
            "noise":          data.get("noise", False),
            "riot":           data.get("riot", False),
            "classification": data.get("classification", "unknown"),
            "name":           data.get("name", ""),
            "link":           data.get("link", ""),
            "is_malicious":   data.get("classification") == "malicious",
            "is_benign_scanner": data.get("riot", False),
            "checked_at":     datetime.now().isoformat(),
        }
        _cache_set(cache_key, result, IP_TTL_SEC)
        return result

    except Exception as e:
        logger.debug(f"GreyNoise check failed for {ip}: {e}")
        return {"source": "greynoise", "ip": ip, "error": str(e)}


# ── Abuse.ch MalwareBazaar ─────────────────────────────────────────────────────

def check_hash_malwarebazaar(file_hash: str) -> dict:
    """
    Check file hash via Abuse.ch MalwareBazaar API (free, no key needed).
    POST-based API, supports SHA256.
    """
    cache_key = f"mb:{file_hash}"
    cached = _cache_get(cache_key)
    if cached:
        return {**cached, "cached": True}

    try:
        import urllib.request
        import urllib.parse
        import json

        if len(file_hash) != 64:
            return {"source": "malwarebazaar", "error": "sha256_required"}

        data = urllib.parse.urlencode({"query": "get_info", "hash": file_hash}).encode()
        req  = urllib.request.Request(
            "https://mb-api.abuse.ch/api/v1/",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp_data = json.loads(resp.read())

        query_status = resp_data.get("query_status", "")
        if query_status == "hash_not_found":
            result = {
                "source":       "malwarebazaar",
                "hash":         file_hash,
                "found":        False,
                "is_malicious": False,
                "verdict":      "NOT_FOUND",
                "checked_at":   datetime.now().isoformat(),
            }
        else:
            info = (resp_data.get("data") or [{}])[0]
            result = {
                "source":       "malwarebazaar",
                "hash":         file_hash,
                "found":        True,
                "is_malicious": True,
                "verdict":      "MALICIOUS",
                "malware_family": info.get("signature", ""),
                "file_type":    info.get("file_type", ""),
                "tags":         info.get("tags", []),
                "first_seen":   info.get("first_seen", ""),
                "checked_at":   datetime.now().isoformat(),
            }
        _cache_set(cache_key, result, HASH_TTL_SEC)
        return result

    except Exception as e:
        logger.debug(f"MalwareBazaar check failed for {file_hash[:16]}: {e}")
        return {"source": "malwarebazaar", "hash": file_hash, "error": str(e)}


# ── Abuse.ch URLhaus ───────────────────────────────────────────────────────────

def check_ip_urlhaus(ip: str) -> dict:
    """
    Check IP/host via Abuse.ch URLhaus API (free, no key needed).
    Returns known malicious URLs hosted on this IP.
    """
    cache_key = f"uh:{ip}"
    cached = _cache_get(cache_key)
    if cached:
        return {**cached, "cached": True}

    try:
        import urllib.request
        import urllib.parse
        import json

        data = urllib.parse.urlencode({"host": ip}).encode()
        req  = urllib.request.Request(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            resp_data = json.loads(resp.read())

        status = resp_data.get("query_status", "")
        if status == "no_results":
            result = {
                "source":       "urlhaus",
                "ip":           ip,
                "found":        False,
                "is_malicious": False,
                "checked_at":   datetime.now().isoformat(),
            }
        else:
            urls  = resp_data.get("urls", [])
            online = sum(1 for u in urls if u.get("url_status") == "online")
            result = {
                "source":       "urlhaus",
                "ip":           ip,
                "found":        True,
                "is_malicious": True,
                "url_count":    len(urls),
                "online_count": online,
                "tags":         list({tag for u in urls for tag in (u.get("tags") or [])}),
                "checked_at":   datetime.now().isoformat(),
            }
        _cache_set(cache_key, result, IP_TTL_SEC)
        return result

    except Exception as e:
        logger.debug(f"URLhaus check failed for {ip}: {e}")
        return {"source": "urlhaus", "ip": ip, "error": str(e)}


# ── Process file hash computation ──────────────────────────────────────────────

def hash_process_executable(process: dict) -> str:
    """Compute SHA256 of a process's executable file."""
    try:
        exe = process.get("exe") or ""
        if not exe or not Path(exe).exists():
            return ""
        sha256 = hashlib.sha256()
        with open(exe, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return ""


# ── Batch process intelligence ─────────────────────────────────────────────────

def check_processes_intel(processes: list, vt_api_key: str = "") -> list:
    """
    Check suspicious processes against threat intel feeds.
    Only checks processes not in system32/Program Files (reduces noise).
    Returns list of flagged processes with intel verdicts.
    """
    results = []
    SKIP_PATHS = (
        "c:\\windows\\system32",
        "c:\\windows\\syswow64",
        "c:\\program files\\",
        "c:\\program files (x86)\\",
    )

    checked = 0
    for proc in processes:
        exe = (proc.get("exe") or "").lower()
        if not exe or any(exe.startswith(skip) for skip in SKIP_PATHS):
            continue
        if checked >= 5:   # limit API calls per scan
            break

        file_hash = hash_process_executable(proc)
        if not file_hash:
            continue

        checked += 1
        intel = {
            "pid":          proc.get("pid"),
            "name":         proc.get("name"),
            "exe":          proc.get("exe"),
            "hash":         file_hash,
            "sources":      [],
            "is_malicious": False,
            "verdict":      "UNKNOWN",
        }

        # Abuse.ch MalwareBazaar (free, no key)
        mb_result = check_hash_malwarebazaar(file_hash)
        intel["sources"].append(mb_result)
        if mb_result.get("is_malicious"):
            intel["is_malicious"] = True
            intel["verdict"]      = "MALICIOUS"
            intel["family"]       = mb_result.get("malware_family", "")

        # VirusTotal (needs API key)
        if vt_api_key and not intel["is_malicious"]:
            vt_result = check_hash_virustotal(file_hash, vt_api_key)
            intel["sources"].append(vt_result)
            if vt_result.get("is_malicious"):
                intel["is_malicious"] = True
                intel["verdict"]      = "MALICIOUS"
                intel["detection_pct"] = vt_result.get("detection_pct", 0)

        if intel["is_malicious"]:
            results.append(intel)

    return results


def check_connections_intel(connections: list) -> list:
    """
    Check network connection IPs against threat intel.
    Only external IPs, max 10 per scan to respect rate limits.
    """
    results = []
    checked_ips: set = set()

    for conn in connections:
        ip = conn.get("remote_ip", "")
        if not ip or ip in ("127.0.0.1", "::1", "") or ip in checked_ips:
            continue
        # Skip private ranges
        if ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.")):
            continue
        if len(checked_ips) >= 10:
            break

        checked_ips.add(ip)
        intel: dict = {"ip": ip, "sources": [], "is_malicious": False}

        # GreyNoise (free community)
        gn = check_ip_greynoise(ip)
        intel["sources"].append(gn)
        if gn.get("is_malicious"):
            intel["is_malicious"] = True
            intel["greynoise_class"] = gn.get("classification")
            intel["greynoise_name"]  = gn.get("name", "")

        # URLhaus (free)
        uh = check_ip_urlhaus(ip)
        intel["sources"].append(uh)
        if uh.get("is_malicious"):
            intel["is_malicious"] = True
            intel["urlhaus_urls"] = uh.get("url_count", 0)

        if intel["is_malicious"]:
            results.append(intel)

    return results


# ── Main entry point ───────────────────────────────────────────────────────────

def run_threat_intel_scan(snapshot: dict, vt_api_key: str = "") -> dict:
    """
    Full threat intel scan:
    - Check suspicious process hashes against MalwareBazaar + VirusTotal
    - Check external connection IPs against GreyNoise + URLhaus
    """
    processes   = snapshot.get("all_processes") or []
    connections = snapshot.get("all_connections") or []

    # Only check processes not in whitelist paths (filter out system)
    suspicious_procs = [
        p for p in processes
        if p.get("exe")
        and not any(
            (p.get("exe") or "").lower().startswith(skip)
            for skip in ("c:\\windows\\system32", "c:\\program files\\", "c:\\windows\\syswow64")
        )
    ]

    malicious_processes   = check_processes_intel(suspicious_procs[:20], vt_api_key)
    malicious_connections = check_connections_intel(connections)

    total_malicious = len(malicious_processes) + len(malicious_connections)
    risk = "CRITICAL" if total_malicious >= 2 else "HIGH" if total_malicious == 1 else "SAFE"

    rule_alerts = []
    for mp in malicious_processes:
        rule_alerts.append({
            "rule":      "MALWARE_DETECTED",
            "severity":  "CRITICAL",
            "message":   f"Malware detected: {mp['name']} (PID {mp['pid']}) — {mp.get('family', 'Unknown family')}",
            "timestamp": datetime.now().isoformat(),
            "pid":       mp.get("pid"),
        })
    for mc in malicious_connections:
        rule_alerts.append({
            "rule":      "KNOWN_BAD_IP",
            "severity":  "HIGH",
            "message":   f"Connection to known malicious IP: {mc['ip']}",
            "timestamp": datetime.now().isoformat(),
            "ip":        mc.get("ip"),
        })

    return {
        "checked_at":           datetime.now().isoformat(),
        "risk":                 risk,
        "malicious_processes":  malicious_processes,
        "malicious_connections": malicious_connections,
        "total_malicious":      total_malicious,
        "rule_alerts":          rule_alerts,
        "cache_entries":        len(_cache),
        "sources_used":         ["malwarebazaar", "greynoise", "urlhaus"]
                                + (["virustotal"] if vt_api_key else []),
    }
