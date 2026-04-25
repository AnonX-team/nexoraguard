"""
Threat Intelligence — AbuseIPDB Integration
Checks IP reputation against AbuseIPDB free API.

Free tier: 1,000 checks/day
API key: Get free at https://www.abuseipdb.com/register

If no API key is configured, falls back to local heuristics only.
"""
import time
import logging
import requests
from config import ENV_MODE

logger = logging.getLogger(__name__)

# ── Cache ─────────────────────────────────────────────────────────────────────
_cache: dict[str, dict] = {}
CACHE_TTL   = 7200   # 2 hours (IPs don't change reputation fast)
REQUEST_TIMEOUT = 5

# ── Known malicious IP ranges / ASNs (no API needed) ─────────────────────────
# These are well-known attack infrastructure providers
KNOWN_BAD_ASNS = {
    "AS4134",   # China Telecom (frequent scanner)
    "AS4837",   # China Unicom
    "AS9009",   # M247 (bulletproof hosting)
    "AS49581",  # Ferdinand Zink (abuse)
    "AS20473",  # Choopa (common VPS abuse)
}

KNOWN_TOR_EXIT_PREFIXES = (
    # Simplified — real implementation would use Tor exit node list
    "199.249.", "185.220.", "171.25.", "162.247.",
)


def _get_abuseipdb_key() -> str:
    """Get AbuseIPDB API key from user config or env."""
    try:
        from user_config import get_api_key as _get
        # Store under a different key for AbuseIPDB (use same settings system)
        import os
        return os.environ.get("ABUSEIPDB_API_KEY", "")
    except Exception:
        return ""


def _local_heuristic(ip: str) -> dict:
    """
    Basic local threat scoring without any API call.
    Returns a lightweight reputation dict.
    """
    score = 0
    flags = []

    # Tor exit node heuristic
    if any(ip.startswith(p) for p in KNOWN_TOR_EXIT_PREFIXES):
        score += 60
        flags.append("possible_tor_exit")

    # Known bad ASN (requires additional lookup — skip for now)

    return {
        "ip":               ip,
        "abuse_score":      score,
        "total_reports":    0,
        "last_reported":    None,
        "isp":              "",
        "usage_type":       "Unknown",
        "is_tor":           "possible_tor_exit" in flags,
        "is_whitelisted":   False,
        "flags":            flags,
        "source":           "local_heuristic",
        "threat_level":     _score_to_level(score),
    }


def _score_to_level(score: int) -> str:
    if score >= 75: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 10: return "LOW"
    return "CLEAN"


def check_ip(ip: str, api_key: str = "") -> dict:
    """
    Check a single IP against AbuseIPDB.
    Falls back to local heuristics if no API key is available.
    """
    if not ip:
        return {}

    # Skip private IPs
    private_prefixes = ("127.", "10.", "192.168.", "0.", "::1")
    if any(ip.startswith(p) for p in private_prefixes):
        return {"ip": ip, "private": True, "abuse_score": 0, "threat_level": "CLEAN"}

    # Cache hit
    now = time.time()
    if ip in _cache and _cache[ip]["expires_at"] > now:
        return _cache[ip]["data"]

    key = api_key or _get_abuseipdb_key()

    if not key:
        result = _local_heuristic(ip)
        _cache[ip] = {"data": result, "expires_at": now + 600}
        return result

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        d = resp.json().get("data", {})

        score = d.get("abuseConfidenceScore", 0)
        result = {
            "ip":               ip,
            "abuse_score":      score,
            "total_reports":    d.get("totalReports", 0),
            "last_reported":    d.get("lastReportedAt", ""),
            "isp":              d.get("isp", ""),
            "usage_type":       d.get("usageType", ""),
            "is_tor":           d.get("isTor", False),
            "is_whitelisted":   d.get("isWhitelisted", False),
            "country_code":     d.get("countryCode", ""),
            "flags":            [],
            "source":           "abuseipdb",
            "threat_level":     _score_to_level(score),
        }
        if score >= 75:
            result["flags"].append("high_abuse_confidence")
        if d.get("isTor"):
            result["flags"].append("tor_exit_node")
        if d.get("usageType") in ("Data Center/Web Hosting/Transit", "VPN"):
            result["flags"].append("hosting_or_vpn")

        _cache[ip] = {"data": result, "expires_at": now + CACHE_TTL}
        return result

    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            logger.warning("AbuseIPDB rate limit hit — falling back to local heuristic")
        else:
            logger.debug(f"AbuseIPDB error for {ip}: {e}")
        result = _local_heuristic(ip)
        _cache[ip] = {"data": result, "expires_at": now + 300}
        return result
    except Exception as e:
        logger.debug(f"Threat intel lookup failed for {ip}: {e}")
        result = _local_heuristic(ip)
        _cache[ip] = {"data": result, "expires_at": now + 300}
        return result


def check_ips_batch(ips: list[str], api_key: str = "") -> dict[str, dict]:
    """Check multiple IPs, return dict ip→result."""
    results = {}
    seen = set()
    for ip in ips:
        if not ip or ip in seen:
            continue
        seen.add(ip)
        results[ip] = check_ip(ip, api_key)
    return results


def enrich_attackers_with_intel(attackers: list[dict], api_key: str = "") -> list[dict]:
    """Add threat intel to brute force attacker list."""
    ips = [a.get("ip", "") for a in attackers if a.get("ip")]
    intel_map = check_ips_batch(ips, api_key)
    for a in attackers:
        ip = a.get("ip", "")
        a["threat_intel"] = intel_map.get(ip, {})
    return attackers
