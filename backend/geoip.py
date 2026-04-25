"""
GeoIP Lookup — Country, City, ISP for IP addresses
Uses ip-api.com free tier (no API key needed, 45 req/min limit).
Results are cached in-memory (TTL: 1 hour) to stay within rate limits.
"""
import time
import logging
import requests
from functools import lru_cache

logger = logging.getLogger(__name__)

# ── In-memory cache (ip → {result, expires_at}) ───────────────────────────────
_cache: dict[str, dict] = {}
CACHE_TTL = 3600   # 1 hour
REQUEST_TIMEOUT = 4  # seconds

# IPs to skip (private/loopback/link-local)
SKIP_PREFIXES = (
    "127.", "0.", "10.", "192.168.", "::1", "fc", "fd",
    "169.254.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.",
)

# Country → flag emoji mapping (common countries)
COUNTRY_FLAGS: dict[str, str] = {
    "US": "🇺🇸", "CN": "🇨🇳", "RU": "🇷🇺", "DE": "🇩🇪", "GB": "🇬🇧",
    "FR": "🇫🇷", "JP": "🇯🇵", "KR": "🇰🇷", "IN": "🇮🇳", "BR": "🇧🇷",
    "CA": "🇨🇦", "AU": "🇦🇺", "NL": "🇳🇱", "SG": "🇸🇬", "HK": "🇭🇰",
    "PK": "🇵🇰", "TR": "🇹🇷", "UA": "🇺🇦", "IR": "🇮🇷", "SA": "🇸🇦",
    "IT": "🇮🇹", "ES": "🇪🇸", "PL": "🇵🇱", "SE": "🇸🇪", "NO": "🇳🇴",
    "FI": "🇫🇮", "CH": "🇨🇭", "AT": "🇦🇹", "BE": "🇧🇪", "CZ": "🇨🇿",
    "MX": "🇲🇽", "AR": "🇦🇷", "ZA": "🇿🇦", "NG": "🇳🇬", "EG": "🇪🇬",
    "TH": "🇹🇭", "VN": "🇻🇳", "ID": "🇮🇩", "MY": "🇲🇾", "PH": "🇵🇭",
    "IL": "🇮🇱", "AE": "🇦🇪", "BD": "🇧🇩", "RO": "🇷🇴", "HU": "🇭🇺",
}

# High-risk countries for threat context (not blocking, just context)
HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "BY", "SY"}


def _is_private(ip: str) -> bool:
    """Return True if IP is private/loopback and should not be looked up."""
    if not ip:
        return True
    return any(ip.startswith(p) for p in SKIP_PREFIXES)


def lookup(ip: str) -> dict:
    """
    Look up GeoIP data for a single IP.
    Returns a dict with: country, country_code, city, isp, flag, risk_hint.
    Returns empty dict for private IPs or on failure.
    """
    if _is_private(ip):
        return {"private": True, "flag": "🏠", "country": "Local", "city": "", "isp": ""}

    # Check cache
    now = time.time()
    if ip in _cache and _cache[ip]["expires_at"] > now:
        return _cache[ip]["data"]

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,city,isp,org,as,query"},
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") == "success":
            cc = data.get("countryCode", "")
            result = {
                "ip":           ip,
                "country":      data.get("country", "Unknown"),
                "country_code": cc,
                "city":         data.get("city", ""),
                "isp":          data.get("isp", data.get("org", "")),
                "flag":         COUNTRY_FLAGS.get(cc, "🌍"),
                "high_risk":    cc in HIGH_RISK_COUNTRIES,
                "private":      False,
            }
        else:
            result = {"ip": ip, "country": "Unknown", "country_code": "", "city": "",
                      "isp": "", "flag": "🌍", "high_risk": False, "private": False}

        _cache[ip] = {"data": result, "expires_at": now + CACHE_TTL}
        return result

    except Exception as e:
        logger.debug(f"GeoIP lookup failed for {ip}: {e}")
        result = {"ip": ip, "country": "Unknown", "country_code": "", "city": "",
                  "isp": "", "flag": "🌍", "high_risk": False, "private": False, "error": True}
        # Cache failures briefly (5 min) to avoid hammering the API
        _cache[ip] = {"data": result, "expires_at": now + 300}
        return result


def lookup_batch(ips: list[str]) -> dict[str, dict]:
    """Look up multiple IPs, return dict ip→result. Skips duplicates and private IPs."""
    results = {}
    seen = set()
    for ip in ips:
        if not ip or ip in seen:
            continue
        seen.add(ip)
        results[ip] = lookup(ip)
    return results


def enrich_connections_with_geo(connections: list[dict]) -> list[dict]:
    """Add 'geo' field to each connection entry using remote_ip."""
    ips = [c.get("remote_ip", "") for c in connections if c.get("remote_ip")]
    geo_map = lookup_batch(ips)
    for conn in connections:
        rip = conn.get("remote_ip", "")
        conn["geo"] = geo_map.get(rip, {}) if rip else {}
    return connections


def enrich_brute_force_with_geo(bf_result: dict) -> dict:
    """Add geo data to brute force attacker IPs."""
    attackers = bf_result.get("attackers", [])
    ips = [a.get("ip", "") for a in attackers if a.get("ip")]
    geo_map = lookup_batch(ips)
    for a in attackers:
        ip = a.get("ip", "")
        a["geo"] = geo_map.get(ip, {})
    return bf_result
