"""
NexoraGuard — Endpoints Manager
Tracks all connected remote agents (multi-machine support).
"""
import time
from datetime import datetime
from typing import Dict, Any

# ── In-memory store ────────────────────────────────────────────────────────────
_endpoints: Dict[str, dict] = {}

# Endpoint is "offline" if no report received in this many seconds
_OFFLINE_THRESHOLD = 90

# ── Agent Secret (shared between server and all agents) ────────────────────��──
AGENT_SECRET = "nexora-agent-key-2024"


def update_endpoint(endpoint_id: str, data: dict):
    """Called when an agent POSTs a report. Updates or creates endpoint entry."""
    now = time.time()
    existing = _endpoints.get(endpoint_id, {})

    # Compute risk from alerts
    alerts = data.get("alerts", [])
    risk = _compute_risk(alerts)

    _endpoints[endpoint_id] = {
        "id":           endpoint_id,
        "hostname":     data.get("hostname", endpoint_id),
        "ip":           data.get("ip", "unknown"),
        "os":           data.get("os", "Windows"),
        "cpu":          data.get("cpu", 0),
        "ram":          data.get("ram", 0),
        "disk":         data.get("disk", 0),
        "processes":    data.get("processes", []),
        "connections":  data.get("connections", []),
        "alerts":       alerts,
        "alert_count":  len(alerts),
        "risk":         risk,
        "last_seen":    now,
        "last_seen_str": datetime.fromtimestamp(now).strftime("%H:%M:%S"),
        "online":       True,
        "agent_version": data.get("agent_version", "1.0"),
        "first_seen":   existing.get("first_seen", now),
    }


def get_all_endpoints() -> list:
    """Return all endpoints, marking stale ones as offline."""
    now = time.time()
    result = []
    for ep in _endpoints.values():
        ep = dict(ep)
        ep["online"] = (now - ep["last_seen"]) < _OFFLINE_THRESHOLD
        ep["seconds_ago"] = int(now - ep["last_seen"])
        # Don't send full process list in summary view
        ep.pop("processes", None)
        ep.pop("connections", None)
        result.append(ep)
    # Sort: online first, then by risk
    result.sort(key=lambda x: (not x["online"], _risk_order(x["risk"])))
    return result


def get_endpoint(endpoint_id: str) -> dict | None:
    """Get full details of a single endpoint."""
    ep = _endpoints.get(endpoint_id)
    if not ep:
        return None
    ep = dict(ep)
    now = time.time()
    ep["online"] = (now - ep["last_seen"]) < _OFFLINE_THRESHOLD
    ep["seconds_ago"] = int(now - ep["last_seen"])
    return ep


def get_endpoint_alerts(endpoint_id: str) -> list:
    ep = _endpoints.get(endpoint_id)
    if not ep:
        return []
    return ep.get("alerts", [])


def get_summary() -> dict:
    """Dashboard summary stats."""
    now = time.time()
    total = len(_endpoints)
    online = sum(1 for ep in _endpoints.values() if (now - ep["last_seen"]) < _OFFLINE_THRESHOLD)
    critical = sum(1 for ep in _endpoints.values() if ep.get("risk") == "CRITICAL")
    total_alerts = sum(ep.get("alert_count", 0) for ep in _endpoints.values())
    return {
        "total": total,
        "online": online,
        "offline": total - online,
        "critical": critical,
        "total_alerts": total_alerts,
    }


def remove_endpoint(endpoint_id: str):
    _endpoints.pop(endpoint_id, None)


# ── Helpers ───────────────────────────────────────────────────────────────────
def _compute_risk(alerts: list) -> str:
    if not alerts:
        return "SAFE"
    severities = [a.get("severity", "LOW") for a in alerts]
    if "CRITICAL" in severities:
        return "CRITICAL"
    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "MEDIUM"
    return "LOW"


def _risk_order(risk: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "SAFE": 4}.get(risk, 5)
