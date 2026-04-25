"""
AI Security Agent — FastAPI Backend
Main API server with real-time security monitoring
"""
import logging
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import os, sys

import auth as _auth

from log_collector import collect_all_logs
from system_monitor import (
    get_full_snapshot, kill_process, get_running_processes,
    get_network_connections, get_network_stats, get_network_summary
)
from detection_engine import full_analysis
from alert_system import dispatch_alert, get_recent_alerts
from file_integrity import (
    check_integrity, create_baseline,
    add_monitored_path, remove_monitored_path, get_paths_info, update_baseline_for_path
)
from bruteforce_guard import (
    analyze_brute_force, block_ip, unblock_ip,
    get_active_blocked_ips, get_all_blocked_ips
)
from process_whitelist import safe_kill_check, get_full_whitelist, add_to_whitelist, remove_from_whitelist
from registry_monitor import check_registry, save_baseline as registry_baseline, remove_startup_entry
from resource_optimizer import adaptive_scanner, resource_guard, get_resource_stats, force_cleanup
from agent import run_agent
from config import SCAN_INTERVAL_SECONDS, ENV_MODE
from error_reporter import report_error

# Logging is configured once in launcher.py (FileHandler → AppData log).
# Do NOT call basicConfig() here — a second call is silently ignored by Python
# but signals a root-logger conflict that confuses uvicorn's dictConfig.
logger = logging.getLogger(__name__)

scanner_running = False
latest_analysis: dict = {}
latest_snapshot: dict = {}
active_ws_clients: set = set()   # track connected websocket clients


async def background_scanner():
    global scanner_running, latest_analysis, latest_snapshot
    scanner_running = True
    logger.info(f"Background scanner started (interval: {SCAN_INTERVAL_SECONDS}s)")
    while scanner_running:
        try:
            logs = collect_all_logs()
            snapshot = get_full_snapshot()
            # Enrich snapshot with full process list + all connections for zero-day/DDoS detectors
            snapshot["all_processes"]  = get_running_processes()
            snapshot["all_connections"] = get_network_connections()
            latest_snapshot = snapshot
            analysis = full_analysis(logs, snapshot)
            latest_analysis = analysis

            # Brute force check — auto-block attackers
            bf = analyze_brute_force()
            if bf.get("auto_blocked_this_scan"):
                logger.warning(f"AUTO-BLOCKED IPs: {bf['auto_blocked_this_scan']}")

            if analysis.get("is_attack") or analysis.get("risk_score", 0) >= 40:
                dispatch_alert(analysis)
                # Windows toast notification for HIGH / CRITICAL threats
                risk = analysis.get("overall_risk", "")
                if risk in ("CRITICAL", "HIGH"):
                    try:
                        from notifier import notify_threat
                        summary = (analysis.get("ai_analysis") or {}).get("summary", f"{risk} threat detected")
                        notify_threat(risk, summary)
                    except Exception:
                        pass
                    # Email alert (non-blocking, fire-and-forget)
                    try:
                        import threading
                        from email_alerts import send_alert_email
                        threading.Thread(target=send_alert_email, args=(analysis,), daemon=True).start()
                    except Exception:
                        pass

            # Adaptive interval + resource stats
            interval = adaptive_scanner.get_next_interval(analysis.get("risk_score", 0))
            res = get_resource_stats()
            logger.info(
                f"Scan | Risk: {analysis.get('overall_risk')} ({analysis.get('risk_score')}/100) "
                f"| RAM: {res['memory_mb']}MB | CPU: {res['cpu_percent']}% | Next: {interval}s"
            )
        except Exception as e:
            logger.error(f"Scanner error: {e}")
            report_error(str(e), context="background_scanner", exc=e)
            interval = SCAN_INTERVAL_SECONDS
        await asyncio.sleep(interval)


def _log_api_key_status():
    """Log API key source to the log file (no console with noconsole EXE)."""
    from config import GROQ_API_KEY
    user_key = ""
    try:
        from user_config import get_api_key
        user_key = get_api_key()
    except Exception:
        pass

    if user_key:
        logger.info(f"API Key: Loaded from AppData config ({user_key[:8]}...{user_key[-4:]})")
    elif GROQ_API_KEY:
        logger.info(f"API Key: Loaded from .env ({GROQ_API_KEY[:8]}...{GROQ_API_KEY[-4:]})")
    else:
        logger.warning("API Key: Not configured — AI agent will be in standby mode")

    return bool(user_key or GROQ_API_KEY)


@asynccontextmanager
async def lifespan(app: FastAPI):
    api_key_loaded = _log_api_key_status()
    logger.info(f"NexoraGuard starting | Mode: {ENV_MODE}")

    # Startup toast notification (fire-and-forget)
    try:
        from notifier import notify_startup
        notify_startup(api_key_loaded)
    except Exception:
        pass

    resource_guard.start()
    task = asyncio.create_task(background_scanner())

    yield

    # ── Shutdown ───────────────────────────────────────────────────────────────
    scanner_running = False
    resource_guard.stop()
    task.cancel()


app = FastAPI(title="NexoraGuard API", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ── Auth Middleware ────────────────────────────────────────────────────────────
_PUBLIC_PATHS = {"/auth/login", "/favicon.ico", "/ui"}

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Require valid JWT for all API routes except login and static assets."""
    path = request.url.path

    # Always allow: login endpoint, static dashboard files, favicon
    if (path in _PUBLIC_PATHS
            or path.startswith("/dashboard")
            or path.startswith("/static")):
        return await call_next(request)

    # WebSocket — token passed as query param ?token=
    if path == "/ws":
        token = request.query_params.get("token", "")
        if not token:
            return JSONResponse(status_code=401, content={"detail": "Missing auth token"})
        try:
            _auth.verify_token(token)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        return await call_next(request)

    # All other routes — require Authorization: Bearer <token>
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required. Please log in."},
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        _auth.verify_token(auth_header[7:])
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    return await call_next(request)


# ── Auth Endpoints ─────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    username: str
    old_password: str
    new_password: str

@app.post("/auth/login")
def route_login(req: LoginRequest):
    """Authenticate and return JWT token."""
    return _auth.login(req.username, req.password)

@app.post("/auth/change-password")
def route_change_password(req: ChangePasswordRequest, request: Request):
    """Change password (requires valid session)."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        _auth.verify_token(auth_header[7:])
    return _auth.change_password(req.username, req.old_password, req.new_password)

@app.get("/auth/me")
def route_me(request: Request):
    """Return current user profile."""
    token = request.headers.get("Authorization", "")[7:]
    username = _auth.verify_token(token)
    return _auth.get_user_info(username)


# Serve dashboard + icon — works both in dev and EXE
def get_resource_path(relative_path: str) -> str:
    """Resolve a path that works in dev AND inside a PyInstaller _internal folder."""
    if getattr(sys, "frozen", False):
        # PyInstaller extracts everything to sys._MEIPASS (_internal/)
        base = sys._MEIPASS
    else:
        # Dev: backend/main.py → two levels up → project root
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative_path)


def get_dashboard_path():
    return get_resource_path("dashboard")

def get_icon_path():
    if getattr(sys, 'frozen', False):
        # onedir: logo.ico is bundled into _internal/ (sys._MEIPASS); check there first.
        meipass_ico = os.path.join(sys._MEIPASS, "logo.ico")
        if os.path.exists(meipass_ico):
            return meipass_ico
        # Fallback: beside the EXE (for manually-placed overrides)
        return os.path.join(os.path.dirname(sys.executable), "logo.ico")
    return get_resource_path("logo.ico")

_dashboard_path = get_dashboard_path()
if os.path.exists(_dashboard_path):
    app.mount("/dashboard", StaticFiles(directory=_dashboard_path, html=True), name="dashboard")

@app.get("/ui")
def open_ui():
    """Redirect to dashboard."""
    return FileResponse(os.path.join(_dashboard_path, "index.html"))

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    """Serve the Nexora Cyber Tech icon for browser tabs and Windows taskbar."""
    path = get_icon_path()
    if os.path.exists(path):
        return FileResponse(path, media_type="image/x-icon")
    raise HTTPException(status_code=404, detail="favicon not found")


class KillProcessRequest(BaseModel):
    pid: int
    name: str = ""

class BlockIPRequest(BaseModel):
    ip: str
    reason: str = "Manual block"

class ApiKeyRequest(BaseModel):
    api_key: str

class WhitelistRequest(BaseModel):
    process_name: str

class RegistryRemoveRequest(BaseModel):
    key_path: str
    name: str

class ChatRequest(BaseModel):
    message: str
    history: list = []

class IntegrityPathRequest(BaseModel):
    path: str

class EmailConfigRequest(BaseModel):
    smtp_host:    str
    smtp_port:    int = 587
    username:     str
    password:     str
    recipient:    str
    use_tls:      bool = True
    from_name:    str = "NexoraGuard"
    min_severity: str = "HIGH"

class IsolationRequest(BaseModel):
    reason: str = "Manual quarantine"

class GeoIPRequest(BaseModel):
    ip: str

class ThreatIntelRequest(BaseModel):
    ip: str
    api_key: str = ""


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "name": "NexoraGuard", "version": "1.0.0",
        "status": "running",
        "scanner": "active" if scanner_running else "stopped",
        "licensed": True,
        "edition": "PRO",
        "mode": ENV_MODE,
    }


@app.get("/license")
def license_status():
    return {"licensed": True, "edition": "PRO", "message": "License check disabled"}


@app.get("/config")
def get_config():
    return {
        "env_mode": ENV_MODE,
        "licensed": True,
        "edition": "PRO",
        "features": {},
        "lite_mode": False,
    }


@app.get("/status")
def get_status():
    """Dashboard status card data."""
    snap = latest_snapshot or {}
    procs = []
    try:
        procs = get_running_processes()
    except Exception:
        pass
    conns = []
    try:
        conns = get_network_connections()
    except Exception:
        pass

    return {
        "status": "ok" if latest_analysis else "initializing",
        "timestamp": latest_analysis.get("timestamp") if latest_analysis else datetime.now().isoformat(),
        "overall_risk": latest_analysis.get("overall_risk", "UNKNOWN") if latest_analysis else "UNKNOWN",
        "risk_score": latest_analysis.get("risk_score", 0) if latest_analysis else 0,
        "is_attack": latest_analysis.get("is_attack", False) if latest_analysis else False,
        "rule_alert_count": latest_analysis.get("rule_alert_count", 0) if latest_analysis else 0,
        "system_stats": snap.get("system_stats", {}),
        "hostname": snap.get("hostname", ""),
        "total_processes": len(procs),
        "total_connections": len([c for c in conns if c.get("remote_addr")]),
        "suspicious_process_count": len([p for p in procs if p.get("suspicious")]),
        "suspicious_connection_count": len([c for c in conns if c.get("suspicious_port")]),
    }


@app.get("/analysis")
def get_analysis():
    if not latest_analysis:
        raise HTTPException(status_code=503, detail="Analysis not yet available")
    return latest_analysis


@app.get("/scan")
async def trigger_scan():
    """Manual full scan."""
    try:
        logs = collect_all_logs()
        snapshot = get_full_snapshot()
        global latest_snapshot, latest_analysis
        latest_snapshot = snapshot
        analysis = full_analysis(logs, snapshot)
        latest_analysis = analysis
        dispatch_alert(analysis)
        return analysis
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/remediation")
def get_remediation():
    """Get latest AI remediation steps."""
    if not latest_analysis:
        raise HTTPException(status_code=503, detail="No analysis available yet")
    return latest_analysis.get("remediation", {
        "threat_verdict": "System Clean",
        "remediation_steps": []
    })


@app.get("/processes")
def get_all_processes(sort_by: str = Query("cpu", enum=["cpu", "memory", "name"]), limit: int = Query(100)):
    """All running processes, sorted."""
    procs = get_running_processes()
    if sort_by == "cpu":
        procs.sort(key=lambda x: x.get("cpu", 0), reverse=True)
    elif sort_by == "memory":
        procs.sort(key=lambda x: x.get("memory", 0), reverse=True)
    else:
        procs.sort(key=lambda x: x.get("name", "").lower())
    return {
        "processes": procs[:limit],
        "total": len(procs),
        "suspicious_count": len([p for p in procs if p.get("suspicious")])
    }


@app.get("/processes/suspicious")
def get_suspicious_processes():
    from system_monitor import get_suspicious_processes as _get
    procs = _get()
    return {"suspicious_processes": procs, "count": len(procs)}


@app.post("/processes/kill")
def kill_proc(req: KillProcessRequest):
    # Safety check — never kill critical OS or whitelisted processes
    if req.name:
        check = safe_kill_check(req.pid, req.name)
        if not check["allowed"]:
            raise HTTPException(status_code=403, detail=check["message"])
    result = kill_process(req.pid)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result


@app.get("/network")
def get_network():
    conns = get_network_connections()
    stats = get_network_stats()
    active = [c for c in conns if c.get("remote_addr")]
    suspicious = [c for c in conns if c.get("suspicious_port")]
    return {
        "stats": stats,
        "connections": conns,
        "active_count": len(active),
        "suspicious_count": len(suspicious),
        "total_count": len(conns),
    }


@app.get("/alerts")
def get_alerts(limit: int = Query(20, le=100)):
    alerts = get_recent_alerts(limit)
    return {"alerts": alerts, "count": len(alerts)}


@app.get("/timeline")
def get_timeline(limit: int = Query(50, le=200)):
    """
    Threat timeline — last N alerts sorted oldest→newest for charting.
    Each entry: { timestamp, risk, score, is_attack }
    """
    alerts = get_recent_alerts(limit)
    # alerts come in reverse order (newest first) — reverse for timeline
    timeline = list(reversed(alerts))
    return {
        "timeline": timeline,
        "count": len(timeline),
        "generated_at": datetime.now().isoformat(),
    }


@app.get("/integrity")
def file_integrity():
    violations = check_integrity()
    return {
        "checked_at": datetime.now().isoformat(),
        "violations": violations,
        "violation_count": len(violations),
        "clean": len(violations) == 0
    }


@app.post("/integrity/baseline")
def reset_baseline():
    baseline = create_baseline()
    return {"message": "Baseline created successfully", "files_tracked": len(baseline)}


@app.get("/search")
def search(q: str = Query(..., min_length=1)):
    """Search across processes, connections, and alerts."""
    q_lower = q.lower()
    results = {"query": q, "processes": [], "connections": [], "alerts": []}

    # Search processes
    for p in get_running_processes():
        if q_lower in p.get("name", "").lower() or str(p.get("pid", "")) == q:
            results["processes"].append(p)

    # Search connections
    for c in get_network_connections():
        if q_lower in c.get("remote_addr", "").lower() or q_lower in c.get("local_addr", "").lower():
            results["connections"].append(c)

    # Search alerts
    for a in get_recent_alerts(50):
        if q_lower in (a.get("ai_summary") or "").lower() or q_lower in (a.get("risk") or "").lower():
            results["alerts"].append(a)

    results["total"] = len(results["processes"]) + len(results["connections"]) + len(results["alerts"])
    return results


@app.get("/snapshot")
def get_snapshot():
    return get_full_snapshot()


# ── WebSocket — Live Metrics Stream ──────────────────────────────────────────
@app.websocket("/ws")
async def websocket_live(websocket: WebSocket):
    """
    Push lightweight system metrics every 2 seconds.
    Does NOT run AI analysis — uses cached latest_analysis for risk score.
    This keeps CPU usage minimal.
    """
    await websocket.accept()
    active_ws_clients.add(websocket)
    logger.info(f"WebSocket connected — clients: {len(active_ws_clients)}")

    try:
        while True:
            # Lightweight — only psutil calls, no AI
            from system_monitor import get_system_stats, get_network_stats
            stats = get_system_stats()
            net = get_network_stats()

            payload = {
                "type": "metrics",
                "timestamp": datetime.now().isoformat(),
                "cpu": stats.get("cpu_percent", 0),
                "ram": stats.get("ram_percent", 0),
                "disk": stats.get("disk_percent", 0),
                "ram_used_gb": stats.get("ram_used_gb", 0),
                "ram_total_gb": stats.get("ram_total_gb", 0),
                # From cached scanner — no extra cost
                "risk_score": latest_analysis.get("risk_score", 0) if latest_analysis else 0,
                "risk_level": latest_analysis.get("overall_risk", "UNKNOWN") if latest_analysis else "UNKNOWN",
                "is_attack": latest_analysis.get("is_attack", False) if latest_analysis else False,
                "rule_alert_count": latest_analysis.get("rule_alert_count", 0) if latest_analysis else 0,
                "bytes_sent_mb": net.get("bytes_sent_mb", 0),
                "bytes_recv_mb": net.get("bytes_recv_mb", 0),
            }
            await websocket.send_json(payload)
            await asyncio.sleep(2)

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        active_ws_clients.discard(websocket)


@app.get("/bruteforce")
def bruteforce_status():
    """Analyze brute force attempts and auto-block attackers."""
    return analyze_brute_force()

@app.get("/bruteforce/blocked")
def get_blocked():
    """Get all currently blocked IPs."""
    return {"blocked": get_active_blocked_ips(), "count": len(get_active_blocked_ips())}

@app.get("/bruteforce/history")
def get_block_history():
    """Full block/unblock history."""
    return {"history": get_all_blocked_ips()}

@app.post("/bruteforce/block")
def manual_block(req: BlockIPRequest):
    """Manually block an IP address."""
    result = block_ip(req.ip, req.reason)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@app.post("/bruteforce/unblock")
def manual_unblock(req: BlockIPRequest):
    """Unblock an IP address."""
    result = unblock_ip(req.ip)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result


@app.post("/chat")
async def chat(req: ChatRequest):
    try:
        result = run_agent(req.message, req.history)
        return result
    except Exception as e:
        report_error(str(e), context="chat_endpoint", exc=e)
        raise HTTPException(status_code=500, detail=str(e))


# ── Whitelist ─────────────────────────────────────────────────────────────────

@app.get("/whitelist")
def get_whitelist():
    """Get full process whitelist (all tiers)."""
    return get_full_whitelist()

@app.post("/whitelist/add")
def whitelist_add(req: WhitelistRequest):
    result = add_to_whitelist(req.process_name)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@app.post("/whitelist/remove")
def whitelist_remove(req: WhitelistRequest):
    result = remove_from_whitelist(req.process_name)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@app.get("/whitelist/check/{process_name}")
def whitelist_check(process_name: str):
    """Check if a specific process is protected."""
    from process_whitelist import is_protected
    return is_protected(process_name)


# ── Registry Monitor ──────────────────────────────────────────────────────────

@app.get("/registry")
def get_registry():
    """Check registry startup entries against baseline."""
    return check_registry()

@app.post("/registry/baseline")
def registry_new_baseline():
    """Save current registry state as new trusted baseline."""
    return registry_baseline()

@app.post("/registry/remove-entry")
def registry_remove(req: RegistryRemoveRequest):
    """Remove a suspicious startup registry entry."""
    result = remove_startup_entry(req.key_path, req.name)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result


# ── Resource Stats ────────────────────────────────────────────────────────────

@app.get("/resources")
def agent_resources():
    """NexoraGuard's own RAM/CPU usage stats."""
    return get_resource_stats()

@app.post("/resources/cleanup")
def trigger_cleanup():
    """Force garbage collection and cache cleanup."""
    return force_cleanup()


# ── User Settings — API Key ───────────────────────────────────────────────────

@app.get("/settings/api-key")
def api_key_status():
    """
    Return current API key status for the dashboard Settings panel.
    Never returns the actual key — only a masked preview.
    """
    from user_config import has_api_key, get_key_preview
    return {
        "has_key": has_api_key(),
        "key_preview": get_key_preview(),
        "ai_mode": "user_key" if has_api_key() else "standby",
    }

@app.post("/settings/api-key")
def save_api_key(req: ApiKeyRequest):
    """Save the user's API key (encrypted at rest)."""
    from user_config import save_api_key as _save
    key = req.api_key.strip()
    if not key:
        raise HTTPException(status_code=400, detail="API key cannot be empty")
    _save(key)
    return {"success": True, "message": "API key saved and encrypted successfully"}

@app.delete("/settings/api-key")
def remove_api_key():
    """Remove the stored API key (reverts to standby mode)."""
    from user_config import remove_api_key as _remove
    _remove()
    return {"success": True, "message": "API key removed. Agent is now in standby mode."}


# ── File Integrity — Path Management ─────────────────────────────────────────

@app.get("/integrity/paths")
def get_integrity_paths():
    """Get all monitored file paths (builtin + custom) with metadata."""
    return get_paths_info()

@app.post("/integrity/paths/add")
def add_integrity_path(req: IntegrityPathRequest):
    """Add a custom path to file integrity monitoring."""
    result = add_monitored_path(req.path)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    # Auto-add to baseline so it's tracked immediately
    update_baseline_for_path(req.path)
    return result

@app.post("/integrity/paths/remove")
def remove_integrity_path(req: IntegrityPathRequest):
    """Remove a custom path from monitoring (cannot remove builtins)."""
    result = remove_monitored_path(req.path)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result


# ── Report Export ─────────────────────────────────────────────────────────────

@app.get("/report/pdf")
def download_pdf_report():
    """Generate and download a PDF security report from latest scan data."""
    from fastapi.responses import Response
    from report_generator import generate_pdf_report

    if not latest_analysis:
        raise HTTPException(status_code=503, detail="No analysis available yet — run a scan first")

    try:
        snapshot  = latest_snapshot or {}
        alerts    = get_recent_alerts(50)
        integrity = check_integrity()
        pdf_bytes = generate_pdf_report(latest_analysis, snapshot, alerts, integrity)
        filename  = f"nexoraguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    except RuntimeError as e:
        raise HTTPException(status_code=501, detail=str(e))
    except Exception as e:
        report_error(str(e), context="pdf_report", exc=e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/report/excel")
def download_excel_report():
    """Generate and download an Excel security report from latest scan data."""
    from fastapi.responses import Response
    from report_generator import generate_excel_report

    if not latest_analysis:
        raise HTTPException(status_code=503, detail="No analysis available yet — run a scan first")

    try:
        snapshot    = latest_snapshot or {}
        alerts      = get_recent_alerts(200)
        integrity   = check_integrity()
        xlsx_bytes  = generate_excel_report(latest_analysis, snapshot, alerts, integrity)
        filename    = f"nexoraguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        return Response(
            content=xlsx_bytes,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    except RuntimeError as e:
        raise HTTPException(status_code=501, detail=str(e))
    except Exception as e:
        report_error(str(e), context="excel_report", exc=e)
        raise HTTPException(status_code=500, detail=str(e))


# ── Attack Graph / Timeline ───────────────────────────────────────────────────

@app.get("/timeline/attack-graph")
def get_attack_graph(hours: int = Query(24, le=168)):
    """
    Build an attack graph from alert history.
    Groups alerts into attack chains based on time proximity and rule types.
    Returns nodes (events) + edges (causal links) for visualization.
    """
    from datetime import timedelta
    import json as _json

    alerts = get_recent_alerts(200)
    if not alerts:
        return {"nodes": [], "edges": [], "chains": [], "summary": "No alerts in history"}

    # Parse timestamps and build nodes
    nodes = []
    for i, a in enumerate(reversed(alerts)):  # oldest first
        ts_str = a.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str[:19])
        except Exception:
            ts = datetime.now()

        risk  = a.get("risk", "SAFE")
        score = a.get("score", 0)
        rules = a.get("rule_alerts", [])
        rule_names = list({r.get("rule", "") for r in rules if r.get("rule")})

        nodes.append({
            "id":         i,
            "timestamp":  ts.isoformat(),
            "risk":       risk,
            "score":      score,
            "is_attack":  a.get("is_attack", False),
            "rules":      rule_names,
            "label":      f"{risk} ({score})" + (f"\n{', '.join(rule_names[:2])}" if rule_names else ""),
        })

    # Build edges: connect nodes that are within 5 minutes of each other
    edges = []
    WINDOW = timedelta(minutes=5)
    for i in range(1, len(nodes)):
        try:
            t_prev = datetime.fromisoformat(nodes[i-1]["timestamp"])
            t_curr = datetime.fromisoformat(nodes[i]["timestamp"])
            if t_curr - t_prev <= WINDOW:
                edges.append({
                    "from": nodes[i-1]["id"],
                    "to":   nodes[i]["id"],
                    "type": "temporal",
                })
        except Exception:
            pass

    # Group into attack chains (connected components)
    chains = []
    visited = set()
    node_ids = {n["id"] for n in nodes}
    adjacency = {n["id"]: [] for n in nodes}
    for e in edges:
        adjacency[e["from"]].append(e["to"])
        adjacency[e["to"]].append(e["from"])

    for node in nodes:
        nid = node["id"]
        if nid in visited:
            continue
        # BFS
        chain_nodes = []
        queue = [nid]
        while queue:
            curr = queue.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            chain_nodes.append(curr)
            queue.extend(adjacency[curr])

        if len(chain_nodes) >= 2:
            chain_risk = max(
                (n["score"] for n in nodes if n["id"] in chain_nodes), default=0
            )
            chains.append({
                "node_ids":   chain_nodes,
                "node_count": len(chain_nodes),
                "max_score":  chain_risk,
                "attack_chain": any(nodes[i]["is_attack"] for i in range(len(nodes))
                                    if nodes[i]["id"] in chain_nodes),
            })

    # Filter to recent window
    cutoff = datetime.now() - timedelta(hours=hours)
    nodes = [n for n in nodes if datetime.fromisoformat(n["timestamp"]) >= cutoff]

    return {
        "nodes":    nodes,
        "edges":    edges,
        "chains":   chains,
        "summary":  f"{len(nodes)} events, {len(chains)} attack chain(s) in last {hours}h",
        "generated_at": datetime.now().isoformat(),
    }


# ── Windows Service Management ────────────────────────────────────────────────

@app.get("/service/status")
def service_status():
    """Get Windows Service installation and running state."""
    try:
        from windows_service import get_service_state
        return get_service_state()
    except Exception as e:
        return {"installed": False, "state": "ERROR", "error": str(e)}

@app.post("/service/install")
def service_install():
    """Install NexoraGuard as a Windows Service (requires Admin)."""
    try:
        from windows_service import install_service
        install_service()
        return {"success": True, "message": "Service installed successfully. Use /service/start to start it."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Service install failed: {e}")

@app.post("/service/start")
def service_start():
    """Start the NexoraGuard Windows Service."""
    try:
        from windows_service import start_service
        start_service()
        return {"success": True, "message": "Service started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Service start failed: {e}")

@app.post("/service/stop")
def service_stop():
    """Stop the NexoraGuard Windows Service."""
    try:
        from windows_service import stop_service
        stop_service()
        return {"success": True, "message": "Service stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Service stop failed: {e}")

@app.post("/service/remove")
def service_remove():
    """Uninstall the NexoraGuard Windows Service."""
    try:
        from windows_service import remove_service
        remove_service()
        return {"success": True, "message": "Service removed"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Service remove failed: {e}")


# ── Network summary (IPv4 + IPv6 breakdown) ───────────────────────────────────

@app.get("/network/summary")
def network_summary():
    """Quick IPv4 vs IPv6 breakdown + suspicious counts."""
    return get_network_summary()


# ── GeoIP ─────────────────────────────────────────────────────────────────────

@app.get("/geoip/{ip}")
def geoip_single(ip: str):
    """Look up country, city, ISP for a single IP address."""
    from geoip import lookup
    return lookup(ip)

@app.post("/geoip/batch")
def geoip_batch(ips: list[str]):
    """Look up GeoIP for a list of IPs."""
    from geoip import lookup_batch
    return lookup_batch(ips)

@app.get("/network/geo")
def network_with_geo():
    """All network connections with GeoIP data enriched."""
    from geoip import enrich_connections_with_geo
    conns = get_network_connections()
    return {"connections": enrich_connections_with_geo(conns), "count": len(conns)}


# ── Threat Intelligence (AbuseIPDB) ──────────────────────────────────────────

@app.get("/threat-intel/{ip}")
def threat_intel_single(ip: str, api_key: str = ""):
    """Check IP reputation via AbuseIPDB."""
    from threat_intel import check_ip
    return check_ip(ip, api_key)

@app.get("/bruteforce/intel")
def bruteforce_with_intel():
    """Brute force analysis with GeoIP + threat intel enrichment."""
    from geoip import enrich_brute_force_with_geo
    from threat_intel import enrich_attackers_with_intel
    bf = analyze_brute_force()
    bf = enrich_brute_force_with_geo(bf)
    attackers = bf.get("attackers", [])
    bf["attackers"] = enrich_attackers_with_intel(attackers)
    return bf


# ── Network Isolation (Quarantine) ───────────────────────────────────────────

@app.get("/isolation/status")
def isolation_status():
    """Get current network isolation state."""
    from network_isolation import get_isolation_state
    return get_isolation_state()

@app.post("/isolation/activate")
def isolation_activate(req: IsolationRequest):
    """ACTIVATE network isolation — blocks all traffic except localhost. Requires Admin."""
    from network_isolation import activate_isolation
    result = activate_isolation(req.reason)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result["message"])
    return result

@app.post("/isolation/deactivate")
def isolation_deactivate():
    """DEACTIVATE network isolation — restore normal traffic."""
    from network_isolation import deactivate_isolation
    return deactivate_isolation()


# ── USB / Removable Device Monitor ───────────────────────────────────────────

@app.get("/usb")
def usb_activity():
    """Check for recent USB device connections and removable media events."""
    from usb_monitor import check_usb_activity
    return check_usb_activity()


# ── MITRE ATT&CK ─────────────────────────────────────────────────────────────

@app.get("/mitre/summary")
def mitre_summary():
    """Get MITRE ATT&CK coverage summary from latest scan."""
    if not latest_analysis:
        raise HTTPException(status_code=503, detail="No analysis available yet")
    return latest_analysis.get("mitre", {})

@app.get("/mitre/mapping")
def mitre_full_mapping():
    """Return full MITRE ATT&CK mapping table used by NexoraGuard."""
    from mitre_mapping import RULE_TO_MITRE, TACTIC_COLORS
    return {"mapping": RULE_TO_MITRE, "tactic_colors": TACTIC_COLORS}


# ── Email Alert Settings ─────────────────────────────────────────────────────

@app.get("/settings/email")
def email_status():
    """Get email alert configuration status (never returns password)."""
    from email_alerts import get_email_status
    return get_email_status()

@app.post("/settings/email")
def save_email(req: EmailConfigRequest):
    """Save SMTP email alert configuration."""
    from email_alerts import save_email_config
    result = save_email_config(req.model_dump())
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@app.delete("/settings/email")
def delete_email():
    """Remove email alert configuration."""
    from email_alerts import delete_email_config
    return delete_email_config()

@app.post("/settings/email/test")
def test_email_endpoint():
    """Send a test email to verify SMTP configuration."""
    from email_alerts import test_email
    result = test_email()
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result


# ── Zero-Day Detection ────────────────────────────────────────────────────────

@app.get("/zero-day")
def zero_day_check():
    """
    Run behavioral anomaly / zero-day detection on the current system state.
    Uses: process entropy, suspicious spawn, LOLBins, process hollowing hints,
    baseline deviation, memory anomaly + AI scoring.
    """
    from zero_day_detector import detect_zero_day
    from detection_engine import get_effective_api_key
    snapshot = latest_snapshot or get_full_snapshot()
    # Ensure all processes available
    if "all_processes" not in snapshot:
        snapshot["all_processes"] = get_running_processes()
    api_key = get_effective_api_key("HIGH")
    return detect_zero_day(snapshot, api_key)


@app.get("/ddos")
def ddos_check():
    """
    Run DDoS / flood attack detection on current network state.
    Detects 15 attack protocols: connection flood, SYN flood, UDP flood, port scan,
    bandwidth spike, entropy flood, DNS/NTP/SSDP/Memcached/LDAP amplification,
    HTTP flood, Slowloris, Carpet Bombing, IoT Botnet.
    Auto-blocks confirmed flooding IPs via Windows Firewall.
    """
    from ddos_detector import detect_ddos
    snapshot = latest_snapshot or get_full_snapshot()
    if "all_connections" not in snapshot:
        snapshot["all_connections"] = get_network_connections()
    if "network_stats" not in snapshot:
        snapshot["network_stats"] = get_network_stats()
    return detect_ddos(snapshot, auto_block=True)


# ── Prevention / Hardening Module (Ethreon-Inspired) ─────────────────────────

# ── UEBA — User Behavior Analytics ───────────────────────────────────────────

@app.get("/ueba")
def ueba_analysis():
    """
    User & Entity Behavior Analytics — detect off-hours logins, new source IPs,
    credential stuffing, account enumeration, rare processes.
    """
    from ueba import analyze_ueba
    logs     = collect_all_logs()
    snapshot = latest_snapshot or get_full_snapshot()
    if "all_processes" not in snapshot:
        snapshot["all_processes"] = get_running_processes()
    return analyze_ueba(logs, snapshot)


# ── Ransomware Detection ──────────────────────────────────────────────────────

@app.get("/ransomware")
def ransomware_check():
    """
    Ransomware behavioral detection — mass file modification, high-entropy writes,
    known ransom extensions, ransom notes, shadow copy deletion.
    """
    from ransomware_detector import detect_ransomware
    logs     = collect_all_logs()
    snapshot = latest_snapshot or get_full_snapshot()
    if "all_processes" not in snapshot:
        snapshot["all_processes"] = get_running_processes()
    return detect_ransomware(logs, snapshot)


# ── Threat Intel Feed ─────────────────────────────────────────────────────────

@app.get("/intel/scan")
def threat_intel_scan():
    """
    Multi-source threat intelligence scan:
    - MalwareBazaar hash check (free)
    - GreyNoise IP reputation (free community)
    - URLhaus malicious IP/domain (free)
    - VirusTotal hash check (requires user API key)
    """
    from threat_intel_feed import run_threat_intel_scan
    from detection_engine import get_effective_api_key
    snapshot = latest_snapshot or get_full_snapshot()
    if "all_processes" not in snapshot:
        snapshot["all_processes"] = get_running_processes()
    if "all_connections" not in snapshot:
        snapshot["all_connections"] = get_network_connections()
    api_key = get_effective_api_key("HIGH")
    return run_threat_intel_scan(snapshot, api_key)


@app.get("/intel/hash/{file_hash}")
def intel_hash_lookup(file_hash: str, vt_key: str = ""):
    """Check a file hash against MalwareBazaar + VirusTotal."""
    from threat_intel_feed import check_hash_malwarebazaar, check_hash_virustotal
    mb  = check_hash_malwarebazaar(file_hash)
    vt  = check_hash_virustotal(file_hash, vt_key) if vt_key else {"skipped": "no_vt_key"}
    is_malicious = mb.get("is_malicious") or vt.get("is_malicious", False)
    return {
        "hash":         file_hash,
        "is_malicious": is_malicious,
        "malwarebazaar": mb,
        "virustotal":   vt,
    }


@app.get("/intel/ip/{ip}")
def intel_ip_lookup(ip: str):
    """Check an IP against GreyNoise + URLhaus + AbuseIPDB."""
    from threat_intel_feed import check_ip_greynoise, check_ip_urlhaus
    from threat_intel import check_ip as abuseipdb_check
    gn  = check_ip_greynoise(ip)
    uh  = check_ip_urlhaus(ip)
    ab  = abuseipdb_check(ip)
    is_malicious = (gn.get("is_malicious") or uh.get("is_malicious") or
                    (ab.get("abuseConfidenceScore", 0) >= 50))
    return {
        "ip":           ip,
        "is_malicious": is_malicious,
        "greynoise":    gn,
        "urlhaus":      uh,
        "abuseipdb":    ab,
    }


# ── Lateral Movement Detection ────────────────────────────────────────────────

@app.get("/lateral-movement")
def lateral_movement_check():
    """
    Lateral movement detection — RDP/SMB/WinRM anomalies,
    Pass-the-Hash indicators, remote service installs.
    """
    from lateral_movement import detect_lateral_movement
    logs     = collect_all_logs()
    snapshot = latest_snapshot or get_full_snapshot()
    if "all_connections" not in snapshot:
        snapshot["all_connections"] = get_network_connections()
    return detect_lateral_movement(logs, snapshot)


# ── Vulnerability Scanner ─────────────────────────────────────────────────────

@app.get("/vulns")
def vuln_scan():
    """
    Vulnerability & patch assessment — missing Windows updates,
    EOL software, weak configurations.
    """
    from vuln_scanner import run_vuln_scan
    return run_vuln_scan()


@app.get("/vulns/software")
def installed_software():
    """List all installed software with versions."""
    from vuln_scanner import get_installed_software
    sw = get_installed_software()
    return {"software": sw, "count": len(sw)}


# ── Combined Security Dashboard feed ─────────────────────────────────────────

@app.get("/security/full")
def full_security_status():
    """
    Combined security status feed for the Security Overview dashboard.
    Runs all detectors and returns unified risk assessment.
    Designed to be polled every 30s from the dashboard.
    """
    from ueba import analyze_ueba
    from ransomware_detector import detect_ransomware
    from lateral_movement import detect_lateral_movement
    from vuln_scanner import run_vuln_scan
    from threat_intel_feed import run_threat_intel_scan
    from detection_engine import get_effective_api_key

    logs     = collect_all_logs()
    snapshot = latest_snapshot or get_full_snapshot()
    if "all_processes" not in snapshot:
        snapshot["all_processes"] = get_running_processes()
    if "all_connections" not in snapshot:
        snapshot["all_connections"] = get_network_connections()

    api_key = get_effective_api_key("HIGH")

    ueba_r   = analyze_ueba(logs, snapshot)
    ransom_r = detect_ransomware(logs, snapshot)
    lateral_r = detect_lateral_movement(logs, snapshot)
    vuln_r   = run_vuln_scan()
    intel_r  = run_threat_intel_scan(snapshot, api_key)

    # Aggregate overall risk
    all_risks = [ueba_r["risk"], ransom_r["risk"], lateral_r["risk"],
                 vuln_r["risk"], intel_r["risk"]]
    risk_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "SAFE": 0}
    overall = max(all_risks, key=lambda r: risk_order.get(r, 0))

    total_alerts = (ueba_r["alert_count"] + ransom_r["alert_count"] +
                    lateral_r["alert_count"] + vuln_r["alert_count"] +
                    intel_r["total_malicious"])

    return {
        "timestamp":     datetime.now().isoformat(),
        "overall_risk":  overall,
        "total_alerts":  total_alerts,
        "ueba":          {"risk": ueba_r["risk"],    "alerts": ueba_r["alert_count"],   "data": ueba_r},
        "ransomware":    {"risk": ransom_r["risk"],  "alerts": ransom_r["alert_count"], "data": ransom_r},
        "lateral":       {"risk": lateral_r["risk"], "alerts": lateral_r["alert_count"],"data": lateral_r},
        "vulns":         {"risk": vuln_r["risk"],    "alerts": vuln_r["alert_count"],   "data": vuln_r},
        "intel":         {"risk": intel_r["risk"],   "alerts": intel_r["total_malicious"], "data": intel_r},
    }


# ── XDR Correlation Engine ────────────────────────────────────────────────────

@app.get("/xdr/incidents")
def xdr_incidents():
    """
    XDR correlated incidents — groups all EDR + NDR alerts into unified incidents.
    Each incident ties endpoint + network events to the same attacker entity.
    """
    from xdr_engine import correlate_alerts, get_xdr_summary
    from ueba import analyze_ueba
    from ransomware_detector import detect_ransomware
    from lateral_movement import detect_lateral_movement
    from vuln_scanner import run_vuln_scan
    from mitre_mapping import enrich_alert_with_mitre

    logs     = collect_all_logs()
    snapshot = latest_snapshot or get_full_snapshot()
    if "all_processes" not in snapshot:
        snapshot["all_processes"] = get_running_processes()
    if "all_connections" not in snapshot:
        snapshot["all_connections"] = get_network_connections()

    # Gather all raw alerts from every detector
    all_raw = []
    try:
        ueba_r    = analyze_ueba(logs, snapshot)
        all_raw.extend(ueba_r.get("alerts", []))
    except Exception:
        pass
    try:
        ransom_r  = detect_ransomware(logs, snapshot)
        all_raw.extend(ransom_r.get("alerts", []))
    except Exception:
        pass
    try:
        lateral_r = detect_lateral_movement(logs, snapshot)
        all_raw.extend(lateral_r.get("alerts", []))
    except Exception:
        pass

    # Rule-based detection engine alerts (enriched with MITRE)
    try:
        from detection_engine import run_all_rules
        rules_result = run_all_rules(logs, snapshot, "", [])
        for a in rules_result.get("rule_alerts", []):
            all_raw.append(enrich_alert_with_mitre(a))
    except Exception:
        pass

    incidents = correlate_alerts(all_raw)
    summary   = get_xdr_summary()

    return {
        "timestamp":  datetime.now().isoformat(),
        "incidents":  incidents,
        "summary":    summary,
        "total_raw_alerts": len(all_raw),
    }


@app.get("/xdr/killchain")
def xdr_killchain():
    """
    Kill chain tracker — maps current active alerts to MITRE ATT&CK stages
    and predicts the attacker's next likely moves.
    """
    from kill_chain_tracker import track_kill_chain
    from ueba import analyze_ueba
    from ransomware_detector import detect_ransomware
    from lateral_movement import detect_lateral_movement
    from mitre_mapping import enrich_alert_with_mitre

    logs     = collect_all_logs()
    snapshot = latest_snapshot or get_full_snapshot()
    if "all_processes" not in snapshot:
        snapshot["all_processes"] = get_running_processes()
    if "all_connections" not in snapshot:
        snapshot["all_connections"] = get_network_connections()

    all_alerts = []
    for fn in [
        lambda: analyze_ueba(logs, snapshot).get("alerts", []),
        lambda: detect_ransomware(logs, snapshot).get("alerts", []),
        lambda: detect_lateral_movement(logs, snapshot).get("alerts", []),
    ]:
        try:
            all_alerts.extend(fn())
        except Exception:
            pass

    try:
        from detection_engine import run_all_rules
        rules_result = run_all_rules(logs, snapshot, "", [])
        for a in rules_result.get("rule_alerts", []):
            all_alerts.append(enrich_alert_with_mitre(a))
    except Exception:
        pass

    return track_kill_chain(all_alerts)


@app.get("/xdr/playbooks")
def xdr_playbooks():
    """
    Evaluate all response playbooks against current threat state.
    Returns triggered playbooks with recommended actions.
    """
    from playbook_engine import evaluate_playbooks, get_playbook_summary, PLAYBOOKS
    from ueba import analyze_ueba
    from ransomware_detector import detect_ransomware
    from lateral_movement import detect_lateral_movement
    from mitre_mapping import enrich_alert_with_mitre

    logs     = collect_all_logs()
    snapshot = latest_snapshot or get_full_snapshot()
    if "all_processes" not in snapshot:
        snapshot["all_processes"] = get_running_processes()
    if "all_connections" not in snapshot:
        snapshot["all_connections"] = get_network_connections()

    all_alerts = []
    for fn in [
        lambda: analyze_ueba(logs, snapshot).get("alerts", []),
        lambda: detect_ransomware(logs, snapshot).get("alerts", []),
        lambda: detect_lateral_movement(logs, snapshot).get("alerts", []),
    ]:
        try:
            all_alerts.extend(fn())
        except Exception:
            pass

    try:
        from detection_engine import run_all_rules
        rules_result = run_all_rules(logs, snapshot, "", [])
        for a in rules_result.get("rule_alerts", []):
            all_alerts.append(enrich_alert_with_mitre(a))
    except Exception:
        pass

    triggered = evaluate_playbooks(all_alerts)
    summary   = get_playbook_summary(triggered)

    return {
        "timestamp":       datetime.now().isoformat(),
        "triggered":       triggered,
        "triggered_count": len(triggered),
        "all_playbooks":   len(PLAYBOOKS),
        "summary":         summary,
    }


@app.post("/xdr/playbook/execute")
def execute_playbook_action(action_type: str, ip: str = "", pid: int = 0,
                             name: str = "", service: str = "", message: str = ""):
    """
    Execute a single automated playbook action.
    action_type: BLOCK_IP | ISOLATE_NETWORK | KILL_PROCESS | DISABLE_SERVICE | LOG_FORENSICS
    """
    from playbook_engine import execute_action
    params = {"ip": ip, "pid": pid, "name": name,
               "service_name": service, "message": message}
    result = execute_action(action_type.upper(), params)
    return {"action": action_type, "params": params, **result}


@app.get("/xdr/full")
def xdr_full():
    """
    Single endpoint for the XDR dashboard page.
    Returns incidents + kill chain + triggered playbooks in one call.
    """
    from xdr_engine import correlate_alerts, get_xdr_summary
    from kill_chain_tracker import track_kill_chain
    from playbook_engine import evaluate_playbooks, get_playbook_summary
    from ueba import analyze_ueba
    from ransomware_detector import detect_ransomware
    from lateral_movement import detect_lateral_movement
    from mitre_mapping import enrich_alert_with_mitre

    logs     = collect_all_logs()
    snapshot = latest_snapshot or get_full_snapshot()
    if "all_processes" not in snapshot:
        snapshot["all_processes"] = get_running_processes()
    if "all_connections" not in snapshot:
        snapshot["all_connections"] = get_network_connections()

    all_alerts = []
    for fn in [
        lambda: analyze_ueba(logs, snapshot).get("alerts", []),
        lambda: detect_ransomware(logs, snapshot).get("alerts", []),
        lambda: detect_lateral_movement(logs, snapshot).get("alerts", []),
    ]:
        try:
            all_alerts.extend(fn())
        except Exception:
            pass

    try:
        from detection_engine import run_all_rules
        rules_result = run_all_rules(logs, snapshot, "", [])
        for a in rules_result.get("rule_alerts", []):
            all_alerts.append(enrich_alert_with_mitre(a))
    except Exception:
        pass

    incidents  = correlate_alerts(all_alerts)
    killchain  = track_kill_chain(all_alerts)
    triggered  = evaluate_playbooks(all_alerts)

    return {
        "timestamp":       datetime.now().isoformat(),
        "incidents":       incidents[:10],
        "xdr_summary":     get_xdr_summary(),
        "killchain":       killchain,
        "playbooks":       triggered,
        "playbook_summary": get_playbook_summary(triggered),
        "total_alerts":    len(all_alerts),
    }


@app.post("/xdr/killchain/reset")
def reset_killchain():
    """Reset kill chain tracking state (after incident closure)."""
    from kill_chain_tracker import reset_kill_chain
    reset_kill_chain()
    return {"message": "Kill chain state reset", "timestamp": datetime.now().isoformat()}


@app.post("/xdr/incident/{incident_id}/close")
def close_incident(incident_id: str):
    """Mark an XDR incident as closed."""
    from xdr_engine import close_incident as _close
    ok = _close(incident_id)
    if ok:
        return {"message": f"Incident {incident_id} closed"}
    raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")


@app.get("/prevention/protocols")
def prevention_protocols():
    """15-protocol DDoS coverage table with amplification factors and MITRE mapping."""
    from prevention_module import get_all_protocol_coverage
    return get_all_protocol_coverage()


@app.get("/prevention/general")
def prevention_general():
    """General Windows baseline hardening recommendations (always applicable)."""
    from prevention_module import get_general_hardening
    return {"recommendations": get_general_hardening(), "count": len(get_general_hardening())}


@app.get("/prevention/for-threat/{alert_type}")
def prevention_for_alert(alert_type: str):
    """Get hardening recommendations for a specific DDoS alert type."""
    from prevention_module import get_recommendations_for_alerts
    dummy_alert = [{"type": alert_type.upper(), "count": 0}]
    recs = get_recommendations_for_alerts(dummy_alert)
    if not recs:
        raise HTTPException(status_code=404, detail=f"No prevention data for alert type: {alert_type}")
    return recs[0]


@app.get("/prevention/live")
def prevention_live():
    """
    Combined live prevention feed: recommendations based on current DDoS detections
    + general hardening baseline. Powers the Prevention tab on the dashboard.
    """
    from ddos_detector import detect_ddos
    from prevention_module import get_recommendations_for_alerts, get_general_hardening, get_all_protocol_coverage
    snapshot = latest_snapshot or get_full_snapshot()
    if "all_connections" not in snapshot:
        snapshot["all_connections"] = get_network_connections()
    if "network_stats" not in snapshot:
        snapshot["network_stats"] = get_network_stats()
    ddos_result  = detect_ddos(snapshot, auto_block=False)
    active_recs  = get_recommendations_for_alerts(ddos_result.get("alerts", []))
    return {
        "timestamp":          datetime.now().isoformat(),
        "active_threats":     ddos_result["alert_count"],
        "ddos_risk":          ddos_result["risk"],
        "active_recs":        active_recs,
        "active_recs_count":  len(active_recs),
        "general_hardening":  get_general_hardening(),
        "protocol_coverage":  get_all_protocol_coverage(),
        "features":           ddos_result.get("features", {}),
    }


@app.get("/threats/live")
def live_threats():
    """
    Combined live threat feed: zero-day anomalies + DDoS + current rule alerts.
    This is the single endpoint the dashboard threat feed polls.
    """
    from zero_day_detector import detect_zero_day
    from ddos_detector import detect_ddos
    from detection_engine import get_effective_api_key
    from mitre_mapping import enrich_alert_with_mitre

    snapshot = latest_snapshot or get_full_snapshot()
    if "all_processes" not in snapshot:
        snapshot["all_processes"] = get_running_processes()
    if "all_connections" not in snapshot:
        snapshot["all_connections"] = get_network_connections()
    if "network_stats" not in snapshot:
        snapshot["network_stats"] = get_network_stats()

    api_key = get_effective_api_key("HIGH")
    zd_result   = detect_zero_day(snapshot, api_key)
    ddos_result = detect_ddos(snapshot, auto_block=True)

    # Combine rule alerts from both detectors + latest analysis
    combined_alerts = []
    for a in (latest_analysis.get("rule_alerts") or []):
        combined_alerts.append({**a, "source": "rule_engine"})
    for a in zd_result.get("rule_alerts", []):
        enrich_alert_with_mitre(a)
        combined_alerts.append({**a, "source": "zero_day"})
    for a in ddos_result.get("rule_alerts", []):
        enrich_alert_with_mitre(a)
        combined_alerts.append({**a, "source": "ddos"})

    # Deduplicate by rule name
    seen_rules = set()
    unique_alerts = []
    for a in combined_alerts:
        k = a.get("rule", "")
        if k not in seen_rules:
            seen_rules.add(k)
            unique_alerts.append(a)

    overall_risk = latest_analysis.get("overall_risk", "SAFE")
    if zd_result["risk"] in ("CRITICAL", "HIGH") and overall_risk not in ("CRITICAL",):
        overall_risk = zd_result["risk"]
    if ddos_result["risk"] == "CRITICAL":
        overall_risk = "CRITICAL"

    # Prevention recommendations for active DDoS alerts
    prevention_recs = []
    try:
        from prevention_module import get_recommendations_for_alerts
        prevention_recs = get_recommendations_for_alerts(ddos_result.get("alerts", []))
    except Exception:
        pass

    return {
        "timestamp":         datetime.now().isoformat(),
        "overall_risk":      overall_risk,
        "total_alerts":      len(unique_alerts),
        "alerts":            unique_alerts,
        "zero_day": {
            "risk":          zd_result["risk"],
            "anomaly_count": zd_result["anomaly_count"],
            "anomalies":     zd_result["anomalies"],
            "ai_verdict":    zd_result.get("ai_verdict"),
            "baseline_ready": zd_result["baseline_ready"],
        },
        "ddos": {
            "risk":            ddos_result["risk"],
            "alert_count":     ddos_result["alert_count"],
            "alerts":          ddos_result["alerts"],
            "auto_blocked":    ddos_result["auto_blocked"],
            "stats":           ddos_result["stats"],
            "features":        ddos_result.get("features", {}),
            "protocol_coverage": ddos_result.get("protocol_coverage", {}),
        },
        "prevention":        prevention_recs,
        "prevention_count":  len(prevention_recs),
    }
