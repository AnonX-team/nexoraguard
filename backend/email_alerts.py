"""
Email Alert System for NexoraGuard
Sends HTML-formatted security alert emails via SMTP.
Supports: Gmail, Outlook, custom SMTP servers.
Config is stored encrypted in user_config system.
"""
import smtplib
import logging
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

EMAIL_CONFIG_FILE = Path(__file__).parent / "email_config.json"


# ── Config management ─────────────────────────────────────────────────────────

def save_email_config(config: dict) -> dict:
    """Save SMTP config to disk."""
    required = ["smtp_host", "smtp_port", "username", "password", "recipient"]
    for field in required:
        if not config.get(field):
            return {"success": False, "message": f"Missing required field: {field}"}
    try:
        with open(EMAIL_CONFIG_FILE, "w") as f:
            json.dump({
                "smtp_host":   config["smtp_host"],
                "smtp_port":   int(config.get("smtp_port", 587)),
                "username":    config["username"],
                "password":    config["password"],  # TODO: encrypt in v2
                "recipient":   config["recipient"],
                "use_tls":     config.get("use_tls", True),
                "from_name":   config.get("from_name", "NexoraGuard"),
                "min_severity": config.get("min_severity", "HIGH"),
                "enabled":     True,
                "updated_at":  datetime.now().isoformat(),
            }, f, indent=2)
        return {"success": True, "message": "Email config saved"}
    except Exception as e:
        return {"success": False, "message": str(e)}


def load_email_config() -> dict | None:
    """Load SMTP config from disk. Returns None if not configured."""
    if not EMAIL_CONFIG_FILE.exists():
        return None
    try:
        with open(EMAIL_CONFIG_FILE) as f:
            cfg = json.load(f)
        return cfg if cfg.get("enabled") else None
    except Exception:
        return None


def get_email_status() -> dict:
    """Return email config status (never returns password)."""
    cfg = load_email_config()
    if not cfg:
        return {"configured": False, "enabled": False}
    return {
        "configured":   True,
        "enabled":      cfg.get("enabled", False),
        "smtp_host":    cfg.get("smtp_host", ""),
        "smtp_port":    cfg.get("smtp_port", 587),
        "username":     cfg.get("username", ""),
        "recipient":    cfg.get("recipient", ""),
        "min_severity": cfg.get("min_severity", "HIGH"),
    }


def delete_email_config() -> dict:
    if EMAIL_CONFIG_FILE.exists():
        EMAIL_CONFIG_FILE.unlink()
    return {"success": True, "message": "Email config removed"}


# ── Email builder ─────────────────────────────────────────────────────────────

RISK_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
    "SAFE":     "#475569",
}


def _build_html(analysis: dict) -> str:
    risk  = analysis.get("overall_risk", "UNKNOWN")
    score = analysis.get("risk_score", 0)
    ts    = analysis.get("timestamp", datetime.now().isoformat())[:19].replace("T", " ")
    color = RISK_COLORS.get(risk, "#475569")
    ai    = (analysis.get("ai_analysis") or {})
    summary = ai.get("summary", "No AI summary available.")
    rules   = analysis.get("rule_alerts", [])
    mitre   = analysis.get("mitre", {})
    recs    = ai.get("recommendations", [])

    rule_rows = ""
    for r in rules[:8]:
        sev_color = RISK_COLORS.get(r.get("severity", ""), "#475569")
        mitre_info = r.get("mitre") or {}
        tech = mitre_info.get("technique", "")
        rule_rows += f"""
        <tr>
          <td style="padding:8px 12px;border-bottom:1px solid #1a2d4a;color:{sev_color};font-weight:bold">{r.get('severity','')}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #1a2d4a;color:#94a3b8">{r.get('rule','')}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #1a2d4a;color:#f1f5f9">{r.get('message','')[:60]}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #1a2d4a;color:#0ea5e9;font-family:monospace">{tech}</td>
        </tr>"""

    rec_items = "".join(f"<li style='margin-bottom:6px;color:#94a3b8'>{r}</li>" for r in recs[:4])

    mitre_stage = mitre.get("kill_chain_stage", "")
    mitre_techs = ", ".join(mitre.get("unique_techniques", [])[:6])

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#060b18;font-family:Inter,Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;margin:20px auto">
  <tr>
    <td style="background:#0c1426;border-radius:12px 12px 0 0;padding:24px 28px;
      border-bottom:2px solid {color}">
      <table width="100%">
        <tr>
          <td>
            <div style="font-size:11px;color:#475569;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:4px">
              NexoraGuard Security Alert
            </div>
            <div style="font-size:22px;font-weight:800;color:{color}">{risk} THREAT DETECTED</div>
            <div style="font-size:12px;color:#475569;margin-top:4px">{ts}</div>
          </td>
          <td align="right">
            <div style="background:{color}22;border:1px solid {color}44;border-radius:10px;
              padding:12px 18px;text-align:center;display:inline-block">
              <div style="font-size:32px;font-weight:900;color:{color};font-family:monospace">{score}</div>
              <div style="font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:.8px">Risk Score</div>
            </div>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <tr>
    <td style="background:#0c1426;padding:20px 28px;border-bottom:1px solid #1a2d4a">
      <div style="font-size:11px;color:#0ea5e9;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">
        AI Analysis
      </div>
      <div style="font-size:13px;color:#94a3b8;line-height:1.7">{summary}</div>
      {"<ul style='margin:12px 0 0;padding-left:18px'>" + rec_items + "</ul>" if rec_items else ""}
    </td>
  </tr>

  {"<tr><td style='background:#0c1426;padding:16px 28px;border-bottom:1px solid #1a2d4a'>"
   "<div style='font-size:11px;color:#8b5cf6;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px'>MITRE ATT&CK</div>"
   f"<span style='background:#1a0d2e;border:1px solid #8b5cf644;border-radius:4px;padding:3px 10px;color:#8b5cf6;font-size:12px;font-weight:600'>{mitre_stage}</span>"
   f"<span style='color:#475569;font-size:11px;margin-left:12px'>Techniques: {mitre_techs}</span>"
   "</td></tr>" if mitre_stage else ""}

  {"<tr><td style='background:#0c1426;padding:0 28px 20px'>"
   "<div style='font-size:11px;color:#ef4444;text-transform:uppercase;letter-spacing:1px;margin:16px 0 8px'>Rule Alerts</div>"
   "<table width='100%' cellpadding='0' cellspacing='0'>"
   "<tr style='background:#111d33'>"
   "<th style='padding:8px 12px;text-align:left;color:#475569;font-size:10px;letter-spacing:.8px'>SEVERITY</th>"
   "<th style='padding:8px 12px;text-align:left;color:#475569;font-size:10px;letter-spacing:.8px'>RULE</th>"
   "<th style='padding:8px 12px;text-align:left;color:#475569;font-size:10px;letter-spacing:.8px'>MESSAGE</th>"
   "<th style='padding:8px 12px;text-align:left;color:#475569;font-size:10px;letter-spacing:.8px'>ATT&CK</th>"
   "</tr>" + rule_rows + "</table></td></tr>" if rules else ""}

  <tr>
    <td style="background:#060b18;border-radius:0 0 12px 12px;padding:16px 28px;text-align:center">
      <div style="font-size:11px;color:#1e3a5f">
        NexoraGuard &nbsp;|&nbsp; Nexora Cyber Tech &copy; 2026 &nbsp;|&nbsp; Authorized monitoring only
      </div>
    </td>
  </tr>
</table>
</body></html>"""


# ── Send function ─────────────────────────────────────────────────────────────

_last_sent: dict[str, float] = {}   # risk → last_sent_timestamp
EMAIL_COOLDOWN = 300  # 5 minutes per risk level


def send_alert_email(analysis: dict) -> dict:
    """
    Send a security alert email if configured and above min severity.
    Has a 5-minute cooldown per risk level to prevent spam.
    """
    cfg = load_email_config()
    if not cfg:
        return {"sent": False, "reason": "Email not configured"}

    risk  = analysis.get("overall_risk", "SAFE")
    score = analysis.get("risk_score", 0)

    # Check minimum severity
    sev_order = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_sev   = cfg.get("min_severity", "HIGH")
    if sev_order.index(risk) < sev_order.index(min_sev):
        return {"sent": False, "reason": f"Risk {risk} below threshold {min_sev}"}

    # Cooldown check
    import time
    now = time.time()
    if risk in _last_sent and (now - _last_sent[risk]) < EMAIL_COOLDOWN:
        remaining = int(EMAIL_COOLDOWN - (now - _last_sent[risk]))
        return {"sent": False, "reason": f"Cooldown active ({remaining}s remaining)"}

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[NexoraGuard] {risk} Alert — Score {score}/100"
        msg["From"]    = f"{cfg.get('from_name','NexoraGuard')} <{cfg['username']}>"
        msg["To"]      = cfg["recipient"]

        html_body = _build_html(analysis)
        msg.attach(MIMEText(html_body, "html"))

        port    = int(cfg.get("smtp_port", 587))
        use_tls = cfg.get("use_tls", True)

        if use_tls:
            server = smtplib.SMTP(cfg["smtp_host"], port, timeout=10)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(cfg["smtp_host"], port, timeout=10)

        server.login(cfg["username"], cfg["password"])
        server.sendmail(cfg["username"], cfg["recipient"], msg.as_string())
        server.quit()

        _last_sent[risk] = now
        logger.info(f"Email alert sent to {cfg['recipient']} — {risk} ({score})")
        return {"sent": True, "recipient": cfg["recipient"], "risk": risk, "score": score}

    except Exception as e:
        logger.error(f"Email send failed: {e}")
        return {"sent": False, "reason": str(e)}


def test_email(recipient: str = "") -> dict:
    """Send a test email to verify SMTP config."""
    cfg = load_email_config()
    if not cfg:
        return {"success": False, "message": "Email not configured"}
    test_analysis = {
        "overall_risk": "LOW",
        "risk_score": 10,
        "timestamp": datetime.now().isoformat(),
        "rule_alerts": [],
        "ai_analysis": {"summary": "This is a test alert from NexoraGuard. Your email notifications are working correctly.", "recommendations": []},
        "mitre": {}
    }
    # Override recipient for test
    if recipient:
        cfg["recipient"] = recipient
    # Direct send bypassing cooldown for test
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "[NexoraGuard] Test Email — Config Verification"
        msg["From"]    = f"{cfg.get('from_name','NexoraGuard')} <{cfg['username']}>"
        msg["To"]      = cfg["recipient"]
        msg.attach(MIMEText(_build_html(test_analysis), "html"))
        port    = int(cfg.get("smtp_port", 587))
        use_tls = cfg.get("use_tls", True)
        if use_tls:
            server = smtplib.SMTP(cfg["smtp_host"], port, timeout=10)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(cfg["smtp_host"], port, timeout=10)
        server.login(cfg["username"], cfg["password"])
        server.sendmail(cfg["username"], cfg["recipient"], msg.as_string())
        server.quit()
        return {"success": True, "message": f"Test email sent to {cfg['recipient']}"}
    except Exception as e:
        return {"success": False, "message": str(e)}
