"""
Alert System
Telegram notifications + Email + local alert log
"""
import requests
import smtplib
import json
import logging
from email.mime.text import MIMEText
from datetime import datetime
from pathlib import Path
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

logger = logging.getLogger(__name__)

ALERT_LOG_FILE = Path(__file__).parent / "alerts.log"


def send_telegram(message: str) -> bool:
    """Send Telegram message via Bot API."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("Telegram not configured — skipping alert")
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            logger.info("Telegram alert sent")
            return True
        else:
            logger.error(f"Telegram error: {response.text}")
            return False
    except Exception as e:
        logger.error(f"Telegram send failed: {e}")
        return False


def format_alert_message(analysis: dict) -> str:
    """Format analysis result as Telegram message."""
    ai = analysis.get("ai_analysis", {})
    risk = analysis.get("overall_risk", "UNKNOWN")
    score = analysis.get("risk_score", 0)
    is_attack = analysis.get("is_attack", False)
    rule_count = analysis.get("rule_alert_count", 0)

    emoji = {
        "CRITICAL": "🚨",
        "HIGH": "⚠️",
        "MEDIUM": "🔶",
        "LOW": "🟡",
        "SAFE": "✅",
        "UNKNOWN": "❓"
    }.get(risk, "❓")

    lines = [
        f"{emoji} <b>AI Security Agent Alert</b>",
        f"━━━━━━━━━━━━━━━━━━━",
        f"🕐 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"🎯 Risk Level: <b>{risk}</b>",
        f"📊 Risk Score: {score}/100",
        f"🚔 Attack Detected: {'YES' if is_attack else 'No'}",
        f"⚡ Rule Alerts: {rule_count}",
        f"",
        f"🧠 <b>AI Summary:</b>",
        f"{ai.get('summary', 'No summary')}",
    ]

    recommendations = ai.get("recommendations", [])
    if recommendations:
        lines.append("")
        lines.append("💡 <b>Recommendations:</b>")
        for i, rec in enumerate(recommendations[:3], 1):
            lines.append(f"  {i}. {rec}")

    rule_alerts = analysis.get("rule_alerts", [])
    if rule_alerts:
        lines.append("")
        lines.append("🔍 <b>Rules Triggered:</b>")
        for alert in rule_alerts[:5]:
            sev_emoji = "🔴" if alert["severity"] == "CRITICAL" else "🟠" if alert["severity"] == "HIGH" else "🟡"
            lines.append(f"  {sev_emoji} {alert['rule']}: {alert['message']}")

    return "\n".join(lines)


def log_alert_to_file(analysis: dict):
    """Write alert to local log file."""
    try:
        with open(ALERT_LOG_FILE, "a", encoding="utf-8") as f:
            entry = {
                "timestamp": datetime.now().isoformat(),
                "risk": analysis.get("overall_risk"),
                "score": analysis.get("risk_score"),
                "is_attack": analysis.get("is_attack"),
                "rule_count": analysis.get("rule_alert_count"),
                "ai_summary": analysis.get("ai_analysis", {}).get("summary", ""),
            }
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.error(f"Failed to write alert log: {e}")


def dispatch_alert(analysis: dict, min_risk_score: int = 40) -> dict:
    """
    Dispatch alert based on risk score.
    Only sends if risk_score >= min_risk_score.
    """
    score = analysis.get("risk_score", 0)
    risk = analysis.get("overall_risk", "SAFE")

    log_alert_to_file(analysis)

    if score < min_risk_score and risk not in ("HIGH", "CRITICAL"):
        return {"sent": False, "reason": f"Risk score {score} below threshold {min_risk_score}"}

    message = format_alert_message(analysis)
    telegram_sent = send_telegram(message)

    return {
        "sent": telegram_sent,
        "risk_level": risk,
        "risk_score": score,
        "message_preview": message[:200]
    }


def get_recent_alerts(limit: int = 20) -> list[dict]:
    """Read recent alerts from log file."""
    if not ALERT_LOG_FILE.exists():
        return []
    alerts = []
    try:
        with open(ALERT_LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in reversed(lines[-limit:]):
            line = line.strip()
            if line:
                alerts.append(json.loads(line))
    except Exception as e:
        logger.error(f"Failed to read alerts: {e}")
    return alerts
