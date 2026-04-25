"""
AI Security Agent — Conversational Agent with Tool Calling
User se baat karta hai, system analyze karta hai, actions leta hai
"""
import json
import logging
from datetime import datetime
import groq as groq_module
from groq import Groq
from config import GROQ_API_KEY
from system_monitor import get_full_snapshot, kill_process, get_running_processes, get_network_connections
from log_collector import collect_all_logs
from detection_engine import full_analysis
from file_integrity import check_integrity
from alert_system import get_recent_alerts
from bruteforce_guard import analyze_brute_force, block_ip, unblock_ip, get_active_blocked_ips

logger = logging.getLogger(__name__)

_STANDBY_RESPONSE = (
    "**AI Agent is in standby mode.**\n\n"
    "To enable 24/7 Smart Analysis, go to **Settings → AI API Key** and enter "
    "your free Groq API key.\n\n"
    "Get a free key at **console.groq.com** (no credit card required).\n\n"
    "Once your key is saved, the agent will have full access to all AI features."
)

def _get_effective_key() -> str:
    """
    Return the best available API key, checking all sources in order.
    Prints a one-line console trace so the source is always visible.
    """
    # Source 1 — user-saved key from Settings (user_config.json beside EXE)
    try:
        from user_config import get_api_key
        user_key = get_api_key()
        if user_key:
            print(f"[Agent] Using API key from user_config.json ({user_key[:8]}...{user_key[-4:]})")
            return user_key
    except Exception as e:
        print(f"[Agent] user_config.json read failed: {e}")

    # Source 2 — .env / environment variable (GROQ_API_KEY)
    if GROQ_API_KEY:
        print(f"[Agent] Using API key from .env / environment ({GROQ_API_KEY[:8]}...{GROQ_API_KEY[-4:]})")
        return GROQ_API_KEY

    print("[Agent] No API key found — returning standby response")
    return ""

# ── Tool Definitions ──────────────────────────────────────────────────────────
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "scan_system",
            "description": "Run a full security scan of the system. Analyzes logs, processes, network, and uses AI to detect threats.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_system_status",
            "description": "Get current system status: CPU, RAM, disk usage, hostname, risk level.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_suspicious_processes",
            "description": "List all suspicious or potentially malicious running processes.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "kill_process",
            "description": "Kill a running process by its PID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID to kill"}
                },
                "required": ["pid"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_network",
            "description": "Check active network connections and detect suspicious ports or connections.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_file_integrity",
            "description": "Check if critical system files have been modified or tampered with.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_alert_history",
            "description": "Get recent security alert history.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Number of recent alerts to retrieve (default 10)"}
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_top_processes",
            "description": "List top running processes sorted by CPU or memory usage.",
            "parameters": {
                "type": "object",
                "properties": {
                    "sort_by": {"type": "string", "enum": ["cpu", "memory"], "description": "Sort by cpu or memory"}
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_brute_force",
            "description": "Check for brute force login attacks, see attacking IPs, and auto-block them.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "block_ip_address",
            "description": "Block a specific IP address via Windows Firewall to stop an attack.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address to block"},
                    "reason": {"type": "string", "description": "Reason for blocking"}
                },
                "required": ["ip"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "unblock_ip_address",
            "description": "Unblock a previously blocked IP address.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address to unblock"}
                },
                "required": ["ip"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_blocked_ips",
            "description": "List all currently blocked IP addresses.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    }
]

SYSTEM_PROMPT = """You are SecureAgent, an elite AI cybersecurity analyst and autonomous security agent.

You have direct access to the user's Windows system and can:
- Run security scans
- Analyze threats in real-time
- Monitor processes, network, and files
- Kill malicious processes
- Explain security events in plain language

Your personality:
- Professional but friendly
- Proactive — suggest actions the user should take
- Clear and concise — avoid jargon unless asked
- When you detect threats, be direct and urgent
- Always explain WHY something is suspicious

When responding:
- Use tools to get real data before answering security questions
- Format responses with clear sections using **bold** for important info
- Give actionable recommendations
- If something looks dangerous, say so clearly"""


# ── Tool Executor ─────────────────────────────────────────────────────────────
def execute_tool(name: str, args: dict) -> str:
    try:
        if name == "scan_system":
            logs = collect_all_logs()
            snap = get_full_snapshot()
            result = full_analysis(logs, snap)
            ai = result.get("ai_analysis", {})
            return json.dumps({
                "risk_level": result.get("overall_risk"),
                "risk_score": result.get("risk_score"),
                "is_attack": result.get("is_attack"),
                "rule_alerts": len(result.get("rule_alerts", [])),
                "ai_summary": ai.get("summary"),
                "recommendations": ai.get("recommendations", []),
                "attack_type": ai.get("attack_type"),
                "rule_details": result.get("rule_alerts", [])[:5]
            })

        elif name == "get_system_status":
            snap = get_full_snapshot()
            stats = snap.get("system_stats", {})
            return json.dumps({
                "hostname": snap.get("hostname"),
                "cpu": stats.get("cpu_percent"),
                "ram_percent": stats.get("ram_percent"),
                "ram_used_gb": stats.get("ram_used_gb"),
                "ram_total_gb": stats.get("ram_total_gb"),
                "disk_percent": stats.get("disk_percent"),
                "disk_free_gb": stats.get("disk_free_gb"),
                "total_processes": snap.get("total_processes"),
                "total_connections": snap.get("total_connections"),
                "timestamp": snap.get("timestamp")
            })

        elif name == "list_suspicious_processes":
            snap = get_full_snapshot()
            procs = snap.get("suspicious_processes", [])
            return json.dumps({
                "count": len(procs),
                "processes": procs
            })

        elif name == "kill_process":
            pid = args.get("pid")
            result = kill_process(pid)
            return json.dumps(result)

        elif name == "check_network":
            conns = get_network_connections()
            suspicious = [c for c in conns if c.get("suspicious_port")]
            active = [c for c in conns if c.get("remote_addr")]
            return json.dumps({
                "total_connections": len(conns),
                "active_connections": len(active),
                "suspicious_connections": len(suspicious),
                "suspicious_details": suspicious[:5],
                "sample_connections": active[:10]
            })

        elif name == "check_file_integrity":
            violations = check_integrity()
            return json.dumps({
                "violations": len(violations),
                "clean": len(violations) == 0,
                "details": violations
            })

        elif name == "get_alert_history":
            limit = args.get("limit", 10)
            alerts = get_recent_alerts(limit)
            return json.dumps({"alerts": alerts, "count": len(alerts)})

        elif name == "list_top_processes":
            sort_by = args.get("sort_by", "cpu")
            procs = get_running_processes()
            sorted_procs = sorted(procs, key=lambda x: x.get(sort_by, 0), reverse=True)[:15]
            return json.dumps({"processes": sorted_procs, "sorted_by": sort_by})

        elif name == "check_brute_force":
            return json.dumps(analyze_brute_force())

        elif name == "block_ip_address":
            ip = args.get("ip", "")
            reason = args.get("reason", "Blocked by AI agent")
            return json.dumps(block_ip(ip, reason))

        elif name == "unblock_ip_address":
            ip = args.get("ip", "")
            return json.dumps(unblock_ip(ip))

        elif name == "list_blocked_ips":
            blocked = get_active_blocked_ips()
            return json.dumps({"blocked_ips": blocked, "count": len(blocked)})

        else:
            return json.dumps({"error": f"Unknown tool: {name}"})

    except Exception as e:
        logger.error(f"Tool {name} failed: {e}")
        return json.dumps({"error": str(e)})


# ── Main Agent Function ───────────────────────────────────────────────────────
def run_agent(user_message: str, history: list[dict]) -> dict:
    """
    Run the AI agent with tool calling.
    Returns: { response, actions_taken, tool_results }

    Key logic:
    - If user has saved their own API key → full AI agent, no restrictions
    - If no user key → show standby message (preserve company quota)
    """
    api_key = _get_effective_key()

    # No key from any source — standby mode
    if not api_key:
        return {
            "response": _STANDBY_RESPONSE,
            "actions_taken": [],
            "tool_results": [],
            "standby": True
        }
    agent_client = Groq(api_key=api_key)

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(history[-10:])
    messages.append({"role": "user", "content": user_message})

    actions_taken = []
    tool_results = []
    max_iterations = 5
    iteration = 0

    while iteration < max_iterations:
        iteration += 1

        try:
            response = agent_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages,
                tools=TOOLS,
                tool_choice="auto",
                max_tokens=1024,
                temperature=0.3
            )
        except groq_module.AuthenticationError as e:
            msg = (
                f"[API ERROR 401 Unauthorized] Your Groq API key is invalid or expired.\n"
                f"  Key preview : {api_key[:8]}...{api_key[-4:] if len(api_key) > 12 else ''}\n"
                f"  Fix        : Go to Settings → Remove Key → re-enter a valid key from console.groq.com\n"
                f"  Detail     : {e}"
            )
            print(msg)
            logger.error(msg)
            return {"response": "**API Error 401:** Invalid API key. Go to Settings and re-enter your Groq key.", "actions_taken": [], "tool_results": [], "error": "401"}
        except groq_module.RateLimitError as e:
            msg = (
                f"[API ERROR 429 Rate Limit] Daily token quota exhausted.\n"
                f"  Free tier limit : 100,000 tokens/day\n"
                f"  Fix             : Wait until midnight (UTC) or upgrade at console.groq.com\n"
                f"  Detail          : {e}"
            )
            print(msg)
            logger.error(msg)
            return {"response": "**API Error 429:** Rate limit reached. Free Groq tier allows 100k tokens/day. Try again tomorrow or upgrade.", "actions_taken": [], "tool_results": [], "error": "429"}
        except groq_module.APIStatusError as e:
            status = e.status_code
            msg = (
                f"[API ERROR {status}] Groq returned HTTP {status}.\n"
                f"  URL    : https://api.groq.com/openai/v1/chat/completions\n"
                f"  Detail : {e.message}"
            )
            print(msg)
            logger.error(msg)
            return {"response": f"**API Error {status}:** {e.message}", "actions_taken": [], "tool_results": [], "error": str(status)}
        except groq_module.APIConnectionError as e:
            msg = (
                f"[API ERROR — Connection Failed] Could not reach api.groq.com\n"
                f"  Possible causes:\n"
                f"    1. No internet connection\n"
                f"    2. Firewall / antivirus blocking outbound HTTPS\n"
                f"    3. Groq service is down — check status.groq.com\n"
                f"  Detail: {e}"
            )
            print(msg)
            logger.error(msg)
            return {"response": "**Connection Error:** Could not reach Groq API. Check your internet connection or firewall.", "actions_taken": [], "tool_results": [], "error": "connection"}

        msg = response.choices[0].message

        # No tool calls — final answer
        if not msg.tool_calls:
            return {
                "response": msg.content,
                "actions_taken": actions_taken,
                "tool_results": tool_results
            }

        # Execute tool calls
        messages.append({
            "role": "assistant",
            "content": msg.content,
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments}
                }
                for tc in msg.tool_calls
            ]
        })

        for tc in msg.tool_calls:
            tool_name = tc.function.name
            try:
                tool_args = json.loads(tc.function.arguments)
            except Exception:
                tool_args = {}

            result = execute_tool(tool_name, tool_args)
            actions_taken.append(tool_name)
            tool_results.append({"tool": tool_name, "result": json.loads(result)})

            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result
            })

    return {
        "response": "Analysis complete. Please ask a specific question.",
        "actions_taken": actions_taken,
        "tool_results": tool_results
    }
