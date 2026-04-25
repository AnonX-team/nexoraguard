"""
Prevention Module — NexoraGuard (Ethreon-Inspired)
Per-protocol hardening recommendations and proactive security measures.

Maps each DDoS/attack alert type to specific Windows hardening actions:
  - Windows Firewall (netsh) rules
  - Registry TCP/IP hardening
  - Service disablement commands
  - Manual configuration steps

Ethreon Coverage Parity:
  - 15 DDoS protocol prevention actions
  - Amplification factor reference (DNS 179×, NTP 556×, Memcached 51,200×, etc.)
  - General Windows hardening baseline
  - MITRE ATT&CK prevented technique mapping

MITRE ATT&CK:
  T1498 — Network Denial of Service
  T1499 — Endpoint Denial of Service
  T1046 — Network Service Discovery
"""
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


# ── Per-protocol hardening table ───────────────────────────────────────────────

PROTOCOL_HARDENING: dict = {

    "CONNECTION_FLOOD": {
        "title":       "TCP Connection Flood Mitigation",
        "description": "Excessive TCP connections from single IP — TCP stack exhaustion attack.",
        "severity":    "CRITICAL",
        "mitre":       "T1498.001",
        "protocol":    "TCP",
        "actions": [
            {
                "action":   "Enable SYN cookie protection",
                "command":  "netsh int tcp set global autotuninglevel=normal",
                "type":     "command",
                "priority": "HIGH",
                "detail":   "SYN cookies allow the server to handle SYN floods without maintaining half-open state.",
            },
            {
                "action":   "Reduce TCP TIME_WAIT timeout to reclaim sockets faster",
                "command":  "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v TcpTimedWaitDelay /t REG_DWORD /d 30 /f",
                "type":     "registry",
                "priority": "HIGH",
            },
            {
                "action":   "Block flooding source IP via Windows Firewall",
                "command":  "netsh advfirewall firewall add rule name=\"Block Flood IP\" protocol=TCP dir=in remoteip=<ATTACKER_IP> action=block",
                "type":     "firewall",
                "priority": "HIGH",
            },
            {
                "action":   "Contact upstream ISP for traffic scrubbing if attack persists",
                "type":     "manual",
                "priority": "MEDIUM",
                "detail":   "ISP-level null routing (RTBH) drops attack traffic before it reaches your connection.",
            },
        ],
    },

    "SYN_FLOOD": {
        "title":       "SYN Flood Defense",
        "description": "Half-open TCP connection accumulation — TCP stack targeted to exhaust resources.",
        "severity":    "CRITICAL",
        "mitre":       "T1498.001",
        "protocol":    "TCP/SYN",
        "actions": [
            {
                "action":   "Enable SYN attack protection (level 2)",
                "command":  "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v SynAttackProtect /t REG_DWORD /d 2 /f",
                "type":     "registry",
                "priority": "CRITICAL",
            },
            {
                "action":   "Reduce maximum half-open connections",
                "command":  "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v TcpMaxHalfOpen /t REG_DWORD /d 100 /f",
                "type":     "registry",
                "priority": "HIGH",
            },
            {
                "action":   "Reduce maximum retried half-open connections",
                "command":  "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v TcpMaxHalfOpenRetried /t REG_DWORD /d 80 /f",
                "type":     "registry",
                "priority": "HIGH",
            },
            {
                "action":   "Enable TCP RST response for invalid connections",
                "type":     "manual",
                "priority": "MEDIUM",
                "detail":   "Configure Windows Filtering Platform (WFP) to send RST for connections exceeding SYN rate limit.",
            },
        ],
    },

    "UDP_FLOOD": {
        "title":       "UDP Flood Mitigation",
        "description": "High-volume UDP traffic — connectionless flood exhausting bandwidth and CPU.",
        "severity":    "HIGH",
        "mitre":       "T1498.001",
        "protocol":    "UDP",
        "actions": [
            {
                "action":   "Block inbound UDP on all non-essential ports",
                "command":  "netsh advfirewall firewall add rule name=\"Block UDP Flood\" protocol=UDP dir=in action=block localport=1-1024",
                "type":     "firewall",
                "priority": "HIGH",
            },
            {
                "action":   "Disable legacy UDP services (Chargen, Echo, Discard)",
                "command":  "sc stop chargen && sc config chargen start=disabled",
                "type":     "command",
                "priority": "HIGH",
                "detail":   "Ports 7 (Echo), 9 (Discard), 19 (Chargen) are common UDP amplification vectors.",
            },
            {
                "action":   "Enable UDP rate limiting on edge router",
                "type":     "manual",
                "priority": "MEDIUM",
                "detail":   "Configure router to rate-limit UDP packets per second per source IP.",
            },
        ],
    },

    "DNS_AMPLIFICATION": {
        "title":       "DNS Amplification Defense",
        "description": "DNS reflection/amplification attack (179× amplification factor).",
        "severity":    "CRITICAL",
        "mitre":       "T1498.002",
        "protocol":    "DNS",
        "amp_factor":  179,
        "actions": [
            {
                "action":   "Disable open DNS recursion if running a DNS server",
                "type":     "manual",
                "priority": "CRITICAL",
                "detail":   "In DNS server config: restrict recursion to internal ranges only. Example for BIND: allow-recursion { 192.168.0.0/16; }; Block external recursive queries entirely.",
            },
            {
                "action":   "Block outbound UDP 53 from non-DNS services",
                "command":  "netsh advfirewall firewall add rule name=\"Restrict DNS\" protocol=UDP dir=out remoteport=53 action=block",
                "type":     "firewall",
                "priority": "HIGH",
            },
            {
                "action":   "Enable DNS Response Rate Limiting (RRL)",
                "type":     "manual",
                "priority": "HIGH",
                "detail":   "RRL caps responses per second to each source, preventing your DNS server from being an amplifier.",
            },
        ],
    },

    "NTP_AMPLIFICATION": {
        "title":       "NTP Amplification Defense",
        "description": "NTP monlist amplification attack (556× amplification — highest common protocol).",
        "severity":    "CRITICAL",
        "mitre":       "T1498.002",
        "protocol":    "NTP",
        "amp_factor":  556,
        "actions": [
            {
                "action":   "Disable NTP monlist command on NTP server",
                "type":     "manual",
                "priority": "CRITICAL",
                "detail":   "Add 'disable monitor' to ntp.conf. Monlist returns up to 600 recent clients per query = 556× amplification. This single change eliminates the attack vector.",
            },
            {
                "action":   "Block inbound UDP 123 if not running NTP server",
                "command":  "netsh advfirewall firewall add rule name=\"Block NTP\" protocol=UDP dir=in localport=123 action=block",
                "type":     "firewall",
                "priority": "HIGH",
            },
            {
                "action":   "Upgrade NTP to version 4.2.7p26+ (monlist disabled by default)",
                "type":     "manual",
                "priority": "HIGH",
                "detail":   "Versions prior to 4.2.7p26 have monlist enabled by default. Upgrade removes the vulnerability entirely.",
            },
        ],
    },

    "SSDP_AMPLIFICATION": {
        "title":       "SSDP/UPnP Amplification Defense",
        "description": "SSDP reflection via UPnP (30× amplification).",
        "severity":    "HIGH",
        "mitre":       "T1498.002",
        "protocol":    "SSDP",
        "amp_factor":  30,
        "actions": [
            {
                "action":   "Disable Windows UPnP service",
                "command":  "sc stop upnphost && sc config upnphost start=disabled",
                "type":     "command",
                "priority": "HIGH",
            },
            {
                "action":   "Block UDP 1900 (SSDP discovery port)",
                "command":  "netsh advfirewall firewall add rule name=\"Block SSDP\" protocol=UDP dir=in localport=1900 action=block",
                "type":     "firewall",
                "priority": "HIGH",
            },
            {
                "action":   "Disable UPnP on your router/modem",
                "type":     "manual",
                "priority": "MEDIUM",
                "detail":   "Log into router admin panel and disable UPnP. This prevents router from serving as SSDP reflector.",
            },
        ],
    },

    "MEMCACHED_AMPLIFICATION": {
        "title":       "Memcached Reflection Defense",
        "description": "Memcached UDP reflection (51,200× amplification — highest of any protocol).",
        "severity":    "CRITICAL",
        "mitre":       "T1498.002",
        "protocol":    "Memcached",
        "amp_factor":  51200,
        "actions": [
            {
                "action":   "Block UDP 11211 IMMEDIATELY (Memcached)",
                "command":  "netsh advfirewall firewall add rule name=\"Block Memcached UDP\" protocol=UDP dir=in localport=11211 action=block",
                "type":     "firewall",
                "priority": "CRITICAL",
                "detail":   "51,200× amplification makes Memcached the most dangerous reflector. Block immediately.",
            },
            {
                "action":   "Bind Memcached to localhost only",
                "command":  "memcached -l 127.0.0.1",
                "type":     "command",
                "priority": "CRITICAL",
                "detail":   "Memcached must NEVER be internet-accessible. Bind to 127.0.0.1 or use firewall whitelist.",
            },
            {
                "action":   "Disable Memcached UDP entirely",
                "command":  "memcached -U 0",
                "type":     "command",
                "priority": "HIGH",
                "detail":   "UDP is unnecessary for most Memcached deployments. Disable with -U 0 to eliminate reflection surface.",
            },
        ],
    },

    "LDAP_AMPLIFICATION": {
        "title":       "LDAP/CLDAP Reflection Defense",
        "description": "LDAP reflection via anonymous bind queries (70× amplification).",
        "severity":    "HIGH",
        "mitre":       "T1498.002",
        "protocol":    "LDAP",
        "amp_factor":  70,
        "actions": [
            {
                "action":   "Disable anonymous LDAP binding",
                "type":     "manual",
                "priority": "HIGH",
                "detail":   "Active Directory: Group Policy → Computer Config → Windows Settings → Security Settings → Local Policies → Security Options → 'Network access: Allow anonymous SID/name translation' → Disabled.",
            },
            {
                "action":   "Block UDP 389 (CLDAP) from external IPs",
                "command":  "netsh advfirewall firewall add rule name=\"Block CLDAP\" protocol=UDP dir=in localport=389 action=block",
                "type":     "firewall",
                "priority": "HIGH",
            },
            {
                "action":   "Restrict LDAP to internal network only",
                "type":     "manual",
                "priority": "MEDIUM",
                "detail":   "Configure DC firewall to block LDAP (389, 636) and CLDAP (389/UDP) from untrusted network segments.",
            },
        ],
    },

    "HTTP_FLOOD": {
        "title":       "HTTP GET/POST Flood Mitigation",
        "description": "Application-layer HTTP flood — high request rate exhausting web server threads.",
        "severity":    "CRITICAL",
        "mitre":       "T1499.004",
        "protocol":    "HTTP",
        "actions": [
            {
                "action":   "Enable web server rate limiting",
                "type":     "manual",
                "priority": "HIGH",
                "detail":   "IIS: Dynamic IP Restrictions module. nginx: limit_req_zone. Apache: mod_evasive or mod_limitipconn. Cap at 100 req/min per IP.",
            },
            {
                "action":   "Block flooding IP via Windows Firewall",
                "command":  "netsh advfirewall firewall add rule name=\"Block HTTP Flood\" protocol=TCP dir=in remoteip=<ATTACKER_IP> localport=80,443 action=block",
                "type":     "firewall",
                "priority": "HIGH",
            },
            {
                "action":   "Deploy Web Application Firewall (WAF)",
                "type":     "manual",
                "priority": "HIGH",
                "detail":   "Cloudflare, AWS WAF, or Windows WAP with HTTP flood detection rules. Challenges suspected bot IPs with JS challenge or CAPTCHA.",
            },
            {
                "action":   "Enable CAPTCHA for suspicious request patterns",
                "type":     "manual",
                "priority": "MEDIUM",
                "detail":   "Add challenge (hCaptcha, reCAPTCHA) for IPs exceeding threshold — distinguishes bots from legitimate users.",
            },
        ],
    },

    "SLOWLORIS": {
        "title":       "Slowloris Defense",
        "description": "Slow HTTP connection attack — partial headers holding connections open to exhaust web server pool.",
        "severity":    "HIGH",
        "mitre":       "T1499.004",
        "protocol":    "HTTP/Slowloris",
        "actions": [
            {
                "action":   "Set short timeout for incomplete HTTP request headers",
                "type":     "manual",
                "priority": "HIGH",
                "detail":   "Apache: RequestReadTimeout header=10-20,MinRate=500. nginx: client_header_timeout 10s. IIS: connectionTimeout=10. Close connections that don't complete headers within 10-20s.",
            },
            {
                "action":   "Limit maximum concurrent connections per IP",
                "type":     "manual",
                "priority": "HIGH",
                "detail":   "Apache: mod_limitipconn (MaxConnPerIP 20). nginx: limit_conn zone 20. IIS: Dynamic IP Restrictions with max concurrent requests = 20.",
            },
            {
                "action":   "Use nginx as reverse proxy in front of application server",
                "type":     "manual",
                "priority": "MEDIUM",
                "detail":   "nginx buffers slow clients and only forwards complete requests to backend — transparently eliminates Slowloris impact on application servers.",
            },
        ],
    },

    "PORT_SCAN": {
        "title":       "Port Scan Defense",
        "description": "Active network reconnaissance — attacker mapping open services before attack.",
        "severity":    "HIGH",
        "mitre":       "T1046",
        "protocol":    "TCP",
        "actions": [
            {
                "action":   "Block scanning IP immediately via NexoraGuard",
                "type":     "firewall",
                "priority": "HIGH",
                "detail":   "Use the Brute Force tab Block button or /bruteforce/block API endpoint to add Windows Firewall rule.",
            },
            {
                "action":   "Enable Windows Defender firewall on all profiles",
                "command":  "netsh advfirewall set allprofiles state on",
                "type":     "command",
                "priority": "HIGH",
            },
            {
                "action":   "Close unused listening ports",
                "type":     "manual",
                "priority": "MEDIUM",
                "detail":   "Use NexoraGuard Network tab to identify all LISTEN state services. Disable or uninstall services not required.",
            },
            {
                "action":   "Enable port-based stealth mode (no ICMP unreachable on blocked ports)",
                "type":     "manual",
                "priority": "LOW",
                "detail":   "By default, closed ports return TCP RST, confirming their existence. Configure firewall to DROP instead of REJECT to slow port scanning.",
            },
        ],
    },

    "CARPET_BOMBING": {
        "title":       "Carpet Bombing Defense",
        "description": "Subnet-distributed flood — multiple /24 IPs targeting you to evade per-IP thresholds.",
        "severity":    "HIGH",
        "mitre":       "T1498.001",
        "protocol":    "Multi-vector",
        "actions": [
            {
                "action":   "Block entire attacking /24 subnet",
                "command":  "netsh advfirewall firewall add rule name=\"Block Attacking Subnet\" protocol=any dir=in remoteip=<SUBNET>/24 action=block",
                "type":     "firewall",
                "priority": "HIGH",
                "detail":   "Use with caution — entire subnet block may affect legitimate users sharing the range. Verify with GeoIP data first.",
            },
            {
                "action":   "Request ISP for BGP RTBH (Remote Triggered Black Hole)",
                "type":     "manual",
                "priority": "HIGH",
                "detail":   "For subnet-level carpet bombing, ISP upstream filtering is most effective. Request BGP null-routing of the attacking /24 prefix.",
            },
            {
                "action":   "Implement geographic IP blocking for confirmed attack regions",
                "type":     "manual",
                "priority": "MEDIUM",
                "detail":   "If attack sources are geographically concentrated, geo-block the region via upstream CDN (Cloudflare, Akamai) or Windows Firewall with GeoIP lists.",
            },
        ],
    },

    "IOT_BOTNET": {
        "title":       "IoT Botnet (Mirai-style) Defense",
        "description": "Distributed IoT botnet flood — many unique compromised devices, each contributing few connections.",
        "severity":    "HIGH",
        "mitre":       "T1498.001",
        "protocol":    "Botnet/Mirai",
        "actions": [
            {
                "action":   "Switch to aggregate rate limiting (not per-IP)",
                "type":     "manual",
                "priority": "HIGH",
                "detail":   "Botnet distributes across many IPs to evade per-IP limits. Use total connection-rate limiting at service level: nginx limit_req (global zone), not per-IP zone.",
            },
            {
                "action":   "Enable JavaScript challenge or CAPTCHA for new visitors",
                "type":     "manual",
                "priority": "HIGH",
                "detail":   "IoT bots cannot execute JavaScript or solve CAPTCHAs. Cloudflare Under Attack Mode or similar instantly blocks ~99% of botnet traffic.",
            },
            {
                "action":   "Report attacking IPs to AbuseIPDB and ISP abuse contacts",
                "type":     "manual",
                "priority": "MEDIUM",
                "detail":   "Coordinated reporting to AbuseIPDB, Spamhaus DROP, and ISP abuse teams helps get compromised device owners notified and C2 infrastructure taken down.",
            },
            {
                "action":   "Fingerprint and share botnet indicators",
                "type":     "manual",
                "priority": "LOW",
                "detail":   "Capture connection patterns, User-Agents, and timing signatures to identify botnet variant (Mirai, Satori, Bashlite). Share with security community via threat sharing platforms.",
            },
        ],
    },

    "BANDWIDTH_SPIKE": {
        "title":       "Volumetric Attack Defense",
        "description": "Sudden bandwidth spike exceeding 3σ from baseline — possible volumetric flood consuming uplink.",
        "severity":    "HIGH",
        "mitre":       "T1498",
        "protocol":    "Multi-vector",
        "actions": [
            {
                "action":   "Contact ISP for upstream traffic scrubbing",
                "type":     "manual",
                "priority": "HIGH",
                "detail":   "Volumetric attacks exceeding your uplink capacity can only be mitigated upstream. Contact ISP for null-routing or scrubbing center activation immediately.",
            },
            {
                "action":   "Enable QoS to prioritize management traffic",
                "type":     "manual",
                "priority": "MEDIUM",
                "detail":   "Configure router QoS to guarantee bandwidth for management/SSH traffic so you maintain control even under attack.",
            },
            {
                "action":   "Activate CDN-based DDoS protection",
                "type":     "manual",
                "priority": "MEDIUM",
                "detail":   "Services like Cloudflare, Akamai, or AWS Shield absorb volumetric attacks at their global network edges before traffic reaches your infrastructure.",
            },
        ],
    },
}


# ── General hardening baseline (Ethreon Prevention Module parity) ─────────────

GENERAL_HARDENING: list = [
    {
        "category":       "Firewall",
        "title":          "Enable Windows Defender Firewall on all profiles",
        "command":        "netsh advfirewall set allprofiles state on",
        "type":           "command",
        "priority":       "CRITICAL",
        "mitre_prevents": ["T1498", "T1499", "T1046"],
    },
    {
        "category":       "TCP/IP Hardening",
        "title":          "Disable ICMP redirects (routing manipulation prevention)",
        "command":        "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v EnableICMPRedirect /t REG_DWORD /d 0 /f",
        "type":           "registry",
        "priority":       "HIGH",
        "mitre_prevents": ["T1498", "T1557"],
    },
    {
        "category":       "TCP/IP Hardening",
        "title":          "Enable SYN attack protection at OS level",
        "command":        "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v SynAttackProtect /t REG_DWORD /d 2 /f",
        "type":           "registry",
        "priority":       "HIGH",
        "mitre_prevents": ["T1498.001"],
    },
    {
        "category":       "Services",
        "title":          "Disable Remote Registry service",
        "command":        "sc stop RemoteRegistry && sc config RemoteRegistry start=disabled",
        "type":           "command",
        "priority":       "HIGH",
        "mitre_prevents": ["T1021", "T1046"],
    },
    {
        "category":       "Network",
        "title":          "Disable LLMNR (Link-Local Multicast Name Resolution)",
        "type":           "manual",
        "priority":       "HIGH",
        "detail":         "Group Policy: Computer Config → Admin Templates → Network → DNS Client → 'Turn off multicast name resolution' = Enabled. Prevents LLMNR poisoning attacks.",
        "mitre_prevents": ["T1557"],
    },
    {
        "category":       "Network",
        "title":          "Disable NetBIOS over TCP/IP",
        "type":           "manual",
        "priority":       "MEDIUM",
        "detail":         "Network Adapter → IPv4 Properties → Advanced → WINS → 'Disable NetBIOS over TCP/IP'. Eliminates NBT-NS poisoning vector.",
        "mitre_prevents": ["T1557"],
    },
    {
        "category":       "Monitoring",
        "title":          "Keep NexoraGuard scan interval ≤15s during active threats",
        "type":           "config",
        "priority":       "MEDIUM",
        "detail":         "NexoraGuard auto-adjusts scan interval based on risk score. During HIGH/CRITICAL threats it automatically drops to minimum 10s interval.",
        "mitre_prevents": ["T1498", "T1499"],
    },
]


# ── Alert type → protocol key mapping ─────────────────────────────────────────

_ALERT_TO_PROTOCOL: dict = {
    "CONNECTION_FLOOD":        "CONNECTION_FLOOD",
    "CONNECTION_SURGE":        "CONNECTION_FLOOD",
    "SYN_FLOOD":               "SYN_FLOOD",
    "SYN_SURGE":               "SYN_FLOOD",
    "TIME_WAIT_FLOOD":         "SYN_FLOOD",
    "UDP_FLOOD":               "UDP_FLOOD",
    "UDP_SURGE":               "UDP_FLOOD",
    "UDP_SOURCE_FLOOD":        "UDP_FLOOD",
    "DNS_AMPLIFICATION":       "DNS_AMPLIFICATION",
    "NTP_AMPLIFICATION":       "NTP_AMPLIFICATION",
    "SSDP_AMPLIFICATION":      "SSDP_AMPLIFICATION",
    "MEMCACHED_AMPLIFICATION": "MEMCACHED_AMPLIFICATION",
    "LDAP_AMPLIFICATION":      "LDAP_AMPLIFICATION",
    "CHARGEN_AMPLIFICATION":   "UDP_FLOOD",
    "PORTMAPPER_AMPLIFICATION":"UDP_FLOOD",
    "HTTP_FLOOD":              "HTTP_FLOOD",
    "HTTP_FLOOD_SURGE":        "HTTP_FLOOD",
    "SLOWLORIS":               "SLOWLORIS",
    "PORT_SCAN":               "PORT_SCAN",
    "CARPET_BOMBING":          "CARPET_BOMBING",
    "IOT_BOTNET":              "IOT_BOTNET",
    "BANDWIDTH_SPIKE":         "BANDWIDTH_SPIKE",
    "ENTROPY_FLOOD":           "BANDWIDTH_SPIKE",
    "ENTROPY_LOW":             "BANDWIDTH_SPIKE",
}


# ── Public API ─────────────────────────────────────────────────────────────────

def get_recommendations_for_alerts(ddos_alerts: list) -> list:
    """
    Given DDoS detection alerts, return protocol-specific hardening recommendations.
    Deduplicates by protocol — returns at most one recommendation set per protocol.
    """
    recommendations = []
    seen_protocols: set = set()
    for alert in ddos_alerts:
        proto_key = _ALERT_TO_PROTOCOL.get(alert.get("type", ""))
        if not proto_key or proto_key in seen_protocols:
            continue
        rec = PROTOCOL_HARDENING.get(proto_key)
        if not rec:
            continue
        seen_protocols.add(proto_key)
        recommendations.append({
            **rec,
            "triggered_by":  alert.get("type"),
            "source_ip":     alert.get("source_ip"),
            "attack_count":  alert.get("count", 0),
            "generated_at":  datetime.now().isoformat(),
        })
    return recommendations


def get_general_hardening() -> list:
    """Return general baseline hardening recommendations (always applicable)."""
    return GENERAL_HARDENING


def get_protocol_by_key(key: str) -> dict:
    """Return hardening details for a specific protocol key."""
    return PROTOCOL_HARDENING.get(key, {})


def get_all_protocol_coverage() -> dict:
    """Return the 15-protocol coverage table (mirrors Ethreon protocol list)."""
    return {
        "total_protocols": 15,
        "protocols": [
            {"id": 1,  "name": "TCP Connection Flood",  "mitre": "T1498.001", "amp_factor": None,  "key": "CONNECTION_FLOOD",        "severity": "CRITICAL"},
            {"id": 2,  "name": "SYN Flood",             "mitre": "T1498.001", "amp_factor": None,  "key": "SYN_FLOOD",               "severity": "CRITICAL"},
            {"id": 3,  "name": "UDP Flood",             "mitre": "T1498.001", "amp_factor": None,  "key": "UDP_FLOOD",               "severity": "HIGH"},
            {"id": 4,  "name": "DNS Amplification",     "mitre": "T1498.002", "amp_factor": 179,   "key": "DNS_AMPLIFICATION",       "severity": "CRITICAL"},
            {"id": 5,  "name": "NTP Amplification",     "mitre": "T1498.002", "amp_factor": 556,   "key": "NTP_AMPLIFICATION",       "severity": "CRITICAL"},
            {"id": 6,  "name": "SSDP/UPnP Amplification","mitre":"T1498.002", "amp_factor": 30,    "key": "SSDP_AMPLIFICATION",      "severity": "HIGH"},
            {"id": 7,  "name": "Memcached Reflection",  "mitre": "T1498.002", "amp_factor": 51200, "key": "MEMCACHED_AMPLIFICATION",  "severity": "CRITICAL"},
            {"id": 8,  "name": "LDAP/CLDAP Reflection", "mitre": "T1498.002", "amp_factor": 70,    "key": "LDAP_AMPLIFICATION",      "severity": "HIGH"},
            {"id": 9,  "name": "HTTP GET/POST Flood",   "mitre": "T1499.004", "amp_factor": None,  "key": "HTTP_FLOOD",              "severity": "CRITICAL"},
            {"id": 10, "name": "Slowloris",             "mitre": "T1499.004", "amp_factor": None,  "key": "SLOWLORIS",               "severity": "HIGH"},
            {"id": 11, "name": "Port Scan",             "mitre": "T1046",    "amp_factor": None,  "key": "PORT_SCAN",               "severity": "HIGH"},
            {"id": 12, "name": "Carpet Bombing",        "mitre": "T1498.001", "amp_factor": None,  "key": "CARPET_BOMBING",          "severity": "HIGH"},
            {"id": 13, "name": "IoT Botnet (Mirai)",    "mitre": "T1498.001", "amp_factor": None,  "key": "IOT_BOTNET",              "severity": "HIGH"},
            {"id": 14, "name": "Bandwidth Spike",       "mitre": "T1498",    "amp_factor": None,  "key": "BANDWIDTH_SPIKE",         "severity": "HIGH"},
            {"id": 15, "name": "Entropy Flood",         "mitre": "T1498.001", "amp_factor": None,  "key": "ENTROPY_FLOOD",           "severity": "CRITICAL"},
        ],
    }
