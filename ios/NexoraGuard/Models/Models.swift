import Foundation

// MARK: - Status

struct StatusResponse: Codable {
    let status: String?
    let timestamp: String?
    let overallRisk: String?
    let riskScore: Int
    let isAttack: Bool
    let ruleAlertCount: Int
    let hostname: String?
    let totalProcesses: Int
    let totalConnections: Int
    let suspiciousProcessCount: Int
    let suspiciousConnectionCount: Int
    let systemStats: SystemStats?

    enum CodingKeys: String, CodingKey {
        case status, timestamp, hostname
        case overallRisk = "overall_risk"
        case riskScore = "risk_score"
        case isAttack = "is_attack"
        case ruleAlertCount = "rule_alert_count"
        case totalProcesses = "total_processes"
        case totalConnections = "total_connections"
        case suspiciousProcessCount = "suspicious_process_count"
        case suspiciousConnectionCount = "suspicious_connection_count"
        case systemStats = "system_stats"
    }
}

struct SystemStats: Codable {
    let cpuPercent: Double
    let ramPercent: Double
    let diskPercent: Double
    let ramUsedGb: Double
    let ramTotalGb: Double

    enum CodingKeys: String, CodingKey {
        case cpuPercent = "cpu_percent"
        case ramPercent = "ram_percent"
        case diskPercent = "disk_percent"
        case ramUsedGb = "ram_used_gb"
        case ramTotalGb = "ram_total_gb"
    }
}

// MARK: - Alerts

struct AlertsResponse: Codable {
    let alerts: [Alert]
    let count: Int
}

struct Alert: Codable, Identifiable {
    var id: String { timestamp ?? UUID().uuidString }
    let timestamp: String?
    let risk: String?
    let score: Int
    let isAttack: Bool
    let ruleCount: Int
    let aiSummary: String?

    enum CodingKeys: String, CodingKey {
        case timestamp, risk, score
        case isAttack = "is_attack"
        case ruleCount = "rule_count"
        case aiSummary = "ai_summary"
    }
}

// MARK: - Network

struct NetworkResponse: Codable {
    let stats: NetworkStats?
    let connections: [Connection]
    let activeCount: Int
    let suspiciousCount: Int
    let totalCount: Int

    enum CodingKeys: String, CodingKey {
        case stats, connections
        case activeCount = "active_count"
        case suspiciousCount = "suspicious_count"
        case totalCount = "total_count"
    }
}

struct NetworkStats: Codable {
    let bytesSentMb: Double
    let bytesRecvMb: Double
    let packetsSent: Int
    let packetsRecv: Int

    enum CodingKeys: String, CodingKey {
        case bytesSentMb = "bytes_sent_mb"
        case bytesRecvMb = "bytes_recv_mb"
        case packetsSent = "packets_sent"
        case packetsRecv = "packets_recv"
    }
}

struct Connection: Codable, Identifiable {
    var id: String { "\(pid)-\(localAddr ?? "")-\(remoteAddr ?? "")" }
    let pid: Int
    let status: String?
    let localAddr: String?
    let remoteAddr: String?
    let suspiciousPort: Bool

    enum CodingKeys: String, CodingKey {
        case pid, status
        case localAddr = "local_addr"
        case remoteAddr = "remote_addr"
        case suspiciousPort = "suspicious_port"
    }
}

// MARK: - Chat

struct ChatRequest: Codable {
    let message: String
    let history: [ChatHistoryMessage]
}

struct ChatHistoryMessage: Codable {
    let role: String
    let content: String
}

struct ChatResponse: Codable {
    let response: String?
    let error: String?
    let model: String?
}

struct ChatBubble: Identifiable {
    let id = UUID()
    let sender: Sender
    let text: String
    let time: String

    enum Sender { case user, agent }
}

// MARK: - Timeline

struct TimelineResponse: Codable {
    let timeline: [Alert]
    let count: Int
    let generatedAt: String?

    enum CodingKeys: String, CodingKey {
        case timeline, count
        case generatedAt = "generated_at"
    }
}

// MARK: - Root

struct RootResponse: Codable {
    let name: String?
    let version: String?
    let status: String?
    let scanner: String?
    let licensed: Bool
    let edition: String?
    let mode: String?
}

// MARK: - Processes

struct ProcessesResponse: Codable {
    let suspiciousProcesses: [SuspiciousProcess]
    let count: Int

    enum CodingKeys: String, CodingKey {
        case suspiciousProcesses = "suspicious_processes"
        case count
    }
}

struct SuspiciousProcess: Codable, Identifiable {
    var id: Int { pid }
    let pid: Int
    let name: String?
    let cpu: Double
    let memory: Double
    let status: String?
}

// MARK: - Risk helpers

extension String {
    var riskColor: String {
        switch self {
        case "CRITICAL": return "#D32F2F"
        case "HIGH":     return "#F57C00"
        case "MEDIUM":   return "#F9A825"
        case "LOW":      return "#388E3C"
        default:         return "#1976D2"
        }
    }
}
