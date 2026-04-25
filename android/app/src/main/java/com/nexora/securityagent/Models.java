package com.nexora.securityagent;

import java.util.List;

// ── Status Response ───────────────────────────────────────────────────────────
class StatusResponse {
    String status;
    String timestamp;
    String overall_risk;
    int risk_score;
    boolean is_attack;
    int rule_alert_count;
    String hostname;
    int total_processes;
    int total_connections;
    int suspicious_process_count;
    int suspicious_connection_count;
    SystemStats system_stats;

    static class SystemStats {
        double cpu_percent;
        double ram_percent;
        double disk_percent;
        double ram_used_gb;
        double ram_total_gb;
    }
}

// ── Analysis Response ─────────────────────────────────────────────────────────
class AnalysisResponse {
    String timestamp;
    String overall_risk;
    int risk_score;
    boolean is_attack;
    int rule_alert_count;
    List<RuleAlert> rule_alerts;
    AiAnalysis ai_analysis;

    static class RuleAlert {
        String rule;
        String severity;
        String message;
        String timestamp;
    }

    static class AiAnalysis {
        String risk_level;
        int risk_score;
        boolean is_attack;
        String attack_type;
        String summary;
        List<String> recommendations;
    }
}

// ── Alerts Response ───────────────────────────────────────────────────────────
class AlertsResponse {
    List<Alert> alerts;
    int count;

    static class Alert {
        String timestamp;
        String risk;
        int score;
        boolean is_attack;
        int rule_count;
        String ai_summary;
    }
}

// ── Processes Response ────────────────────────────────────────────────────────
class ProcessesResponse {
    List<Process> suspicious_processes;
    int count;

    static class Process {
        int pid;
        String name;
        double cpu;
        double memory;
        String status;
        boolean suspicious;
    }
}

// ── Network Response ──────────────────────────────────────────────────────────
class NetworkResponse {
    NetworkStats stats;
    List<Connection> connections;
    int active_count;
    int suspicious_count;
    int total_count;

    static class NetworkStats {
        double bytes_sent_mb;
        double bytes_recv_mb;
        long packets_sent;
        long packets_recv;
    }

    static class Connection {
        int pid;
        String status;
        String local_addr;
        String remote_addr;
        boolean suspicious_port;
    }
}

// ── Integrity Response ────────────────────────────────────────────────────────
class IntegrityResponse {
    String checked_at;
    List<Violation> violations;
    int violation_count;
    boolean clean;

    static class Violation {
        String path;
        String status;
        String severity;
        String message;
    }
}

// ── Kill Request/Response ─────────────────────────────────────────────────────
class KillRequest {
    int pid;
    String name;
    KillRequest(int pid, String name) {
        this.pid = pid;
        this.name = name;
    }
}

class KillResponse {
    boolean success;
    String message;
}

// ── Chat Request/Response ─────────────────────────────────────────────────────
class ChatRequest {
    String message;
    List<ChatMessage> history;

    ChatRequest(String message, List<ChatMessage> history) {
        this.message = message;
        this.history = history;
    }
}

class ChatMessage {
    String role;   // "user" or "assistant"
    String content;

    ChatMessage(String role, String content) {
        this.role = role;
        this.content = content;
    }
}

class ChatResponse {
    String response;
    String error;
    String model;
}

// ── Timeline Response ─────────────────────────────────────────────────────────
class TimelineResponse {
    java.util.List<TimelineEntry> timeline;
    int count;
    String generated_at;

    static class TimelineEntry {
        String timestamp;
        String risk;
        int score;
        boolean is_attack;
        int rule_count;
        String ai_summary;
    }
}

// ── Root/Status Response ──────────────────────────────────────────────────────
class RootResponse {
    String name;
    String version;
    String status;
    String scanner;
    boolean licensed;
    String edition;
    String mode;
}
