import SwiftUI

struct DashboardView: View {

    @ObservedObject private var poller = ThreatPollingManager.shared
    @State private var isScanning = false
    @State private var recentAlerts: [Alert] = []
    @State private var isRefreshing = false

    var body: some View {
        NavigationView {
            ZStack {
                Color.bgDark.ignoresSafeArea()

                ScrollView {
                    RefreshControl(isRefreshing: $isRefreshing, onRefresh: refresh)
                    VStack(spacing: 12) {

                        // ── Header ──────────────────────────────────────
                        headerRow

                        // ── Main Risk Card ───────────────────────────────
                        riskCard

                        // ── System Stats ─────────────────────────────────
                        systemStatsRow

                        // ── Process + Connection counts ──────────────────
                        processConnectionRow

                        // ── Info row ─────────────────────────────────────
                        infoRow

                        // ── Scan button ──────────────────────────────────
                        scanButton

                        // ── Recent Alerts ────────────────────────────────
                        SectionHeader(title: "RECENT ALERTS")
                        alertsList
                    }
                    .padding(.horizontal, 16)
                    .padding(.bottom, 16)
                }
            }
            .navigationBarHidden(true)
        }
        .onAppear(perform: loadAlerts)
    }

    // MARK: - Subviews

    private var headerRow: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("NEXORAGUARD")
                    .font(.system(size: 20, weight: .bold, design: .monospaced))
                    .foregroundColor(.accentCyan)
                    .kerning(2)
                Text(poller.latestStatus?.hostname ?? "Connecting...")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.textSecondary)
            }
            Spacer()
            HStack(spacing: 6) {
                Circle()
                    .fill(poller.isConnected ? Color.riskLow : Color.riskCritical)
                    .frame(width: 8, height: 8)
                Text(poller.isConnected ? "Live" : "Offline")
                    .font(.system(size: 11))
                    .foregroundColor(poller.isConnected ? .riskLow : .riskCritical)
            }
        }
        .padding(.top, 8)
    }

    private var riskCard: some View {
        let risk  = poller.latestStatus?.overallRisk ?? "ANALYZING"
        let score = poller.latestStatus?.riskScore ?? 0
        let isAtk = poller.latestStatus?.isAttack ?? false

        return VStack(alignment: .leading, spacing: 8) {
            Text("THREAT LEVEL")
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundColor(.white.opacity(0.7))
                .kerning(2)

            Text(risk)
                .font(.system(size: 38, weight: .bold, design: .monospaced))
                .foregroundColor(.white)

            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 5)
                        .fill(Color.white.opacity(0.2))
                        .frame(height: 10)
                    RoundedRectangle(cornerRadius: 5)
                        .fill(Color.white)
                        .frame(width: geo.size.width * CGFloat(score) / 100, height: 10)
                }
            }
            .frame(height: 10)

            HStack {
                Text("\(score)/100")
                    .font(.system(size: 16, weight: .bold, design: .monospaced))
                    .foregroundColor(.white)
                Spacer()
                Text(isAtk ? "ATTACK DETECTED" : "System Monitored")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(isAtk ? Color.riskCritical : Color.riskLow)
            }
        }
        .padding(20)
        .background(Color.riskColor(for: risk))
        .cornerRadius(16)
    }

    private var systemStatsRow: some View {
        let stats = poller.latestStatus?.systemStats
        return HStack(spacing: 8) {
            StatCard(label: "CPU",  value: pct(stats?.cpuPercent))
            StatCard(label: "RAM",  value: pct(stats?.ramPercent))
            StatCard(label: "DISK", value: pct(stats?.diskPercent))
        }
    }

    private var processConnectionRow: some View {
        let s = poller.latestStatus
        return HStack(spacing: 8) {
            StatCard(
                label: "PROCESSES",
                value: "\(s?.totalProcesses ?? 0)",
                subtitle: "\(s?.suspiciousProcessCount ?? 0) suspicious",
                valueColor: .textPrimary
            )
            StatCard(
                label: "CONNECTIONS",
                value: "\(s?.totalConnections ?? 0)",
                subtitle: "\(s?.suspiciousConnectionCount ?? 0) suspicious",
                valueColor: .textPrimary
            )
        }
    }

    private var infoRow: some View {
        let s = poller.latestStatus
        return HStack {
            Text("\(s?.ruleAlertCount ?? 0) rules triggered")
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.riskHigh)
            Spacer()
            if let ts = s?.timestamp, ts.count >= 19 {
                Text("Last: \(String(ts.prefix(19)).replacingOccurrences(of: "T", with: " "))")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.textSecondary)
            }
        }
    }

    private var scanButton: some View {
        Button(action: triggerScan) {
            HStack {
                if isScanning {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .bgDark))
                        .scaleEffect(0.8)
                }
                Text(isScanning ? "SCANNING..." : "SCAN NOW")
                    .font(.system(size: 15, weight: .bold, design: .monospaced))
                    .kerning(1)
            }
            .foregroundColor(.bgDark)
            .frame(maxWidth: .infinity)
            .frame(height: 52)
            .background(Color.accentCyan)
            .cornerRadius(12)
        }
        .disabled(isScanning)
    }

    private var alertsList: some View {
        VStack(spacing: 0) {
            if recentAlerts.isEmpty {
                Text("No recent alerts — system clean")
                    .font(.system(size: 13))
                    .foregroundColor(.riskLow)
                    .padding()
            } else {
                ForEach(recentAlerts) { alert in
                    alertRow(alert)
                    if alert.id != recentAlerts.last?.id {
                        Divider().background(Color.divider)
                    }
                }
            }
        }
        .background(Color.bgCard2)
        .cornerRadius(12)
    }

    private func alertRow(_ alert: Alert) -> some View {
        HStack(alignment: .top, spacing: 10) {
            RoundedRectangle(cornerRadius: 2)
                .fill(Color.riskColor(for: alert.risk))
                .frame(width: 3)
                .frame(minHeight: 36)

            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    RiskBadge(risk: alert.risk)
                    Spacer()
                    if let ts = alert.timestamp, ts.count >= 19 {
                        Text(String(ts.suffix(from: ts.index(ts.startIndex, offsetBy: 11)).prefix(8)))
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(.textSecondary)
                    }
                }
                Text(alert.aiSummary ?? "No summary")
                    .font(.system(size: 13))
                    .foregroundColor(.textPrimary)
                    .lineLimit(2)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
    }

    // MARK: - Actions

    private func refresh() {
        loadAlerts()
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            isRefreshing = false
        }
    }

    private func loadAlerts() {
        APIService.shared.getAlerts(limit: 5) { result in
            DispatchQueue.main.async {
                if case .success(let resp) = result {
                    recentAlerts = resp.alerts
                }
            }
        }
    }

    private func triggerScan() {
        isScanning = true
        APIService.shared.triggerScan { _ in
            DispatchQueue.main.async {
                isScanning = false
                loadAlerts()
            }
        }
    }

    private func pct(_ val: Double?) -> String {
        guard let v = val else { return "–%" }
        return String(format: "%.1f%%", v)
    }
}

// MARK: - Pull-to-refresh helper (iOS 14 compatible)

struct RefreshControl: View {
    @Binding var isRefreshing: Bool
    let onRefresh: () -> Void

    var body: some View { EmptyView() }
}
