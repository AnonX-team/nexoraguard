import SwiftUI

struct AlertsView: View {

    @State private var allAlerts: [Alert] = []
    @State private var activeFilter = "ALL"
    @State private var isLoading = false

    private let filters = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]

    var filtered: [Alert] {
        guard activeFilter != "ALL" else { return allAlerts }
        return allAlerts.filter { $0.risk == activeFilter }
    }

    var body: some View {
        NavigationView {
            ZStack {
                Color.bgDark.ignoresSafeArea()

                VStack(spacing: 0) {
                    // ── Header ────────────────────────────────────────────
                    HStack {
                        Text("SECURITY ALERTS")
                            .font(.system(size: 16, weight: .bold, design: .monospaced))
                            .foregroundColor(.accentCyan)
                            .kerning(1)
                        Spacer()
                        Text("\(allAlerts.count)")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.white)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(Color.riskCritical)
                            .cornerRadius(4)
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                    .background(Color.bgCard)

                    // ── Filter chips ──────────────────────────────────────
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(filters, id: \.self) { f in
                                Button(f) { activeFilter = f }
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(activeFilter == f ? .bgDark : .textSecondary)
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 7)
                                    .background(activeFilter == f ? Color.accentCyan : Color.bgCard)
                                    .cornerRadius(20)
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                    }

                    // ── List ──────────────────────────────────────────────
                    if isLoading {
                        Spacer()
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: .accentCyan))
                        Spacer()
                    } else if filtered.isEmpty {
                        Spacer()
                        VStack(spacing: 8) {
                            Image(systemName: "checkmark.shield.fill")
                                .font(.system(size: 40))
                                .foregroundColor(.riskLow)
                            Text(allAlerts.isEmpty ? "No alerts yet" : "No \(activeFilter) alerts")
                                .foregroundColor(.textSecondary)
                        }
                        Spacer()
                    } else {
                        List(filtered) { alert in
                            AlertRow(alert: alert)
                                .listRowBackground(Color.bgDark)
                                .listRowInsets(EdgeInsets(top: 4, leading: 12, bottom: 4, trailing: 12))
                        }
                        .listStyle(.plain)
                        .refreshable { await loadAlerts() }
                    }
                }
            }
            .navigationBarHidden(true)
        }
        .onAppear { Task { await loadAlerts() } }
    }

    @MainActor
    private func loadAlerts() async {
        isLoading = allAlerts.isEmpty
        await withCheckedContinuation { continuation in
            APIService.shared.getAlerts(limit: 50) { result in
                if case .success(let resp) = result {
                    allAlerts = resp.alerts
                }
                continuation.resume()
            }
        }
        isLoading = false
    }
}

// MARK: - Alert row

struct AlertRow: View {
    let alert: Alert

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            RoundedRectangle(cornerRadius: 2)
                .fill(Color.riskColor(for: alert.risk))
                .frame(width: 4)
                .frame(minHeight: 50)

            VStack(alignment: .leading, spacing: 5) {
                HStack {
                    RiskBadge(risk: alert.risk)
                    Spacer()
                    if let ts = alert.timestamp, ts.count >= 19 {
                        Text(ts.prefix(19).replacingOccurrences(of: "T", with: " "))
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundColor(.textSecondary)
                    }
                }
                Text(alert.aiSummary ?? "No summary available")
                    .font(.system(size: 13))
                    .foregroundColor(.textPrimary)
                    .lineLimit(3)

                Text("Score: \(alert.score)/100 · Rules: \(alert.ruleCount)")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.textSecondary)
            }
        }
        .padding(.vertical, 8)
    }
}
