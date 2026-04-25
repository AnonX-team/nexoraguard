import SwiftUI

struct NetworkView: View {

    @State private var networkData: NetworkResponse?
    @State private var showSuspiciousOnly = false
    @State private var isLoading = false

    var connections: [Connection] {
        let all = networkData?.connections ?? []
        return showSuspiciousOnly ? all.filter { $0.suspiciousPort } : all
    }

    var body: some View {
        NavigationView {
            ZStack {
                Color.bgDark.ignoresSafeArea()

                VStack(spacing: 0) {
                    // ── Header ────────────────────────────────────────────
                    HStack {
                        Text("NETWORK MONITOR")
                            .font(.system(size: 16, weight: .bold, design: .monospaced))
                            .foregroundColor(.accentCyan)
                            .kerning(1)
                        Spacer()
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                    .background(Color.bgCard)

                    // ── Stats ─────────────────────────────────────────────
                    HStack(spacing: 8) {
                        StatCard(
                            label: "UPLOAD",
                            value: mbString(networkData?.stats?.bytesSentMb),
                            valueColor: .riskLow
                        )
                        StatCard(
                            label: "DOWNLOAD",
                            value: mbString(networkData?.stats?.bytesRecvMb),
                            valueColor: .accentCyan
                        )
                        StatCard(
                            label: "SUSPICIOUS",
                            value: "\(networkData?.suspiciousCount ?? 0)",
                            valueColor: networkData?.suspiciousCount ?? 0 > 0 ? .riskHigh : .riskLow
                        )
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)

                    // ── Filter toggle ─────────────────────────────────────
                    HStack(spacing: 8) {
                        filterButton("All", selected: !showSuspiciousOnly) {
                            showSuspiciousOnly = false
                        }
                        filterButton("Suspicious Only", selected: showSuspiciousOnly) {
                            showSuspiciousOnly = true
                        }
                        Spacer()
                        Text("\(connections.count) connections")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.textSecondary)
                    }
                    .padding(.horizontal, 12)
                    .padding(.bottom, 8)

                    // ── List ──────────────────────────────────────────────
                    if isLoading {
                        Spacer()
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: .accentCyan))
                        Spacer()
                    } else {
                        List(connections) { conn in
                            ConnectionRow(connection: conn)
                                .listRowBackground(Color.bgDark)
                                .listRowInsets(EdgeInsets(top: 3, leading: 12, bottom: 3, trailing: 12))
                        }
                        .listStyle(.plain)
                        .refreshable { await loadNetwork() }
                    }
                }
            }
            .navigationBarHidden(true)
        }
        .onAppear { Task { await loadNetwork() } }
    }

    private func filterButton(_ title: String, selected: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 12, weight: selected ? .bold : .regular))
                .foregroundColor(selected ? .bgDark : .textSecondary)
                .padding(.horizontal, 14)
                .padding(.vertical, 7)
                .background(selected ? Color.accentCyan : Color.bgCard)
                .cornerRadius(8)
        }
    }

    @MainActor
    private func loadNetwork() async {
        isLoading = networkData == nil
        await withCheckedContinuation { continuation in
            APIService.shared.getNetwork { result in
                if case .success(let data) = result {
                    networkData = data
                }
                continuation.resume()
            }
        }
        isLoading = false
    }

    private func mbString(_ val: Double?) -> String {
        guard let v = val else { return "– MB" }
        return String(format: "%.1f MB", v)
    }
}

// MARK: - Connection row

struct ConnectionRow: View {
    let connection: Connection

    var body: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(connection.suspiciousPort ? Color.riskCritical : Color.riskLow)
                .frame(width: 7, height: 7)

            VStack(alignment: .leading, spacing: 3) {
                Text(connection.remoteAddr?.isEmpty == false
                     ? connection.remoteAddr! : "(listening)")
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundColor(.textPrimary)

                Text(connection.localAddr ?? "")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.textSecondary)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 3) {
                Text(connection.status ?? "")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(connection.suspiciousPort ? .riskHigh : .riskLow)
                if connection.pid > 0 {
                    Text("PID \(connection.pid)")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.textSecondary)
                }
            }
        }
        .padding(.vertical, 6)
    }
}
