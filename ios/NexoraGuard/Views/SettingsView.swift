import SwiftUI

struct SettingsView: View {

    @ObservedObject private var prefs = AppPrefs.shared
    @State private var urlInput = AppPrefs.shared.serverURL
    @State private var connectionStatus = ""
    @State private var connectionColor = Color.textSecondary
    @State private var isTesting = false

    private let intervalLabels = ["15s", "30s", "1m", "2m", "5m", "10m"]

    var body: some View {
        NavigationView {
            ZStack {
                Color.bgDark.ignoresSafeArea()

                ScrollView {
                    VStack(spacing: 0) {
                        // ── Header ────────────────────────────────────────
                        HStack {
                            Text("SETTINGS")
                                .font(.system(size: 16, weight: .bold, design: .monospaced))
                                .foregroundColor(.accentCyan)
                                .kerning(1)
                            Spacer()
                        }
                        .padding(.horizontal, 16)
                        .padding(.vertical, 12)
                        .background(Color.bgCard)

                        VStack(spacing: 16) {
                            // ── Server Config ─────────────────────────────
                            SectionHeader(title: "SERVER CONFIGURATION")

                            VStack(alignment: .leading, spacing: 12) {
                                Text("Backend URL")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textSecondary)

                                TextField("http://192.168.1.100:8000/", text: $urlInput)
                                    .font(.system(size: 13, design: .monospaced))
                                    .foregroundColor(.textPrimary)
                                    .padding(12)
                                    .background(Color.bgCard2)
                                    .cornerRadius(8)
                                    .keyboardType(.URL)
                                    .autocapitalization(.none)
                                    .disableAutocorrection(true)

                                Button(action: saveAndTest) {
                                    HStack {
                                        if isTesting {
                                            ProgressView()
                                                .progressViewStyle(CircularProgressViewStyle(tint: .bgDark))
                                                .scaleEffect(0.8)
                                        }
                                        Text(isTesting ? "Testing..." : "Save & Connect")
                                            .font(.system(size: 14, weight: .bold))
                                    }
                                    .foregroundColor(.bgDark)
                                    .frame(maxWidth: .infinity)
                                    .frame(height: 44)
                                    .background(Color.accentCyan)
                                    .cornerRadius(8)
                                }
                                .disabled(isTesting)

                                if !connectionStatus.isEmpty {
                                    Text(connectionStatus)
                                        .font(.system(size: 11, design: .monospaced))
                                        .foregroundColor(connectionColor)
                                }
                            }
                            .padding(16)
                            .background(Color.bgCard)
                            .cornerRadius(12)

                            // ── Notifications ─────────────────────────────
                            SectionHeader(title: "NOTIFICATIONS")

                            VStack(spacing: 0) {
                                HStack {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text("Threat Alerts")
                                            .font(.system(size: 14))
                                            .foregroundColor(.textPrimary)
                                        Text("Notify on HIGH / CRITICAL threats")
                                            .font(.system(size: 11))
                                            .foregroundColor(.textSecondary)
                                    }
                                    Spacer()
                                    Toggle("", isOn: $prefs.notificationsEnabled)
                                        .tint(.accentCyan)
                                }
                                .padding(16)

                                Divider().background(Color.divider)

                                VStack(alignment: .leading, spacing: 10) {
                                    HStack {
                                        Text("Poll Interval")
                                            .font(.system(size: 14))
                                            .foregroundColor(.textPrimary)
                                        Spacer()
                                        Text(intervalLabels[prefs.pollIntervalIndex])
                                            .font(.system(size: 13, design: .monospaced))
                                            .foregroundColor(.accentCyan)
                                    }
                                    Slider(
                                        value: Binding(
                                            get: { Double(prefs.pollIntervalIndex) },
                                            set: { prefs.pollIntervalIndex = Int($0) }
                                        ),
                                        in: 0...5,
                                        step: 1
                                    )
                                    .accentColor(.accentCyan)
                                }
                                .padding(16)
                            }
                            .background(Color.bgCard)
                            .cornerRadius(12)

                            // ── About ─────────────────────────────────────
                            VStack(alignment: .leading, spacing: 6) {
                                Text("NexoraGuard for iOS")
                                    .font(.system(size: 14, weight: .bold))
                                    .foregroundColor(.textPrimary)
                                Text("Version 2.0.0 — PRO Edition")
                                    .font(.system(size: 12))
                                    .foregroundColor(.textSecondary)
                                Text("AI-Powered Security Monitoring")
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(.accentCyan)
                            }
                            .padding(16)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.bgCard)
                            .cornerRadius(12)
                        }
                        .padding(16)
                    }
                }
            }
            .navigationBarHidden(true)
        }
    }

    // MARK: - Actions

    private func saveAndTest() {
        var url = urlInput.trimmingCharacters(in: .whitespaces)
        guard !url.isEmpty else { return }
        if !url.hasSuffix("/") { url += "/" }
        prefs.serverURL = url
        urlInput = url

        isTesting = true
        connectionStatus = "Testing connection..."
        connectionColor  = .riskMedium

        APIService.shared.getRoot { result in
            DispatchQueue.main.async {
                isTesting = false
                switch result {
                case .success(let root):
                    connectionStatus = "Connected! NexoraGuard v\(root.version ?? "?") — \(root.scanner ?? "?")"
                    connectionColor  = .riskLow
                    ThreatPollingManager.shared.restartWithNewInterval()
                case .failure(let err):
                    connectionStatus = "Failed: \(err.localizedDescription)"
                    connectionColor  = .riskCritical
                }
            }
        }
    }
}
