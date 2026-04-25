import Foundation
import Combine

/// Polls /status on a configurable interval and publishes the result.
/// DashboardView observes latestStatus; NotificationManager handles alerts.
final class ThreatPollingManager: ObservableObject {

    static let shared = ThreatPollingManager()

    @Published var latestStatus: StatusResponse?
    @Published var isConnected: Bool = false

    private var timer: Timer?
    private let prefs = AppPrefs.shared

    private init() {}

    func start() {
        scheduleTimer()
        poll() // immediate first poll
    }

    func stop() {
        timer?.invalidate()
        timer = nil
    }

    func restartWithNewInterval() {
        stop()
        start()
    }

    private func scheduleTimer() {
        let interval = TimeInterval(prefs.pollIntervalSeconds)
        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            self?.poll()
        }
    }

    private func poll() {
        APIService.shared.getStatus { [weak self] result in
            DispatchQueue.main.async {
                switch result {
                case .success(let status):
                    self?.latestStatus = status
                    self?.isConnected  = true
                    NotificationManager.shared.evaluateAndNotify(status: status)
                case .failure:
                    self?.isConnected = false
                }
            }
        }
    }
}
