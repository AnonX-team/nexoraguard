import UserNotifications
import UIKit

final class NotificationManager {

    static let shared = NotificationManager()
    private var lastNotifiedRisk = ""

    private init() {}

    func requestPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
    }

    func postThreatAlert(risk: String, summary: String) {
        guard AppPrefs.shared.notificationsEnabled else { return }

        let content = UNMutableNotificationContent()
        content.title = "NexoraGuard — \(risk) Threat"
        content.body  = summary.isEmpty
            ? "Threat detected on your monitored system."
            : summary
        content.sound = .defaultCritical
        content.categoryIdentifier = "THREAT"

        // Color badge via userInfo (used in DashboardView to flash)
        content.userInfo = ["risk": risk]

        let request = UNNotificationRequest(
            identifier: "threat-\(Date().timeIntervalSince1970)",
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request)
    }

    /// Call after each poll — fires notification only on new HIGH/CRITICAL event
    func evaluateAndNotify(status: StatusResponse) {
        let risk = status.overallRisk ?? "UNKNOWN"
        let isSerious = risk == "CRITICAL" || risk == "HIGH"

        if isSerious && risk != lastNotifiedRisk {
            let summary = "\(status.ruleAlertCount) rules triggered. "
                + "\(status.suspiciousProcessCount) suspicious processes, "
                + "\(status.suspiciousConnectionCount) suspicious connections."
            postThreatAlert(risk: risk, summary: summary)
            lastNotifiedRisk = risk
        } else if !isSerious {
            lastNotifiedRisk = "" // reset so next spike fires again
        }
    }
}
