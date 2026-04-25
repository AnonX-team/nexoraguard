import Foundation

final class AppPrefs: ObservableObject {

    static let shared = AppPrefs()

    private let defaults = UserDefaults.standard

    private enum Key {
        static let serverURL          = "server_url"
        static let notificationsOn    = "notifications_enabled"
        static let pollIntervalIndex  = "poll_interval_index"
    }

    static let pollIntervals = [15, 30, 60, 120, 300, 600]
    static let defaultURL    = "http://192.168.1.100:8000/"

    @Published var serverURL: String {
        didSet { defaults.set(serverURL, forKey: Key.serverURL) }
    }

    @Published var notificationsEnabled: Bool {
        didSet { defaults.set(notificationsEnabled, forKey: Key.notificationsOn) }
    }

    @Published var pollIntervalIndex: Int {
        didSet { defaults.set(pollIntervalIndex, forKey: Key.pollIntervalIndex) }
    }

    var pollIntervalSeconds: Int {
        let idx = pollIntervalIndex
        guard idx >= 0 && idx < Self.pollIntervals.count else { return 30 }
        return Self.pollIntervals[idx]
    }

    private init() {
        serverURL = defaults.string(forKey: Key.serverURL) ?? Self.defaultURL
        notificationsEnabled = defaults.object(forKey: Key.notificationsOn) as? Bool ?? true
        pollIntervalIndex = defaults.integer(forKey: Key.pollIntervalIndex)
    }
}
