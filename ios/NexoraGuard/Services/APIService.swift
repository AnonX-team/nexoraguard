import Foundation

final class APIService: ObservableObject {

    static let shared = APIService()

    private var baseURL: String {
        AppPrefs.shared.serverURL
    }

    private let session: URLSession = {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest  = 15
        config.timeoutIntervalForResource = 30
        return URLSession(configuration: config)
    }()

    // MARK: - Generic request

    private func request<T: Decodable>(
        path: String,
        method: String = "GET",
        body: Data? = nil,
        completion: @escaping (Result<T, Error>) -> Void
    ) {
        guard let url = URL(string: baseURL + path) else {
            completion(.failure(URLError(.badURL)))
            return
        }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = body

        session.dataTask(with: req) { data, _, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            guard let data = data else {
                completion(.failure(URLError(.zeroByteResource)))
                return
            }
            do {
                let decoded = try JSONDecoder().decode(T.self, from: data)
                completion(.success(decoded))
            } catch {
                completion(.failure(error))
            }
        }.resume()
    }

    // MARK: - Endpoints

    func getRoot(completion: @escaping (Result<RootResponse, Error>) -> Void) {
        request(path: "", completion: completion)
    }

    func getStatus(completion: @escaping (Result<StatusResponse, Error>) -> Void) {
        request(path: "status", completion: completion)
    }

    func triggerScan(completion: @escaping (Result<StatusResponse, Error>) -> Void) {
        request(path: "scan", completion: completion)
    }

    func getAlerts(limit: Int = 50, completion: @escaping (Result<AlertsResponse, Error>) -> Void) {
        request(path: "alerts?limit=\(limit)", completion: completion)
    }

    func getNetwork(completion: @escaping (Result<NetworkResponse, Error>) -> Void) {
        request(path: "network", completion: completion)
    }

    func getTimeline(limit: Int = 50, completion: @escaping (Result<TimelineResponse, Error>) -> Void) {
        request(path: "timeline?limit=\(limit)", completion: completion)
    }

    func getSuspiciousProcesses(completion: @escaping (Result<ProcessesResponse, Error>) -> Void) {
        request(path: "processes/suspicious", completion: completion)
    }

    func chat(message: String, history: [ChatHistoryMessage], completion: @escaping (Result<ChatResponse, Error>) -> Void) {
        let body = ChatRequest(message: message, history: history)
        guard let data = try? JSONEncoder().encode(body) else { return }
        request(path: "chat", method: "POST", body: data, completion: completion)
    }
}
