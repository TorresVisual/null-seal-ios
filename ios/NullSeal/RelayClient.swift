import Foundation

/// URLSession side of the core's relay transport. The core signs method and path, so both go
/// out exactly as given. Blocking by design: the core calls it from a background task.
/// Redirects are refused: the relay never redirects, and following one would re-send the
/// signed headers to another host.
final class URLSessionTransport: NSObject, RelayTransport, URLSessionTaskDelegate, @unchecked Sendable {
    private let base: String
    private var session: URLSession!

    init(base: String) {
        self.base = base.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        super.init()
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }

    func urlSession(
        _ session: URLSession, task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)  // hand the 3xx back as the response; the core treats it as a refusal
    }

    func send(method: String, path: String, headers: [Header], body: Data) throws -> RelayResponse {
        guard let url = URL(string: base + path) else { throw VaultError.Invalid }
        var req = URLRequest(url: url)
        req.httpMethod = method
        for h in headers { req.setValue(h.value, forHTTPHeaderField: h.name) }
        if method == "POST" || method == "PUT" {
            req.setValue("application/json", forHTTPHeaderField: "content-type")
            req.httpBody = body
        }
        let done = DispatchSemaphore(value: 0)
        var result: Result<RelayResponse, VaultError> = .failure(.Network)
        session.dataTask(with: req) { data, res, err in
            if err == nil, let http = res as? HTTPURLResponse {
                result = .success(RelayResponse(status: UInt16(http.statusCode), body: data ?? Data()))
            }
            done.signal()
        }.resume()
        done.wait()
        return try result.get()
    }
}
