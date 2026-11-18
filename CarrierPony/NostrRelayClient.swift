// NostrRelayClient.swift
// NIP-01 relay client over URLSessionWebSocketTask (native, no dependency). Publishes
// with EVENT, subscribes with REQ/CLOSE, and dispatches EVENT / OK / EOSE / NOTICE /
// CLOSED from the relay. The Android twin hand-rolls the websocket; here Foundation
// carries the framing, TLS, and ping/pong. Mirrors RelayClient's role: one per relay.

import Foundation

/// The Nostr kind CarrierPony posts sealed envelopes under (regular/stored range).
enum NostrKind { static let mailbox = 1314 }

/// A parsed relay-to-client message (the subset we act on).
enum NostrRelayMessage {
    case event(subId: String, event: [String: Any])
    case ok(eventId: String, accepted: Bool, message: String)
    case eose(subId: String)
    case notice(String)
    case closed(subId: String, message: String)
}

/// Reconnect backoff shared by both platforms' relay clients: a capped exponential
/// delay with jitter. A drop after a healthy stretch (>= stableSeconds up) resets the
/// backoff so a normal disconnect reconnects promptly; rapid flapping backs off.
enum NostrReconnect {
    static let baseSeconds = 1.0
    static let capSeconds = 30.0
    static let stableSeconds = 20.0
    static let maxAttempt = 5

    static func delay(attempt: Int) -> Double {
        let capped = min(baseSeconds * pow(2.0, Double(attempt)), capSeconds)
        return capped * (0.8 + Double.random(in: 0...0.4))
    }
}

final class NostrRelayClient: NSObject {
    let url: URL
    private var task: URLSessionWebSocketTask?
    private lazy var session = URLSession(configuration: .default)
    private var closing = false
    private var attempt = 0
    private var connectedAt = Date()

    var onMessage: ((NostrRelayMessage) -> Void)?
    /// Fired on the main queue after each (re)connect so the owner can restore its
    /// subscriptions on the fresh socket.
    var onReady: (() -> Void)?

    init(url: URL) { self.url = url }

    func connect() {
        closing = false
        openSocket()
    }

    private func openSocket() {
        let t = session.webSocketTask(with: url)
        task = t
        connectedAt = Date()
        t.resume()
        NSLog("CPNOSTR CONNECT relay=%@ attempt=%d", url.host ?? url.absoluteString, attempt)
        receiveLoop()
        DispatchQueue.main.async { [weak self] in
            guard let self, !self.closing else { return }
            self.onReady?()
        }
    }

    func close() {
        closing = true
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
    }

    func publish(eventJson: String) async throws { try await send("[\"EVENT\",\(eventJson)]") }
    func subscribe(subId: String, filterJson: String) async throws {
        try await send("[\"REQ\",\(NostrRelayClient.jsonString(subId)),\(filterJson)]")
    }
    func closeSub(_ subId: String) async throws {
        try await send("[\"CLOSE\",\(NostrRelayClient.jsonString(subId))]")
    }

    private func send(_ text: String) async throws {
        guard let task else { throw URLError(.notConnectedToInternet) }
        try await task.send(.string(text))
    }

    private func receiveLoop() {
        task?.receive { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure:
                self.scheduleReconnect()
            case .success(let message):
                if case .string(let text) = message, let parsed = NostrRelayClient.parse(text) {
                    self.onMessage?(parsed)
                }
                self.receiveLoop()
            }
        }
    }

    /// The socket ended. Unless we closed it deliberately, reconnect after a backoff
    /// delay and let the owner re-subscribe via onReady.
    private func scheduleReconnect() {
        DispatchQueue.main.async { [weak self] in
            guard let self, !self.closing else { return }
            self.task = nil
            if Date().timeIntervalSince(self.connectedAt) >= NostrReconnect.stableSeconds {
                self.attempt = 0
            } else {
                self.attempt = min(self.attempt + 1, NostrReconnect.maxAttempt)
            }
            let delay = NostrReconnect.delay(attempt: self.attempt)
            NSLog("CPNOSTR RECONNECT relay=%@ in %.1fs attempt=%d", self.url.host ?? self.url.absoluteString, delay, self.attempt)
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self, !self.closing else { return }
                self.openSocket()
            }
        }
    }

    /// Parse one relay-to-client JSON message. Exposed for tests.
    static func parse(_ text: String) -> NostrRelayMessage? {
        guard let data = text.data(using: .utf8),
              let arr = try? JSONSerialization.jsonObject(with: data) as? [Any],
              let type = arr.first as? String else { return nil }
        switch type {
        case "EVENT":
            guard arr.count >= 3, let sub = arr[1] as? String, let ev = arr[2] as? [String: Any] else { return nil }
            return .event(subId: sub, event: ev)
        case "OK":
            guard arr.count >= 3, let id = arr[1] as? String, let ok = arr[2] as? Bool else { return nil }
            return .ok(eventId: id, accepted: ok, message: arr.count > 3 ? (arr[3] as? String ?? "") : "")
        case "EOSE":
            guard arr.count >= 2, let sub = arr[1] as? String else { return nil }
            return .eose(subId: sub)
        case "NOTICE":
            return .notice(arr.count >= 2 ? (arr[1] as? String ?? "") : "")
        case "CLOSED":
            guard arr.count >= 2, let sub = arr[1] as? String else { return nil }
            return .closed(subId: sub, message: arr.count > 2 ? (arr[2] as? String ?? "") : "")
        default:
            return nil
        }
    }

    /// Filter for our own inbound window: {"kinds":[1314],"#t":[addr,...]}.
    static func mailboxFilter(addresses: [String]) -> String {
        let list = addresses.map { jsonString($0) }.joined(separator: ",")
        return "{\"kinds\":[\(NostrKind.mailbox)],\"#t\":[\(list)]}"
    }

    /// Filter matching one event by id: {"ids":[id]}.
    static func idFilter(_ eventId: String) -> String { "{\"ids\":[\(jsonString(eventId))]}" }

    /// A minimally-escaped JSON string literal (matches NostrSerialize.str).
    static func jsonString(_ s: String) -> String { NostrSerialize.str(s) }
}
