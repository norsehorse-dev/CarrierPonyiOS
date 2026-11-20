// NostrTransport.swift
// The Nostr transport (2.3) on the CarrierPony seam. A store-and-forward accelerator
// like the relay: ChatStore hands it the sealed mailbox address for a message and it
// posts a kind-1314 event tagged with that address to a set of Nostr relays, giving
// delivery a path that does not depend on the CarrierPony relay. Send only here; the
// receive side (subscribe to our own inbound window) lands in M3b. Opt-in, off by
// default (AppConfig.nostrEnabled).

import Foundation

/// Holds the live connections to the configured Nostr relays and publishes events,
/// resolving each publish once any relay OKs it (or a timeout).
@MainActor
final class NostrTransportManager {
    private var clients: [NostrRelayClient] = []
    private var pending: [String: CheckedContinuation<Bool, Never>] = [:]
    private var lastAddresses: [String] = []
    // Relays cap the size of a single REQ filter, so a window of many hundreds of
    // #t values in one filter gets silently truncated and some mailboxes are never
    // actually subscribed. Split the window across several REQ sub ids, each a
    // bounded filter, and close any sub ids left over when the window shrinks.
    private var activeSubCount = 0
    private let subChunk = 200

    /// Called with (mailbox address, base64 content) for each sealed event received on
    /// the inbound subscription. AppModel routes it into ChatStore's ingest.
    var onNostrEvent: ((String, String) -> Void)?

    /// True when at least one relay connection is up.
    var isConnected: Bool { !clients.isEmpty }

    /// Connect to the given relays, replacing any existing connections.
    func start(relayURLs: [URL]) {
        stop()
        clients = relayURLs.map { url in
            let client = NostrRelayClient(url: url)
            client.onMessage = { [weak self] message in
                switch message {
                case .ok(let eventId, let accepted, _):
                    Task { @MainActor in self?.resolve(eventId, accepted) }
                case .event(_, let event):
                    Task { @MainActor in self?.deliver(event: event) }
                default:
                    break
                }
            }
            client.onReady = { [weak self, weak client] in
                guard let client else { return }
                Task { @MainActor in self?.resubscribe(client) }
            }
            client.connect()
            return client
        }
    }

    /// Drop all connections and fail any publish still waiting.
    func stop() {
        for client in clients { client.close() }
        clients = []
        let waiters = pending
        pending = [:]
        for (_, cont) in waiters { cont.resume(returning: false) }
    }

    private func resolve(_ eventId: String, _ accepted: Bool) {
        guard let cont = pending.removeValue(forKey: eventId) else { return }
        cont.resume(returning: accepted)
    }

    private func deliver(event: [String: Any]) {
        guard let content = event["content"] as? String,
              let tags = event["tags"] as? [[String]],
              let address = tags.first(where: { $0.count >= 2 && $0[0] == "t" })?[1] else { return }
        NSLog("CPNOSTR RX event mailbox=%@", String(address.suffix(8)))
        onNostrEvent?(address, content)
    }

    /// Subscribe to our inbound mailbox addresses on every relay under a stable sub id
    /// (so a window refresh replaces the filter). Matching events arrive via
    /// onNostrEvent. A large window is one filter with many #t values.
    func subscribe(addresses: [String]) {
        // The window is handed over on every upkeep pass, changed or not. A relay
        // answers each new REQ by sending every stored event again, so only ask
        // when the set of addresses is different.
        if activeSubCount > 0, Set(addresses) == Set(lastAddresses) { return }
        lastAddresses = addresses
        guard !clients.isEmpty else { return }
        let chunks = stride(from: 0, to: addresses.count, by: subChunk).map {
            Array(addresses[$0..<min($0 + subChunk, addresses.count)])
        }
        let prevCount = activeSubCount
        activeSubCount = chunks.count
        NSLog("CPNOSTR SUB addresses=%d chunks=%d relays=%d", addresses.count, chunks.count, clients.count)
        for client in clients {
            Task {
                for (i, chunk) in chunks.enumerated() {
                    try? await client.subscribe(subId: "cpin\(i)", filterJson: NostrRelayClient.mailboxFilter(addresses: chunk))
                }
                if prevCount > chunks.count {
                    for i in chunks.count..<prevCount { try? await client.closeSub("cpin\(i)") }
                }
            }
        }
    }

    /// Re-send the current inbound window to one relay after it (re)connects, so the
    /// receive path survives a dropped socket.
    private func resubscribe(_ client: NostrRelayClient) {
        guard !lastAddresses.isEmpty else { return }
        let chunks = stride(from: 0, to: lastAddresses.count, by: subChunk).map {
            Array(lastAddresses[$0..<min($0 + subChunk, lastAddresses.count)])
        }
        NSLog("CPNOSTR RESUB relay=%@ addresses=%d chunks=%d", client.url.host ?? client.url.absoluteString, lastAddresses.count, chunks.count)
        Task {
            for (i, chunk) in chunks.enumerated() {
                try? await client.subscribe(subId: "cpin\(i)", filterJson: NostrRelayClient.mailboxFilter(addresses: chunk))
            }
        }
    }

    /// Publish a sealed envelope to `mailbox` as a kind-1314 event with a fresh
    /// ephemeral key. Returns true once any relay accepts it, false on timeout or if
    /// no relay is connected. The pending waiter is registered before the publish
    /// starts, so an OK that arrives immediately is not missed.
    func publish(envelope: Data, mailbox: String, createdAt: Int64) async -> Bool {
        guard !clients.isEmpty else { return false }
        let secretKey = NostrEventBuilder.randomSecretKey()
        guard let event = try? NostrEventBuilder.build(
            secretKey: secretKey, createdAt: createdAt, kind: NostrKind.mailbox,
            tags: [["t", mailbox]], content: envelope.base64EncodedString()) else { return false }
        let json = event.json()
        let eventId = event.id
        NSLog("CPNOSTR TX mailbox=%@ event=%@ relays=%d", String(mailbox.suffix(8)), String(eventId.suffix(8)), clients.count)
        let accepted = await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            pending[eventId] = cont
            Task { @MainActor in
                for client in clients { try? await client.publish(eventJson: json) }
            }
            Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: 6_000_000_000)
                self?.resolve(eventId, false)
            }
        }
        NSLog("CPNOSTR TX result mailbox=%@ accepted=%@", String(mailbox.suffix(8)), accepted ? "YES" : "no")
        return accepted
    }
}

/// A `Transport` over Nostr relays. Store-and-forward, best-effort, concurrent with
/// the relay. Delivers only to sealed-capable peers, since it needs the mailbox
/// address; a nil mailbox (not sealed-capable yet) just means no Nostr delivery.
@MainActor
final class NostrTransport: Transport {
    let id: TransportID = .nostr
    let capabilities = TransportCapabilities(storeAndForward: true, revealsIP: true, worksOffline: false)

    private let manager: NostrTransportManager
    init(manager: NostrTransportManager) { self.manager = manager }

    func canReach(_ peer: Fingerprint) -> Bool { AppConfig.nostrEnabled && manager.isConnected }

    func send(_ envelope: Data, to peer: Fingerprint, mailbox: String?, expiresAt: Int, silent: Bool) async throws -> Bool {
        guard AppConfig.nostrEnabled, let mailbox else { return false }
        return await manager.publish(envelope: envelope, mailbox: mailbox, createdAt: Int64(Date().timeIntervalSince1970))
    }
}
