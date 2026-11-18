// LanDirect.swift
// CarrierPony
//
// LAN-direct networking (2.1). See CarrierPony-2.1-Transport-LANDirect-Design.md
// for the byte-exact wire protocol ("Wire protocol v1").
//
// M2 (done): advertise + browse `_carrierpony._tcp` with a random per-launch node
// id; show "N nearby".
// M3a (this file, gated behind AppConfig.lanDirectEnabled, off by default):
// resolve + connect to nearby nodes and run the identify handshake, mapping a
// random node to a known contact using the per-pair sealed keys both sides share.
// No envelopes move yet - a matched contact just shows as "reachable over LAN".
// M3b adds the 0x04 ENVELOPE frame and wires delivery into ChatStore.
//
// This file lives under the synchronized CarrierPony/ group so it compiles into
// the app target without a project-file edit.

import Foundation
import Network
import Observation
import CryptoKit

// A CarrierPony device seen on the local network. In M2/M3 we only know its
// per-launch node id (the Bonjour service name), never a fingerprint until the
// identify handshake matches it to a known contact.
struct DiscoveredNode: Identifiable, Hashable {
    let nodeID: String
    var id: String { nodeID }
}

// MARK: - Wire crypto (must match Android LanCrypto byte-for-byte)

enum LanCrypto {
    static let magic = Data("CPL1".utf8)

    // Frame types.
    static let tHello: UInt8 = 0x01
    static let tHelloAck: UInt8 = 0x02
    static let tNoMatch: UInt8 = 0x03
    static let tEnvelope: UInt8 = 0x04   // M3b

    private static let labelPair = Data("cp-lan-v1".utf8)
    private static let labelId = Data("cp-lan-id-v1".utf8)
    private static let labelIdAck = Data("cp-lan-id-v1-ack".utf8)

    static func randomBytes(_ n: Int) -> Data {
        var b = [UInt8](repeating: 0, count: n)
        _ = SecRandomCopyBytes(kSecRandomDefault, n, &b)
        return Data(b)
    }

    private static func hmac(key: Data, _ message: Data) -> Data {
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))
        return Data(mac)
    }

    /// Direction-independent per-pair LAN key from the two directional inbound keys.
    static func pairKey(myInbound: Data, peerInbound: Data) -> Data {
        let (lo, hi) = lexSort(myInbound, peerInbound)
        return hmac(key: labelPair, lo + hi)
    }

    static func helloTag(pairKey: Data, dialerNonce: Data) -> Data {
        hmac(key: pairKey, labelId + dialerNonce)
    }

    static func ackTag(pairKey: Data, dialerNonce: Data, listenerNonce: Data) -> Data {
        hmac(key: pairKey, labelIdAck + dialerNonce + listenerNonce)
    }

    static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= a[a.startIndex + i] ^ b[b.startIndex + i] }
        return diff == 0
    }

    private static func lexSort(_ a: Data, _ b: Data) -> (Data, Data) {
        let aa = [UInt8](a), bb = [UInt8](b)
        for i in 0..<min(aa.count, bb.count) {
            if aa[i] != bb[i] { return aa[i] < bb[i] ? (a, b) : (b, a) }
        }
        return aa.count <= bb.count ? (a, b) : (b, a)
    }

    static func frame(_ type: UInt8, _ payload: Data) -> Data {
        var out = Data([type])
        var len = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: &len) { out.append(contentsOf: $0) }
        out.append(payload)
        return out
    }
}

// MARK: - Non-isolated socket I/O over an NWConnection

enum LanIO {
    enum IOError: Error { case closed, badState, timeout }

    static func send(_ conn: NWConnection, _ data: Data) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.send(content: data, completion: .contentProcessed { error in
                if let error { cont.resume(throwing: error) } else { cont.resume() }
            })
        }
    }

    /// Read exactly n bytes, or throw if the connection closes first.
    static func readExactly(_ conn: NWConnection, _ n: Int) async throws -> Data {
        var acc = Data()
        while acc.count < n {
            let want = n - acc.count
            let chunk: Data = try await withCheckedThrowingContinuation { cont in
                conn.receive(minimumIncompleteLength: 1, maximumLength: want) { data, _, isComplete, error in
                    if let error { cont.resume(throwing: error); return }
                    if let data, !data.isEmpty { cont.resume(returning: data); return }
                    if isComplete { cont.resume(throwing: IOError.closed); return }
                    cont.resume(returning: Data())
                }
            }
            if chunk.isEmpty { throw IOError.closed }
            acc.append(chunk)
        }
        return acc
    }

    /// Read one framed message: returns (type, payload).
    static func readFrame(_ conn: NWConnection) async throws -> (UInt8, Data) {
        let header = try await readExactly(conn, 5)
        let b = [UInt8](header)
        let type = b[0]
        let n = (Int(b[1]) << 24) | (Int(b[2]) << 16) | (Int(b[3]) << 8) | Int(b[4])
        // Guard against a hostile length. Handshake frames are tiny; M3b envelopes
        // are bounded by the attachment cap plus overhead.
        guard n >= 0, n <= 80 * 1024 * 1024 else { throw IOError.badState }
        let payload = n == 0 ? Data() : try await readExactly(conn, n)
        return (type, payload)
    }

    static func open(_ endpoint: NWEndpoint) async throws -> NWConnection {
        let conn = NWConnection(to: endpoint, using: LanNet.params())
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            var resumed = false
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if !resumed { resumed = true; cont.resume() }
                case .failed(let e), .waiting(let e):
                    if !resumed { resumed = true; cont.resume(throwing: e) }
                case .cancelled:
                    if !resumed { resumed = true; cont.resume(throwing: IOError.closed) }
                default: break
                }
            }
            conn.start(queue: LanQueue.shared)
        }
        return conn
    }
}

enum LanQueue { static let shared = DispatchQueue(label: "com.carrierpony.lan") }

// LAN-direct must ride Wi-Fi, never cellular: a phone with data on would otherwise
// route these connections over cellular and never reach a peer's local IP (the
// "only works in airplane mode" symptom). Prohibit cellular on every LAN socket.
enum LanNet {
    static func params() -> NWParameters {
        let p = NWParameters.tcp
        p.prohibitedInterfaceTypes = [.cellular]
        return p
    }
}

// MARK: - Discovery + identify engine

@MainActor
@Observable
final class LanDiscovery {

    static let serviceType = "_carrierpony._tcp"

    private let nodeID = LanCrypto.randomBytes(8).map { String(format: "%02x", $0) }.joined()

    private(set) var nearby: [DiscoveredNode] = []
    /// Fingerprint hexes of known contacts currently identified on the LAN
    /// (either we dialed and matched them, or they dialed us and matched).
    private(set) var reachable: Set<String> = []

    /// Supplied by AppModel: the active identity's contact -> per-pair LAN key.
    var keyProvider: (() -> [String: Data])?
    /// M3b hook: hand a received envelope to ChatStore's ingest path. Unused in M3a.
    var onEnvelope: ((Data) -> Void)?

    private var listener: NWListener?
    private var browser: NWBrowser?
    private var running = false

    private var endpoints: [String: NWEndpoint] = [:]     // nodeID -> endpoint
    private var nodeToFpr: [String: String] = [:]          // nodeID -> matched fpr
    private var probed: Set<String> = []                   // "nodeID|fpr" attempted
    private var sweepTask: Task<Void, Never>?

    var identifyEnabled: Bool { AppConfig.lanDirectEnabled && keyProvider != nil }

    /// Called when the LAN-direct toggle flips. Turning it on starts an identify
    /// sweep against nodes already discovered; turning it off clears matches so
    /// nothing shows as reachable.
    func lanDidToggle() {
        if identifyEnabled {
            kickSweep()
        } else {
            reachable = []
            nodeToFpr = [:]
            probed = []
        }
    }

    func start() {
        guard !running else { return }
        running = true
        startAdvertising()
        startBrowsing()
    }

    func stop() {
        running = false
        sweepTask?.cancel(); sweepTask = nil
        listener?.cancel(); listener = nil
        browser?.cancel(); browser = nil
        nearby = []; reachable = []
        endpoints = [:]; nodeToFpr = [:]; probed = []
    }

    // MARK: Advertise (and accept, when identify is enabled)

    private func startAdvertising() {
        do {
            let listener = try NWListener(using: LanNet.params())
            listener.service = NWListener.Service(name: nodeID, type: LanDiscovery.serviceType)
            listener.newConnectionHandler = { [weak self] connection in
                connection.start(queue: LanQueue.shared)
                Task { @MainActor in
                    guard let self, self.identifyEnabled else { connection.cancel(); return }
                    await self.handleInbound(connection)
                }
            }
            listener.start(queue: LanQueue.shared)
            self.listener = listener
        } catch {
            // Advertising failed; browsing still works.
        }
    }

    // MARK: Browse

    private func startBrowsing() {
        let browser = NWBrowser(for: .bonjour(type: LanDiscovery.serviceType, domain: nil), using: LanNet.params())
        browser.browseResultsChangedHandler = { [weak self] results, _ in
            var found: [(String, NWEndpoint)] = []
            for result in results {
                if case let .service(name, _, _, _) = result.endpoint {
                    found.append((name, result.endpoint))
                }
            }
            Task { @MainActor in
                guard let self else { return }
                let mine = self.nodeID
                var eps: [String: NWEndpoint] = [:]
                for (name, ep) in found where name != mine { eps[name] = ep }
                self.endpoints = eps
                self.nearby = eps.keys.sorted().map { DiscoveredNode(nodeID: $0) }
                // Drop reachability for nodes that vanished.
                let gone = Set(self.nodeToFpr.keys).subtracting(eps.keys)
                for nid in gone {
                    if let fpr = self.nodeToFpr[nid] { self.reachable.remove(fpr) }
                    self.nodeToFpr[nid] = nil
                }
                if self.identifyEnabled { self.kickSweep() }
            }
        }
        browser.start(queue: LanQueue.shared)
        self.browser = browser
    }

    // MARK: Identify sweep (dialer side)

    private func kickSweep() {
        guard sweepTask == nil else { return }
        sweepTask = Task { @MainActor [weak self] in
            await self?.runSweep()
            self?.sweepTask = nil
        }
    }

    private func runSweep() async {
        guard identifyEnabled, let keys = keyProvider?() else { return }
        for (nodeID, endpoint) in endpoints {
            if nodeToFpr[nodeID] != nil { continue }
            for (fpr, pairKey) in keys {
                let mark = "\(nodeID)|\(fpr)"
                if probed.contains(mark) { continue }
                probed.insert(mark)
                if await identify(endpoint: endpoint, targetFpr: fpr, pairKey: pairKey) {
                    nodeToFpr[nodeID] = fpr
                    reachable.insert(fpr)
                    break
                }
            }
        }
    }

    /// Dial a node and run the identify handshake. Returns the open, authenticated
    /// connection on a verified match (caller must cancel it), or nil.
    private func handshakeDial(endpoint: NWEndpoint, pairKey: Data) async -> NWConnection? {
        guard let conn = try? await LanIO.open(endpoint) else { return nil }
        let dnonce = LanCrypto.randomBytes(16)
        let tag = LanCrypto.helloTag(pairKey: pairKey, dialerNonce: dnonce)
        let hello = LanCrypto.magic + LanCrypto.frame(LanCrypto.tHello, dnonce + tag)
        do {
            try await LanIO.send(conn, hello)
            let (type, payload) = try await LanIO.readFrame(conn)
            guard type == LanCrypto.tHelloAck, payload.count == 48 else { conn.cancel(); return nil }
            let lnonce = Data(payload.prefix(16))
            let gotTag = Data(payload.suffix(32))
            let want = LanCrypto.ackTag(pairKey: pairKey, dialerNonce: dnonce, listenerNonce: lnonce)
            if LanCrypto.constantTimeEquals(gotTag, want) { return conn }
            conn.cancel(); return nil
        } catch {
            conn.cancel(); return nil
        }
    }

    /// Probe whether a node is `targetFpr` (identify only, no delivery).
    private func identify(endpoint: NWEndpoint, targetFpr: String, pairKey: Data) async -> Bool {
        guard let conn = await handshakeDial(endpoint: endpoint, pairKey: pairKey) else { return false }
        conn.cancel()
        return true
    }

    /// True if the peer is a known contact currently identified on this LAN.
    func canReachLan(_ fprHex: String) -> Bool {
        identifyEnabled && reachable.contains(fprHex.lowercased())
    }

    /// Deliver one sealed envelope to a peer over the LAN (M3b). Best-effort:
    /// returns true only if a matched node accepted the framed envelope; the relay
    /// is the authority, so any failure just falls back to it.
    func deliver(peerHex: String, envelope: Data) async -> Bool {
        let target = peerHex.lowercased()
        guard identifyEnabled, let keys = keyProvider?(), let pairKey = keys[target] else { return false }
        guard let node = nodeToFpr.first(where: { $0.value == target })?.key,
              let endpoint = endpoints[node] else { return false }
        guard let conn = await handshakeDial(endpoint: endpoint, pairKey: pairKey) else { return false }
        defer { conn.cancel() }
        do {
            try await LanIO.send(conn, LanCrypto.frame(LanCrypto.tEnvelope, envelope))
            return true
        } catch {
            return false
        }
    }

    // MARK: Identify (listener side)

    private func handleInbound(_ conn: NWConnection) async {
        defer { conn.cancel() }
        guard let keys = keyProvider?() else { return }
        do {
            let magic = try await LanIO.readExactly(conn, 4)
            guard magic == LanCrypto.magic else { return }
            let (type, payload) = try await LanIO.readFrame(conn)
            guard type == LanCrypto.tHello, payload.count == 48 else { return }
            let dnonce = Data(payload.prefix(16))
            let gotTag = Data(payload.suffix(32))
            for (fpr, pairKey) in keys {
                let want = LanCrypto.helloTag(pairKey: pairKey, dialerNonce: dnonce)
                if LanCrypto.constantTimeEquals(gotTag, want) {
                    let lnonce = LanCrypto.randomBytes(16)
                    let ackTag = LanCrypto.ackTag(pairKey: pairKey, dialerNonce: dnonce, listenerNonce: lnonce)
                    let ack = LanCrypto.frame(LanCrypto.tHelloAck, lnonce + ackTag)
                    try await LanIO.send(conn, ack)
                    reachable.insert(fpr)
                    await receiveLoop(conn)
                    return
                }
            }
            // No match: reply an ACK-shaped random blob so a passive observer
            // cannot tell match from no-match by length, then close.
            let blob = LanCrypto.frame(LanCrypto.tNoMatch, LanCrypto.randomBytes(48))
            try? await LanIO.send(conn, blob)
        } catch {
            // Malformed or dropped; nothing to do.
        }
    }

    /// After a matched handshake, read envelope frames until the peer closes,
    /// handing each to ChatStore's ingest path (dedupe by message id is free).
    private func receiveLoop(_ conn: NWConnection) async {
        while true {
            guard let (type, payload) = try? await LanIO.readFrame(conn) else { return }
            if type == LanCrypto.tEnvelope {
                onEnvelope?(payload)
            } else {
                return
            }
        }
    }
}

// MARK: - LAN-direct as a Transport (M3b)

// Wraps LanDiscovery so ChatStore can treat direct LAN delivery like any other
// transport. Non-store-and-forward, reveals this device's IP to the peer, works
// with no internet. The relay stays the authority; this only accelerates.
@MainActor
final class LanDirectTransport: Transport {
    let id: TransportID = .lanDirect
    let capabilities = TransportCapabilities(storeAndForward: false, revealsIP: true, worksOffline: true)

    private let discovery: LanDiscovery
    init(discovery: LanDiscovery) { self.discovery = discovery }

    func canReach(_ peer: Fingerprint) -> Bool { discovery.canReachLan(peer.hex) }

    func send(_ envelope: Data, to peer: Fingerprint, mailbox: String?, expiresAt: Int, silent: Bool) async throws -> Bool {
        await discovery.deliver(peerHex: peer.hex, envelope: envelope)
    }
}
