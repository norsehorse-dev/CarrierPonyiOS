// WanDirect.swift
// Bridges CarrierPony's sealed control-op signaling and per-pair LAN keys to the
// PonyDirect WAN transport (STUN + authenticated UDP hole punching). PonyDirect
// carries only opaque bytes and never sees the app's raw keys; it calls back on its
// own queue, so key material is snapshotted under a lock and outbound signals hop
// through a closure the app sets. UI state is surfaced via onConnectedChange, which
// the app marshals onto the main actor.

import Foundation
import PonyDirect

/// Encodes/decodes a PonyDirect signal onto CarrierPony's existing webrtc-* control
/// ops. Offer/answer carry the candidate list + session nonce as JSON in the `sdp`
/// field; ice carries one "ip:port" in the `candidate` field. (The op names are kept
/// from M1 to reuse the sealed control-op plumbing; the payload is ours, not SDP.)
enum WanSignalCodec {
    static func encode(_ s: PonyDirectSignal) -> (op: String, sdp: String?, candidate: String?) {
        switch s.kind {
        case .offer, .answer:
            let payload: [String: Any] = [
                "c": s.candidates,
                "s": (s.sessionNonce ?? Data()).base64EncodedString(),
            ]
            let sdp = (try? JSONSerialization.data(withJSONObject: payload))
                .flatMap { String(data: $0, encoding: .utf8) }
            return (s.kind == .offer ? "webrtc-offer" : "webrtc-answer", sdp, nil)
        case .ice:
            return ("webrtc-ice", nil, s.candidate)
        }
    }

    static func decode(op: String, sdp: String?, candidate: String?) -> PonyDirectSignal? {
        switch op {
        case "webrtc-offer", "webrtc-answer":
            guard let sdp, let data = sdp.data(using: .utf8),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
            let candidates = obj["c"] as? [String] ?? []
            let nonce = (obj["s"] as? String).flatMap { Data(base64Encoded: $0) }
            return PonyDirectSignal(kind: op == "webrtc-offer" ? .offer : .answer,
                                    candidates: candidates, sessionNonce: nonce)
        case "webrtc-ice":
            guard let candidate else { return nil }
            return PonyDirectSignal(kind: .ice, candidate: candidate)
        default:
            return nil
        }
    }
}

/// Thread-safe bridge between the app (main actor) and PonyDirect (its own queue).
final class WanDirectBridge: NSObject, PonyDirectKeyProvider, PonyDirectSignaling, PonyDirectWanDelegate {

    private let lock = NSLock()
    private var keySnapshot: [String: Data] = [:]      // peerHex (lower) -> 32B pair key
    private var connected: Set<String> = []

    /// Set by the app: relays one outbound signaling op (op, peerHex, sdp, candidate).
    var sendOp: ((String, String, String?, String?) -> Void)?
    /// Set by the app: current connected-peer count (called off the main actor).
    var onConnectedChange: ((Int) -> Void)?
    /// Set by the app: a payload arrived on a direct path (M3 delivery). No-op in M2.
    var onPayload: ((String, Data) -> Void)?
    /// Set by the app on enable: our own fingerprint hex, for the initiator role check.
    var selfHex: String?

    private(set) var wan: PonyDirectWan?

    /// Refresh the per-pair key snapshot. Called on the main actor with the store's
    /// sealed-capable contact keys.
    func updateKeys(_ keys: [String: Data]) {
        lock.lock(); keySnapshot = keys; lock.unlock()
    }

    /// Bring the WAN transport up. Returns false if the UDP socket could not bind.
    @discardableResult
    func enable(stunHost: String, stunPort: UInt16) -> Bool {
        guard wan == nil else { return true }
        do {
            let w = try PonyDirectWan(stun: .init(host: stunHost, port: stunPort), keys: self, signaling: self)
            w.delegate = self
            wan = w
            return true
        } catch {
            return false
        }
    }

    func disable() {
        wan = nil
        lock.lock(); connected.removeAll(); lock.unlock()
        onConnectedChange?(0)
    }

    /// Open a path to a peer as the initiator. The app calls this only for the peer
    /// whose fingerprint sorts after ours, so exactly one side offers; the other side
    /// creates its session when the offer arrives.
    func openPath(peerHex: String) {
        wan?.open(peer: peerHex.lowercased(), as: .initiator)
    }

    /// Feed an incoming signaling op parsed from a sealed control op.
    func handleIncoming(peerHex: String, op: String, sdp: String?, candidate: String?) {
        guard let wan, let signal = WanSignalCodec.decode(op: op, sdp: sdp, candidate: candidate) else { return }
        wan.handleSignal(signal, fromPeer: peerHex.lowercased())
    }

    /// True when at least one direct path is up.
    var connectedCount: Int {
        lock.lock(); defer { lock.unlock() }
        return connected.count
    }

    // MARK: PonyDirectKeyProvider (off main)
    func pairKey(forPeer peerID: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return keySnapshot[peerID.lowercased()]
    }

    // MARK: PonyDirectSignaling (off main)
    func sendSignal(_ signal: PonyDirectSignal, toPeer peerID: String) {
        let (op, sdp, candidate) = WanSignalCodec.encode(signal)
        sendOp?(op, peerID, sdp, candidate)
    }

    // MARK: PonyDirectWanDelegate (delivered on the main queue by PonyDirectWan)
    func wan(_ wan: PonyDirectWan, peer peerID: String, didChangeState state: PonyDirectWan.PathState) {
        lock.lock()
        if state == .connected { connected.insert(peerID) } else { connected.remove(peerID) }
        let count = connected.count
        lock.unlock()
        onConnectedChange?(count)
    }

    func wan(_ wan: PonyDirectWan, peer peerID: String, didReceivePayload payload: Data) {
        onPayload?(peerID, payload)
    }
}

extension WanDirectBridge {
    /// True when a direct WAN path to this peer is live. Also lazily starts a path the
    /// first time we are asked to reach an initiator peer, so paths exist only for the
    /// contacts actually messaged rather than every contact at once. Idempotent -
    /// open() guards an existing session.
    func canReach(_ peerHex: String) -> Bool {
        guard AppConfig.wanDirectEnabled, let wan = wan else { return false }
        let peer = peerHex.lowercased()
        if wan.state(ofPeer: peer) == .connected { return true }
        if let mine = selfHex, mine < peer { wan.open(peer: peer, as: .initiator) }
        return false
    }

    /// Deliver over the direct path, resolving true only once every chunk is acked
    /// (or false if there is no path, it is oversized, or the ARQ deadline passes).
    func sendDirect(_ payload: Data, toPeer peerHex: String) async -> Bool {
        guard let wan = wan else { return false }
        return await withCheckedContinuation { cont in
            let queued = wan.sendPayload(payload, toPeer: peerHex.lowercased()) { delivered in
                cont.resume(returning: delivered)
            }
            if !queued { cont.resume(returning: false) }
        }
    }
}

/// A `Transport` over the PonyDirect WAN path. The relay stays authoritative; this
/// is a best-effort accelerator that can also carry the whole message when the relay
/// is unreachable, since `send` resolves only on confirmed delivery.
final class WanDirectTransport: Transport {
    let id: TransportID = .wanDirect
    let capabilities = TransportCapabilities(storeAndForward: false, revealsIP: true, worksOffline: false)

    private let bridge: WanDirectBridge
    init(bridge: WanDirectBridge) { self.bridge = bridge }

    func canReach(_ peer: Fingerprint) -> Bool { bridge.canReach(peer.hex) }

    func send(_ envelope: Data, to peer: Fingerprint, mailbox: String?, expiresAt: Int, silent: Bool) async throws -> Bool {
        await bridge.sendDirect(envelope, toPeer: peer.hex)
    }
}
