import Foundation
import CryptoKit
import Security

final class RelayClient {
    private let baseURL: String
    private let crypto: CryptoEngine
    private let deviceID: String
    private let session: URLSession
    private let decoder: JSONDecoder

    init(baseURL: String, crypto: CryptoEngine, deviceID: String, session: URLSession = .shared) {
        var trimmed = baseURL
        while trimmed.hasSuffix("/") {
            trimmed.removeLast()
        }
        self.baseURL = trimmed
        self.crypto = crypto
        self.deviceID = deviceID
        self.session = session
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        self.decoder = d
    }

    func registerDevice(label: String? = nil) async throws {
        let nonce = try await challenge(for: crypto.fingerprint.hex)
        let sig = try crypto.detachedSignature(over: Data(nonce.utf8))
        var body: [String: Any] = [
            "fpr": crypto.fingerprint.hex,
            "pubkey": try crypto.armoredPublicKey(),
            "device_id": deviceID,
            "nonce": nonce,
            "sig": sig,
        ]
        if let label = label {
            body["label"] = label
        }
        let _: OkResponse = try await post("/v1/register-device", body: body)
    }

    // `silent` marks a send that should wake the recipient to sync but not raise a
    // banner: control messages (read receipts, profile updates, deletes) and
    // cross-device self-copies, none of which surface anything to read. The relay
    // turns a silent send into a content-available background push. Real messages
    // leave it false and keep the alert.
    func send(envelope: Data, to recipient: Fingerprint, expiresAt: Int, silent: Bool = false, kind: String? = nil) async throws -> SendResponse {
        var body = try await authBody()
        body["to_fpr"] = recipient.hex
        body["envelope"] = envelope.base64EncodedString()
        body["expires_at"] = expiresAt
        if silent {
            body["silent"] = true
        }
        // "request" marks a contact request, so the relay can word the push for
        // it. The relay learns nothing else from it: this route already shows it
        // who is writing to whom. A relay that does not know the field ignores it.
        if let kind {
            body["kind"] = kind
        }
        return try await post("/v1/send", body: body)
    }

    func inbox() async throws -> [InboxMessage] {
        var body = try await authBody()
        body["device_id"] = deviceID
        let response: InboxResponse = try await post("/v1/inbox", body: body)
        return response.messages
    }

    @discardableResult
    func ack(messageIDs: [String]) async throws -> Int {
        var body = try await authBody()
        body["device_id"] = deviceID
        body["message_ids"] = messageIDs
        let response: AckResponse = try await post("/v1/ack", body: body)
        return response.acked
    }

    func registerPush(token: String) async throws {
        var body = try await authBody()
        body["device_id"] = deviceID
        body["push_token"] = token
        let _: OkResponse = try await post("/v1/register-push", body: body)
    }

    /// Store (or clear) this device's gateway wake token on the relay. An empty
    /// string clears it. The relay never sees the push token, only this opaque
    /// token it uses to nudge the gateway.
    func registerWake(wakeToken: String) async throws {
        var body = try await authBody()
        body["device_id"] = deviceID
        body["wake_token"] = wakeToken
        let _: OkResponse = try await post("/v1/register-wake", body: body)
    }

    // MARK: - Pairing

    /// Publish a pairing offer carrying this identity's public key. Returns a
    /// one-time token the peer uses to accept.
    func pairOffer(pubkey: String) async throws -> PairOfferResponse {
        var body = try await authBody()
        body["pubkey"] = pubkey
        return try await post("/v1/pair/offer", body: body)
    }

    /// Accept an offer by token, submitting this identity's public key and
    /// receiving the offerer's key in return.
    func pairAccept(token: String, pubkey: String) async throws -> PairAcceptResponse {
        var body = try await authBody()
        body["token"] = token
        body["pubkey"] = pubkey
        return try await post("/v1/pair/accept", body: body)
    }

    /// Poll an offer this identity created. Once accepted, carries the
    /// responder's fingerprint and public key.
    func pairStatus(token: String) async throws -> PairStatusResponse {
        var body = try await authBody()
        body["token"] = token
        return try await post("/v1/pair/status", body: body)
    }

    func submitReport(reportedFingerprint: Fingerprint, category: String, description: String?, content: String?) async throws {
        var body = try await authBody()
        body["reported_fpr"] = reportedFingerprint.hex
        body["category"] = category
        if let description, !description.isEmpty { body["description"] = description }
        if let content, !content.isEmpty { body["content"] = content }
        let _: OkResponse = try await post("/v1/report", body: body)
    }

    private func challenge(for fpr: String) async throws -> String {
        let response: ChallengeResponse = try await post("/v1/challenge", body: ["fpr": fpr])
        return response.nonce
    }

    private func authBody() async throws -> [String: Any] {
        let nonce = try await challenge(for: crypto.fingerprint.hex)
        let sig = try crypto.detachedSignature(over: Data(nonce.utf8))
        return ["fpr": crypto.fingerprint.hex, "nonce": nonce, "sig": sig]
    }

    private func post<T: Decodable>(_ path: String, body: [String: Any]) async throws -> T {
        guard let url = URL(string: baseURL + path) else {
            throw RelayError(status: -1, code: "bad_url")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw RelayError(status: -1, code: "no_response")
        }
        guard http.statusCode == 200 else {
            let code = (try? decoder.decode(ErrorBody.self, from: data))?.error
            throw RelayError(status: http.statusCode, code: code)
        }
        return try decoder.decode(T.self, from: data)
    }
}

struct GatewayError: Error { let status: Int; let detail: String? }

/// Minimal client for the CarrierPony push gateway. Identity-agnostic: it holds
/// only a push token and hands back an opaque wake token, with no PGP auth.
enum GatewayClient {
    static func registerPush(deviceID: String, token: String, platform: String, apnsEnv: String? = nil) async throws -> String {
        var body: [String: Any] = ["device_id": deviceID, "push_token": token, "platform": platform]
        if let apnsEnv { body["apns_env"] = apnsEnv }
        guard let url = URL(string: AppConfig.gatewayBaseURL + "/v1/register-push") else {
            throw GatewayError(status: 0, detail: "bad_url")
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        req.timeoutInterval = 15
        let (data, resp) = try await URLSession.shared.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else { throw GatewayError(status: code, detail: nil) }
        let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        guard let wake = obj?["wake_token"] as? String, !wake.isEmpty else {
            throw GatewayError(status: 200, detail: "no_wake_token")
        }
        return wake
    }

    static func deregister(wakeToken: String) async {
        guard let url = URL(string: AppConfig.gatewayBaseURL + "/v1/deregister") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["wake_token": wakeToken])
        req.timeoutInterval = 15
        _ = try? await URLSession.shared.data(for: req)
    }
}

// MARK: - Sealed sender: address derivation

// Opaque rotating mailbox addresses and the device auth for the /v1/sealed/*
// endpoints. Kept in lockstep with the relay's src/sealed.php and the Android
// client. See CarrierPony-2.0-SealedSender-Design.md.
enum MailboxCrypto {

    /// The address for the n-th message on a per-pair key, matching the relay's
    /// 64-hex mailbox id: HMAC-SHA256(key, context || uint64_be(counter)). The
    /// pair key is the raw 32 secret bytes, used directly as the HMAC key.
    static func address(key: Data, counter: UInt64, context: String = "cpmbx1") -> String {
        var message = Data(context.utf8)
        var be = counter.bigEndian
        withUnsafeBytes(of: &be) { message.append(contentsOf: $0) }
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))
        return hex(Data(mac))
    }

    /// A group message address for one ordered sender->recipient pair, derived
    /// from the group's epoch key so any member can compute it and it rotates on
    /// rekey: HMAC-SHA256(epochKey, context || sender_fpr || recipient_fpr || uint64_be(counter)).
    static func groupAddress(epochKey: Data, senderFprHex: String, recipientFprHex: String, counter: UInt64, context: String = "cpgmbx1") -> String {
        var message = Data(context.utf8)
        message.append(contentsOf: Data(senderFprHex.utf8))
        message.append(contentsOf: Data(recipientFprHex.utf8))
        var be = counter.bigEndian
        withUnsafeBytes(of: &be) { message.append(contentsOf: $0) }
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: epochKey))
        return hex(Data(mac))
    }

    /// Device proof for register-mailboxes / inbox / ack: HMAC over
    /// "action:device_id:ts" with the device_key hex STRING used directly as the
    /// key bytes (no hex decode), matching cp_sealed_verify on the relay.
    static func deviceAuth(deviceKeyHex: String, action: String, deviceID: String, ts: Int) -> String {
        let key = SymmetricKey(data: Data(deviceKeyHex.utf8))
        let mac = HMAC<SHA256>.authenticationCode(for: Data("\(action):\(deviceID):\(ts)".utf8), using: key)
        return hex(Data(mac))
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func randomBytes(_ count: Int) -> Data {
        var data = Data(count: count)
        let ok = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        if ok != errSecSuccess {
            // Fallback: the system RNG. Reached only if SecRandom is unavailable.
            data = Data((0..<count).map { _ in UInt8.random(in: 0...255) })
        }
        return data
    }
}

// MARK: - Sealed sender: per-pair state + Keychain

// Everything a device needs for sealed delivery with one peer. myInboundKey is
// generated by this device and handed to the peer (they address us with it, we
// register and derive our receive addresses from it). peerInboundKey arrives
// from the peer; we address them with it. Counters advance independently per
// direction. A pair is sealed-capable once peerInboundKey is set.
struct SealedPairState: Codable {
    var myInboundKey: Data
    var peerInboundKey: Data?
    var sendCounter: UInt64
    var receiveHigh: UInt64
    var sharedMine: Bool

    var canSend: Bool { peerInboundKey != nil }
}

// Keychain-backed secrets for sealed sender, mirroring GroupKeyStore. The
// device_key is minted once; per-pair state is stored under the peer fingerprint.
final class SealedKeyStore {

    private let service = "com.carrierpony.sealed"
    private let deviceAccount = "device-key"
    private let deviceIDAccount = "device-id"

    // Every stored item is namespaced by this store's identity fingerprint, so
    // each account holds its OWN sealed device and pair/group state. Without this,
    // two accounts sharing one sealed device would let the relay link them.
    private let identityScope: String

    /// Create a store scoped to one identity. On first use it migrates the
    /// pre-account (un-namespaced) items into this identity's namespace so the
    /// primary account keeps its working sealed device and mailbox claims.
    init(identityHex: String) {
        self.identityScope = identityHex
        migrateLegacy()
    }

    private func scoped(_ account: String) -> String {
        identityScope.isEmpty ? account : "\(identityScope).\(account)"
    }

    private func isLegacyAccount(_ account: String) -> Bool {
        account == deviceAccount || account == deviceIDAccount
            || account.hasPrefix("pair.") || account.hasPrefix("group.")
    }

    private func migrateLegacy() {
        guard !identityScope.isEmpty else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let items = result as? [[String: Any]] else { return }
        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String,
                  let data = item[kSecValueData as String] as? Data,
                  isLegacyAccount(account) else { continue }
            SecItemAdd([
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: "\(identityScope).\(account)",
                kSecValueData as String: data,
            ] as CFDictionary, nil)   // no-op if the namespaced item already exists
            SecItemDelete([
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
            ] as CFDictionary)
        }
    }

    /// This device's sealed auth key (64 hex), minted once and persisted.
    func deviceKey() -> String {
        if let existing = readString(account: deviceAccount) { return existing }
        let hex = MailboxCrypto.hex(MailboxCrypto.randomBytes(32))
        writeData(Data(hex.utf8), account: deviceAccount)
        return hex
    }

    /// This device's sealed device_id (32 hex), independent of the push/legacy
    /// device id and kept in the SAME keychain store as device_key so the two
    /// share one lifecycle: if the store is cleared, both regenerate together and
    /// the relay sees a fresh device, instead of a new key colliding with a stale
    /// first-claimed device_id. Keeping it off the push id also stops the relay
    /// linking this "anonymous" sealed device to the fingerprint-routed one.
    func deviceID() -> String {
        if let existing = readString(account: deviceIDAccount) { return existing }
        // Seed from the existing push/legacy id the FIRST time, so a device that
        // already registered sealed mailboxes under that id keeps owning them (the
        // addresses are key-derived and first-claimed by whichever device_id
        // registered them; switching would orphan those claims). From here it
        // lives in this keychain store, sharing device_key's lifecycle.
        let seed = anyOtherAccountHasSealedDevice()
            ? MailboxCrypto.hex(MailboxCrypto.randomBytes(16))
            : AppConfig.deviceID
        writeData(Data(seed.utf8), account: deviceIDAccount)
        return seed
    }

    /// True when another account already holds a sealed device_id on this install.
    /// Only the first sealed account may seed its id from the shared push id; a
    /// later account must start with a fresh random id, or two accounts would
    /// present the same sealed device to the relay and be linkable.
    private func anyOtherAccountHasSealedDevice() -> Bool {
        let mine = scoped(deviceIDAccount)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let items = result as? [[String: Any]] else { return false }
        let suffix = ".\(deviceIDAccount)"
        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String else { continue }
            if account.hasSuffix(suffix) && account != mine { return true }
        }
        return false
    }

    /// Mint a FRESH random sealed device_id (keeping device_key), so the next
    /// register-device lands on a device row the relay has never claimed. Recovers
    /// from a relay 401 (the seeded id was first-claimed under a key this device
    /// no longer holds); safe because a device hitting 401 never registered any
    /// mailboxes, so there are no claims to orphan. Pair/group state untouched.
    func rotateDeviceIdentity() {
        writeData(Data(MailboxCrypto.hex(MailboxCrypto.randomBytes(16)).utf8), account: deviceIDAccount)
    }

    func newPairKey() -> Data { MailboxCrypto.randomBytes(32) }

    func pair(_ peerHex: String) -> SealedPairState? {
        guard let data = readData(account: "pair.\(peerHex.lowercased())") else { return nil }
        return try? JSONDecoder().decode(SealedPairState.self, from: data)
    }

    func setPair(_ peerHex: String, _ state: SealedPairState) {
        guard let data = try? JSONEncoder().encode(state) else { return }
        writeData(data, account: "pair.\(peerHex.lowercased())")
    }

    func deletePair(_ peerHex: String) {
        delete(account: "pair.\(peerHex.lowercased())")
    }

    /// Wipe every sealed secret (device key, all pair state, all group state) on
    /// sign-out or reset.
    func purge() {
        // Delete only THIS identity's sealed items, leaving other accounts intact.
        // With no scope set, fall back to clearing the whole service.
        guard !identityScope.isEmpty else {
            SecItemDelete([
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
            ] as CFDictionary)
            return
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let items = result as? [[String: Any]] else { return }
        let mine = "\(identityScope)."
        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String,
                  account.hasPrefix(mine) else { continue }
            SecItemDelete([
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
            ] as CFDictionary)
        }
    }

    // MARK: Keychain primitives

    private func base(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: scoped(account),
        ]
    }

    private func writeData(_ data: Data, account: String) {
        SecItemDelete(base(account) as CFDictionary)
        var add = base(account)
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }

    private func readData(account: String) -> Data? {
        var query = base(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess, let data = out as? Data else {
            return nil
        }
        return data
    }

    private func readString(account: String) -> String? {
        readData(account: account).flatMap { String(data: $0, encoding: .utf8) }
    }

    private func delete(account: String) {
        SecItemDelete(base(account) as CFDictionary)
    }
}

// A registered receive address routes to either a 1:1 pair stream or a group
// stream (identified by the group and the co-member who sends on it).
enum SealedRoute {
    case pair(Fingerprint, UInt64)
    case group(String, Fingerprint, UInt64)
}

// Sealed group delivery state, per group and epoch: my outbound counter to each
// member, and the high-water of what I have received from each member. Reset when
// the epoch rotates (rekey), since the address space changes with the key.
//
// heard and since are for GroupDelivery: the members a group message has
// arrived from in this epoch, and when I first sent to each member in it.
struct SealedGroupState: Codable {
    var epoch: Int
    var sendCounters: [String: UInt64]
    var recvHighs: [String: UInt64]
    var heard: Set<String>
    var since: [String: Int]

    init(epoch: Int, sendCounters: [String: UInt64], recvHighs: [String: UInt64],
         heard: Set<String> = [], since: [String: Int] = [:]) {
        self.epoch = epoch
        self.sendCounters = sendCounters
        self.recvHighs = recvHighs
        self.heard = heard
        self.since = since
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        epoch = try container.decode(Int.self, forKey: .epoch)
        sendCounters = try container.decode([String: UInt64].self, forKey: .sendCounters)
        recvHighs = try container.decode([String: UInt64].self, forKey: .recvHighs)
        // State written before this field existed: a member I have received
        // from on their group address was plainly listening.
        heard = try container.decodeIfPresent(Set<String>.self, forKey: .heard) ?? Set(recvHighs.keys)
        since = try container.decodeIfPresent([String: Int].self, forKey: .since) ?? [:]
    }
}

// Which way a group message travels to a member: the group's own sealed
// address, or the per-contact path.
//
// A group address is one the recipient registers with the relay only after it
// has received the group key. Until then the address does not exist, and the
// relay accepts a deposit to an address it does not know and drops it, on
// purpose, so that nobody can probe which addresses exist. A member who was
// added while offline, or whose account was not the active one, would lose
// everything said before their next refresh, with no error on either side.
//
// The per-contact path is store-and-forward to an address the member already
// has. So a member gets group messages that way until they are known to be
// listening in this epoch, and by the group address from then on.
//
// "Known to be listening" means a group message has arrived from them in this
// epoch: they could only have sent it with the key, and an app registers its
// addresses in the same refresh in which it gets the key. A member who never
// posts moves to the group address peerPathSeconds after my first message to
// them in the epoch, which is as long as a message lives.
//
// Nothing is sent twice, and no group address is used up while the member
// cannot be listening on it, so the two sides' counters cannot drift apart
// while one of them is away.
enum GroupDelivery {
    static let peerPathSeconds = 30 * 86_400

    static func usePeerPath(_ state: SealedGroupState?, member memberHex: String, now: Int) -> Bool {
        guard let state else { return true }
        if state.heard.contains(memberHex) { return false }
        guard let first = state.since[memberHex] else { return true }
        return now - first < peerPathSeconds
    }
}

extension SealedKeyStore {
    func group(_ groupID: String) -> SealedGroupState? {
        guard let data = readData(account: "group.\(groupID)") else { return nil }
        return try? JSONDecoder().decode(SealedGroupState.self, from: data)
    }
    func setGroup(_ groupID: String, _ state: SealedGroupState) {
        guard let data = try? JSONEncoder().encode(state) else { return }
        writeData(data, account: "group.\(groupID)")
    }
    func deleteGroupState(_ groupID: String) {
        delete(account: "group.\(groupID)")
    }
}

// MARK: - Sealed sender: relay endpoints

// Same-file extension so these can reuse RelayClient's private post() and
// deviceID. All five endpoints are fingerprint-free; send carries no auth at all.
extension RelayClient {

    /// Register (or refresh) this anonymous device with the relay's sealed side.
    func sealedRegisterDevice(sealedDeviceID: String, deviceKey: String, wakeToken: String?) async throws {
        var body: [String: Any] = ["device_id": sealedDeviceID, "device_key": deviceKey]
        if let wakeToken, !wakeToken.isEmpty { body["wake_token"] = wakeToken }
        let ts = Int(Date().timeIntervalSince1970)
        body["ts"] = ts
        body["auth"] = MailboxCrypto.deviceAuth(deviceKeyHex: deviceKey, action: "register", deviceID: sealedDeviceID, ts: ts)
        let _: SealedOkResponse = try await post("/v1/sealed/register-device", body: body)
    }

    /// Register a batch of upcoming receive addresses, each with an expiry.
    @discardableResult
    func sealedRegisterMailboxes(sealedDeviceID: String, deviceKey: String, mailboxes: [[String: Any]]) async throws -> Int {
        let ts = Int(Date().timeIntervalSince1970)
        let body: [String: Any] = [
            "device_id": sealedDeviceID,
            "ts": ts,
            "auth": MailboxCrypto.deviceAuth(deviceKeyHex: deviceKey, action: "mbx", deviceID: sealedDeviceID, ts: ts),
            "mailboxes": mailboxes,
        ]
        let r: SealedOkResponse = try await post("/v1/sealed/register-mailboxes", body: body)
        return r.registered ?? 0
    }

    /// Deposit a sealed envelope at a mailbox. No authentication: the address is
    /// the capability. `silent` marks a wake-without-banner as on the legacy path.
    func sealedSend(mailbox: String, envelope: Data, expiresAt: Int, silent: Bool = false) async throws {
        var body: [String: Any] = [
            "mailbox": mailbox,
            "envelope": envelope.base64EncodedString(),
            "expires_at": expiresAt,
        ]
        if silent { body["silent"] = true }
        let _: SealedSendResponse = try await post("/v1/sealed/send", body: body)
    }

    /// Fetch messages across this device's registered mailboxes.
    /// `skip` lists relay message ids to leave out (envelopes that keep failing to
    /// open), so they can't crowd new ones out of a size-capped answer. A relay
    /// that predates it ignores the field.
    func sealedInbox(sealedDeviceID: String, deviceKey: String, skip: [String] = []) async throws -> [SealedInboxMessage] {
        let ts = Int(Date().timeIntervalSince1970)
        var body: [String: Any] = [
            "device_id": sealedDeviceID,
            "ts": ts,
            "auth": MailboxCrypto.deviceAuth(deviceKeyHex: deviceKey, action: "inbox", deviceID: sealedDeviceID, ts: ts),
        ]
        if !skip.isEmpty { body["skip"] = skip }
        let r: SealedInboxResponse = try await post("/v1/sealed/inbox", body: body)
        return r.messages
    }

    @discardableResult
    func sealedAck(sealedDeviceID: String, deviceKey: String, messageIDs: [String]) async throws -> Int {
        let ts = Int(Date().timeIntervalSince1970)
        let body: [String: Any] = [
            "device_id": sealedDeviceID,
            "ts": ts,
            "auth": MailboxCrypto.deviceAuth(deviceKeyHex: deviceKey, action: "ack", deviceID: sealedDeviceID, ts: ts),
            "message_ids": messageIDs,
        ]
        let r: SealedAckResponse = try await post("/v1/sealed/ack", body: body)
        return r.deleted
    }
}

// MARK: - Transport seam (2.1)

// What carries a sealed envelope from us to a peer. The relay is the default
// store-and-forward path; LAN-direct and future transports (SMS, Meshtastic,
// Nostr) are alternatives. The sealed envelope, crypto, and pair state stay
// ABOVE this seam in ChatStore; a Transport only decides how the opaque bytes
// reach the peer. See CarrierPony-2.1-Transport-LANDirect-Design.md.
enum TransportID { case relay, lanDirect, wanDirect, nostr }

struct TransportCapabilities {
    var storeAndForward: Bool
    var revealsIP: Bool
    var worksOffline: Bool
}

@MainActor
protocol Transport {
    var id: TransportID { get }
    var capabilities: TransportCapabilities { get }
    /// True if this transport can deliver to that peer right now (relay: always;
    /// LAN: only a peer currently discovered on the network).
    func canReach(_ peer: Fingerprint) -> Bool
    /// Deliver one sealed envelope. Returns true if delivered, false to let the
    /// caller fall through to the next transport; throws on a hard error, which
    /// the relay (the last transport) surfaces to the user exactly as before.
    /// mailbox is the sealed address ChatStore computed once for this message; the
    /// store-and-forward transports post to it and the direct transports ignore it.
    func send(_ envelope: Data, to peer: Fingerprint, mailbox: String?, expiresAt: Int, silent: Bool) async throws -> Bool
}

// The default transport: the relay's store-and-forward path. It takes the sealed
// mailbox address ChatStore computed for the message and posts the envelope to it.
@MainActor
final class RelayTransport: Transport {
    let id: TransportID = .relay
    let capabilities = TransportCapabilities(storeAndForward: true, revealsIP: false, worksOffline: false)

    private let relay: RelayClient

    init(relay: RelayClient) {
        self.relay = relay
    }

    func canReach(_ peer: Fingerprint) -> Bool { true }

    func send(_ envelope: Data, to peer: Fingerprint, mailbox: String?, expiresAt: Int, silent: Bool) async throws -> Bool {
        if let mailbox {
            try await relay.sealedSend(mailbox: mailbox, envelope: envelope, expiresAt: expiresAt, silent: silent)
        } else {
            _ = try await relay.send(envelope: envelope, to: peer, expiresAt: expiresAt, silent: silent)
        }
        return true
    }
}
