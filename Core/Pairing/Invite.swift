import Foundation

// An invite is what the offerer sends over a channel they already trust (Signal,
// SMS, email, in person). It carries the one-time relay token plus the offerer's
// fingerprint. The fingerprint is the anti-MITM anchor: when the invitee accepts,
// their app fetches the offerer's key from the relay and requires it to hash to
// this fingerprint before adding the contact. Because the fingerprint travelled
// out-of-band, the relay cannot substitute a key without the invitee noticing.
//
// Wire form: "CPPAIR1:" + base64url(JSON). Compact enough for a text message or a
// QR, and prefixed so a pasted invite is easy to recognize.

struct Invite: Codable {
    let v: Int
    let t: String     // one-time relay token (32 hex)
    let f: String     // offerer fingerprint (40 hex)
    let n: String?    // offerer display name, optional
    let c: [String]?  // what the offerer's app supports (PairingCaps); absent before 4.0

    static let prefix = "CPPAIR1:"
    static let currentVersion = 1

    init(token: String, fingerprint: Fingerprint, name: String?, caps: [String]? = PairingCaps.current) {
        self.v = Self.currentVersion
        self.t = token
        self.f = fingerprint.hex
        self.n = (name?.isEmpty == false) ? name : nil
        self.c = PairingCaps.normalized(caps)
    }

    // Written out so that a caps field of the wrong shape reads as no caps
    // and the invite still decodes.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        v = try container.decode(Int.self, forKey: .v)
        t = try container.decode(String.self, forKey: .t)
        f = try container.decode(String.self, forKey: .f)
        n = try container.decodeIfPresent(String.self, forKey: .n)
        c = PairingCaps.decode(from: container, forKey: .c)
    }

    var fingerprint: Fingerprint? { Fingerprint(f) }

    func encoded() -> String? {
        guard let json = try? JSONEncoder().encode(self) else { return nil }
        return Self.prefix + Self.base64urlEncode(json)
    }

    static func decode(_ text: String) -> Invite? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix(prefix) else { return nil }
        let b64 = String(trimmed.dropFirst(prefix.count))
        guard let data = base64urlDecode(b64),
              let invite = try? JSONDecoder().decode(Invite.self, from: data),
              invite.fingerprint != nil,
              invite.t.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil else {
            return nil
        }
        return invite
    }

    // MARK: - base64url (no padding)

    private static func base64urlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func base64urlDecode(_ s: String) -> Data? {
        var b = s.replacingOccurrences(of: "-", with: "+")
                 .replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b.append("=") }
        return Data(base64Encoded: b)
    }
}

// A pairing offer this identity created that hasn't been accepted yet. Persisted
// per identity so acceptance is still detected after the invite screen — or the
// whole app — has been closed: the invitee may paste an emailed invite hours
// later, and the pending list is swept on every inbox refresh and at the next
// launch until the offer is accepted or expires.
struct PendingInvite: Codable, Equatable {
    let token: String        // one-time relay token (32 hex)
    let name: String?        // display name the invite carried when created
    let createdAt: Date
    let expiresAt: Date?     // derived from the relay's expires_in; nil if absent
    // Set for the in-person live-QR offerer: the exchange happened face to face,
    // so completing this side (even later, from the background sweep) marks the
    // contact verified. Optional so invites persisted before this field decode
    // as nil, treated as remote trust-on-first-use.
    var inPerson: Bool?
    // The relay no longer knows the token (404/4xx), so it is not polled again,
    // but it is kept for the grace window in case the responder's pair-complete
    // op arrives. Optional so older persisted invites decode as nil (false).
    var relayGone: Bool?

    /// Rebuild the shareable invite. The fingerprint is supplied by the caller
    /// (always the current identity's — the pending list is keyed per identity).
    func invite(fingerprint: Fingerprint) -> Invite {
        Invite(token: token, fingerprint: fingerprint, name: name)
    }
}

// How long an offerer keeps a pairing offer it created. Expiry only ends the
// window for a NEW accept; an offer accepted while the offerer's app was closed
// must still be collectable afterwards, from the relay (which keeps accepted
// offers for 30 days) or from the responder's pair-complete op. So an offer is
// dropped only once it is past expiry plus this grace period. Mirrors Android's
// PairingRetention.
enum PairingRetention {
    static let grace: TimeInterval = 30 * 86_400
    /// Offers the relay gave no expiry for are kept this long after creation.
    static let noExpiryKeep: TimeInterval = 31 * 86_400

    static func isStale(_ invite: PendingInvite, now: Date = Date()) -> Bool {
        if let expiresAt = invite.expiresAt { return now > expiresAt.addingTimeInterval(grace) }
        return now > invite.createdAt.addingTimeInterval(noExpiryKeep)
    }
}
