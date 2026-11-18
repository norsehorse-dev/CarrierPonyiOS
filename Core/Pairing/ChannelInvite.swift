import Foundation

// A broadcast-channel subscribe invite: a reusable link/QR an admin shares
// publicly so anyone can subscribe. Unlike a pairing Invite (a one-time relay
// token), this carries the admin's public key directly, so a stranger can seal a
// channel-subscribe to the admin with no prior pairing. It reveals only the
// channel id, the admin's identity, and the admin's key - nothing the relay can
// use to map the channel's membership.
//
// Wire form: "CPCHAN1:" + base64url(JSON), matching the CPPAIR1 shape so the same
// scanner and paste box recognize it. Both platforms must parse each other's
// invites.

struct ChannelInvite: Codable {
    let v: Int
    let c: String     // channel/group id (32 hex)
    let f: String     // admin fingerprint (40 hex, or 64 for v6)
    let k: String     // admin armored public key
    let t: String?    // optional invite token (gated channels); nil = open
    let n: String?    // channel name, optional (display only)
    let caps: [String]?  // what the admin's app supports (PairingCaps); absent before 4.0

    static let prefix = "CPCHAN1:"
    static let currentVersion = 1

    init(channelId: String, adminFingerprint: Fingerprint, adminArmoredKey: String,
         token: String?, name: String?, caps: [String]? = PairingCaps.current) {
        self.v = Self.currentVersion
        self.c = channelId
        self.f = adminFingerprint.hex
        self.k = adminArmoredKey
        self.t = (token?.isEmpty == false) ? token : nil
        self.n = (name?.isEmpty == false) ? name : nil
        self.caps = PairingCaps.normalized(caps)
    }

    // Written out so that a caps field of the wrong shape reads as no caps
    // and the invite still decodes.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        v = try container.decode(Int.self, forKey: .v)
        c = try container.decode(String.self, forKey: .c)
        f = try container.decode(String.self, forKey: .f)
        k = try container.decode(String.self, forKey: .k)
        t = try container.decodeIfPresent(String.self, forKey: .t)
        n = try container.decodeIfPresent(String.self, forKey: .n)
        caps = PairingCaps.decode(from: container, forKey: .caps)
    }

    var adminFingerprint: Fingerprint? { Fingerprint(f) }

    func encoded() -> String? {
        guard let json = try? JSONEncoder().encode(self) else { return nil }
        return Self.prefix + Self.base64urlEncode(json)
    }

    static func decode(_ text: String) -> ChannelInvite? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix(prefix) else { return nil }
        let b64 = String(trimmed.dropFirst(prefix.count))
        guard let data = base64urlDecode(b64),
              let invite = try? JSONDecoder().decode(ChannelInvite.self, from: data),
              invite.adminFingerprint != nil,
              invite.c.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil,
              !invite.k.isEmpty else {
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
