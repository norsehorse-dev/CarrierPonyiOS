import Foundation

// App-level configuration and small shared helpers for the wiring layer.

enum AppConfig {

    /// The default CarrierPony relay. Used unless the user has pointed the app
    /// at a self-hosted relay in Settings > Relay.
    static let defaultRelayBaseURL = "https://api.carrierpony.com"

    private static let relayURLKey = "cp.relayBaseURL"

    /// The relay this install talks to. Defaults to the CarrierPony relay; a
    /// self-hoster can override it in Settings > Relay. The value is read once
    /// at launch when the network stack is built, so a change takes effect on
    /// the next launch.
    static var relayBaseURL: String {
        if let stored = UserDefaults.standard.string(forKey: relayURLKey),
           isValidRelayURL(stored) {
            return normalizedRelayURL(stored)
        }
        return defaultRelayBaseURL
    }

    /// True when the app is pointed at a relay other than the default.
    static var usingCustomRelay: Bool {
        guard let stored = UserDefaults.standard.string(forKey: relayURLKey),
              !stored.isEmpty else { return false }
        return normalizedRelayURL(stored) != defaultRelayBaseURL
    }

    /// Persist a custom relay base URL. Pass nil, an empty string, or the
    /// default to clear the override and return to the CarrierPony relay.
    /// Returns false (storing nothing) if the URL is not a valid https origin.
    @discardableResult
    static func setRelayBaseURL(_ url: String?) -> Bool {
        guard let url,
              !url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            UserDefaults.standard.removeObject(forKey: relayURLKey)
            return true
        }
        let normalized = normalizedRelayURL(url)
        guard isValidRelayURL(normalized) else { return false }
        if normalized == defaultRelayBaseURL {
            UserDefaults.standard.removeObject(forKey: relayURLKey)
        } else {
            UserDefaults.standard.set(normalized, forKey: relayURLKey)
        }
        return true
    }

    /// Trim whitespace and any trailing slashes. The client appends "/v1/..."
    /// paths, so the stored base must not end in a slash.
    static func normalizedRelayURL(_ url: String) -> String {
        var s = url.trimmingCharacters(in: .whitespacesAndNewlines)
        while s.hasSuffix("/") { s.removeLast() }
        return s
    }

    /// A relay URL must be an https origin with a host. http is refused because
    /// the challenge-response auth (nonce + signature) must not travel in clear.
    static func isValidRelayURL(_ url: String) -> Bool {
        let s = normalizedRelayURL(url)
        guard let comps = URLComponents(string: s),
              comps.scheme?.lowercased() == "https",
              let host = comps.host, !host.isEmpty else { return false }
        return true
    }

    /// Maximum total attachment bytes per message. The relay must accept an
    /// encrypted envelope somewhat larger than this (base64 of the encrypted
    /// container), so keep the relay's max_envelope_bytes above ~1.4x this.
    static let maxAttachmentBytes = 50 * 1024 * 1024

    /// The CarrierPony push gateway. A relay you run yourself can't wake installs
    /// on its own; a user may opt in to be woken through this gateway, which holds
    /// the publisher push credentials and only ever gets a content-free nudge.
    static let gatewayBaseURL = "https://push.carrierpony.com"

    private static let lanDirectKey = "cp.lanDirect"

    /// LAN-direct (2.1): opt-in, off by default. When on, the app identifies known
    /// contacts on the local network and (M3b) delivers to them directly, which
    /// exposes this device's IP to that contact. Off keeps everything on the relay.
    static var lanDirectEnabled: Bool {
        get { UserDefaults.standard.bool(forKey: lanDirectKey) }
        set { UserDefaults.standard.set(newValue, forKey: lanDirectKey) }
    }

    private static let lanSkipRelayKey = "cp.lanSkipRelay"

    /// LAN-direct "skip the relay" (2.1 M4b): when on, a message delivered directly
    /// on the local network is NOT also sent through the relay. Maximizes privacy
    /// (the relay sees nothing) at the cost of the peer's other devices and offline
    /// delivery. Only meaningful when lanDirectEnabled is on. Off by default.
    static var lanDirectSkipRelay: Bool {
        get { UserDefaults.standard.bool(forKey: lanSkipRelayKey) }
        set { UserDefaults.standard.set(newValue, forKey: lanSkipRelayKey) }
    }

    private static let wanDirectKey = "cp.wanDirect"

    /// WAN-direct (2.2): opt-in, off by default. When on, the app sets up direct
    /// peer-to-peer paths over the internet (STUN + authenticated UDP hole punching
    /// via PonyDirect), with the relay only introducing the peers over sealed
    /// signaling. Exposes each peer's IP to the other. Falls back to the relay when a
    /// path cannot be punched (no TURN).
    static var wanDirectEnabled: Bool {
        get { UserDefaults.standard.bool(forKey: wanDirectKey) }
        set { UserDefaults.standard.set(newValue, forKey: wanDirectKey) }
    }

    private static let nostrKey = "cp.nostr"

    /// Nostr transport (2.3): opt-in, off by default. When on, each message is also
    /// posted to the peer's sealed mailbox address on a set of Nostr relays, giving
    /// delivery a path that does not depend on your own relay. Third-party relays see
    /// opaque content under a rotating tag, and they see this device's IP.
    static var nostrEnabled: Bool {
        get { UserDefaults.standard.bool(forKey: nostrKey) }
        set { UserDefaults.standard.set(newValue, forKey: nostrKey) }
    }

    private static let nostrRelaysKey = "cp.nostrRelays"

    /// The default Nostr relays. A self-hoster can point this at their own relay.
    static let defaultNostrRelays = ["wss://relay.damus.io", "wss://nos.lol"]

    /// The Nostr relay set (ws/wss URLs). Defaults to a couple of permissive public
    /// relays until the user sets their own in Settings.
    static var nostrRelays: [String] {
        get { UserDefaults.standard.stringArray(forKey: nostrRelaysKey) ?? defaultNostrRelays }
        set { UserDefaults.standard.set(newValue, forKey: nostrRelaysKey) }
    }

    /// The Nostr relay set as URLs, dropping any that do not parse.
    static var nostrRelayURLs: [URL] { nostrRelays.compactMap { URL(string: $0) } }

    private static let wanStunHostKey = "cp.wanStunHost"
    private static let wanStunPortKey = "cp.wanStunPort"

    /// The STUN server used to learn this device's public address for hole punching.
    /// Empty means "use the relay's host", since a self-hoster runs ponystun on the
    /// same box (UDP 3478). A custom value overrides it.
    static var wanStunHost: String {
        get { UserDefaults.standard.string(forKey: wanStunHostKey) ?? "" }
        set { UserDefaults.standard.set(newValue, forKey: wanStunHostKey) }
    }

    /// The STUN server UDP port. Defaults to 3478.
    static var wanStunPort: Int {
        get {
            let v = UserDefaults.standard.integer(forKey: wanStunPortKey)
            return v == 0 ? 3478 : v
        }
        set { UserDefaults.standard.set(newValue, forKey: wanStunPortKey) }
    }

    private static let gatewayEnabledKey = "cp.gatewayPush"
    private static let wakeTokenKey = "cp.wakeToken"

    /// Whether the user opted in to gateway push. Only meaningful on a custom relay.
    static var gatewayPushEnabled: Bool {
        get { UserDefaults.standard.bool(forKey: gatewayEnabledKey) }
        set { UserDefaults.standard.set(newValue, forKey: gatewayEnabledKey) }
    }

    /// The wake token this device holds from the gateway while opted in.
    static var storedWakeToken: String? {
        get { UserDefaults.standard.string(forKey: wakeTokenKey) }
        set {
            if let newValue { UserDefaults.standard.set(newValue, forKey: wakeTokenKey) }
            else { UserDefaults.standard.removeObject(forKey: wakeTokenKey) }
        }
    }

    /// Per-account wake token: each identity registers its own sealed device with
    /// the gateway, so the relay can't link two accounts by a shared wake token.
    static func storedWakeToken(for fpr: String?) -> String? {
        UserDefaults.standard.string(forKey: wakeTokenKey(for: fpr))
    }

    static func setStoredWakeToken(_ token: String?, for fpr: String?) {
        let key = wakeTokenKey(for: fpr)
        if let token { UserDefaults.standard.set(token, forKey: key) }
        else { UserDefaults.standard.removeObject(forKey: key) }
    }

    private static func wakeTokenKey(for fpr: String?) -> String {
        guard let fpr else { return wakeTokenKey }
        return "\(wakeTokenKey).\(fpr)"
    }

    /// A stable per-install device identifier, minted once and persisted. The
    /// relay requires exactly 32 lowercase hex characters (^[0-9a-f]{32}$), so a
    /// hyphenated/uppercase UUID string won't pass — strip the hyphens and
    /// lowercase it, which yields the 32-hex form the relay was built against.
    static var deviceID: String {
        let key = "cp.deviceID"
        if let existing = UserDefaults.standard.string(forKey: key),
           existing.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil {
            return existing
        }
        let id = UUID().uuidString
            .replacingOccurrences(of: "-", with: "")
            .lowercased()
        UserDefaults.standard.set(id, forKey: key)
        return id
    }
}

// Minimal OpenPGP dearmor: strips the header/footer and the CRC line, returning
// the binary packet bytes. Used to turn a contact's ASCII-armored public key
// into the raw bytes the crypto engine's resolver expects.
enum PGPArmor {
    static func dearmor(_ armored: String) -> Data? {
        let normalized = armored
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        var lines = normalized.components(separatedBy: "\n")

        // Narrow to the armored block if the markers are present.
        if let begin = lines.firstIndex(where: { $0.hasPrefix("-----BEGIN") }) {
            lines = Array(lines[(begin + 1)...])
        }
        if let end = lines.firstIndex(where: { $0.hasPrefix("-----END") }) {
            lines = Array(lines[..<end])
        }
        // Armor headers (Version:, Comment:, ...) run until the first blank line;
        // external keys (gpg, PGPony) include them, and they must not be decoded
        // as base64. Skip everything up to and including that blank line.
        if let blank = lines.firstIndex(where: { $0.trimmingCharacters(in: .whitespaces).isEmpty }) {
            lines = Array(lines[(blank + 1)...])
        }
        // Join the base64 body, dropping the trailing CRC line. Line endings vary
        // (CRLF from Foundation's armor), so ignore any non-base64 characters.
        let body = lines
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("=") }
            .joined()
        guard !body.isEmpty else { return nil }
        return Data(base64Encoded: body, options: .ignoreUnknownCharacters)
    }
}
