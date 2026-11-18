import Foundation

// What an app tells the other side it can do, carried in an invite ("c") and
// in the offline key QR ("caps") as a short list of names.
//
// "v6" means this app can hold a contact whose identity is OpenPGP v6: it
// accepts a 64-character fingerprint, verifies v6 signatures and can encrypt
// to an ML-KEM-768 + X25519 subkey. Every app from 4.0 on says so, whatever
// kind of identity it has itself. Apps before 4.0 say nothing, and their
// parsers skip the field.
//
// The one rule built on it: a v6 identity does not pair with an app that
// cannot hold it. Such an app would add nothing on its side (it rejects the
// fingerprint outright), so this side would be left with a contact who can
// never answer. Refusing before the relay is asked also keeps the one-time
// token unused, so the same invite still works after the other person updates.
//
// A peer whose own fingerprint is v6 needs no cap: only 4.0 or later makes one.
//
// Android carries the same field under the same keys; both platforms must read
// each other's.

enum PairingCaps {

    static let v6 = "v6"

    /// What this build supports.
    static let current: [String] = [v6]

    private static let maxCaps = 16

    /// True when a peer with that fingerprint and those caps can hold a v6 contact.
    static func peerSupportsV6(_ peer: Fingerprint, caps: [String]?) -> Bool {
        peer.isV6 || caps?.contains(v6) == true
    }

    /// Whether the identity `mine` may pair with that peer. Only a v6 identity is ever refused.
    static func canPair(mine: Fingerprint, peer: Fingerprint, peerCaps: [String]?) -> Bool {
        !mine.isV6 || peerSupportsV6(peer, caps: peerCaps)
    }

    /// The list as it is stored and written: nil when there is nothing in it.
    static func normalized(_ caps: [String]?) -> [String]? {
        guard let caps, !caps.isEmpty else { return nil }
        return caps
    }

    /// The caps under `key`, or nil when there are none. Never fails: a field
    /// of the wrong shape, or a name that is not a short lowercase token, is
    /// skipped, because a cap this build does not understand must not make an
    /// invite unreadable.
    static func decode<Key: CodingKey>(from container: KeyedDecodingContainer<Key>, forKey key: Key) -> [String]? {
        guard let entries = try? container.decode([Entry].self, forKey: key) else { return nil }
        return names(in: entries)
    }

    private static func names(in entries: [Entry]) -> [String]? {
        var caps: [String] = []
        for entry in entries.prefix(maxCaps) {
            guard let name = entry.name, isName(name), !caps.contains(name) else { continue }
            caps.append(name)
        }
        return caps.isEmpty ? nil : caps
    }

    /// One to sixteen of a-z, 0-9, "_" and "-".
    private static func isName(_ name: String) -> Bool {
        let bytes = Array(name.utf8)
        guard (1...16).contains(bytes.count) else { return false }
        return bytes.allSatisfy {
            ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x5F || $0 == 0x2D
        }
    }

    /// A caps field for a type that leaves its coding to the compiler (a
    /// control message, a stored contact). Reads with the same tolerance as
    /// `decode(from:forKey:)`: whatever is under the key, decoding goes on.
    struct Stated: Codable, Equatable {
        let names: [String]

        /// Nil when there is nothing to state, so the field is left out.
        init?(_ caps: [String]?) {
            guard let caps, !caps.isEmpty else { return nil }
            names = caps
        }

        init(from decoder: Decoder) throws {
            let entries = (try? decoder.singleValueContainer().decode([Entry].self)) ?? []
            names = PairingCaps.names(in: entries) ?? []
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(names)
        }

        /// The names, or nil when the field held none.
        var caps: [String]? { names.isEmpty ? nil : names }
    }

    // One list entry of any JSON type. Only a string yields a name.
    private struct Entry: Decodable {
        let name: String?
        init(from decoder: Decoder) throws {
            name = try? decoder.singleValueContainer().decode(String.self)
        }
    }
}
