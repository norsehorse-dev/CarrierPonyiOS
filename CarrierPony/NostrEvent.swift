// NostrEvent.swift
// NIP-01 event build + BIP340 signing for the Nostr transport (2.3). secp256k1 is
// not in CryptoKit, so signing uses the audited swift-secp256k1 package (product
// P256K) - a C library, fine on iOS and irrelevant to the Android/F-Droid side which
// implements BIP340 in pure JVM. We only SIGN; the sealed envelope self-authenticates
// and relays verify sigs, so no verification path is needed. The id serialization is
// byte-identical to the Kotlin twin (validated against the same reference id).

import Foundation
import CryptoKit
import P256K

/// NIP-01 compact serialization (no whitespace, minimal escaping).
enum NostrSerialize {
    static func str(_ s: String) -> String {
        var out = "\""
        for c in s {
            switch c {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default: out.append(c)
            }
        }
        return out + "\""
    }

    static func tags(_ tags: [[String]]) -> String {
        var out = "["
        for (i, tag) in tags.enumerated() {
            if i > 0 { out += "," }
            out += "["
            for (j, v) in tag.enumerated() { if j > 0 { out += "," }; out += str(v) }
            out += "]"
        }
        return out + "]"
    }

    /// The id preimage: [0,pubkey,created_at,kind,tags,content].
    static func idPreimage(pubkey: String, createdAt: Int64, kind: Int, tags: [[String]], content: String) -> String {
        "[0,\(str(pubkey)),\(createdAt),\(kind),\(NostrSerialize.tags(tags)),\(str(content))]"
    }
}

struct NostrEvent {
    let id: String
    let pubkey: String
    let createdAt: Int64
    let kind: Int
    let tags: [[String]]
    let content: String
    let sig: String

    /// Wire JSON relays accept inside ["EVENT", <this>].
    func json() -> String {
        "{\"id\":\(NostrSerialize.str(id)),\"pubkey\":\(NostrSerialize.str(pubkey)),"
        + "\"created_at\":\(createdAt),\"kind\":\(kind),\"tags\":\(NostrSerialize.tags(tags)),"
        + "\"content\":\(NostrSerialize.str(content)),\"sig\":\(NostrSerialize.str(sig))}"
    }
}

enum NostrEventBuilder {
    /// Build + sign an event with an ephemeral secp256k1 key.
    static func build(secretKey: Data, createdAt: Int64, kind: Int, tags: [[String]], content: String,
                      aux: Data? = nil) throws -> NostrEvent {
        let priv = try P256K.Schnorr.PrivateKey(dataRepresentation: [UInt8](secretKey))
        let pubkey = Data(priv.publicKey.xonly.bytes).hexLower
        let preimage = NostrSerialize.idPreimage(pubkey: pubkey, createdAt: createdAt, kind: kind, tags: tags, content: content)
        var digest = [UInt8](SHA256.hash(data: Data(preimage.utf8)))
        var auxBytes = [UInt8](aux ?? randomBytes(32))
        let sig = try priv.signature(message: &digest, auxiliaryRand: &auxBytes)
        return NostrEvent(id: Data(digest).hexLower, pubkey: pubkey, createdAt: createdAt,
                          kind: kind, tags: tags, content: content, sig: sig.dataRepresentation.hexLower)
    }

    static func randomSecretKey() -> Data { randomBytes(32) }
    static func randomBytes(_ n: Int) -> Data { Data((0..<n).map { _ in UInt8.random(in: 0...255) }) }
}

/// Raw BIP340 signing exposed for the crypto test vectors: signs an arbitrary
/// 32-byte message (not a full event). Internal so the test target reaches it via
/// @testable import and does not need to link P256K itself.
enum NostrCrypto {
    static func signRaw(secretKey: Data, message: Data, aux: Data) throws -> (pubkey: String, sig: String) {
        let priv = try P256K.Schnorr.PrivateKey(dataRepresentation: [UInt8](secretKey))
        var msg = [UInt8](message); var auxB = [UInt8](aux)
        let sig = try priv.signature(message: &msg, auxiliaryRand: &auxB)
        return (Data(priv.publicKey.xonly.bytes).hexLower, sig.dataRepresentation.hexLower)
    }
}

extension Data {
    var hexLower: String {
        let d = "0123456789abcdef"; let da = Array(d)
        var s = ""; s.reserveCapacity(count * 2)
        for b in self { s.append(da[Int(b >> 4)]); s.append(da[Int(b & 0x0F)]) }
        return s
    }
}
