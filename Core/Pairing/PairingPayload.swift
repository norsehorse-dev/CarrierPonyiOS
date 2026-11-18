import Foundation
import CryptoKit

// The data exchanged when pairing: a peer's fingerprint, optional display name,
// and armored public key. Serialized to a compact base64 string for the QR.
//
// Security: on scan we recompute the primary-key fingerprint from the public key
// and require it to equal the claimed fingerprint before storing a contact. The
// fingerprint *is* the identity, so a QR whose key does not hash to its claimed
// fingerprint is rejected — you never store a contact you would then encrypt to
// under a fingerprint that does not match the key.

struct PairingPayload: Codable {
    let v: Int
    let fpr: String       // claimed fingerprint (hex)
    let name: String?
    let pub: String       // armored public key
    let caps: [String]?   // what this app supports (PairingCaps); absent before 4.0

    static let currentVersion = 1

    init(fingerprint: Fingerprint, name: String?, armoredPublicKey: String, caps: [String]? = PairingCaps.current) {
        self.v = Self.currentVersion
        self.fpr = fingerprint.hex
        self.name = name
        self.pub = armoredPublicKey
        self.caps = PairingCaps.normalized(caps)
    }

    // Written out so that a caps field of the wrong shape reads as no caps
    // and the code still decodes.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        v = try container.decode(Int.self, forKey: .v)
        fpr = try container.decode(String.self, forKey: .fpr)
        name = try container.decodeIfPresent(String.self, forKey: .name)
        pub = try container.decode(String.self, forKey: .pub)
        caps = PairingCaps.decode(from: container, forKey: .caps)
    }

    func encoded() -> String? {
        guard let json = try? JSONEncoder().encode(self) else { return nil }
        return json.base64EncodedString()
    }

    static func decode(_ text: String) -> PairingPayload? {
        guard let data = Data(base64Encoded: text),
              let payload = try? JSONDecoder().decode(PairingPayload.self, from: data) else {
            return nil
        }
        return payload
    }

    /// Build a Contact only if the claimed fingerprint matches the public key.
    /// Returns nil for a malformed key or a fingerprint mismatch.
    func verifiedContact() -> Contact? {
        guard let fingerprint = Fingerprint(fpr),
              let computed = OpenPGPKeyID.primaryFingerprint(armoredPublicKey: pub),
              computed == fingerprint.hex else {
            return nil
        }
        return Contact(
            fingerprint: fingerprint,
            publicKey: PublicKey(fingerprint: fingerprint, armored: pub),
            name: name,
            trust: .verified
        )
    }
}

// Computes the OpenPGP primary-key fingerprint from an armored public key.
// v4: SHA-1(0x99 || 2-byte len || body). v6: SHA-256(0x9B || 4-byte len || body).
// Fingerprint accepts both lengths, so a v4 or a v6 key can be a contact.
enum OpenPGPKeyID {

    static func primaryFingerprint(armoredPublicKey: String) -> String? {
        guard let data = PGPArmor.dearmor(armoredPublicKey) else { return nil }
        let bytes = [UInt8](data)
        guard !bytes.isEmpty else { return nil }

        var i = 0
        let header = bytes[0]
        var tag = 0
        var length = 0

        if header & 0x40 != 0 {              // new-format packet
            tag = Int(header & 0x3F); i = 1
            guard i < bytes.count else { return nil }
            let o = Int(bytes[i]); i += 1
            if o < 192 {
                length = o
            } else if o < 224 {
                guard i < bytes.count else { return nil }
                length = ((o - 192) << 8) + Int(bytes[i]) + 192; i += 1
            } else if o == 255 {
                guard i + 4 <= bytes.count else { return nil }
                length = (Int(bytes[i]) << 24) | (Int(bytes[i+1]) << 16) | (Int(bytes[i+2]) << 8) | Int(bytes[i+3]); i += 4
            } else {
                return nil
            }
        } else {                             // old-format packet
            tag = Int((header >> 2) & 0x0F)
            let lengthType = Int(header & 0x03); i = 1
            switch lengthType {
            case 0: guard i < bytes.count else { return nil }; length = Int(bytes[i]); i += 1
            case 1: guard i + 2 <= bytes.count else { return nil }; length = (Int(bytes[i]) << 8) | Int(bytes[i+1]); i += 2
            case 2: guard i + 4 <= bytes.count else { return nil }; length = (Int(bytes[i]) << 24) | (Int(bytes[i+1]) << 16) | (Int(bytes[i+2]) << 8) | Int(bytes[i+3]); i += 4
            default: return nil
            }
        }

        guard tag == 6, i + length <= bytes.count else { return nil }   // tag 6 = public key
        let body = Array(bytes[i..<(i + length)])
        guard let version = body.first else { return nil }

        if version == 4 {
            var input: [UInt8] = [0x99, UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
            input.append(contentsOf: body)
            let digest = Insecure.SHA1.hash(data: Data(input))
            return digest.map { String(format: "%02X", $0) }.joined()
        } else if version == 6 {
            var input: [UInt8] = [0x9B,
                UInt8((length >> 24) & 0xFF), UInt8((length >> 16) & 0xFF),
                UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
            input.append(contentsOf: body)
            let digest = SHA256.hash(data: Data(input))
            return digest.map { String(format: "%02X", $0) }.joined()
        }
        return nil
    }
}
