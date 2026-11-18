import Foundation
import NorseHorsePGPCore

// Reading a public key someone handed over as text or as a file, to add them
// as a contact. Pairing delivers a key the other app wrote; this path takes
// whatever a person pastes, so it has to say clearly what is wrong with it.
//
// A key is usable when it has the shape the apps make and can encrypt to:
//   v4: Ed25519 primary key, Curve25519 encryption subkey
//   v6: Ed25519 primary key, ML-KEM-768 + X25519 encryption subkey
// and the primary key has signed for that subkey, the same line held every
// time a message is encrypted.
//
// What comes back is the first key in the input, as clean armor with nothing
// around it: no comment headers, no surrounding text, no further keys.
// Android's CPContactKey answers the same way for the same input.

enum ContactKey {

    struct Usable {
        let fingerprint: Fingerprint
        let armoredPublicKey: String
        /// The name in the key's first user ID, if it has one.
        let name: String?
    }

    enum Result {
        /// A key the app can hold as a contact.
        case usable(Usable)
        /// A secret key. Never something to hand to another person.
        case secretKey
        /// Not an OpenPGP public key at all.
        case notAKey
        /// A real public key, but not one the app can use: another algorithm,
        /// no encryption subkey, a subkey its primary key has not signed, or a
        /// revoked key.
        case unsupported
    }

    /// Anything larger is not one person's public key.
    static let maxInputBytes = 256 * 1024

    private static let beginPublic = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    private static let endPublic = "-----END PGP PUBLIC KEY BLOCK-----"
    private static let privateMark = "PGP PRIVATE KEY BLOCK"

    /// Inspect pasted text.
    static func inspect(_ text: String) -> Result {
        inspect(Data(text.utf8))
    }

    /// Inspect a file's bytes, armored or binary.
    static func inspect(_ input: Data) -> Result {
        guard !input.isEmpty, input.count <= maxInputBytes else { return .notAKey }
        guard let decoded = binary(input) else {
            return looksPrivate(input) ? .secretKey : .notAKey
        }
        let binary = Data(decoded)
        guard let packets = packets(in: binary), let primary = packets.first else { return .notAKey }
        if primary.tag == 5 { return .secretKey }
        guard primary.tag == 6 else { return .notAKey }

        // The first key only: everything up to the next primary key.
        let rest = packets.dropFirst()
        let end = rest.first(where: { $0.tag == 6 || $0.tag == 5 })?.start ?? binary.count
        let first = Data(binary[0..<end])
        let own = packets.prefix(while: { $0.start < end })

        // Version, then four bytes of creation time, then the algorithm.
        guard primary.body.count > 5 else { return .notAKey }
        let version = primary.body[0]
        let algorithm = primary.body[5]

        // A revocation of the key itself comes before its first user ID.
        for packet in own.dropFirst() {
            if packet.tag == 13 || packet.tag == 14 { break }
            if packet.tag == 2, packet.body.count > 1, packet.body[1] == 0x20 { return .unsupported }
        }

        let usable: Bool
        switch version {
        case 4:
            guard algorithm == 22,
                  (try? OpenPGPPacketParser.ed25519PublicKey(fromPublicKeyData: first)) != nil,
                  let recipient = try? OpenPGPPacketParser.cv25519Recipient(fromPublicKey: first) else {
                return .unsupported
            }
            usable = OpenPGPPacketParser.isBound(recipient, inPublicKey: first)
        case 6:
            guard algorithm == 27,
                  (try? OpenPGPPacketParser.ed25519PublicKey(fromPublicKeyData: first)) != nil,
                  let recipient = try? OpenPGPPacketParser.compositeRecipient(fromV6PublicKey: first) else {
                return .unsupported
            }
            usable = OpenPGPPacketParser.isBound(recipient, inPublicKey: first)
        default:
            return .unsupported
        }
        guard usable else { return .unsupported }

        let armored = armor(first)
        guard let hex = OpenPGPKeyID.primaryFingerprint(armoredPublicKey: armored),
              let fingerprint = Fingerprint(hex) else { return .notAKey }
        return .usable(Usable(fingerprint: fingerprint, armoredPublicKey: armored,
                              name: KeyImport.userIDName(fromSecretKey: first)))
    }

    // MARK: - Packets

    struct Packet {
        let tag: UInt8
        let start: Int      // offset of the packet's first byte
        let body: [UInt8]
    }

    /// The packets of a binary OpenPGP stream, or nil if it does not parse as
    /// one from start to finish. Partial body lengths do not occur in a key.
    static func packets(in data: Data) -> [Packet]? {
        let bytes = [UInt8](data)
        var packets: [Packet] = []
        var i = 0
        while i < bytes.count {
            let start = i
            let header = bytes[i]; i += 1
            guard header & 0x80 != 0 else { return nil }
            let tag: UInt8
            var length = 0
            if header & 0x40 != 0 {
                tag = header & 0x3F
                guard i < bytes.count else { return nil }
                let first = Int(bytes[i]); i += 1
                if first < 192 {
                    length = first
                } else if first < 224 {
                    guard i < bytes.count else { return nil }
                    length = ((first - 192) << 8) + Int(bytes[i]) + 192; i += 1
                } else if first == 255 {
                    guard i + 4 <= bytes.count else { return nil }
                    length = Int(bytes[i]) << 24 | Int(bytes[i + 1]) << 16 | Int(bytes[i + 2]) << 8 | Int(bytes[i + 3]); i += 4
                } else {
                    return nil
                }
            } else {
                tag = (header >> 2) & 0x0F
                switch header & 0x03 {
                case 0:
                    guard i < bytes.count else { return nil }
                    length = Int(bytes[i]); i += 1
                case 1:
                    guard i + 2 <= bytes.count else { return nil }
                    length = Int(bytes[i]) << 8 | Int(bytes[i + 1]); i += 2
                case 2:
                    guard i + 4 <= bytes.count else { return nil }
                    length = Int(bytes[i]) << 24 | Int(bytes[i + 1]) << 16 | Int(bytes[i + 2]) << 8 | Int(bytes[i + 3]); i += 4
                default:
                    return nil
                }
            }
            guard length >= 0, i + length <= bytes.count else { return nil }
            packets.append(Packet(tag: tag, start: start, body: Array(bytes[i..<(i + length)])))
            i += length
        }
        return packets.isEmpty ? nil : packets
    }

    // MARK: - Armor

    /// The binary packets of the input: the public key block if it is armored
    /// text (whatever surrounds it), else the bytes as they are. Nil when it is
    /// text with no public key block in it, or armor that does not decode.
    private static func binary(_ input: Data) -> Data? {
        let head = String(decoding: input.prefix(64 * 1024), as: UTF8.self)
        guard head.contains("-----BEGIN PGP") else {
            // Binary packets start with a byte whose top bit is set.
            return (input[input.startIndex] & 0x80) != 0 ? input : nil
        }
        let text = String(decoding: input, as: UTF8.self)
        guard let begin = text.range(of: beginPublic),
              let end = text.range(of: endPublic, range: begin.upperBound..<text.endIndex) else { return nil }
        return PGPArmor.dearmor(String(text[begin.lowerBound..<end.upperBound]))
    }

    private static func looksPrivate(_ input: Data) -> Bool {
        String(decoding: input.prefix(64 * 1024), as: UTF8.self).contains(privateMark)
    }

    static func armor(_ binary: Data) -> String {
        let body = binary.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        var crc: UInt32 = 0xB704CE
        for byte in binary {
            crc ^= UInt32(byte) << 16
            for _ in 0..<8 {
                crc <<= 1
                if crc & 0x1000000 != 0 { crc ^= 0x1864CFB }
            }
        }
        crc &= 0xFFFFFF
        let checksum = Data([UInt8(crc >> 16), UInt8((crc >> 8) & 0xFF), UInt8(crc & 0xFF)]).base64EncodedString()
        return "\(beginPublic)\n\n\(body)\n=\(checksum)\n\(endPublic)\n"
    }

    /// The file a shared public key is saved under: the name on the key, or the
    /// end of its fingerprint when the key has no name. Only letters, digits,
    /// spaces, dashes and underscores are kept, so it is safe as a file name.
    static func fileName(armoredPublicKey: String, fingerprint: Fingerprint) -> String {
        var name: String?
        if let binary = PGPArmor.dearmor(armoredPublicKey), let raw = KeyImport.userIDName(fromSecretKey: binary) {
            let kept = String(raw.unicodeScalars.filter {
                CharacterSet.alphanumerics.contains($0) || $0 == " " || $0 == "-" || $0 == "_"
            }.map(Character.init))
            let cut = String(kept.trimmingCharacters(in: .whitespaces).prefix(40)).trimmingCharacters(in: .whitespaces)
            if !cut.isEmpty { name = cut }
        }
        return (name ?? "carrierpony-\(fingerprint.hex.suffix(8))") + ".asc"
    }
}

// MARK: - A key file handed over by another app

/// A public key file opened with CarrierPony from Files, Mail, AirDrop or a
/// PGP app's share sheet. It is only ever loaded into Add by Public Key, where
/// the usual check runs and the person still taps Add contact.
struct IncomingKey: Identifiable, Equatable {
    let id = UUID()
    /// The file's bytes, or nil when it could not be read.
    let data: Data?

    static func == (a: IncomingKey, b: IncomingKey) -> Bool { a.id == b.id }
}

extension ContactKey {

    /// Reads one byte more than a key may be at most, so an oversized file is
    /// turned down by the key check without being loaded whole.
    static func read(fileAt url: URL) -> Data? {
        guard url.isFileURL else { return nil }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        return try? handle.read(upToCount: maxInputBytes + 1)
    }

    /// iOS copies a file opened with the app into Documents/Inbox and leaves
    /// it there. Remove that copy once it has been read.
    static func removeInboxCopy(_ url: URL) {
        guard url.isFileURL, url.deletingLastPathComponent().lastPathComponent == "Inbox" else { return }
        try? FileManager.default.removeItem(at: url)
    }
}
