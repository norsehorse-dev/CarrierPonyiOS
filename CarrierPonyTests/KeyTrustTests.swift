//
//  KeyTrustTests.swift
//  CarrierPonyTests
//
//  A contact is pinned by their primary key. Their encryption subkey is used
//  only when that primary key has signed for it. Every kind of key the apps
//  produce has to pass, and a key with the right primary and somebody else's
//  subkey has to be refused before anything is encrypted to it. The Android
//  core's CPKeyTrustTest holds the same line.
//

import Foundation
import Testing
import NorseHorsePGPCore
@testable import CarrierPony

struct KeyTrustTests {

    private struct Packet {
        let tag: UInt8
        let body: [UInt8]

        // New-format framing, which is what both key generators write.
        var raw: [UInt8] {
            var out: [UInt8] = [0xC0 | tag]
            let n = body.count
            if n < 192 {
                out.append(UInt8(n))
            } else if n < 8384 {
                out.append(UInt8((n - 192) >> 8 + 192))
                out.append(UInt8((n - 192) & 0xFF))
            } else {
                out += [0xFF, UInt8((n >> 24) & 0xFF), UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)]
            }
            return out + body
        }
    }

    private func split(_ data: Data) throws -> [Packet] {
        let bytes = [UInt8](data)
        var out: [Packet] = []
        var i = 0
        while i < bytes.count {
            try #require(bytes[i] & 0xC0 == 0xC0)
            let tag = bytes[i] & 0x3F
            i += 1
            var length = 0
            if bytes[i] < 192 {
                length = Int(bytes[i]); i += 1
            } else if bytes[i] < 224 {
                length = (Int(bytes[i]) - 192) << 8 + Int(bytes[i + 1]) + 192; i += 2
            } else {
                try #require(bytes[i] == 255)
                length = Int(bytes[i + 1]) << 24 | Int(bytes[i + 2]) << 16 | Int(bytes[i + 3]) << 8 | Int(bytes[i + 4]); i += 5
            }
            try #require(i + length <= bytes.count)
            out.append(Packet(tag: tag, body: Array(bytes[i..<i + length])))
            i += length
        }
        return out
    }

    private func join(_ packets: [Packet]) -> Data { Data(packets.flatMap { $0.raw }) }

    private func publicData(_ identity: GeneratedIdentity) throws -> Data {
        try #require(PGPArmor.dearmor(identity.armoredPublicKey))
    }

    private func v4(_ name: String = "Test Pony") throws -> GeneratedIdentity {
        try OpenPGPKeyGenerator.generateV4Identity(name: name, email: "test@carrierpony.com")
    }

    private func v6(_ name: String = "Test Pony") throws -> GeneratedIdentity {
        try OpenPGPKeyGenerator.generateV6Identity(name: name, email: "test@carrierpony.com")
    }

    // Whether the encryption subkey found in `key` is bound to its primary.
    private func encryptionSubkeyIsBound(_ key: Data) throws -> Bool {
        if OpenPGPPacketParser.openPGPKeyVersion(from: key) == 6 {
            let recipient = try #require(try OpenPGPPacketParser.compositeRecipient(fromV6PublicKey: key))
            return OpenPGPPacketParser.isBound(recipient, inPublicKey: key)
        }
        let recipient = try OpenPGPPacketParser.cv25519Recipient(fromPublicKey: key)
        return OpenPGPPacketParser.isBound(recipient, inPublicKey: key)
    }

    // The victim's primary key and user ID with the attacker's subkey, which
    // still carries the attacker's own, perfectly valid, binding.
    private func graft(victim: Data, attacker: Data) throws -> Data {
        let mine = try split(victim)
        let theirs = try split(attacker)
        let firstSubkey = try #require(mine.firstIndex { $0.tag == 14 })
        let theirSubkey = try #require(theirs.firstIndex { $0.tag == 14 })
        return join(Array(mine[..<firstSubkey]) + Array(theirs[theirSubkey...]))
    }

    private func engine(for identity: GeneratedIdentity, contactKey: Data, contact: Fingerprint) throws -> PGPonyCryptoEngine {
        PGPonyCryptoEngine(
            fingerprint: try #require(Fingerprint(identity.fingerprint)), secretKey: identity.secretKey,
            armoredPublicKey: identity.armoredPublicKey, publicKeyData: { $0 == contact ? contactKey : nil }
        )
    }

    // MARK: - Keys the apps produce are accepted

    @Test func generatedV4AndV6IdentitiesAreBound() throws {
        for _ in 0..<50 {
            #expect(try encryptionSubkeyIsBound(try publicData(try v4())))
            #expect(try encryptionSubkeyIsBound(try publicData(try v6())))
        }
    }

    // Keys made by the Android core and earlier fixtures from this one, under
    // /tmp/carrierpony-fixtures/shared. Skipped when that folder is absent.
    @Test func sharedFixtureKeysAreBound() throws {
        let directory = URL(fileURLWithPath: "/tmp/carrierpony-fixtures/shared", isDirectory: true)
        var checked = 0
        for name in ["ios-v4", "ios-v6", "peer-android-v4", "peer-android-v6"] {
            guard let armored = try? String(contentsOf: directory.appendingPathComponent("\(name)-public.asc"), encoding: .utf8) else {
                continue
            }
            let key = try #require(PGPArmor.dearmor(armored))
            #expect(try encryptionSubkeyIsBound(key), "\(name)")
            checked += 1
        }
        if checked > 0 {
            try "bound-fixture-keys checked=\(checked)\n".write(
                to: directory.appendingPathComponent("ios-key-trust.txt"), atomically: true, encoding: .utf8)
        }
    }

    // MARK: - Somebody else's subkey under the right primary is refused

    @Test func graftedSubkeyIsNotBound() throws {
        for make in [v4, v6] {
            let victim = try publicData(try make("Victim"))
            let attacker = try publicData(try make("Attacker"))
            let forged = try graft(victim: victim, attacker: attacker)
            // Still the victim's fingerprint, so a pin on the primary key alone would pass it.
            #expect(OpenPGPPacketParser.openPGPKeyVersion(from: forged) == OpenPGPPacketParser.openPGPKeyVersion(from: victim))
            #expect(try encryptionSubkeyIsBound(victim))
            #expect(try !encryptionSubkeyIsBound(forged))
        }
    }

    @Test func encryptingToAGraftedSubkeyIsRefused() throws {
        for make in [v4, v6] {
            let sender = try make("Sender")
            let victim = try make("Victim")
            let attacker = try make("Attacker")
            let victimFingerprint = try #require(Fingerprint(victim.fingerprint))
            let victimKey = PublicKey(fingerprint: victimFingerprint, armored: victim.armoredPublicKey)

            let forged = try graft(victim: try publicData(victim), attacker: try publicData(attacker))
            let fooled = try engine(for: sender, contactKey: forged, contact: victimFingerprint)
            #expect(throws: KeyTrustError.encryptionSubkeyNotBound) {
                _ = try fooled.signAndEncrypt(Data("secret".utf8), to: victimKey)
            }

            let honest = try engine(for: sender, contactKey: try publicData(victim), contact: victimFingerprint)
            #expect(try !honest.signAndEncrypt(Data("secret".utf8), to: victimKey).isEmpty)
        }
    }

    @Test func subkeyWithNoBindingIsNotBound() throws {
        for make in [v4, v6] {
            let key = try publicData(try make("A"))
            var packets = try split(key)
            #expect(packets.last?.tag == 2)
            packets.removeLast()
            #expect(try !encryptionSubkeyIsBound(join(packets)))
        }
    }

    @Test func alteredBindingOrSubkeyIsNotBound() throws {
        for make in [v4, v6] {
            let packets = try split(try publicData(try make("A")))
            let subkeyIndex = try #require(packets.firstIndex { $0.tag == 14 })

            // One bit in the signature value, at the very end of the binding.
            var badSignature = packets
            var body = badSignature[badSignature.count - 1].body
            body[body.count - 1] ^= 0x01
            badSignature[badSignature.count - 1] = Packet(tag: 2, body: body)
            #expect(try !encryptionSubkeyIsBound(join(badSignature)))

            // One bit in the subkey's key material: a different key under the same binding.
            var badSubkey = packets
            var subkeyBody = badSubkey[subkeyIndex].body
            subkeyBody[subkeyBody.count - 10] ^= 0x01
            badSubkey[subkeyIndex] = Packet(tag: 14, body: subkeyBody)
            #expect(try !encryptionSubkeyIsBound(join(badSubkey)))
        }
    }

    // MARK: - Bindings written by the old encoder still count

    // Before it was corrected, this core wrote a signature value that began
    // with a zero octet at full width under a bit count that left the zero
    // out. Identities made then are in use, and their bindings must still be
    // accepted. This rewrites a fresh binding into that layout and checks it.
    @Test func bindingInTheOldEncoderLayoutIsStillBound() throws {
        var converted = 0
        var attempts = 0
        while converted < 3 && attempts < 4000 {
            attempts += 1
            let key = try publicData(try v4())
            var packets = try split(key)
            guard let old = oldLayout(ofV4Signature: packets[packets.count - 1].body) else { continue }
            packets[packets.count - 1] = Packet(tag: 2, body: old)
            let rewritten = join(packets)
            #expect(rewritten.count > key.count)
            #expect(try encryptionSubkeyIsBound(rewritten))
            converted += 1
        }
        #expect(converted == 3, "found \(converted) candidates in \(attempts) identities")
    }

    // A v4 signature body with any short R or S padded back to 32 octets under
    // its unchanged bit count. Nil when both are already 32 octets.
    private func oldLayout(ofV4Signature body: [UInt8]) -> [UInt8]? {
        guard body.count > 10, body[0] == 4 else { return nil }
        var i = 4
        let hashed = Int(body[i]) << 8 | Int(body[i + 1]); i += 2 + hashed
        let unhashed = Int(body[i]) << 8 | Int(body[i + 1]); i += 2 + unhashed
        i += 2
        var out = Array(body[..<i])
        var padded = false
        for _ in 0..<2 {
            guard i + 2 <= body.count else { return nil }
            let bits = Int(body[i]) << 8 | Int(body[i + 1])
            let length = (bits + 7) / 8
            guard length <= 32, i + 2 + length <= body.count else { return nil }
            out += [body[i], body[i + 1]]
            out += [UInt8](repeating: 0, count: 32 - length)
            out += body[(i + 2)..<(i + 2 + length)]
            if length < 32 { padded = true }
            i += 2 + length
        }
        guard i == body.count else { return nil }
        return padded ? out : nil
    }
}
