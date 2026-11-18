//
//  V6MessageTests.swift
//  CarrierPonyTests
//
//  Messages to and from v6 identities, through the same engine the app uses.
//  A v6 recipient gets a v6 session-key packet for its ML-KEM-768 + X25519
//  subkey and a SEIPDv2 body; a v4 recipient gets what it always got. The
//  signature follows the sender's version.
//
//  The last suite trades envelopes with the Android core. It reads identities
//  and envelopes the Android tests wrote, and writes envelopes for them to
//  open, all under /tmp/carrierpony-fixtures/shared. Skipped when that folder
//  is absent.
//

import Foundation
import Testing
import NorseHorsePGPCore
@testable import CarrierPony

private struct Party {
    let fingerprint: Fingerprint
    let secretKey: Data
    let armoredPublicKey: String
    let publicKeyData: Data

    var publicKey: PublicKey { PublicKey(fingerprint: fingerprint, armored: armoredPublicKey) }

    init(_ identity: GeneratedIdentity) throws {
        fingerprint = try #require(Fingerprint(identity.fingerprint))
        secretKey = identity.secretKey
        armoredPublicKey = identity.armoredPublicKey
        publicKeyData = try #require(PGPArmor.dearmor(identity.armoredPublicKey))
    }

    init(fingerprint: String, secretKey: Data, armoredPublicKey: String) throws {
        self.fingerprint = try #require(Fingerprint(fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)))
        self.secretKey = secretKey
        self.armoredPublicKey = armoredPublicKey
        publicKeyData = try #require(PGPArmor.dearmor(armoredPublicKey))
    }

    static func v4(_ name: String) throws -> Party {
        try Party(OpenPGPKeyGenerator.generateV4Identity(name: name, email: "test@carrierpony.com"))
    }

    static func v6(_ name: String) throws -> Party {
        try Party(OpenPGPKeyGenerator.generateV6Identity(name: name, email: "test@carrierpony.com"))
    }

    // An engine for this party that knows the given contacts.
    func engine(knowing contacts: [Party]) -> PGPonyCryptoEngine {
        var keys: [Fingerprint: Data] = [fingerprint: publicKeyData]
        for contact in contacts { keys[contact.fingerprint] = contact.publicKeyData }
        return PGPonyCryptoEngine(
            fingerprint: fingerprint, secretKey: secretKey,
            armoredPublicKey: armoredPublicKey, publicKeyData: { keys[$0] }
        )
    }
}

// First packet of an envelope: its tag and body. Session-key packets are
// always new format with a one, two or five octet length.
private func firstPacket(_ envelope: Data) throws -> (tag: UInt8, body: [UInt8]) {
    let bytes = [UInt8](envelope)
    try #require(bytes.count > 6 && bytes[0] & 0xC0 == 0xC0)
    var i = 1
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
    return (bytes[0] & 0x3F, Array(bytes[i..<i + length]))
}

struct V6MessageTests {

    private func exchange(from sender: Party, to recipient: Party, _ text: String) throws -> Data {
        let envelope = try sender.engine(knowing: [recipient])
            .signAndEncrypt(Data(text.utf8), to: recipient.publicKey)
        let opened = try recipient.engine(knowing: [sender]).decryptAndVerify(envelope)
        #expect(opened.plaintext == Data(text.utf8))
        #expect(opened.sender == sender.fingerprint)
        return envelope
    }

    @Test func v6ToV6UsesTheCompositeSubkeyAndSEIPDv2() throws {
        let envelope = try exchange(from: try .v6("A"), to: try .v6("B"), "v6 to v6")
        let pkesk = try firstPacket(envelope)
        #expect(pkesk.tag == 1)
        #expect(pkesk.body[0] == 6)
        #expect(pkesk.body[1] == 33 && pkesk.body[2] == 6)
        #expect(pkesk.body[35] == 35)
        // version, size, key version, fingerprint, algorithm, ephemeral, ciphertext, size, wrapped key
        #expect(pkesk.body.count == 1 + 1 + 1 + 32 + 1 + 32 + 1088 + 1 + 40)
    }

    @Test func v4ToV6UsesTheCompositeSubkey() throws {
        let envelope = try exchange(from: try .v4("A"), to: try .v6("B"), "v4 to v6")
        let pkesk = try firstPacket(envelope)
        #expect(pkesk.tag == 1 && pkesk.body[0] == 6 && pkesk.body[35] == 35)
    }

    @Test func v6ToV4KeepsTheV4Container() throws {
        let envelope = try exchange(from: try .v6("A"), to: try .v4("B"), "v6 to v4")
        let pkesk = try firstPacket(envelope)
        #expect(pkesk.tag == 1 && pkesk.body[0] == 3)
    }

    @Test func v4ToV4IsUnchanged() throws {
        let envelope = try exchange(from: try .v4("A"), to: try .v4("B"), "v4 to v4")
        #expect(try firstPacket(envelope).body[0] == 3)
    }

    @Test func smallAndLargeMessagesRoundTrip() throws {
        let a = try Party.v6("A"), b = try Party.v6("B")
        // SEIPDv2 works in 4096-octet chunks: cover less than one, exactly one, and several.
        for size in [1, 4095, 4096, 4097, 70_000] {
            let plaintext = Data((0..<size).map { UInt8(truncatingIfNeeded: $0 &* 31) })
            let envelope = try a.engine(knowing: [b]).signAndEncrypt(plaintext, to: b.publicKey)
            let opened = try b.engine(knowing: [a]).decryptAndVerify(envelope)
            #expect(opened.plaintext == plaintext, "size \(size)")
        }
    }

    @Test func someoneElseCannotOpenIt() throws {
        let a = try Party.v6("A"), b = try Party.v6("B"), c = try Party.v6("C")
        let envelope = try a.engine(knowing: [b]).signAndEncrypt(Data("for b".utf8), to: b.publicKey)
        #expect(throws: (any Error).self) { _ = try c.engine(knowing: [a]).decryptAndVerify(envelope) }
        #expect(throws: (any Error).self) { _ = try c.engine(knowing: [a]).decryptOnly(envelope) }
        let v4 = try Party.v4("D")
        #expect(throws: (any Error).self) { _ = try v4.engine(knowing: [a]).decryptOnly(envelope) }
    }

    @Test func tamperingIsCaught() throws {
        let a = try Party.v6("A"), b = try Party.v6("B")
        let envelope = try a.engine(knowing: [b]).signAndEncrypt(Data("intact".utf8), to: b.publicKey)
        let recipient = b.engine(knowing: [a])
        // In the ML-KEM ciphertext, in the wrapped session key, and in the body.
        for offset in [200, 1170, envelope.count - 20] {
            var altered = [UInt8](envelope)
            altered[offset] ^= 0x01
            #expect(throws: (any Error).self, "offset \(offset)") { _ = try recipient.decryptAndVerify(Data(altered)) }
            #expect(throws: (any Error).self, "offset \(offset)") { _ = try recipient.decryptOnly(Data(altered)) }
        }
    }

    @Test func unknownSenderIsRefusedButDecryptOnlyStillOpens() throws {
        let a = try Party.v6("A"), b = try Party.v6("B")
        let envelope = try a.engine(knowing: [b]).signAndEncrypt(Data("hello".utf8), to: b.publicKey)
        let stranger = PGPonyCryptoEngine(
            fingerprint: b.fingerprint, secretKey: b.secretKey,
            armoredPublicKey: b.armoredPublicKey, publicKeyData: { _ in nil }
        )
        #expect(throws: CryptoError.noValidSignature) { _ = try stranger.decryptAndVerify(envelope) }
        #expect(try stranger.decryptOnly(envelope) == Data("hello".utf8))
    }

    // The recipient looks the sender up by the fingerprint the signature
    // names. If that lookup hands back somebody else's key, the signature
    // must not verify.
    @Test func signatureFromAnotherKeyIsRefused() throws {
        let a = try Party.v6("A"), b = try Party.v6("B"), impostor = try Party.v6("C")
        let envelope = try a.engine(knowing: [b]).signAndEncrypt(Data("hello".utf8), to: b.publicKey)
        let confused = PGPonyCryptoEngine(
            fingerprint: b.fingerprint, secretKey: b.secretKey,
            armoredPublicKey: b.armoredPublicKey, publicKeyData: { _ in impostor.publicKeyData }
        )
        #expect(throws: (any Error).self) { _ = try confused.decryptAndVerify(envelope) }
    }

    @Test func relayChallengeSignaturesStillVerify() throws {
        for party in [try Party.v4("A"), try Party.v6("B")] {
            let engine = party.engine(knowing: [])
            let challenge = Data("challenge-0123456789".utf8)
            let signature = try engine.detachedSignature(over: challenge)
            #expect(signature.contains("BEGIN PGP SIGNATURE"))
        }
    }
}

struct SharedEnvelopeTests {

    private let directory = URL(fileURLWithPath: "/tmp/carrierpony-fixtures/shared", isDirectory: true)

    private func text(_ name: String) -> String? {
        try? String(contentsOf: directory.appendingPathComponent(name), encoding: .utf8)
    }

    private func base64(_ name: String) -> Data? {
        text(name).flatMap { Data(base64Encoded: $0.filter { !$0.isWhitespace }) }
    }

    private func party(_ prefix: String, armoredSecret: Bool) throws -> Party? {
        guard let fingerprint = text("\(prefix)-fingerprint.txt"),
              let armoredPublic = text("\(prefix)-public.asc") else { return nil }
        let secret: Data?
        if armoredSecret {
            secret = text("\(prefix)-secret.asc").flatMap { PGPArmor.dearmor($0) }
        } else {
            secret = base64("\(prefix)-secret.b64")
        }
        guard let secret else { return nil }
        return try Party(fingerprint: fingerprint, secretKey: secret, armoredPublicKey: armoredPublic)
    }

    @Test func tradeEnvelopesWithTheAndroidCore() throws {
        guard let iosV4 = try party("ios-v4", armoredSecret: true),
              let iosV6 = try party("ios-v6", armoredSecret: true),
              let androidV4 = try party("peer-android-v4", armoredSecret: false),
              let androidV6 = try party("peer-android-v6", armoredSecret: false) else {
            return
        }
        #expect(!androidV4.fingerprint.isV6 && androidV6.fingerprint.isV6)
        #expect(!iosV4.fingerprint.isV6 && iosV6.fingerprint.isV6)

        // Envelopes the Android core wrote open here.
        let inbound: [(name: String, sender: Party, recipient: Party)] = [
            ("android-v4-to-ios-v6", androidV4, iosV6),
            ("android-v6-to-ios-v6", androidV6, iosV6),
            ("android-v6-to-ios-v4", androidV6, iosV4),
        ]
        var opened = 0
        for item in inbound {
            let envelope = try #require(base64("\(item.name).b64"), "missing \(item.name)")
            let message = try item.recipient.engine(knowing: [item.sender]).decryptAndVerify(envelope)
            #expect(message.sender == item.sender.fingerprint, "\(item.name)")
            #expect(message.plaintext == Data(item.name.utf8), "\(item.name)")
            opened += 1
        }

        // Envelopes for the Android core to open. The plaintext is the file's name.
        let outbound: [(name: String, sender: Party, recipient: Party)] = [
            ("ios-v6-to-android-v4", iosV6, androidV4),
            ("ios-v6-to-android-v6", iosV6, androidV6),
            ("ios-v4-to-android-v6", iosV4, androidV6),
        ]
        for item in outbound {
            let envelope = try item.sender.engine(knowing: [item.recipient])
                .signAndEncrypt(Data(item.name.utf8), to: item.recipient.publicKey)
            try envelope.base64EncodedString().write(
                to: directory.appendingPathComponent("\(item.name).b64"), atomically: true, encoding: .utf8)
        }
        try "opened=\(opened) of \(inbound.count) written=\(outbound.count)\n".write(
            to: directory.appendingPathComponent("ios-trade.txt"), atomically: true, encoding: .utf8)
    }
}
