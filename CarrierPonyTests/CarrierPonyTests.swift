//
//  CarrierPonyTests.swift
//  CarrierPonyTests
//
//

import Foundation
import Testing
import NorseHorsePGPCore
@testable import CarrierPony

// Fingerprint accepts v4 (40 hex) and v6 (64 hex) and nothing else. The
// safety-number vectors are shared with Android (FingerprintTest.kt and
// PairingTest.kt) and must match digit for digit.
struct FingerprintTests {

    let v4 = "08108C383A81C409F3E28757397AC5A52B6C5A8D"
    let v4b = "05299C734EA466728C71BD7ACDD6B5F7C410B233"
    let v6a = "0F1E2D3C4B5A69788796A5B4C3D2E1F00112233445566778899AABBCCDDEEFF0"
    let v6b = "A1B2C3D4E5F60718293A4B5C6D7E8F90FFEEDDCCBBAA99887766554433221100"

    @Test func acceptsV4AndV6() throws {
        let four = try #require(Fingerprint(v4))
        let six = try #require(Fingerprint(v6a))
        #expect(!four.isV6)
        #expect(six.isV6)
        #expect(four.hex.count == 40)
        #expect(six.hex.count == 64)
    }

    @Test func normalizesToUppercase() throws {
        let lower = try #require(Fingerprint(v6a.lowercased()))
        #expect(lower.hex == v6a)
        #expect(lower == Fingerprint(v6a))
    }

    @Test func rejectsOtherLengths() {
        for n in [0, 39, 41, 50, 63, 65, 80] {
            #expect(Fingerprint(String(repeating: "A", count: n)) == nil, "length \(n)")
        }
    }

    @Test func rejectsNonHex() {
        #expect(Fingerprint(String(repeating: "G", count: 40)) == nil)
        #expect(Fingerprint(String(repeating: "G", count: 64)) == nil)
        #expect(Fingerprint(String(v4.dropLast()) + " ") == nil)
        // Fullwidth and Arabic-Indic digits are not hex.
        #expect(Fingerprint(String(repeating: "\u{FF11}", count: 40)) == nil)
        #expect(Fingerprint(String(repeating: "\u{0661}", count: 64)) == nil)
    }

    @Test func safetyNumberV4MatchesCrossPlatformVector() throws {
        let a = try #require(Fingerprint(v4))
        let b = try #require(Fingerprint(v4b))
        #expect(SafetyNumber.compute(a, b) == "254835486535974676843358408500344941892165948799090198347439")
    }

    @Test func safetyNumberV6MatchesCrossPlatformVector() throws {
        let a = try #require(Fingerprint(v6a))
        let b = try #require(Fingerprint(v6b))
        #expect(SafetyNumber.compute(a, b) == "784770140712922461606816496090514746184762508438433826276267")
        #expect(SafetyNumber.compute(a, b) == SafetyNumber.compute(b, a))
    }

    @Test func safetyNumberMixedMatchesCrossPlatformVector() throws {
        let four = try #require(Fingerprint(v4))
        let six = try #require(Fingerprint(v6a))
        #expect(SafetyNumber.compute(four, six) == "488344755630788373039536550042141250842433193540265516197226")
        #expect(SafetyNumber.compute(four, six) == SafetyNumber.compute(six, four))
    }

    @Test func inviteRoundTripsAV6Fingerprint() throws {
        let fingerprint = try #require(Fingerprint(v6a))
        let invite = Invite(token: "0123456789abcdef0123456789abcdef", fingerprint: fingerprint, name: "Sea Biscuit")
        let encoded = try #require(invite.encoded())
        let decoded = try #require(Invite.decode(encoded))
        #expect(decoded.fingerprint?.hex == v6a)
    }
}

// Writes a throwaway identity made by the iOS key generator to
// /tmp/carrierpony-fixtures, for the Android core's cross-platform tests. The
// key is generated fresh on every run and belongs to nobody.
struct FixtureEmitterTests {

    @Test func emitV4IdentityForAndroid() throws {
        let identity = try OpenPGPKeyGenerator.generateV4Identity(name: "iOS Fixture", email: "fixture@carrierpony.com")
        #expect(identity.fingerprint.count == 40)

        let directory = URL(fileURLWithPath: "/tmp/carrierpony-fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try identity.armoredPublicKey.write(to: directory.appendingPathComponent("ios-v4-public.asc"), atomically: true, encoding: .utf8)
        try identity.armoredSecretKey.write(to: directory.appendingPathComponent("ios-v4-secret.asc"), atomically: true, encoding: .utf8)
        try identity.fingerprint.write(to: directory.appendingPathComponent("ios-v4-fingerprint.txt"), atomically: true, encoding: .utf8)
    }

    // Writes many freshly generated public keys, one base64 line each, so the
    // Android core's audit can check every binding signature. A binding that
    // fails for one key in hundreds points at an encoding edge case, and only
    // volume finds those.
    @Test func emitManyV4PublicKeysForAudit() throws {
        let count = 5000
        var lines: [String] = []
        lines.reserveCapacity(count)
        for _ in 0..<count {
            let identity = try OpenPGPKeyGenerator.generateV4Identity(name: "Audit", email: "audit@carrierpony.com")
            lines.append(Data(identity.armoredPublicKey.utf8).base64EncodedString())
        }
        let directory = URL(fileURLWithPath: "/tmp/carrierpony-fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try lines.joined(separator: "\n").write(to: directory.appendingPathComponent("ios-v4-many.b64"), atomically: true, encoding: .utf8)
        #expect(lines.count == count)
    }
}

// Sends many signed messages from one iOS-made identity to another and counts
// how many the receiving side rejects. Every message here is well formed in
// intent, so any rejection is a fault in how it was written or read. The
// rejected envelopes are saved, with the keys needed to open them, so the
// Android core can test against real ones.
struct MessageStressTests {

    @Test func countRejectedMessages() throws {
        let sender = try OpenPGPKeyGenerator.generateV4Identity(name: "Stress Sender", email: "stress@carrierpony.com")
        let recipient = try OpenPGPKeyGenerator.generateV4Identity(name: "Stress Recipient", email: "stress@carrierpony.com")
        let senderFingerprint = try #require(Fingerprint(sender.fingerprint))
        let recipientFingerprint = try #require(Fingerprint(recipient.fingerprint))
        let keys: [Fingerprint: Data] = [
            senderFingerprint: try #require(PGPArmor.dearmor(sender.armoredPublicKey)),
            recipientFingerprint: try #require(PGPArmor.dearmor(recipient.armoredPublicKey)),
        ]
        let senderEngine = PGPonyCryptoEngine(
            fingerprint: senderFingerprint, secretKey: sender.secretKey,
            armoredPublicKey: sender.armoredPublicKey, publicKeyData: { keys[$0] }
        )
        let recipientEngine = PGPonyCryptoEngine(
            fingerprint: recipientFingerprint, secretKey: recipient.secretKey,
            armoredPublicKey: recipient.armoredPublicKey, publicKeyData: { keys[$0] }
        )
        let recipientKey = PublicKey(fingerprint: recipientFingerprint, armored: recipient.armoredPublicKey)

        let count = 5000
        var rejected: [String] = []
        for index in 0..<count {
            let envelope = try senderEngine.signAndEncrypt(Data("stress message \(index)".utf8), to: recipientKey)
            do {
                _ = try recipientEngine.decryptAndVerify(envelope)
            } catch {
                rejected.append(envelope.base64EncodedString())
            }
        }

        let directory = URL(fileURLWithPath: "/tmp/carrierpony-fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        func write(_ text: String, _ name: String) throws {
            try text.write(to: directory.appendingPathComponent(name), atomically: true, encoding: .utf8)
        }
        try write("sent=\(count) rejected=\(rejected.count)\n", "ios-message-stress.txt")
        try write(recipient.armoredSecretKey, "ios-quirk-recipient-secret.asc")
        try write(sender.armoredPublicKey, "ios-quirk-sender-public.asc")
        try write(sender.fingerprint, "ios-quirk-sender-fingerprint.txt")
        try write(rejected.prefix(40).joined(separator: "\n"), "ios-quirk-envelopes.b64")
    }
}

// Messages written by the encoder before it was corrected must still open.
// /tmp/carrierpony-fixtures/pre-fix holds envelopes that build's own parser
// rejected, with the keys to open them. Skipped when that folder is absent.
struct OldEncoderTests {

    @Test func messagesFromTheOldEncoderStillVerify() throws {
        let directory = URL(fileURLWithPath: "/tmp/carrierpony-fixtures/pre-fix", isDirectory: true)
        func read(_ name: String) -> String? {
            try? String(contentsOf: directory.appendingPathComponent(name), encoding: .utf8)
        }
        guard let envelopes = read("ios-quirk-envelopes.b64"),
              let recipientSecretArmored = read("ios-quirk-recipient-secret.asc"),
              let senderPublicArmored = read("ios-quirk-sender-public.asc"),
              let senderFingerprintText = read("ios-quirk-sender-fingerprint.txt") else {
            return
        }
        let lines = envelopes.split(separator: "\n").map(String.init).filter { !$0.isEmpty }
        guard !lines.isEmpty else { return }

        let senderFingerprint = try #require(Fingerprint(senderFingerprintText.trimmingCharacters(in: .whitespacesAndNewlines)))
        let senderPublic = try #require(PGPArmor.dearmor(senderPublicArmored))
        let recipientSecret = try #require(PGPArmor.dearmor(recipientSecretArmored))
        // The recipient's own fingerprint is not needed to decrypt; any valid one will do.
        let recipientEngine = PGPonyCryptoEngine(
            fingerprint: senderFingerprint, secretKey: recipientSecret,
            armoredPublicKey: "", publicKeyData: { $0 == senderFingerprint ? senderPublic : nil }
        )
        var verified = 0
        for line in lines {
            let envelope = try #require(Data(base64Encoded: line))
            let message = try recipientEngine.decryptAndVerify(envelope)
            #expect(message.sender == senderFingerprint)
            verified += 1
        }
        #expect(verified == lines.count)
        try "old-encoder envelopes=\(lines.count) verified=\(verified)\n".write(
            to: URL(fileURLWithPath: "/tmp/carrierpony-fixtures/ios-old-encoder.txt"), atomically: true, encoding: .utf8)
    }
}

// Generates many identities and uses each one: sign with it, then verify with
// its own public key. An identity that cannot do that is broken from the
// moment it is created. The count goes to a file; the test itself only fails
// if generation throws.
struct IdentityStressTests {

    @Test func countIdentitiesThatCannotSign() throws {
        let count = 5000
        var broken = 0
        var firstError = ""
        for _ in 0..<count {
            let identity = try OpenPGPKeyGenerator.generateV4Identity(name: "Stress", email: "stress@carrierpony.com")
            guard let fingerprint = Fingerprint(identity.fingerprint) else { broken += 1; continue }
            let engine = PGPonyCryptoEngine(
                fingerprint: fingerprint, secretKey: identity.secretKey,
                armoredPublicKey: identity.armoredPublicKey, publicKeyData: { _ in nil }
            )
            let data = Data("challenge".utf8)
            do {
                let signature = try engine.detachedSignature(over: data)
                let key = PublicKey(fingerprint: fingerprint, armored: identity.armoredPublicKey)
                if try !engine.verifyDetached(signature: signature, over: data, signerPublicKey: key) {
                    broken += 1
                    if firstError.isEmpty { firstError = "signature did not verify" }
                }
            } catch {
                broken += 1
                if firstError.isEmpty { firstError = "\(error)" }
            }
        }
        let directory = URL(fileURLWithPath: "/tmp/carrierpony-fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try "identities=\(count) cannot-sign=\(broken) first-error=\(firstError)\n".write(
            to: directory.appendingPathComponent("ios-identity-stress.txt"), atomically: true, encoding: .utf8)
    }

    // An identity made before the secret-key encoding was corrected, whose seed
    // starts with a zero octet, is stored with the bit count of 31 octets and
    // all 32 octets after it. This rebuilds that exact layout from freshly made
    // identities (a correct key of that kind is one octet shorter: put the zero
    // octet back and bump the packet length) and checks each one can still
    // sign. That is what a person stuck on such an identity gets on updating.
    @Test func identitiesStoredInTheOldLayoutStillSign() throws {
        func canSign(fingerprint: Fingerprint, secretKey: Data, armoredPublicKey: String) -> Bool {
            let engine = PGPonyCryptoEngine(
                fingerprint: fingerprint, secretKey: secretKey,
                armoredPublicKey: armoredPublicKey, publicKeyData: { _ in nil }
            )
            let data = Data("challenge".utf8)
            guard let signature = try? engine.detachedSignature(over: data) else { return false }
            let key = PublicKey(fingerprint: fingerprint, armored: armoredPublicKey)
            return (try? engine.verifyDetached(signature: signature, over: data, signerPublicKey: key)) ?? false
        }

        var identities: [GeneratedIdentity] = []
        for _ in 0..<5000 {
            identities.append(try OpenPGPKeyGenerator.generateV4Identity(name: "Stress", email: "stress@carrierpony.com"))
        }
        // The primary secret-key packet comes first: 0xC5, a one-octet length, the body.
        let lengths = identities.compactMap { identity -> Int? in
            let bytes = [UInt8](identity.secretKey)
            return bytes.count > 2 && bytes[0] == 0xC5 && bytes[1] < 192 ? Int(bytes[1]) : nil
        }
        let fullLength = try #require(lengths.max())

        var converted = 0
        var usable = 0
        for identity in identities {
            var bytes = [UInt8](identity.secretKey)
            guard bytes.count > 2, bytes[0] == 0xC5, Int(bytes[1]) == fullLength - 1 else { continue }
            // The 31-octet value sits just before the two-octet checksum that ends the body.
            let valueStart = 2 + Int(bytes[1]) - 2 - 31
            bytes.insert(0, at: valueStart)
            bytes[1] += 1
            converted += 1
            guard let fingerprint = Fingerprint(identity.fingerprint) else { continue }
            if canSign(fingerprint: fingerprint, secretKey: Data(bytes), armoredPublicKey: identity.armoredPublicKey) {
                usable += 1
            }
        }
        let directory = URL(fileURLWithPath: "/tmp/carrierpony-fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try "old-layout-secrets converted=\(converted) can-sign=\(usable)\n".write(
            to: directory.appendingPathComponent("ios-old-secret.txt"), atomically: true, encoding: .utf8)
        #expect(converted > 0)
        #expect(usable == converted)
    }
}
