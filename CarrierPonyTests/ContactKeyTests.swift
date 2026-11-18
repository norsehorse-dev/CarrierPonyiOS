//
//  ContactKeyTests.swift
//  CarrierPonyTests
//
//  A public key pasted or opened from a file, to add its owner as a contact.
//  Both kinds of key the apps make have to come through, however the text
//  around them looks, and everything else has to be turned away with the
//  right reason: a secret key, a key the app cannot encrypt to, and text that
//  is not a key. Also the contact-request message that follows an add. The
//  Android suites CPContactKeyTest and ContactRequestTest hold the same line.
//

import Foundation
import Testing
import NorseHorsePGPCore
@testable import CarrierPony

struct ContactKeyTests {

    private func v4(_ name: String = "Sea Biscuit") throws -> GeneratedIdentity {
        try OpenPGPKeyGenerator.generateV4Identity(name: name, email: "test@carrierpony.com")
    }

    private func v6(_ name: String = "Sea Biscuit") throws -> GeneratedIdentity {
        try OpenPGPKeyGenerator.generateV6Identity(name: name, email: "test@carrierpony.com")
    }

    private func binary(_ identity: GeneratedIdentity) throws -> Data {
        try #require(PGPArmor.dearmor(identity.armoredPublicKey))
    }

    private func usable(_ result: ContactKey.Result) throws -> ContactKey.Usable {
        guard case .usable(let key) = result else {
            Issue.record("expected a usable key, got \(result)")
            throw CancellationError()
        }
        return key
    }

    private func isSecret(_ result: ContactKey.Result) -> Bool {
        if case .secretKey = result { return true }
        return false
    }

    private func isNotAKey(_ result: ContactKey.Result) -> Bool {
        if case .notAKey = result { return true }
        return false
    }

    private func isUnsupported(_ result: ContactKey.Result) -> Bool {
        if case .unsupported = result { return true }
        return false
    }

    // MARK: - Keys that come through

    @Test func bothKindsOfKeyComeThroughAsText() throws {
        for identity in [try v4(), try v6()] {
            let key = try usable(ContactKey.inspect(identity.armoredPublicKey))
            #expect(key.fingerprint.hex == identity.fingerprint.uppercased())
            #expect(key.name == "Sea Biscuit")
            // What comes back is the same key.
            let back = try #require(PGPArmor.dearmor(key.armoredPublicKey))
            #expect(back == (try binary(identity)))
            #expect(OpenPGPKeyID.primaryFingerprint(armoredPublicKey: key.armoredPublicKey) == key.fingerprint.hex)
        }
    }

    @Test func bothKindsOfKeyComeThroughAsABinaryFile() throws {
        for identity in [try v4(), try v6()] {
            let raw = try binary(identity)
            let key = try usable(ContactKey.inspect(raw))
            #expect(key.fingerprint.hex == identity.fingerprint.uppercased())
            let back = try #require(PGPArmor.dearmor(key.armoredPublicKey))
            #expect(back == raw)
        }
    }

    @Test func aMessageCanBeEncryptedToTheKeyThatComesBack() throws {
        let me = try v6("Me")
        let myFingerprint = try #require(Fingerprint(me.fingerprint))
        for them in [try v4("Them"), try v6("Them")] {
            let key = try usable(ContactKey.inspect("Here is my key:\n\n\(them.armoredPublicKey)\nThanks"))
            let theirData = try #require(PGPArmor.dearmor(key.armoredPublicKey))
            let mine = PGPonyCryptoEngine(
                fingerprint: myFingerprint, secretKey: me.secretKey, armoredPublicKey: me.armoredPublicKey,
                publicKeyData: { $0 == key.fingerprint ? theirData : nil }
            )
            let envelope = try mine.signAndEncrypt(
                Data("hello".utf8), to: PublicKey(fingerprint: key.fingerprint, armored: key.armoredPublicKey)
            )
            let theirs = PGPonyCryptoEngine(
                fingerprint: key.fingerprint, secretKey: them.secretKey, armoredPublicKey: them.armoredPublicKey,
                publicKeyData: { _ in nil }
            )
            #expect(try theirs.decryptOnly(envelope) == Data("hello".utf8))
        }
    }

    @Test func textAroundTheKeyAndCommentHeadersAreIgnored() throws {
        let identity = try v4()
        let body = identity.armoredPublicKey
            .replacingOccurrences(of: "\r\n", with: "\n")
            .components(separatedBy: "\n")
            .filter { !$0.hasPrefix("-----BEGIN") && !$0.contains(": ") }
            .drop(while: { $0.isEmpty })
            .joined(separator: "\r\n")
        let withHeaders = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nComment: sent from somewhere\r\nVersion: Something 1.0\r\n\r\n" + body
        let pasted = "On Monday they wrote:\r\n> key below\r\n\r\n\(withHeaders)\r\n-- \r\nsignature line"
        let key = try usable(ContactKey.inspect(pasted))
        #expect(key.fingerprint.hex == identity.fingerprint.uppercased())
        #expect(!key.armoredPublicKey.contains("Comment"))
        #expect(!key.armoredPublicKey.contains("Version"))
        #expect(!key.armoredPublicKey.contains("signature line"))
        let trimmed = key.armoredPublicKey.trimmingCharacters(in: .whitespacesAndNewlines)
        #expect(trimmed.hasPrefix("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        #expect(trimmed.hasSuffix("-----END PGP PUBLIC KEY BLOCK-----"))
    }

    @Test func onlyTheFirstKeyOfSeveralIsTaken() throws {
        let first = try v6("First")
        let second = try v4("Second")
        for (a, b) in [(first, second), (second, first)] {
            let wanted = try binary(a)
            let both = wanted + (try binary(b))
            let key = try usable(ContactKey.inspect(both))
            #expect(key.fingerprint.hex == a.fingerprint.uppercased())
            let back = try #require(PGPArmor.dearmor(key.armoredPublicKey))
            #expect(back == wanted)
            // The same two keys as one armored block.
            let fromArmor = try usable(ContactKey.inspect(ContactKey.armor(both)))
            #expect(fromArmor.fingerprint.hex == a.fingerprint.uppercased())
        }
    }

    @Test func theArmorWrittenHereIsReadByTheOtherSide() throws {
        // Android reads this armor with a strict decoder that checks the CRC line.
        // The check value for the three bytes "abc" under OpenPGP's CRC-24 is known.
        let armored = ContactKey.armor(Data("abc".utf8))
        #expect(armored == "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nYWJj\n=uhx7\n-----END PGP PUBLIC KEY BLOCK-----\n")
    }

    // MARK: - Keys that are turned away

    @Test func aSecretKeyIsNamedAsOne() throws {
        for identity in [try v4(), try v6()] {
            #expect(isSecret(ContactKey.inspect(identity.secretKey)))
        }
        let broken = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nnot base64 at all\n-----END PGP PRIVATE KEY BLOCK-----"
        #expect(isSecret(ContactKey.inspect(broken)))
    }

    @Test func thingsThatAreNotKeysAreTurnedAway() throws {
        #expect(isNotAKey(ContactKey.inspect("")))
        #expect(isNotAKey(ContactKey.inspect("hello there")))
        #expect(isNotAKey(ContactKey.inspect("CPPAIR1:eyJ2IjoxfQ")))
        #expect(isNotAKey(ContactKey.inspect(Data(repeating: 0x41, count: 64))))
        #expect(isNotAKey(ContactKey.inspect(Data(repeating: 0xC6, count: 64))))
        #expect(isNotAKey(ContactKey.inspect(Data(repeating: 0x41, count: ContactKey.maxInputBytes + 1))))
        let whole = try v4().armoredPublicKey
        #expect(isNotAKey(ContactKey.inspect(String(whole.prefix(whole.count / 2)))))
        let signature = "-----BEGIN PGP SIGNATURE-----\n\nYWJj\n=uhx7\n-----END PGP SIGNATURE-----\n"
        #expect(isNotAKey(ContactKey.inspect(signature)))
    }

    @Test func aSubkeyThePrimaryHasNotSignedIsUnsupported() throws {
        // The victim's primary key and user ID, with somebody else's encryption subkey.
        for (victim, attacker) in [(try v6("Victim"), try v6("Attacker")), (try v4("Victim"), try v4("Attacker"))] {
            let victimData = try binary(victim)
            let attackerData = try binary(attacker)
            let victimPackets = try #require(ContactKey.packets(in: victimData))
            let attackerPackets = try #require(ContactKey.packets(in: attackerData))
            let victimSubkey = try #require(victimPackets.first(where: { $0.tag == 14 }))
            let attackerSubkey = try #require(attackerPackets.first(where: { $0.tag == 14 }))
            let grafted = victimData.prefix(victimSubkey.start) + attackerData.suffix(from: attackerSubkey.start)
            #expect(isUnsupported(ContactKey.inspect(Data(grafted))))
        }
    }

    @Test func aV6KeyWithoutTheMLKEMSubkeyIsUnsupported() throws {
        // The primary key and user ID alone: a real key, with nothing to encrypt to.
        for identity in [try v6(), try v4()] {
            let data = try binary(identity)
            let packets = try #require(ContactKey.packets(in: data))
            let subkey = try #require(packets.first(where: { $0.tag == 14 }))
            #expect(isUnsupported(ContactKey.inspect(Data(data.prefix(subkey.start)))))
        }
    }

    // MARK: - The file name

    @Test func theSharedFileIsNamedAfterTheKey() throws {
        let plain = try v4("Sea Biscuit")
        let plainFingerprint = try #require(Fingerprint(plain.fingerprint))
        #expect(ContactKey.fileName(armoredPublicKey: plain.armoredPublicKey, fingerprint: plainFingerprint) == "Sea Biscuit.asc")
        let odd = try v4("../Sea: Biscuit?*")
        let oddFingerprint = try #require(Fingerprint(odd.fingerprint))
        #expect(ContactKey.fileName(armoredPublicKey: odd.armoredPublicKey, fingerprint: oddFingerprint) == "Sea Biscuit.asc")
        let none = try v4("///")
        let fingerprint = try #require(Fingerprint(none.fingerprint))
        #expect(ContactKey.fileName(armoredPublicKey: none.armoredPublicKey, fingerprint: fingerprint)
                == "carrierpony-\(fingerprint.hex.suffix(8)).asc")
    }

    // MARK: - The request

    @Test func theRequestCarriesKeyNameAndCaps() throws {
        var sent = ChatStore.ControlOp(op: "contact-request", targetMessageID: "", at: 1_800_000_000, name: "Sea Biscuit")
        sent.pubkey = "KEY"
        sent.caps = PairingCaps.Stated(PairingCaps.current)
        let data = try JSONEncoder().encode(sent)
        let written = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(written["op"] as? String == "contact-request")
        #expect(written["pubkey"] as? String == "KEY")
        #expect(written["name"] as? String == "Sea Biscuit")
        #expect(written["caps"] as? [String] == ["v6"])
    }

    @Test func aRequestAsAndroidWritesItDecodes() throws {
        let json = #"{"op":"contact-request","target_message_id":"","at":1800000000,"name":"Sea Biscuit","pubkey":"KEY","caps":["v6"]}"#
        let read = try JSONDecoder().decode(ChatStore.ControlOp.self, from: Data(json.utf8))
        #expect(read.pubkey == "KEY")
        #expect(read.name == "Sea Biscuit")
        #expect(read.caps?.caps == ["v6"])
    }

    // MARK: - Key files opened from another app

    private func tempFile(_ data: Data, in folder: String? = nil) throws -> URL {
        var dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        if let folder { dir = dir.appendingPathComponent(folder) }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("key.asc")
        try data.write(to: url)
        return url
    }

    @Test func aKeyFileIsReadWhole() throws {
        let data = Data((0..<1000).map { UInt8($0 % 251) })
        let url = try tempFile(data)
        #expect(ContactKey.read(fileAt: url) == data)
    }

    @Test func anOversizedFileStopsOneByteOverAndIsRefused() throws {
        let url = try tempFile(Data(repeating: 0x41, count: ContactKey.maxInputBytes * 3))
        let read = try #require(ContactKey.read(fileAt: url))
        #expect(read.count == ContactKey.maxInputBytes + 1)
        guard case .notAKey = ContactKey.inspect(read) else {
            Issue.record("an oversized file should not pass as a key")
            return
        }
    }

    @Test func aMissingFileOrWebLinkGivesNothing() {
        let missing = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        #expect(ContactKey.read(fileAt: missing) == nil)
        #expect(ContactKey.read(fileAt: URL(string: "https://example.com/key.asc")!) == nil)
    }

    @Test func onlyTheInboxCopyIsRemoved() throws {
        let inbox = try tempFile(Data([1, 2, 3]), in: "Inbox")
        let elsewhere = try tempFile(Data([1, 2, 3]), in: "Documents")
        ContactKey.removeInboxCopy(inbox)
        ContactKey.removeInboxCopy(elsewhere)
        #expect(!FileManager.default.fileExists(atPath: inbox.path))
        #expect(FileManager.default.fileExists(atPath: elsewhere.path))
    }

    @Test func eachIncomingKeyIsItsOwnArrival() {
        let data = Data([1, 2, 3])
        #expect(IncomingKey(data: data) != IncomingKey(data: data))
    }
}
