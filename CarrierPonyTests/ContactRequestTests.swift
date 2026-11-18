//
//  ContactRequestTests.swift
//  CarrierPonyTests
//
//  Receiving a contact request. Two things are pinned here. A request is only
//  believed when its envelope was signed by the key it carries, checked with
//  a key that is not a contact's. And the list of waiting requests stays
//  bounded and remembers who was declined, because anyone who has a public
//  key can send one. The Android suite ContactRequestStoreTest holds the same
//  line.
//

import Foundation
import Testing
import NorseHorsePGPCore
@testable import CarrierPony

@MainActor
struct ContactRequestTests {

    private struct Party {
        let fingerprint: Fingerprint
        let secretKey: Data
        let armored: String

        var key: PublicKey { PublicKey(fingerprint: fingerprint, armored: armored) }

        // An engine for this party that knows nobody.
        var engine: PGPonyCryptoEngine {
            PGPonyCryptoEngine(fingerprint: fingerprint, secretKey: secretKey,
                               armoredPublicKey: armored, publicKeyData: { _ in nil })
        }
    }

    private func party(v6: Bool, _ name: String) throws -> Party {
        let made = v6
            ? try OpenPGPKeyGenerator.generateV6Identity(name: name, email: "test@carrierpony.com")
            : try OpenPGPKeyGenerator.generateV4Identity(name: name, email: "test@carrierpony.com")
        let fingerprint = try #require(Fingerprint(made.fingerprint))
        return Party(fingerprint: fingerprint, secretKey: made.secretKey, armored: made.armoredPublicKey)
    }

    // MARK: - The signature check

    @Test func anEnvelopeVerifiesUnderTheKeyItsSenderHandsOver() throws {
        for (senderV6, receiverV6) in [(true, true), (false, true), (true, false), (false, false)] {
            let sender = try party(v6: senderV6, "S")
            let receiver = try party(v6: receiverV6, "R")
            let envelope = try sender.engine.signAndEncrypt(Data("request".utf8), to: receiver.key)
            // The receiver does not know the sender, so the ordinary open refuses.
            #expect(throws: (any Error).self) {
                _ = try receiver.engine.decryptAndVerify(envelope)
            }
            let opened = try receiver.engine.decryptAndVerify(envelope, signer: sender.key)
            #expect(opened.sender == sender.fingerprint)
            #expect(opened.plaintext == Data("request".utf8))
        }
    }

    @Test func anEnvelopeSignedBySomeoneElseDoesNotVerifyUnderABorrowedKey() throws {
        let receiver = try party(v6: true, "Receiver")
        let impostor = try party(v6: true, "Impostor")
        for victimV6 in [true, false] {
            let victim = try party(v6: victimV6, "Victim")
            // The impostor signs, and would hand over the victim's public key.
            let envelope = try impostor.engine.signAndEncrypt(Data("request".utf8), to: receiver.key)
            #expect(throws: (any Error).self) {
                _ = try receiver.engine.decryptAndVerify(envelope, signer: victim.key)
            }
            // A key offered under a fingerprint that is not its own is refused too.
            let mislabelled = PublicKey(fingerprint: victim.fingerprint, armored: impostor.armored)
            #expect(throws: (any Error).self) {
                _ = try receiver.engine.decryptAndVerify(envelope, signer: mislabelled)
            }
        }
    }

    // MARK: - The waiting list

    private let a = Fingerprint("08108C383A81C409F3E28757397AC5A52B6C5A8D")!
    private let b = Fingerprint("0F1E2D3C4B5A69788796A5B4C3D2E1F00112233445566778899AABBCCDDEEFF0")!

    private func request(_ fingerprint: Fingerprint, name: String? = "Sea Biscuit", caps: [String]? = ["v6"]) -> ContactRequest {
        ContactRequest(fingerprint: fingerprint, armoredPublicKey: "KEY-\(fingerprint.hex.suffix(4))",
                       name: name, caps: caps, receivedAt: 1_800_000_000)
    }

    // A store on its own file, removed when the test is done.
    private func withStore(_ body: (ContactRequestStore, String) throws -> Void) rethrows {
        let account = "TEST" + UUID().uuidString.replacingOccurrences(of: "-", with: "")
        let store = ContactRequestStore()
        store.activate(account)
        defer { store.deleteFile(account) }
        try body(store, account)
    }

    @Test func requestsPersistAcrossInstances() throws {
        try withStore { store, account in
            #expect(store.add(request(a)))
            #expect(store.add(request(b, name: nil, caps: nil)))
            let again = ContactRequestStore()
            again.activate(account)
            #expect(again.requests.map(\.fingerprint) == [a, b])
            #expect(again.requests[0].name == "Sea Biscuit")
            #expect(again.requests[0].caps == ["v6"])
            #expect(again.requests[0].armoredPublicKey == "KEY-\(a.hex.suffix(4))")
            #expect(again.requests[0].receivedAt == 1_800_000_000)
            #expect(again.requests[1].name == nil)
            #expect(again.requests[1].caps == nil)
        }
    }

    @Test func oneRequestPerPerson() throws {
        try withStore { store, _ in
            #expect(store.add(request(a, name: "First")))
            #expect(store.add(request(a, name: "Second")))
            #expect(store.requests.count == 1)
            #expect(store.requests[0].name == "Second")
        }
    }

    @Test func aDeclinedPersonIsIgnoredFromThenOn() throws {
        try withStore { store, account in
            store.add(request(a))
            store.decline(a)
            #expect(store.requests.isEmpty)
            #expect(store.isDeclined(a))
            #expect(!store.add(request(a)))
            // It survives a restart, and it is per person.
            let again = ContactRequestStore()
            again.activate(account)
            #expect(!again.add(request(a)))
            #expect(again.add(request(b)))
            // Adding their key yourself clears it.
            again.clearDeclined(a)
            #expect(!again.isDeclined(a))
            #expect(again.add(request(a)))
        }
    }

    @Test func removingARequestRemembersNothing() throws {
        try withStore { store, _ in
            store.add(request(a))
            store.remove(a)
            #expect(store.requests.isEmpty)
            #expect(!store.isDeclined(a))
            #expect(store.add(request(a)))
        }
    }

    @Test func theListIsCapped() throws {
        try withStore { store, _ in
            func numbered(_ i: Int) throws -> Fingerprint {
                let hex = String(i, radix: 16, uppercase: true)
                return try #require(Fingerprint(String(repeating: "0", count: 40 - hex.count) + hex))
            }
            for i in 1...ContactRequestStore.maxRequests {
                let fingerprint = try numbered(i)
                #expect(store.add(request(fingerprint)))
            }
            #expect(!store.add(request(a)))
            #expect(store.requests.count == ContactRequestStore.maxRequests)
            // Someone already on the list can still replace their own request.
            let first = try numbered(1)
            #expect(store.add(request(first, name: "Again")))
            #expect(store.requests.count == ContactRequestStore.maxRequests)
        }
    }

    @Test func namesAreCleanedBeforeTheyAreShown() throws {
        #expect(ContactRequestStore.cleanName("  Sea\u{0000} Biscuit\n") == "Sea Biscuit")
        #expect(ContactRequestStore.cleanName(String(repeating: "x", count: 500))?.count == ContactRequestStore.maxNameLength)
        #expect(ContactRequestStore.cleanName("   \n\t ") == nil)
        #expect(ContactRequestStore.cleanName(nil) == nil)
        try withStore { store, _ in
            store.add(request(a, name: "A\nB" + String(repeating: "y", count: 200)))
            let name = try #require(store.requests[0].name)
            #expect(name.count == ContactRequestStore.maxNameLength)
            #expect(!name.contains("\n"))
        }
    }

    @Test func accountsHaveSeparateLists() throws {
        let one = "TEST" + UUID().uuidString.replacingOccurrences(of: "-", with: "")
        let two = "TEST" + UUID().uuidString.replacingOccurrences(of: "-", with: "")
        let store = ContactRequestStore()
        defer { store.deleteFile(one); store.deleteFile(two) }
        store.activate(one)
        store.add(request(a))
        store.decline(b)
        // The same instance follows an account switch.
        store.activate(two)
        #expect(store.requests.isEmpty)
        #expect(!store.isDeclined(b))
        store.activate(one)
        #expect(store.requests.map(\.fingerprint) == [a])
        #expect(store.isDeclined(b))
    }
}
