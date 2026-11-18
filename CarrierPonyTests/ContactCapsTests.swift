//
//  ContactCapsTests.swift
//  CarrierPonyTests
//
//  What a contact's app says it supports, after pairing: how it travels in a
//  control message, and how it is kept with the contact. A control message
//  from an app before 4.0, or from a later one with fields this build does not
//  know, has to read exactly as it did before.
//

import Foundation
import Testing
@testable import CarrierPony

@MainActor
struct ContactCapsTests {

    private let v4 = Fingerprint("08108C383A81C409F3E28757397AC5A52B6C5A8D")!
    private let v6 = Fingerprint("0F1E2D3C4B5A69788796A5B4C3D2E1F00112233445566778899AABBCCDDEEFF0")!

    private func op(_ json: String) -> ChatStore.ControlOp? {
        try? JSONDecoder().decode(ChatStore.ControlOp.self, from: Data(json.utf8))
    }

    private func object(_ op: ChatStore.ControlOp) throws -> [String: Any] {
        let data = try JSONEncoder().encode(op)
        return try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func contact(_ fingerprint: Fingerprint, caps: [String]? = nil) -> Contact {
        Contact(fingerprint: fingerprint, publicKey: PublicKey(fingerprint: fingerprint, armored: "key"),
                name: "Sea Biscuit", trust: .unverified, nickname: nil, caps: caps)
    }

    // A store on its own file, removed when the test is done.
    private func withStore(_ body: (ContactStore, String) throws -> Void) rethrows {
        let account = "TEST" + UUID().uuidString.replacingOccurrences(of: "-", with: "")
        let store = ContactStore()
        store.activate(account)
        defer { store.deleteFile(account) }
        try body(store, account)
    }

    // MARK: - Control messages

    @Test func theCapsOpCarriesAListUnderCaps() throws {
        var sent = ChatStore.ControlOp(op: "caps", targetMessageID: "", at: 1_800_000_000)
        sent.caps = PairingCaps.Stated(PairingCaps.current)
        let written = try object(sent)
        #expect(written["op"] as? String == "caps")
        #expect(written["caps"] as? [String] == ["v6"])
    }

    @Test func anOpWithoutCapsIsWrittenWithoutTheField() throws {
        let sent = ChatStore.ControlOp(op: "profile", targetMessageID: "", at: 1_800_000_000, name: "Sea Biscuit")
        #expect(try object(sent)["caps"] == nil)
        #expect(PairingCaps.Stated(nil) == nil)
        #expect(PairingCaps.Stated([]) == nil)
    }

    @Test func opsAsAndroidWritesThemDecode() throws {
        let caps = try #require(op(#"{"op":"caps","target_message_id":"","at":1800000000,"caps":["v6"]}"#))
        #expect(caps.op == "caps")
        #expect(caps.caps?.caps == ["v6"])

        let profile = try #require(op(#"{"op":"profile","target_message_id":"","at":1800000000,"name":"Sea Biscuit","caps":["v6"]}"#))
        #expect(profile.name == "Sea Biscuit")
        #expect(profile.caps?.caps == ["v6"])
    }

    @Test func aProfileFromBeforeFourHasNoCaps() throws {
        let profile = try #require(op(#"{"op":"profile","target_message_id":"","at":1800000000,"name":"Sea Biscuit"}"#))
        #expect(profile.name == "Sea Biscuit")
        #expect(profile.caps == nil)
    }

    @Test func capsOfTheWrongShapeDoNotLoseTheOp() throws {
        for odd in [#""v6""#, "7", "true", #"{"later":true}"#, "null", "[]", #"[7,"Not A Cap",{"a":1}]"#] {
            let json = #"{"op":"profile","target_message_id":"","at":1800000000,"name":"Sea Biscuit","caps":"# + odd + "}"
            let profile = try #require(op(json), "caps: \(odd)")
            #expect(profile.name == "Sea Biscuit")
            #expect(profile.caps?.caps == nil)
        }
    }

    @Test func unknownCapsAreKeptAndJunkIsDropped() throws {
        let json = #"{"op":"caps","target_message_id":"","at":1800000000,"caps":["v6","calls","Not A Cap",7,"v6"],"later":{"x":1}}"#
        let caps = try #require(op(json))
        #expect(caps.caps?.caps == ["v6", "calls"])
    }

    // MARK: - Kept with the contact

    @Test func capsAreStoredAndReadBack() throws {
        try withStore { store, account in
            store.add(contact(v4, caps: ["v6"]))
            store.add(contact(v6))
            let again = ContactStore()
            again.activate(account)
            #expect(again.contact(v4)?.caps == ["v6"])
            #expect(again.contact(v6)?.caps == nil)
            #expect(again.contact(v4)?.name == "Sea Biscuit")
        }
    }

    @Test func setCapsRecordsTheLatestStatement() throws {
        try withStore { store, account in
            store.add(contact(v4))
            #expect(store.contact(v4)?.caps == nil)
            store.setCaps(v4, caps: ["v6"])
            #expect(store.contact(v4)?.caps == ["v6"])
            store.setCaps(v4, caps: ["v6", "calls"])
            #expect(store.contact(v4)?.caps == ["v6", "calls"])
            let again = ContactStore()
            again.activate(account)
            #expect(again.contact(v4)?.caps == ["v6", "calls"])
            // Someone who is not a contact is not made one.
            store.setCaps(v6, caps: ["v6"])
            #expect(store.contact(v6) == nil)
        }
    }

    @Test func addingAContactAgainKeepsWhatTheirAppSaid() throws {
        try withStore { store, _ in
            store.add(contact(v4, caps: ["v6"]))
            // A second pairing or a channel subscribe brings a record with no caps.
            store.add(contact(v4))
            #expect(store.contact(v4)?.caps == ["v6"])
            #expect(store.contacts.count == 1)
            // A record that brings its own replaces them.
            store.add(contact(v4, caps: ["v6", "calls"]))
            #expect(store.contact(v4)?.caps == ["v6", "calls"])
        }
    }

    @Test func aContactsFileFromBeforeFourStillLoads() throws {
        let account = "TEST" + UUID().uuidString.replacingOccurrences(of: "-", with: "")
        let dir = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                              appropriateFor: nil, create: true)
        let file = dir.appendingPathComponent("carrierpony-contacts-\(account).json")
        let old = #"[{"fingerprint":"08108C383A81C409F3E28757397AC5A52B6C5A8D","armored":"key","name":"Sea Biscuit","trust":"verified"}]"#
        try Data(old.utf8).write(to: file)
        let store = ContactStore()
        store.activate(account)
        defer { store.deleteFile(account) }
        let loaded = try #require(store.contact(v4))
        #expect(loaded.caps == nil)
        #expect(loaded.name == "Sea Biscuit")
        #expect(loaded.trust == .verified)
    }
}
