//
//  PairingCapsTests.swift
//  CarrierPonyTests
//
//  The caps field on invites and offline key codes, and the one rule built on
//  it: a v6 identity does not pair with an app that cannot hold a v6 contact.
//
//  The literal invites below are fixed strings, written the way each kind of
//  app writes them. The Android suite (PairingCapsTest) decodes the same
//  strings, so both platforms read each other's invites, old and new.
//

import Foundation
import Testing
import NorseHorsePGPCore
@testable import CarrierPony

struct PairingCapsTests {

    private let token = "0123456789abcdef0123456789abcdef"
    private let v4 = Fingerprint("08108C383A81C409F3E28757397AC5A52B6C5A8D")!
    private let v4b = Fingerprint("05299C734EA466728C71BD7ACDD6B5F7C410B233")!
    private let v6 = Fingerprint("0F1E2D3C4B5A69788796A5B4C3D2E1F00112233445566778899AABBCCDDEEFF0")!
    private let v6b = Fingerprint("A1B2C3D4E5F60718293A4B5C6D7E8F90FFEEDDCCBBAA99887766554433221100")!

    // An invite from an app before 4.0: no caps.
    private let oldV4Invite = "CPPAIR1:eyJ2IjoxLCJ0IjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYiLCJmIjoiMDgxMDhDMzgzQTgxQzQwOUYzRTI4NzU3Mzk3QUM1QTUyQjZDNUE4RCIsIm4iOiJTZWEgQmlzY3VpdCJ9"
    // The same invite from 4.0.
    private let newV4Invite = "CPPAIR1:eyJ2IjoxLCJ0IjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYiLCJmIjoiMDgxMDhDMzgzQTgxQzQwOUYzRTI4NzU3Mzk3QUM1QTUyQjZDNUE4RCIsIm4iOiJTZWEgQmlzY3VpdCIsImMiOlsidjYiXX0"
    // A v6 identity's invite, no name.
    private let newV6Invite = "CPPAIR1:eyJ2IjoxLCJ0IjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYiLCJmIjoiMEYxRTJEM0M0QjVBNjk3ODg3OTZBNUI0QzNEMkUxRjAwMTEyMjMzNDQ1NTY2Nzc4ODk5QUFCQkNDRERFRUZGMCIsImMiOlsidjYiXX0"
    // From some later version: caps this build has never heard of, entries that
    // are not cap names at all, and a field this build does not know.
    private let futureInvite = "CPPAIR1:eyJ2IjoxLCJ0IjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYiLCJmIjoiMDgxMDhDMzgzQTgxQzQwOUYzRTI4NzU3Mzk3QUM1QTUyQjZDNUE4RCIsImMiOlsidjYiLCJjYWxscyIsIk5vdCBBIENhcCIsNywieHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eCJdLCJ6Ijp7ImxhdGVyIjp0cnVlfX0"
    // "c" is a string where a list belongs.
    private let oddCapsInvite = "CPPAIR1:eyJ2IjoxLCJ0IjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYiLCJmIjoiMDgxMDhDMzgzQTgxQzQwOUYzRTI4NzU3Mzk3QUM1QTUyQjZDNUE4RCIsImMiOiJ2NiJ9"

    private func json(invite: String) throws -> [String: Any] {
        var body = String(invite.dropFirst(Invite.prefix.count))
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while body.count % 4 != 0 { body.append("=") }
        let data = try #require(Data(base64Encoded: body))
        return try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    // MARK: - Invites

    @Test func newInvitesSayV6() throws {
        for fingerprint in [v4, v6] {
            let invite = Invite(token: token, fingerprint: fingerprint, name: "Sea Biscuit")
            #expect(invite.c == ["v6"])
            let text = try #require(invite.encoded())
            let decoded = try #require(Invite.decode(text))
            #expect(decoded.c == ["v6"])
            #expect(decoded.fingerprint == fingerprint)
            #expect(decoded.t == token)
            #expect(decoded.n == "Sea Biscuit")
        }
    }

    @Test func capsAreWrittenAsAListUnderC() throws {
        let written = try json(invite: try #require(Invite(token: token, fingerprint: v4, name: nil).encoded()))
        #expect(written["c"] as? [String] == ["v6"])
        // Everything an older app reads is still where it looks for it.
        #expect(written["v"] as? Int == 1)
        #expect(written["t"] as? String == token)
        #expect(written["f"] as? String == v4.hex)
        #expect(written["n"] == nil)
    }

    @Test func inviteFromBeforeFourHasNoCaps() throws {
        let invite = try #require(Invite.decode(oldV4Invite))
        #expect(invite.c == nil)
        #expect(invite.fingerprint == v4)
        #expect(invite.n == "Sea Biscuit")
    }

    @Test func fixedFourPointZeroInvitesDecode() throws {
        let fromV4 = try #require(Invite.decode(newV4Invite))
        #expect(fromV4.c == ["v6"])
        #expect(fromV4.fingerprint == v4)
        #expect(fromV4.n == "Sea Biscuit")

        let fromV6 = try #require(Invite.decode(newV6Invite))
        #expect(fromV6.c == ["v6"])
        #expect(fromV6.fingerprint == v6)
        #expect(fromV6.fingerprint?.isV6 == true)
        #expect(fromV6.n == nil)
    }

    @Test func unknownCapsAndFieldsDoNotBreakAnInvite() throws {
        let invite = try #require(Invite.decode(futureInvite))
        // The names this build does not know are kept; the entries that are not
        // cap names (a phrase, a number, an overlong string) are dropped.
        #expect(invite.c == ["v6", "calls"])
        #expect(invite.fingerprint == v4)
    }

    @Test func capsOfTheWrongShapeCountAsNone() throws {
        let invite = try #require(Invite.decode(oddCapsInvite))
        #expect(invite.c == nil)
        #expect(invite.fingerprint == v4)
    }

    @Test func inviteWithoutCapsIsWrittenWithoutTheField() throws {
        let none = try #require(Invite(token: token, fingerprint: v4, name: nil, caps: nil).encoded())
        #expect(try json(invite: none)["c"] == nil)
        let empty = try #require(Invite(token: token, fingerprint: v4, name: nil, caps: []).encoded())
        #expect(try json(invite: empty)["c"] == nil)
    }

    // MARK: - Offline key code

    @Test func payloadCarriesCapsAndStillVerifies() throws {
        let identities = [
            try OpenPGPKeyGenerator.generateV4Identity(name: "Test Pony", email: "test@carrierpony.com"),
            try OpenPGPKeyGenerator.generateV6Identity(name: "Test Pony", email: "test@carrierpony.com")
        ]
        for identity in identities {
            let fingerprint = try #require(Fingerprint(identity.fingerprint))
            let payload = PairingPayload(fingerprint: fingerprint, name: nil, armoredPublicKey: identity.armoredPublicKey)
            #expect(payload.caps == ["v6"])
            let text = try #require(payload.encoded())
            let decoded = try #require(PairingPayload.decode(text))
            #expect(decoded.caps == ["v6"])
            #expect(decoded.verifiedContact()?.fingerprint == fingerprint)
        }
    }

    @Test func payloadFromBeforeFourHasNoCaps() throws {
        let identity = try OpenPGPKeyGenerator.generateV4Identity(name: "Test Pony", email: "test@carrierpony.com")
        let fingerprint = try #require(Fingerprint(identity.fingerprint))
        let old = PairingPayload(fingerprint: fingerprint, name: nil, armoredPublicKey: identity.armoredPublicKey, caps: nil)
        let text = try #require(old.encoded())
        let data = try #require(Data(base64Encoded: text))
        let written = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(written["caps"] == nil)
        let decoded = try #require(PairingPayload.decode(text))
        #expect(decoded.caps == nil)
        #expect(decoded.verifiedContact() != nil)
    }

    @Test func payloadCapsOfTheWrongShapeCountAsNone() throws {
        let identity = try OpenPGPKeyGenerator.generateV4Identity(name: "Test Pony", email: "test@carrierpony.com")
        let object: [String: Any] = ["v": 1, "fpr": identity.fingerprint, "pub": identity.armoredPublicKey, "caps": ["later": true]]
        let text = try JSONSerialization.data(withJSONObject: object).base64EncodedString()
        let decoded = try #require(PairingPayload.decode(text))
        #expect(decoded.caps == nil)
        #expect(decoded.verifiedContact() != nil)
    }

    // MARK: - The rule

    @Test func aV4IdentityPairsWithAnyone() {
        #expect(PairingCaps.canPair(mine: v4, peer: v4b, peerCaps: nil))
        #expect(PairingCaps.canPair(mine: v4, peer: v4b, peerCaps: ["v6"]))
        #expect(PairingCaps.canPair(mine: v4, peer: v6, peerCaps: ["v6"]))
        #expect(PairingCaps.canPair(mine: v4, peer: v6, peerCaps: nil))
    }

    @Test func aV6IdentityNeedsAPeerThatCanHoldIt() {
        // A v4 peer on 4.0 says so.
        #expect(PairingCaps.canPair(mine: v6, peer: v4, peerCaps: ["v6"]))
        #expect(PairingCaps.canPair(mine: v6, peer: v4, peerCaps: ["calls", "v6"]))
        // A v4 peer that says nothing, or names only other things, is before 4.0.
        #expect(!PairingCaps.canPair(mine: v6, peer: v4, peerCaps: nil))
        #expect(!PairingCaps.canPair(mine: v6, peer: v4, peerCaps: []))
        #expect(!PairingCaps.canPair(mine: v6, peer: v4, peerCaps: ["calls"]))
        #expect(!PairingCaps.canPair(mine: v6, peer: v4, peerCaps: ["V6"]))
        // A v6 peer needs no cap: only 4.0 or later makes one.
        #expect(PairingCaps.canPair(mine: v6, peer: v6b, peerCaps: nil))
        #expect(PairingCaps.canPair(mine: v6, peer: v6b, peerCaps: ["v6"]))
    }

    @Test func theRuleAppliedToTheFixedInvites() throws {
        let old = try #require(Invite.decode(oldV4Invite))
        let new = try #require(Invite.decode(newV4Invite))
        let fromV6 = try #require(Invite.decode(newV6Invite))
        let oldFpr = try #require(old.fingerprint)
        let newFpr = try #require(new.fingerprint)
        let v6Fpr = try #require(fromV6.fingerprint)
        // A v6 identity opening each of them.
        #expect(!PairingCaps.canPair(mine: v6b, peer: oldFpr, peerCaps: old.c))
        #expect(PairingCaps.canPair(mine: v6b, peer: newFpr, peerCaps: new.c))
        #expect(PairingCaps.canPair(mine: v6b, peer: v6Fpr, peerCaps: fromV6.c))
        // A v4 identity opening each of them.
        #expect(PairingCaps.canPair(mine: v4b, peer: oldFpr, peerCaps: old.c))
        #expect(PairingCaps.canPair(mine: v4b, peer: newFpr, peerCaps: new.c))
        #expect(PairingCaps.canPair(mine: v4b, peer: v6Fpr, peerCaps: fromV6.c))
    }
}
