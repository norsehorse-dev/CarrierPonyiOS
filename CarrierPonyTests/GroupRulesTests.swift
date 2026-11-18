//
//  GroupRulesTests.swift
//  CarrierPonyTests
//
//  A group whose roster includes a v6 identity needs every member on 4.0,
//  because an older app drops a member it cannot parse and tells nobody. These
//  tests pin who gets named, and that a roster with no v6 identity is never
//  touched. The Android suite GroupRulesTest holds the same line. The channel
//  invite's caps field is checked here too.
//

import Foundation
import Testing
@testable import CarrierPony

struct GroupRulesTests {

    private let v4a = Fingerprint("08108C383A81C409F3E28757397AC5A52B6C5A8D")!
    private let v4b = Fingerprint("05299C734EA466728C71BD7ACDD6B5F7C410B233")!
    private let v4c = Fingerprint("61D27B04E1E90899E8D162824891888765D64C51")!
    private let v6a = Fingerprint("0F1E2D3C4B5A69788796A5B4C3D2E1F00112233445566778899AABBCCDDEEFF0")!
    private let v6b = Fingerprint("A1B2C3D4E5F60718293A4B5C6D7E8F90FFEEDDCCBBAA99887766554433221100")!

    private func member(_ fingerprint: Fingerprint, _ label: String, _ caps: String...) -> GroupRules.Member {
        GroupRules.Member(fingerprint: fingerprint, caps: caps.isEmpty ? nil : caps, label: label)
    }

    private func blocked(_ roster: GroupRules.Member...) -> [String] {
        GroupRules.needingUpdate(roster).map(\.label)
    }

    // MARK: - The rule

    @Test func aGroupWithNoV6IdentityIsNeverRestricted() {
        // Nobody has said what they support, exactly as in every group made before 4.0.
        #expect(blocked(member(v4a, "me"), member(v4b, "Bob"), member(v4c, "Carol")).isEmpty)
        #expect(blocked(member(v4a, "me", "v6"), member(v4b, "Bob")).isEmpty)
        #expect(blocked().isEmpty)
    }

    @Test func aV6MemberNeedsEveryoneOnFour() {
        #expect(blocked(member(v4a, "me", "v6"), member(v4b, "Bob"), member(v6a, "Six")) == ["Bob"])
        #expect(blocked(member(v4a, "me", "v6"), member(v4b, "Bob"), member(v4c, "Carol"), member(v6a, "Six")) == ["Bob", "Carol"])
        // Naming some other capability is not enough.
        #expect(blocked(member(v4a, "me", "v6"), member(v4b, "Bob", "calls"), member(v6a, "Six")) == ["Bob"])
    }

    @Test func itIsFineOnceEveryoneHasSaidSo() {
        #expect(blocked(member(v4a, "me", "v6"), member(v4b, "Bob", "v6"), member(v6a, "Six")).isEmpty)
        #expect(blocked(member(v4a, "me", "v6"), member(v4b, "Bob", "calls", "v6"), member(v6a, "Six")).isEmpty)
    }

    @Test func v6MembersNeedNoCap() {
        #expect(blocked(member(v6a, "me"), member(v6b, "Other Six")).isEmpty)
        #expect(blocked(member(v6a, "me", "v6"), member(v6b, "Other Six"), member(v4b, "Bob", "v6")).isEmpty)
    }

    @Test func theCreatorBeingV6IsEnoughToApplyTheRule() {
        #expect(blocked(member(v6a, "me", "v6"), member(v4b, "Bob")) == ["Bob"])
    }

    // MARK: - Channel invites

    private let channel = "00112233445566778899aabbccddeeff"

    private func invite(_ fields: [String: Any]) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: fields)
        let body = data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return ChannelInvite.prefix + body
    }

    private func fields(of invite: String) throws -> [String: Any] {
        var body = String(invite.dropFirst(ChannelInvite.prefix.count))
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while body.count % 4 != 0 { body.append("=") }
        let data = try #require(Data(base64Encoded: body))
        return try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    @Test func aNewChannelInviteSaysV6() throws {
        let made = ChannelInvite(channelId: channel, adminFingerprint: v4a, adminArmoredKey: "key", token: nil, name: "News")
        #expect(made.caps == ["v6"])
        let text = try #require(made.encoded())
        let written = try fields(of: text)
        #expect(written["caps"] as? [String] == ["v6"])
        // Everything an older app reads is still where it looks for it.
        #expect(written["c"] as? String == channel)
        #expect(written["f"] as? String == v4a.hex)
        #expect(written["k"] as? String == "key")
        #expect(written["n"] as? String == "News")
        let read = try #require(ChannelInvite.decode(text))
        #expect(read.caps == ["v6"])
        #expect(read.adminFingerprint == v4a)
    }

    @Test func aChannelInviteFromBeforeFourHasNoCaps() throws {
        let text = try invite(["v": 1, "c": channel, "f": v4a.hex, "k": "key", "n": "News"])
        let read = try #require(ChannelInvite.decode(text))
        #expect(read.caps == nil)
        #expect(read.n == "News")
    }

    @Test func channelInviteCapsOfTheWrongShapeCountAsNone() throws {
        let odd = try invite(["v": 1, "c": channel, "f": v4a.hex, "k": "key", "caps": "v6"])
        let oddRead = try #require(ChannelInvite.decode(odd))
        #expect(oddRead.caps == nil)
        let later = try invite(["v": 1, "c": channel, "f": v4a.hex, "k": "key",
                                "caps": ["v6", "calls", "Not A Cap", 7], "z": ["later": true]])
        let laterRead = try #require(ChannelInvite.decode(later))
        #expect(laterRead.caps == ["v6", "calls"])
    }

    @Test func aV6SubscriberNeedsAnAdminOnFour() throws {
        let oldText = try invite(["v": 1, "c": channel, "f": v4a.hex, "k": "key"])
        let newText = try invite(["v": 1, "c": channel, "f": v4a.hex, "k": "key", "caps": ["v6"]])
        let v6Text = try invite(["v": 1, "c": channel, "f": v6a.hex, "k": "key"])
        let old = try #require(ChannelInvite.decode(oldText))
        let new = try #require(ChannelInvite.decode(newText))
        let fromV6 = try #require(ChannelInvite.decode(v6Text))
        for (subscriber, invite, allowed) in [
            (v6b, old, false), (v6b, new, true), (v6b, fromV6, true),
            (v4b, old, true), (v4b, new, true), (v4b, fromV6, true),
        ] {
            let admin = try #require(invite.adminFingerprint)
            #expect(PairingCaps.canPair(mine: subscriber, peer: admin, peerCaps: invite.caps) == allowed)
        }
    }
}
