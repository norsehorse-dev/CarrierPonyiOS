//
//  GroupDeliveryTests.swift
//  CarrierPonyTests
//
//  Which way a group message travels to a member. A member's group address
//  only exists on the relay after they have received the group key, and the
//  relay silently drops anything sent to an address it does not know. So a
//  member gets group messages by the per-contact path until a group message
//  has arrived from them in the current epoch, and by the group address after.
//  The Android suite GroupDeliveryTest holds the same line.
//

import Foundation
import Testing
@testable import CarrierPony

struct GroupDeliveryTests {

    private let bob = "05299C734EA466728C71BD7ACDD6B5F7C410B233"
    private let six = "0F1E2D3C4B5A69788796A5B4C3D2E1F00112233445566778899AABBCCDDEEFF0"
    private let day = 86_400
    private let t0 = 1_800_000_000

    private func fresh() -> SealedGroupState {
        SealedGroupState(epoch: 0, sendCounters: [:], recvHighs: [:])
    }

    @Test func aMemberNotHeardFromGoesByThePeerPath() {
        #expect(GroupDelivery.usePeerPath(nil, member: bob, now: t0))
        #expect(GroupDelivery.usePeerPath(fresh(), member: bob, now: t0))
        var state = fresh()
        state.since[bob] = t0
        #expect(GroupDelivery.usePeerPath(state, member: bob, now: t0 + 1))
        #expect(GroupDelivery.usePeerPath(state, member: bob, now: t0 + 29 * day))
    }

    @Test func onceHeardTheyGoByTheGroupAddress() {
        var state = fresh()
        state.since[bob] = t0
        state.heard.insert(bob)
        #expect(!GroupDelivery.usePeerPath(state, member: bob, now: t0 + 1))
        // Hearing from one member says nothing about another.
        #expect(GroupDelivery.usePeerPath(state, member: six, now: t0 + 1))
    }

    @Test func aMemberWhoNeverPostsMovesOverAfterThirtyDays() {
        var state = fresh()
        state.since[bob] = t0
        #expect(GroupDelivery.usePeerPath(state, member: bob, now: t0 + 30 * day - 1))
        #expect(!GroupDelivery.usePeerPath(state, member: bob, now: t0 + 30 * day))
        #expect(!GroupDelivery.usePeerPath(state, member: bob, now: t0 + 90 * day))
    }

    @Test func stateRoundTripsWithTheNewFields() throws {
        var state = SealedGroupState(epoch: 3, sendCounters: [bob: 7], recvHighs: [six: 2])
        state.heard.insert(six)
        state.since[bob] = t0
        let data = try JSONEncoder().encode(state)
        let restored = try JSONDecoder().decode(SealedGroupState.self, from: data)
        #expect(restored.epoch == 3)
        #expect(restored.sendCounters == [bob: 7])
        #expect(restored.recvHighs == [six: 2])
        #expect(restored.heard == [six])
        #expect(restored.since == [bob: t0])
    }

    // State saved by a build before this one has neither field. A member whose
    // messages have been arriving on their group address was plainly listening,
    // so an established group carries on as it was. Anyone else starts on the
    // per-contact path.
    @Test func stateFromAnOlderBuildKeepsEstablishedMembersOnTheGroupAddress() throws {
        let old = #"{"epoch":2,"sendCounters":{"\#(bob)":5,"\#(six)":1},"recvHighs":{"\#(bob)":9}}"#
        let state = try JSONDecoder().decode(SealedGroupState.self, from: Data(old.utf8))
        #expect(state.heard == [bob])
        #expect(state.since.isEmpty)
        #expect(state.sendCounters[bob] == 5)
        #expect(!GroupDelivery.usePeerPath(state, member: bob, now: t0))
        #expect(GroupDelivery.usePeerPath(state, member: six, now: t0))
    }
}
