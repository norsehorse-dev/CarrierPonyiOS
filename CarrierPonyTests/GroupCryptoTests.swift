import XCTest
import CryptoKit
@testable import CarrierPony

// Real crypto round-trip for group messaging, using the baked-in DevIdentity keys
// (Alice and Bob). Runs on the Mac with no device or relay. This is the
// deterministic check that the sign + AES-GCM + detached-signature-verify path
// actually works, in particular that verifyDetachedEd25519 (the new core helper)
// verifies a detached signature over the group container.

#if DEBUG
final class GroupCryptoTests: XCTestCase {

    private func engine(for identity: Identity) -> PGPonyCryptoEngine {
        PGPonyCryptoEngine(
            fingerprint: identity.fingerprint,
            secretKey: identity.secretKey,
            armoredPublicKey: identity.armoredPublicKey,
            publicKeyData: { _ in nil }
        )
    }

    private func roster(_ alice: Identity, _ bob: Identity) -> [GroupMember] {
        [
            GroupMember(fingerprint: alice.fingerprint, armoredPublicKey: alice.armoredPublicKey, name: "Alice", isAdmin: true),
            GroupMember(fingerprint: bob.fingerprint, armoredPublicKey: bob.armoredPublicKey, name: "Bob", isAdmin: false),
        ]
    }

    // Alice seals a message; opening it verifies her signature against the roster.
    func testRoundTripVerifies() throws {
        let alice = try XCTUnwrap(DevIdentity.alice)
        let bob = try XCTUnwrap(DevIdentity.bob)
        let aliceEngine = engine(for: alice)
        let group = ChatGroup(groupID: "0011aabb", name: "Test", members: roster(alice, bob), epoch: 0)
        let key = SymmetricKey(size: .bits256)
        let container = Data("hello group, this is signed and encrypted".utf8)

        let payload = try GroupCrypto.seal(container: container, groupID: group.groupID,
                                           sender: alice.fingerprint, epoch: 0, key: key, crypto: aliceEngine)
        // Bob's device opens it: same roster, same epoch key.
        let bobEngine = engine(for: bob)
        let opened = try GroupCrypto.open(payload: payload, group: group,
                                          keyFor: { $0 == 0 ? key : nil }, crypto: bobEngine)

        XCTAssertEqual(opened.sender, alice.fingerprint)
        XCTAssertEqual(opened.container, container)
    }

    // The wrong epoch key must fail (AES-GCM authentication).
    func testWrongKeyFails() throws {
        let alice = try XCTUnwrap(DevIdentity.alice)
        let bob = try XCTUnwrap(DevIdentity.bob)
        let aliceEngine = engine(for: alice)
        let group = ChatGroup(groupID: "0011aabb", name: "Test", members: roster(alice, bob), epoch: 0)
        let key = SymmetricKey(size: .bits256)
        let payload = try GroupCrypto.seal(container: Data("secret".utf8), groupID: group.groupID,
                                           sender: alice.fingerprint, epoch: 0, key: key, crypto: aliceEngine)

        XCTAssertThrowsError(try GroupCrypto.open(payload: payload, group: group,
                                                  keyFor: { _ in SymmetricKey(size: .bits256) }, crypto: aliceEngine))
    }

    // A forged sender label must be rejected: Alice signs, but the box claims Bob,
    // so verifying Alice's signature against Bob's roster key fails.
    func testForgedSenderRejected() throws {
        let alice = try XCTUnwrap(DevIdentity.alice)
        let bob = try XCTUnwrap(DevIdentity.bob)
        let aliceEngine = engine(for: alice)
        let group = ChatGroup(groupID: "0011aabb", name: "Test", members: roster(alice, bob), epoch: 0)
        let key = SymmetricKey(size: .bits256)
        let container = Data("I am pretending to be Bob".utf8)

        let sig = try aliceEngine.detachedSignature(over: container)   // signed by Alice
        let sealed = try AES.GCM.seal(container, using: key)
        let forged = GroupSealedBox(groupID: group.groupID, sender: bob.fingerprint.hex, epoch: 0,
                                    sig: sig, ct: try XCTUnwrap(sealed.combined).base64EncodedString())
        let payload = try JSONEncoder().encode(forged)

        XCTAssertThrowsError(try GroupCrypto.open(payload: payload, group: group,
                                                  keyFor: { $0 == 0 ? key : nil }, crypto: aliceEngine)) { error in
            XCTAssertEqual(error as? GroupCryptoError, GroupCryptoError.badSignature)
        }
    }
}
#endif
