//
//  V6IdentityAppTests.swift
//  CarrierPonyTests
//
//  A v6 identity through the app's own layers, the ones above the core: group
//  messages, the encrypted backup, and the name read back from the key. From
//  4.0 this is what a new account is, so each of these has to work for it and
//  alongside a v4 identity. Messages between the two kinds are covered by
//  V6MessageTests; the Android suite V6IdentityAppTest holds the same line.
//

import Foundation
import CryptoKit
import Testing
import NorseHorsePGPCore
@testable import CarrierPony

struct V6IdentityAppTests {

    private func v4(_ name: String) throws -> Identity {
        try identity(OpenPGPKeyGenerator.generateV4Identity(name: name, email: "test@carrierpony.com"))
    }

    private func v6(_ name: String) throws -> Identity {
        try identity(OpenPGPKeyGenerator.generateV6Identity(name: name, email: "test@carrierpony.com"))
    }

    private func identity(_ generated: GeneratedIdentity) throws -> Identity {
        Identity(
            fingerprint: try #require(Fingerprint(generated.fingerprint)),
            secretKey: generated.secretKey,
            armoredPublicKey: generated.armoredPublicKey
        )
    }

    // An engine for this identity that knows the given contacts.
    private func engine(_ own: Identity, knowing contacts: [Identity] = []) throws -> PGPonyCryptoEngine {
        var keys: [Fingerprint: Data] = [:]
        for each in [own] + contacts {
            keys[each.fingerprint] = try #require(PGPArmor.dearmor(each.armoredPublicKey))
        }
        return PGPonyCryptoEngine(
            fingerprint: own.fingerprint, secretKey: own.secretKey,
            armoredPublicKey: own.armoredPublicKey, publicKeyData: { keys[$0] }
        )
    }

    private func group(_ members: [Identity]) -> ChatGroup {
        ChatGroup(
            groupID: "00112233445566778899aabbccddeeff",
            name: "Mixed",
            members: members.enumerated().map { index, member in
                GroupMember(fingerprint: member.fingerprint, armoredPublicKey: member.armoredPublicKey,
                            name: nil, isAdmin: index == 0)
            },
            epoch: 0
        )
    }

    // MARK: - The identity itself

    @Test func aNewIdentityIsV6() throws {
        let made = try v6("Sea Biscuit")
        #expect(made.fingerprint.isV6)
        #expect(made.fingerprint.hex.count == 64)
        let computed = try #require(OpenPGPKeyID.primaryFingerprint(armoredPublicKey: made.armoredPublicKey))
        #expect(computed.uppercased() == made.fingerprint.hex)
    }

    @Test func theNameIsReadBackFromTheKey() throws {
        #expect(KeyImport.userIDName(fromSecretKey: try v6("Sea Biscuit").secretKey) == "Sea Biscuit")
        #expect(KeyImport.userIDName(fromSecretKey: try v4("Sea Biscuit").secretKey) == "Sea Biscuit")
    }

    // MARK: - Groups

    @Test func groupMessagesVerifyInAMixedGroup() throws {
        let old = try v4("Old")
        let new = try v6("New")
        let other = try v6("Other")
        let members = [old, new, other]
        let roster = group(members)
        let key = SymmetricKey(size: .bits256)

        for sender in members {
            let container = Data("from \(sender.fingerprint.hex)".utf8)
            let payload = try GroupCrypto.seal(container: container, groupID: roster.groupID,
                                               sender: sender.fingerprint, epoch: 0, key: key,
                                               crypto: try engine(sender))
            for reader in members where reader.fingerprint != sender.fingerprint {
                let opened = try GroupCrypto.open(payload: payload, group: roster,
                                                  keyFor: { $0 == 0 ? key : nil },
                                                  crypto: try engine(reader))
                #expect(opened.sender == sender.fingerprint)
                #expect(opened.container == container)
            }
        }
    }

    @Test func aV6MemberCannotBeImpersonatedInAGroup() throws {
        let victim = try v6("Victim")
        let forger = try v6("Forger")
        let reader = try v4("Reader")
        let roster = group([victim, forger, reader])
        let key = SymmetricKey(size: .bits256)

        // The forger signs with their own key and names the victim as sender.
        let payload = try GroupCrypto.seal(container: Data("not from the victim".utf8), groupID: roster.groupID,
                                           sender: victim.fingerprint, epoch: 0, key: key,
                                           crypto: try engine(forger))
        let readerEngine = try engine(reader)
        #expect(throws: (any Error).self) {
            _ = try GroupCrypto.open(payload: payload, group: roster,
                                 keyFor: { $0 == 0 ? key : nil }, crypto: readerEngine)
        }
    }

    // MARK: - Backup

    @Test func backupRoundTripsAndTheRestoredIdentityWorks() throws {
        let original = try v6("Sea Biscuit")
        let friend = try v4("Friend")
        let blob = try IdentityBackup.export(original, passphrase: "correct horse battery")
        let restored = try IdentityBackup.restore(blob, passphrase: "correct horse battery")

        #expect(restored.fingerprint == original.fingerprint)
        #expect(restored.secretKey == original.secretKey)
        #expect(restored.armoredPublicKey == original.armoredPublicKey)

        // The restored identity opens what was sent to the original, and what
        // it sends is accepted as coming from the same person.
        let incoming = try engine(friend, knowing: [original])
            .signAndEncrypt(Data("to the original".utf8), to: PublicKey(fingerprint: original.fingerprint, armored: original.armoredPublicKey))
        let opened = try engine(restored, knowing: [friend]).decryptAndVerify(incoming)
        #expect(opened.sender == friend.fingerprint)
        #expect(opened.plaintext == Data("to the original".utf8))

        let outgoing = try engine(restored, knowing: [friend])
            .signAndEncrypt(Data("from the restored".utf8), to: PublicKey(fingerprint: friend.fingerprint, armored: friend.armoredPublicKey))
        let read = try engine(friend, knowing: [original]).decryptAndVerify(outgoing)
        #expect(read.sender == original.fingerprint)
        #expect(read.plaintext == Data("from the restored".utf8))
    }

    @Test func backupWithTheWrongPassphraseIsRefused() throws {
        let blob = try IdentityBackup.export(try v6("Sea Biscuit"), passphrase: "correct horse battery")
        #expect(throws: (any Error).self) {
            _ = try IdentityBackup.restore(blob, passphrase: "wrong horse battery")
        }
    }
}
