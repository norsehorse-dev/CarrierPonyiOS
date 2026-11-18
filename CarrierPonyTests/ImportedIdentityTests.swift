//
//  ImportedIdentityTests.swift
//  CarrierPonyTests
//
//  An identity imported from another app's v6 key. The two fixtures are
//  throwaway keys exported from PGPony Android, one unprotected and one under
//  the passphrase "a", the same two the Android suites use. Their shape is not
//  the one CarrierPony makes: a certify-only Ed25519 primary, an Ed25519 signing
//  subkey, a plain X25519 subkey and the ML-KEM-768 + X25519 subkey. The
//  protected one keeps its classic keys under CFB and its ML-KEM subkey under
//  AEAD with Argon2. Such a key signs with its subkey, so a receiver has to find
//  the contact from the subkey a signature names.
//

import Foundation
import Testing
import NorseHorsePGPCore
@testable import CarrierPony

struct ImportedIdentityTests {

    static let unprotectedFingerprint = "DA92AD1ADD5E10FD5135559FBD05CB8B9CD3B9AB704CBA482688AD12C3024F13"
    static let protectedFingerprint = "874AABA8729AEF776BDB8221D28B3B15EEB7FB3CCF37D866102A5EBE3C5C2F83"

    static let unprotectedKey = """
    -----BEGIN PGP PRIVATE KEY BLOCK-----
    
    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
    GLtWbLx39lTTXQI=
    =A2ml
    -----END PGP PRIVATE KEY BLOCK-----
    """

    static let protectedKey = """
    -----BEGIN PGP PRIVATE KEY BLOCK-----
    
    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
    l2SxlujbIIJWneTdFUIJ
    =q6u/
    -----END PGP PRIVATE KEY BLOCK-----
    """

    private func imported(protected: Bool) throws -> Identity {
        let inspection = try KeyImport.inspect(protected ? Self.protectedKey : Self.unprotectedKey)
        return try KeyImport.makeIdentity(inspection, passphrase: protected ? "a" : nil)
    }

    private func friend() throws -> Identity {
        let generated = try OpenPGPKeyGenerator.generateV6Identity(name: "Friend", email: "friend@carrierpony.com")
        return Identity(
            fingerprint: try #require(Fingerprint(generated.fingerprint)),
            secretKey: generated.secretKey,
            armoredPublicKey: generated.armoredPublicKey
        )
    }

    // An engine for this identity that knows the given contacts. With
    // `subkeyLookup` off it is the engine as it was before signing subkeys.
    private func engine(_ own: Identity, passphrase: String? = nil, knowing contacts: [Identity] = [],
                        subkeyLookup: Bool = true) throws -> PGPonyCryptoEngine {
        var keys: [Fingerprint: Data] = [:]
        for each in [own] + contacts {
            keys[each.fingerprint] = try #require(PGPArmor.dearmor(each.armoredPublicKey))
        }
        let all = Array(keys.values)
        return PGPonyCryptoEngine(
            fingerprint: own.fingerprint, secretKey: own.secretKey,
            armoredPublicKey: own.armoredPublicKey, publicKeyData: { keys[$0] },
            passphrase: { passphrase },
            signerKeys: { subkeyLookup ? all : [] }
        )
    }

    private func publicKey(_ identity: Identity) -> PublicKey {
        PublicKey(fingerprint: identity.fingerprint, armored: identity.armoredPublicKey)
    }

    // MARK: - Importing

    @Test func anUnprotectedKeyBecomesAnIdentity() throws {
        let inspection = try KeyImport.inspect(Self.unprotectedKey)
        #expect(!inspection.needsPassphrase)
        let identity = try KeyImport.makeIdentity(inspection, passphrase: nil)
        #expect(identity.fingerprint.hex == Self.unprotectedFingerprint)
        #expect(identity.fingerprint.isV6)
        #expect(!identity.protected)
        #expect(KeyImport.userIDName(fromSecretKey: inspection.secretKey) == "carrierpony test")
    }

    @Test func aProtectedKeyBecomesAnIdentityWithItsPassphrase() throws {
        let inspection = try KeyImport.inspect(Self.protectedKey)
        #expect(inspection.needsPassphrase)
        let identity = try KeyImport.makeIdentity(inspection, passphrase: "a")
        #expect(identity.fingerprint.hex == Self.protectedFingerprint)
        #expect(identity.protected)
    }

    @Test func aWrongOrMissingPassphraseIsRefused() throws {
        let inspection = try KeyImport.inspect(Self.protectedKey)
        for attempt in ["b", "", nil] as [String?] {
            #expect(throws: KeyImportError.self) {
                _ = try KeyImport.makeIdentity(inspection, passphrase: attempt)
            }
        }
    }

    @Test func theImportedPublicKeyIsUsableAsAContact() throws {
        let identity = try imported(protected: true)
        guard case .usable(let key) = ContactKey.inspect(identity.armoredPublicKey) else {
            Issue.record("the imported public key should be usable as a contact")
            return
        }
        #expect(key.fingerprint == identity.fingerprint)
    }

    // MARK: - Signing subkey

    @Test func onlyTheSigningSubkeyMaySignForTheKey() throws {
        let identity = try imported(protected: false)
        let data = try #require(PGPArmor.dearmor(identity.armoredPublicKey))
        let fingerprints = OpenPGPPacketParser.keyFingerprints(inPublicKey: data)
        // Primary, signing subkey, X25519 subkey, ML-KEM-768 + X25519 subkey.
        #expect(fingerprints.count == 4)
        #expect(OpenPGPPacketParser.isBoundSigner(subkeyFingerprint: fingerprints[1], inPublicKey: data))
        // The encryption subkeys are bound, but have not signed the primary back.
        #expect(OpenPGPPacketParser.isBound(subkeyFingerprint: fingerprints[2], inPublicKey: data))
        #expect(!OpenPGPPacketParser.isBoundSigner(subkeyFingerprint: fingerprints[2], inPublicKey: data))
        #expect(!OpenPGPPacketParser.isBoundSigner(subkeyFingerprint: fingerprints[3], inPublicKey: data))
        // A fingerprint that is not in the key at all.
        #expect(!OpenPGPPacketParser.isBoundSigner(subkeyFingerprint: [UInt8](repeating: 7, count: 32), inPublicKey: data))
    }

    // MARK: - Messages

    @Test func aContactFindsTheSenderFromTheSigningSubkey() throws {
        for protected in [false, true] {
            let me = try imported(protected: protected)
            let peer = try friend()
            let plaintext = Data("hello from an imported identity".utf8)
            let envelope = try engine(me, passphrase: protected ? "a" : nil, knowing: [peer])
                .signAndEncrypt(plaintext, to: publicKey(peer))
            let opened = try engine(peer, knowing: [me]).decryptAndVerify(envelope)
            #expect(opened.plaintext == plaintext)
            // The sender is the contact, not its signing subkey.
            #expect(opened.sender == me.fingerprint)
        }
    }

    @Test func withoutTheSubkeyLookupTheSenderIsUnknown() throws {
        let me = try imported(protected: false)
        let peer = try friend()
        let envelope = try engine(me, knowing: [peer]).signAndEncrypt(Data([1, 2, 3]), to: publicKey(peer))
        #expect(throws: (any Error).self) {
            _ = try engine(peer, knowing: [me], subkeyLookup: false).decryptAndVerify(envelope)
        }
    }

    @Test func anImportedIdentityThatIsNotAContactIsStillUnknown() throws {
        let me = try imported(protected: false)
        let peer = try friend()
        let envelope = try engine(me, knowing: [peer]).signAndEncrypt(Data([1, 2, 3]), to: publicKey(peer))
        #expect(throws: (any Error).self) {
            _ = try engine(peer).decryptAndVerify(envelope)
        }
    }

    @Test func aKnownSignerCheckAcceptsTheSigningSubkey() throws {
        let me = try imported(protected: false)
        let peer = try friend()
        let plaintext = Data("contact request".utf8)
        let envelope = try engine(me, knowing: [peer]).signAndEncrypt(plaintext, to: publicKey(peer))
        let opened = try engine(peer).decryptAndVerify(envelope, signer: publicKey(me))
        #expect(opened.plaintext == plaintext)
        #expect(opened.sender == me.fingerprint)
    }

    @Test func theProtectedIdentityReadsItsContactsMessages() throws {
        let me = try imported(protected: true)
        let peer = try friend()
        let plaintext = Data("reply".utf8)
        let envelope = try engine(peer, knowing: [me]).signAndEncrypt(plaintext, to: publicKey(me))

        PGPonyCryptoEngine.forgetUnlockedKeys()
        let mine = try engine(me, passphrase: "a", knowing: [peer])
        #expect(try mine.decryptAndVerify(envelope).plaintext == plaintext)
        // The second read uses the key held in memory.
        #expect(try mine.decryptAndVerify(envelope).sender == peer.fingerprint)

        // Without the passphrase, and after the lock has cleared the held key,
        // the message does not open.
        PGPonyCryptoEngine.forgetUnlockedKeys()
        #expect(throws: (any Error).self) {
            _ = try engine(me, knowing: [peer]).decryptAndVerify(envelope)
        }
    }

    @Test func twoImportedIdentitiesTalkToEachOther() throws {
        let first = try imported(protected: false)
        let second = try imported(protected: true)
        let plaintext = Data("imported to imported".utf8)
        let envelope = try engine(first, knowing: [second]).signAndEncrypt(plaintext, to: publicKey(second))
        let opened = try engine(second, passphrase: "a", knowing: [first]).decryptAndVerify(envelope)
        #expect(opened.plaintext == plaintext)
        #expect(opened.sender == first.fingerprint)
    }

    @Test func aDetachedSignatureFromTheSigningSubkeyVerifies() throws {
        let me = try imported(protected: true)
        let nonce = Data("relay challenge".utf8)
        let mine = try engine(me, passphrase: "a")
        let signature = try mine.detachedSignature(over: nonce)
        #expect(try mine.verifyDetached(signature: signature, over: nonce, signerPublicKey: publicKey(me)))
        #expect(try !mine.verifyDetached(signature: signature, over: Data("another nonce".utf8), signerPublicKey: publicKey(me)))
    }

    // MARK: - Existing shapes still import

    @Test func aGeneratedV6IdentityStillImports() throws {
        let generated = try OpenPGPKeyGenerator.generateV6Identity(name: "Own", email: "own@carrierpony.com")
        #expect(!OpenPGPPacketParser.v6SecretKeyNeedsPassphrase(generated.secretKey))
        // The public key derived from the secret key is the same identity.
        let derived = try OpenPGPPacketParser.transferablePublicKey(fromSecretKey: generated.secretKey)
        #expect(OpenPGPKeyID.primaryFingerprint(armoredPublicKey: derived)?.uppercased() == generated.fingerprint)
        let inspection = KeyImport.Inspection(
            secretKey: generated.secretKey, armoredPublic: derived, needsPassphrase: false)
        #expect(try KeyImport.makeIdentity(inspection, passphrase: nil).fingerprint.hex == generated.fingerprint)
    }
}
