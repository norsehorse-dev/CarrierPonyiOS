import Foundation
import CryptoKit
import NorseHorsePGPCore

// The single integration point between CarrierPony and PGPonyCore.
// Everything else depends only on the CryptoEngine protocol.
//
// Depends only on PGPonyCore (Apache-2.0, no third-party dependencies). No
// ObjectivePGP, no closed app code. The identity's secret key bytes, its armored
// public key, and a public-key resolver are injected by the app, since key
// storage is app state, not crypto.
//
// Supports both OpenPGP v4 and v6 (RFC 9580) identities and recipients:
//   v4  Ed25519 primary that signs + Cv25519 encryption subkey
//   v6  Ed25519 primary that signs + ML-KEM-768 + X25519 (algorithm 35) subkey
// A v6 identity imported from another app can have a certify-only primary and
// a signing subkey. It signs with that subkey, and a receiver finds the contact
// from the subkey a signature names (see decryptAndVerify).
// The key version is detected from the key bytes with openPGPKeyVersion(from:),
// so a v4 identity can message a v6 contact and vice versa. The container
// follows the recipient (v3 PKESK + SEIPDv1 for v4, v6 PKESK + SEIPDv2 for v6)
// and the inline signature follows the sender. Both match what the Android
// core writes in CPMessenger, and each side's tests open the other's envelopes.
//
// A v6 key with a plain X25519 subkey and no ML-KEM subkey (another OpenPGP
// stack's default shape) can still be encrypted to and decrypted with.

/// A contact's key that cannot be trusted as it stands.
enum KeyTrustError: Error {
    /// The encryption subkey is not signed by the contact's primary key, or the
    /// primary key has revoked it.
    case encryptionSubkeyNotBound
}

final class PGPonyCryptoEngine: CryptoEngine {

    let fingerprint: Fingerprint
    private let secretKey: Data
    private let armoredPublic: String
    private let publicKeyData: (Fingerprint) -> Data?
    private let passphrase: () -> String?
    /// Every key a message may be signed by, as binary public keys: the
    /// contacts and the identity's own key. Looked through only when a
    /// signature names a key that is no identity's primary key.
    private let signerKeys: () -> [Data]

    /// This identity's OpenPGP key version (4 or 6), detected from its secret
    /// key bytes at construction. Defaults to 4 if detection fails.
    private let version: Int

    init(
        fingerprint: Fingerprint,
        secretKey: Data,
        armoredPublicKey: String,
        publicKeyData: @escaping (Fingerprint) -> Data?,
        passphrase: @escaping () -> String? = { nil },
        signerKeys: @escaping () -> [Data] = { [] }
    ) {
        self.fingerprint = fingerprint
        self.secretKey = secretKey
        self.armoredPublic = armoredPublicKey
        self.publicKeyData = publicKeyData
        self.passphrase = passphrase
        self.signerKeys = signerKeys
        self.version = OpenPGPPacketParser.openPGPKeyVersion(from: secretKey) ?? 4
    }

    func armoredPublicKey() throws -> String {
        armoredPublic
    }

    func detachedSignature(over data: Data) throws -> String {
        // Relay-challenge signing, routed by identity version. v4 emits a
        // version-4 EdDSA-legacy detached signature; v6 emits a version-6
        // (RFC 9580) detached signature. Note: a v6 signature verifies only under
        // an RFC 9580 implementation (Sequoia, gpg 2.5+); gpg 2.4.4 cannot, so a
        // v6 identity requires a v6-capable relay verifier.
        let signing = try mySigningInfo()
        return version == 6
            ? try OpenPGPPacketBuilder.detachedSignatureEd25519V6(over: data, signingInfo: signing)
            : try OpenPGPPacketBuilder.detachedSignatureEd25519(over: data, signingInfo: signing)
    }

    func signAndEncrypt(_ plaintext: Data, to recipient: PublicKey) throws -> Data {
        // A contact's key comes from the contact list. For someone who is not a
        // contact yet (a contact request goes out before they are stored), the
        // key the caller passed is used, and only if it really is the key of
        // the fingerprint it is passed under.
        let recipientData: Data
        if let known = publicKeyData(recipient.fingerprint) {
            recipientData = known
        } else if OpenPGPKeyID.primaryFingerprint(armoredPublicKey: recipient.armored)?.uppercased() == recipient.fingerprint.hex,
                  let passed = PGPArmor.dearmor(recipient.armored) {
            recipientData = passed
        } else {
            throw CryptoError.notImplemented
        }
        let signing = try mySigningInfo()
        // A v6 recipient with an ML-KEM-768 + X25519 subkey is always encrypted
        // to that subkey, so the post-quantum part is never left out.
        //
        // The recipient is pinned by their primary key. A subkey the primary
        // has not signed is not theirs, whoever handed us the key, so it is
        // refused. No falling back to another subkey: that would be a quiet
        // downgrade.
        if let composite = try compositeRecipient(forPublicKeyData: recipientData) {
            guard OpenPGPPacketParser.isBound(composite, inPublicKey: recipientData) else {
                throw KeyTrustError.encryptionSubkeyNotBound
            }
            return try OpenPGPPacketBuilder.buildEncryptedMessage(
                plaintext: plaintext,
                recipients: [],
                signingInfo: signing,
                armor: false,
                compositeRecipients: [composite]
            )
        }
        let cvRecipient = try encryptionRecipient(forPublicKeyData: recipientData)
        guard OpenPGPPacketParser.isBound(cvRecipient, inPublicKey: recipientData) else {
            throw KeyTrustError.encryptionSubkeyNotBound
        }
        return try OpenPGPPacketBuilder.buildEncryptedMessage(
            plaintext: plaintext,
            recipients: [cvRecipient],
            signingInfo: signing,
            armor: false
        )
    }

    func decryptAndVerify(_ message: Data) throws -> VerifiedMessage {
        let contents = try open(message)
        guard let claimed = OpenPGPPacketParser.claimedSignerFingerprint(contents: contents) else {
            throw CryptoError.noValidSignature
        }
        // The usual case: the signature names an identity's primary key.
        if let sender = Fingerprint(claimed), let senderPublic = publicKeyData(sender) {
            let senderEd25519 = try verificationKey(forPublicKeyData: senderPublic)
            guard try OpenPGPPacketParser.verifyInlineSignature(
                contents: contents, signerEd25519PublicKey: senderEd25519
            ) else {
                throw CryptoError.noValidSignature
            }
            return VerifiedMessage(sender: sender, plaintext: contents.literalData)
        }
        // Otherwise it may name a signing subkey of someone we know. The sender
        // is then that identity, named by its primary key.
        guard let subkey = Self.bytes(fromHex: claimed),
              let owner = signerKeys().first(where: { Self.subkeyFingerprints(of: $0).contains(subkey) }),
              let primary = OpenPGPPacketParser.keyFingerprints(inPublicKey: owner).first,
              let sender = Fingerprint(Self.hex(primary)) else {
            throw CryptoError.noValidSignature
        }
        let signerEd25519 = try signingSubkey(subkey, inPublicKeyData: owner)
        guard try OpenPGPPacketParser.verifyInlineSignature(
            contents: contents, signerEd25519PublicKey: signerEd25519
        ) else {
            throw CryptoError.noValidSignature
        }
        return VerifiedMessage(sender: sender, plaintext: contents.literalData)
    }

    func decryptAndVerify(_ message: Data, signer: PublicKey) throws -> VerifiedMessage {
        let contents = try open(message)
        // The key has to be the key of the fingerprint it is offered under, and
        // the envelope has to name that key, or a signing subkey bound to it,
        // as its signer.
        guard OpenPGPKeyID.primaryFingerprint(armoredPublicKey: signer.armored)?.uppercased() == signer.fingerprint.hex,
              let signerData = PGPArmor.dearmor(signer.armored),
              let claimed = OpenPGPPacketParser.claimedSignerFingerprint(contents: contents) else {
            throw CryptoError.noValidSignature
        }
        let signerEd25519: [UInt8]
        if Fingerprint(claimed) == signer.fingerprint {
            signerEd25519 = try verificationKey(forPublicKeyData: signerData)
        } else if let subkey = Self.bytes(fromHex: claimed) {
            signerEd25519 = try signingSubkey(subkey, inPublicKeyData: signerData)
        } else {
            throw CryptoError.noValidSignature
        }
        guard try OpenPGPPacketParser.verifyInlineSignature(
            contents: contents, signerEd25519PublicKey: signerEd25519
        ) else {
            throw CryptoError.noValidSignature
        }
        return VerifiedMessage(sender: signer.fingerprint, plaintext: contents.literalData)
    }

    func decryptOnly(_ message: Data) throws -> Data {
        // Decrypt to our key (the parser enforces the SEIPD integrity gate) but do
        // not resolve or verify the signer. Only for self-authenticating control
        // ops whose payload carries the sender's own key; the caller checks
        // fingerprint == hash(pubkey). Never use for message content.
        try open(message).literalData
    }

    // Decrypt to our own key. A v6 identity with an ML-KEM-768 + X25519 subkey
    // opens with that subkey and nothing else; every other identity opens with
    // its Cv25519 (v4) or X25519 (v6) subkey.
    private func open(_ message: Data) throws -> OpenPGPPacketParser.DecryptedMessageContents {
        if version == 6, let composite = try myCompositeKey() {
            return try OpenPGPPacketParser.decryptMessageReturningInnerPackets(
                messageData: message, decryptionKeys: [], compositeKeys: [composite]
            )
        }
        return try OpenPGPPacketParser.decryptMessageReturningInnerPackets(
            messageData: message, decryptionKeys: [try myDecryptionKey()]
        )
    }

    func verifyDetached(signature: String, over data: Data, signerPublicKey: PublicKey) throws -> Bool {
        try OpenPGPPacketParser.verifyDetachedEd25519(
            armoredSignature: signature,
            over: data,
            signerArmoredPublicKey: signerPublicKey.armored
        )
    }

    // MARK: - Signing subkeys

    /// The Ed25519 key of a signing subkey, once it is known to be bound to the
    /// primary key of `data` and to have signed it back.
    private func signingSubkey(_ fingerprint: [UInt8], inPublicKeyData data: Data) throws -> [UInt8] {
        guard OpenPGPPacketParser.isBoundSigner(subkeyFingerprint: fingerprint, inPublicKey: data) else {
            throw CryptoError.noValidSignature
        }
        return try OpenPGPPacketParser.ed25519PublicKey(fromPublicKeyData: data, keyFingerprint: fingerprint)
    }

    /// The fingerprints of a key's subkeys (everything after the primary).
    private static func subkeyFingerprints(of data: Data) -> [[UInt8]] {
        Array(OpenPGPPacketParser.keyFingerprints(inPublicKey: data).dropFirst())
    }

    private static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }

    private static func bytes(fromHex hex: String) -> [UInt8]? {
        let characters = Array(hex)
        guard characters.count % 2 == 0, !characters.isEmpty else { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(characters.count / 2)
        for index in stride(from: 0, to: characters.count, by: 2) {
            guard let byte = UInt8(String(characters[index...index + 1]), radix: 16) else { return nil }
            out.append(byte)
        }
        return out
    }

    // MARK: - Unlocked ML-KEM key

    /// Unlocked ML-KEM-768 + X25519 keys of protected identities, held for the
    /// process. Unlocking one runs Argon2 (64 MiB, a second or more on a
    /// phone), so it is done once and not for every message. What is held is no
    /// more than the passphrase the app already holds would give.
    /// `forgetUnlockedKeys()` empties it when the app locks or signs out.
    private final class UnlockedKeys: @unchecked Sendable {
        private let lock = NSLock()
        private var keys: [String: CompositeKEMDecryptionKey] = [:]
        // The classic keys of the same identities. Unlocking a protected secret
        // key runs its passphrase KDF, a third of a second on a phone, and that
        // ran on the main actor for every message opened and every relay login
        // signed, which made the whole app stutter.
        private var decryption: [String: Cv25519DecryptionKey] = [:]
        private var signing: [String: Ed25519SigningInfo] = [:]

        func decryptionKey(for id: String) -> Cv25519DecryptionKey? {
            lock.lock(); defer { lock.unlock() }
            return decryption[id]
        }

        func keep(_ key: Cv25519DecryptionKey, for id: String) {
            lock.lock(); defer { lock.unlock() }
            decryption[id] = key
        }

        func signingInfo(for id: String) -> Ed25519SigningInfo? {
            lock.lock(); defer { lock.unlock() }
            return signing[id]
        }

        func keep(_ info: Ed25519SigningInfo, for id: String) {
            lock.lock(); defer { lock.unlock() }
            signing[id] = info
        }

        func key(for id: String) -> CompositeKEMDecryptionKey? {
            lock.lock(); defer { lock.unlock() }
            return keys[id]
        }

        func keep(_ key: CompositeKEMDecryptionKey, for id: String) {
            lock.lock(); defer { lock.unlock() }
            keys[id] = key
        }

        func removeAll() {
            lock.lock(); defer { lock.unlock() }
            keys.removeAll()
            decryption.removeAll()
            signing.removeAll()
        }
    }

    private static let unlocked = UnlockedKeys()

    /// Drop every unlocked ML-KEM key held in memory.
    static func forgetUnlockedKeys() {
        unlocked.removeAll()
    }

    /// Our ML-KEM-768 + X25519 subkey, or nil when the identity has none.
    private func myCompositeKey() throws -> CompositeKEMDecryptionKey? {
        guard let pass = passphrase(), !pass.isEmpty else {
            return try OpenPGPPacketParser.compositeDecryptionKey(fromV6SecretKey: secretKey)
        }
        let digest = SHA256.hash(data: Data(pass.utf8)).map { String(format: "%02x", $0) }.joined()
        let id = fingerprint.hex + ":" + digest
        if let held = Self.unlocked.key(for: id) { return held }
        guard let key = try OpenPGPPacketParser.compositeDecryptionKey(fromV6SecretKey: secretKey, passphrase: pass) else {
            return nil
        }
        Self.unlocked.keep(key, for: id)
        return key
    }

    // MARK: - Version-routed extraction

    // Our own signing key. Identities this app makes sign with the Ed25519
    // primary, v4 and v6 alike. An imported v6 key with a signing subkey signs
    // with that subkey.
    private func mySigningInfo() throws -> Ed25519SigningInfo {
        let pass = passphrase()
        let id = unlockID(pass)
        if let held = Self.unlocked.signingInfo(for: id) { return held }
        let info = version == 6
            ? try OpenPGPPacketParser.ed25519SigningInfo(fromV6SecretKey: secretKey, passphrase: pass)
            : try OpenPGPPacketParser.ed25519SigningInfo(fromSecretKey: secretKey, passphrase: pass)
        Self.unlocked.keep(info, for: id)
        return info
    }

    /// Names one identity under one passphrase in the unlocked-key store, so a
    /// changed passphrase never finds a key unlocked under the old one.
    private func unlockID(_ pass: String?) -> String {
        let digest = SHA256.hash(data: Data((pass ?? "").utf8)).map { String(format: "%02x", $0) }.joined()
        return fingerprint.hex + ":" + digest
    }

    // Our own decryption key. v4 -> Cv25519 subkey; v6 -> X25519 subkey.
    private func myDecryptionKey() throws -> Cv25519DecryptionKey {
        let pass = passphrase()
        let id = unlockID(pass)
        if let held = Self.unlocked.decryptionKey(for: id) { return held }
        let key = version == 6
            ? try OpenPGPPacketParser.x25519DecryptionKey(fromV6SecretKey: secretKey, passphrase: pass)
            : try OpenPGPPacketParser.cv25519DecryptionKey(fromSecretKey: secretKey, passphrase: pass)
        Self.unlocked.keep(key, for: id)
        return key
    }

    // A recipient's encryption key, routed by the recipient's own key version
    // (independent of our identity's version).
    private func encryptionRecipient(forPublicKeyData data: Data) throws -> Cv25519Recipient {
        OpenPGPPacketParser.openPGPKeyVersion(from: data) == 6
            ? try OpenPGPPacketParser.x25519Recipient(fromV6PublicKey: data)
            : try OpenPGPPacketParser.cv25519Recipient(fromPublicKey: data)
    }

    // A v6 recipient's ML-KEM-768 + X25519 subkey, or nil when the key is v4 or
    // has no such subkey.
    private func compositeRecipient(forPublicKeyData data: Data) throws -> CompositeKEMRecipient? {
        guard OpenPGPPacketParser.openPGPKeyVersion(from: data) == 6 else { return nil }
        return try OpenPGPPacketParser.compositeRecipient(fromV6PublicKey: data)
    }

    // A sender's primary Ed25519 verification key, for a signature that names
    // the fingerprint a contact is pinned by. A signature made by a signing
    // subkey names the subkey and goes through signingSubkey(_:inPublicKeyData:).
    private func verificationKey(forPublicKeyData data: Data) throws -> [UInt8] {
        try OpenPGPPacketParser.ed25519PublicKey(fromPublicKeyData: data)
    }
}
