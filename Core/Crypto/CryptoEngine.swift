import Foundation

// An OpenPGP primary-key fingerprint in uppercase hex: 40 characters for a v4
// key (SHA-1), 64 for a v6 key (RFC 9580, SHA-256). It is a contact's identity
// throughout the app and the relay protocol.
struct Fingerprint: Hashable, Codable {
    static let v4Length = 40
    static let v6Length = 64

    let hex: String

    /// True for a v6 (RFC 9580) fingerprint, false for v4.
    var isV6: Bool { hex.count == Self.v6Length }

    /// Nil unless the string is exactly 40 or 64 ASCII hex characters.
    /// (Character.isHexDigit also accepts fullwidth forms, so it is not used.)
    init?(_ string: String) {
        let upper = string.uppercased()
        let bytes = Array(upper.utf8)
        guard bytes.count == Self.v4Length || bytes.count == Self.v6Length,
              bytes.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x46) }) else { return nil }
        self.hex = upper
    }
}

struct PublicKey {
    let fingerprint: Fingerprint
    let armored: String
}

struct VerifiedMessage {
    let sender: Fingerprint
    let plaintext: Data
}

enum CryptoError: Error {
    case noValidSignature
    case decryptionFailed
    case notImplemented
}

protocol CryptoEngine {
    var fingerprint: Fingerprint { get }

    func armoredPublicKey() throws -> String

    func detachedSignature(over data: Data) throws -> String

    func signAndEncrypt(_ plaintext: Data, to recipient: PublicKey) throws -> Data

    func decryptAndVerify(_ message: Data) throws -> VerifiedMessage

    /// Decrypt to our key and enforce the integrity gate, WITHOUT verifying the
    /// signer. Returns the raw plaintext. Only for self-authenticating control
    /// ops (channel-subscribe) whose payload carries the sender's own public key;
    /// the caller must check fingerprint == hash(pubkey). Never for message content.
    func decryptOnly(_ message: Data) throws -> Data
    /// Decrypt and verify an envelope against one given key, which need not be
    /// a contact's. For a control op that carries its sender's key (a contact
    /// request): the op is only believed if the envelope was signed by that
    /// same key. A signature by any other key is noValidSignature.
    func decryptAndVerify(_ message: Data, signer: PublicKey) throws -> VerifiedMessage

    /// Verify an armored Ed25519 detached signature over `data`, made by
    /// `signerPublicKey`. Authenticates a group message's sender against the roster.
    func verifyDetached(signature: String, over data: Data, signerPublicKey: PublicKey) throws -> Bool
}

extension CryptoEngine {
    // Engines that have no use for it (previews, test doubles) refuse.
    func decryptAndVerify(_ message: Data, signer: PublicKey) throws -> VerifiedMessage {
        throw CryptoError.notImplemented
    }
}
