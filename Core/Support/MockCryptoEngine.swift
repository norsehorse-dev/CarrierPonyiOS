import Foundation

// Preview and test only. Performs no real cryptography: it frames the sender
// fingerprint in front of the plaintext so round-trips work in SwiftUI previews
// and unit tests without PGPonyCore. Never use in production.

final class MockCryptoEngine: CryptoEngine {

    let fingerprint: Fingerprint

    init(fingerprint: Fingerprint) {
        self.fingerprint = fingerprint
    }

    func armoredPublicKey() throws -> String {
        "MOCK-PUBLIC-KEY-\(fingerprint.hex)"
    }

    func detachedSignature(over data: Data) throws -> String {
        "MOCK-SIG-\(fingerprint.hex)"
    }

    func signAndEncrypt(_ plaintext: Data, to recipient: PublicKey) throws -> Data {
        var out = Data()
        out.append(Data(fingerprint.hex.utf8))
        out.append(0x00)
        out.append(plaintext)
        return out
    }

    func decryptOnly(_ message: Data) throws -> Data {
        guard let separator = message.firstIndex(of: 0x00) else { throw CryptoError.decryptionFailed }
        return Data(message[message.index(after: separator)...])
    }

    func decryptAndVerify(_ message: Data) throws -> VerifiedMessage {
        guard let separator = message.firstIndex(of: 0x00) else {
            throw CryptoError.decryptionFailed
        }
        let senderBytes = message[message.startIndex..<separator]
        guard let senderHex = String(data: Data(senderBytes), encoding: .utf8),
              let sender = Fingerprint(senderHex) else {
            throw CryptoError.noValidSignature
        }
        let plaintext = Data(message[message.index(after: separator)...])
        return VerifiedMessage(sender: sender, plaintext: plaintext)
    }

    func verifyDetached(signature: String, over data: Data, signerPublicKey: PublicKey) throws -> Bool {
        signature == "MOCK-SIG-\(signerPublicKey.fingerprint.hex)"
    }
}
