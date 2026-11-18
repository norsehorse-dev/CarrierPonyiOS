import Foundation
import CryptoKit

// Seal and open a group message. A message is signed once by the sender (OpenPGP
// Ed25519 detached signature) and encrypted once under the current epoch key
// (CryptoKit AES-GCM). The identical sealed payload is fanned out to every member.
// On open, the epoch key decrypts it and the sender's signature is verified
// against the group roster, so a member cannot forge a message from another.

struct GroupSealedBox: Codable {
    let groupID: String
    let sender: String     // sender fingerprint hex
    let epoch: Int
    let sig: String        // armored detached signature over the plaintext container
    let ct: String         // base64 AES-GCM combined box (nonce + ciphertext + tag)
}

enum GroupCryptoError: Error, Equatable {
    case badBox
    case noKey
    case notMember
    case badSignature
}

enum GroupCrypto {

    /// Sign `container` and encrypt it under `key`, returning the wire payload.
    static func seal(container: Data, groupID: String, sender: Fingerprint, epoch: Int,
                     key: SymmetricKey, crypto: CryptoEngine) throws -> Data {
        let sig = try crypto.detachedSignature(over: container)
        let sealed = try AES.GCM.seal(container, using: key)
        guard let combined = sealed.combined else { throw GroupCryptoError.badBox }
        let box = GroupSealedBox(groupID: groupID, sender: sender.hex, epoch: epoch, sig: sig,
                                 ct: combined.base64EncodedString())
        return try JSONEncoder().encode(box)
    }

    /// Decrypt with the epoch key and verify the sender's signature against the
    /// roster. Returns the sender and the plaintext container.
    static func open(payload: Data, group: ChatGroup,
                     keyFor: (Int) -> SymmetricKey?, crypto: CryptoEngine) throws -> (sender: Fingerprint, container: Data) {
        guard let box = try? JSONDecoder().decode(GroupSealedBox.self, from: payload),
              let ctData = Data(base64Encoded: box.ct),
              let sender = Fingerprint(box.sender) else {
            throw GroupCryptoError.badBox
        }
        guard let member = group.member(sender) else { throw GroupCryptoError.notMember }
        guard let key = keyFor(box.epoch) else { throw GroupCryptoError.noKey }
        let sealed = try AES.GCM.SealedBox(combined: ctData)
        let container = try AES.GCM.open(sealed, using: key)
        guard try crypto.verifyDetached(signature: box.sig, over: container, signerPublicKey: member.publicKey) else {
            throw GroupCryptoError.badSignature
        }
        return (sender, container)
    }
}
