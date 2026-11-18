import Foundation
import Security
import CryptoKit

// Per-epoch group keys, kept in the Keychain and never in the plaintext conversation
// store. A group message is AEAD-encrypted (CryptoKit) under the key for its epoch;
// a rekey writes a new epoch key and bumps Group.epoch. Old epoch keys are kept so
// messages sent before a rekey can still be opened, until the group is left.

enum GroupKeyStore {

    private static let service = "com.carrierpony.groupkey"

    private static func account(_ groupID: String, _ epoch: Int) -> String {
        "\(groupID).\(epoch)"
    }

    static func newKey() -> SymmetricKey {
        SymmetricKey(size: .bits256)
    }

    static func store(_ key: SymmetricKey, groupID: String, epoch: Int) {
        let data = key.withUnsafeBytes { Data($0) }
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(groupID, epoch),
        ]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }

    static func key(groupID: String, epoch: Int) -> SymmetricKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(groupID, epoch),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data else {
            return nil
        }
        return SymmetricKey(data: data)
    }

    static func delete(groupID: String, epoch: Int) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(groupID, epoch),
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// Remove every epoch key for a group, 0 through the current epoch (on leave).
    static func deleteGroup(groupID: String, throughEpoch epoch: Int) {
        guard epoch >= 0 else { return }
        for e in 0...epoch {
            delete(groupID: groupID, epoch: e)
        }
    }
}
