import Foundation
import Security
import LocalAuthentication

// Stores the passphrase for an imported (passphrase-protected) identity in the
// Keychain behind a biometric access-control flag. The key material itself stays
// encrypted under this passphrase at rest; the passphrase only leaves the
// Keychain after a successful Face ID / Touch ID / passcode check.
//
// Reads reuse an already-authenticated LAContext (from the app-lock unlock) via
// kSecUseAuthenticationContext, so unlocking the app and loading the passphrase
// is a single biometric prompt, not two.

enum PassphraseVault {

    private static let service = "com.carrierpony.passphrase"

    /// Store the passphrase for a fingerprint. When requireUserPresence is true
    /// (App Lock on) the item is gated behind biometrics/passcode. When false
    /// (App Lock off) it is protected only by device unlock, so it can be read
    /// silently at launch — matching the user's chosen "no lock" posture.
    static func store(_ passphrase: String, fingerprint: String, requireUserPresence: Bool = true) -> Bool {
        guard let data = passphrase.data(using: .utf8) else { return false }

        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: fingerprint
        ]
        SecItemDelete(base as CFDictionary)

        var add = base
        add[kSecValueData as String] = data

        if requireUserPresence {
            var accessError: Unmanaged<CFError>?
            // .userPresence => biometrics, and the device passcode as a fallback.
            guard let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .userPresence,
                &accessError
            ) else {
                return false
            }
            add[kSecAttrAccessControl as String] = access
        } else {
            add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }

    /// Read the passphrase, reusing an authenticated context to avoid a second prompt.
    static func read(fingerprint: String, context: LAContext) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: fingerprint,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    /// Read without any authentication UI. Succeeds only for an entry stored
    /// without user-presence (App Lock off); returns nil for a presence-gated
    /// entry instead of prompting.
    static func readSilently(fingerprint: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: fingerprint,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    static func delete(fingerprint: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: fingerprint
        ]
        SecItemDelete(query as CFDictionary)
    }
}
