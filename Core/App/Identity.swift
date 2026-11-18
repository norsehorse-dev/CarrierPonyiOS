import Foundation
import Security

// The app's own messaging identity: a v4 Ed25519 signing + Cv25519 encryption
// key (or a v6 key; the crypto engine detects the version from the bytes). The
// secret key never leaves the device and is stored in the Keychain.
//
// This is the material the PGPonyCryptoEngine adapter needs. Where it comes from
// (generated in-app, or imported/paired) is the onboarding flow's job; this type
// just models and persists it.

struct Identity {
    let fingerprint: Fingerprint
    let secretKey: Data          // serialized OpenPGP secret key bytes
    let armoredPublicKey: String // ASCII-armored public key
    var protected: Bool = false  // true if secretKey is passphrase-protected (imported)
}

enum IdentityStoreError: Error {
    case keychain(OSStatus)
    case malformed
}

// Keychain-backed persistence for the single primary identity. Stored as one
// generic-password item (the record contains the secret, so the whole thing
// lives in the Keychain, accessible only after first unlock, this device only).
struct IdentityStore {

    private let service = "com.carrierpony.identity"
    private let idsKey = "cp.identity.ids"
    private let selectedKey = "cp.identity.selected"

    private struct Record: Codable {
        let fingerprint: String
        let secretKeyB64: String
        let armoredPublicKey: String
        let protected: Bool?
    }

    // ── Multi-identity API ─────────────────────────────────────────────

    /// Fingerprint hexes of all stored accounts, in insertion order.
    func list() -> [String] {
        migrateIfNeeded()
        return UserDefaults.standard.stringArray(forKey: idsKey) ?? []
    }

    func selected() -> String? {
        let ids = list()
        if let sel = UserDefaults.standard.string(forKey: selectedKey), ids.contains(sel) { return sel }
        return ids.first
    }

    func setSelected(_ fprHex: String) {
        if list().contains(fprHex) { UserDefaults.standard.set(fprHex, forKey: selectedKey) }
    }

    /// The selected account's identity, nil when none exists.
    func load() throws -> Identity? {
        guard let sel = selected() else { return nil }
        return try load(sel)
    }

    /// One account's identity by fingerprint.
    func load(_ fprHex: String) throws -> Identity? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: fprHex,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = out as? Data else {
            throw IdentityStoreError.keychain(status)
        }
        let record = try JSONDecoder().decode(Record.self, from: data)
        guard let fingerprint = Fingerprint(record.fingerprint),
              let secretKey = Data(base64Encoded: record.secretKeyB64) else {
            throw IdentityStoreError.malformed
        }
        return Identity(
            fingerprint: fingerprint,
            secretKey: secretKey,
            armoredPublicKey: record.armoredPublicKey,
            protected: record.protected ?? false
        )
    }

    /// Add or replace an account and make it the selected one.
    func save(_ identity: Identity) throws {
        migrateIfNeeded()
        let fpr = identity.fingerprint.hex
        let record = Record(
            fingerprint: fpr,
            secretKeyB64: identity.secretKey.base64EncodedString(),
            armoredPublicKey: identity.armoredPublicKey,
            protected: identity.protected
        )
        let data = try JSONEncoder().encode(record)
        try writeItem(account: fpr, data: data)
        var ids = UserDefaults.standard.stringArray(forKey: idsKey) ?? []
        if !ids.contains(fpr) { ids.append(fpr) }
        UserDefaults.standard.set(ids, forKey: idsKey)
        UserDefaults.standard.set(fpr, forKey: selectedKey)
    }

    /// Remove one account; if it was selected, the first remaining becomes
    /// selected. Returns the new selected fingerprint (or nil if none left).
    @discardableResult
    func delete(_ fprHex: String) -> String? {
        deleteItem(account: fprHex)
        var ids = UserDefaults.standard.stringArray(forKey: idsKey) ?? []
        ids.removeAll { $0 == fprHex }
        UserDefaults.standard.set(ids, forKey: idsKey)
        if UserDefaults.standard.string(forKey: selectedKey) == fprHex {
            if let next = ids.first { UserDefaults.standard.set(next, forKey: selectedKey); return next }
            UserDefaults.standard.removeObject(forKey: selectedKey)
            return nil
        }
        return UserDefaults.standard.string(forKey: selectedKey)
    }

    /// Wipe every account (factory reset / full sign-out).
    func deleteAll() {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ] as CFDictionary)
        UserDefaults.standard.removeObject(forKey: idsKey)
        UserDefaults.standard.removeObject(forKey: selectedKey)
    }

    // ── Keychain item helpers ──────────────────────────────────────────

    private func writeItem(account: String, data: Data) throws {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw IdentityStoreError.keychain(status) }
    }

    private func deleteItem(account: String) {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ] as CFDictionary)
    }

    // One-time move from the v1 layout (a single "primary" keychain item, no ids
    // list) to per-fingerprint accounts.
    private func migrateIfNeeded() {
        let defaults = UserDefaults.standard
        if defaults.stringArray(forKey: idsKey) != nil { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "primary",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data,
              let record = try? JSONDecoder().decode(Record.self, from: data) else { return }
        try? writeItem(account: record.fingerprint, data: data)
        defaults.set([record.fingerprint], forKey: idsKey)
        defaults.set(record.fingerprint, forKey: selectedKey)
        deleteItem(account: "primary")
    }
}
