import Foundation
import Observation

// Persistent store of known contacts (peers you have paired with). Contacts are
// app state, not crypto: the crypto engine and the ChatStore both read from here.
// Persisted as JSON in Application Support via a small Codable record, since the
// Contact/PublicKey value types are not themselves Codable.
//
// Pairing (not yet built) is what writes contacts here; until then this is empty
// and the inbox shows its empty state.

@MainActor
@Observable
final class ContactStore {

    private(set) var contacts: [Contact] = []

    private var fileURL: URL
    private let dir: URL

    private struct Record: Codable {
        let fingerprint: String
        let armored: String
        let name: String?
        let trust: String?
        let nickname: String?
        let caps: PairingCaps.Stated?
    }

    init() {
        dir = (try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        )) ?? FileManager.default.temporaryDirectory
        // Points at the legacy file until an identity activates it; contacts stay
        // empty until then (no identity means onboarding).
        fileURL = dir.appendingPathComponent("carrierpony-contacts.json")
    }

    /// Point the store at an identity's contacts and load them. Called on launch
    /// and on every account switch. The first account to activate inherits the
    /// pre-account shared file so a later second account starts empty.
    func activate(_ identityHex: String) {
        let legacy = dir.appendingPathComponent("carrierpony-contacts.json")
        let perAccount = dir.appendingPathComponent("carrierpony-contacts-\(identityHex).json")
        let fm = FileManager.default
        if !fm.fileExists(atPath: perAccount.path), fm.fileExists(atPath: legacy.path) {
            try? fm.moveItem(at: legacy, to: perAccount)
        }
        fileURL = perAccount
        load()
    }

    /// Delete this account's contacts file (used when an account is removed).
    func deleteFile(_ identityHex: String) {
        let f = dir.appendingPathComponent("carrierpony-contacts-\(identityHex).json")
        try? FileManager.default.removeItem(at: f)
    }

    // MARK: - Mutations

    func add(_ contact: Contact) {
        // Re-adding a contact (a second pairing, a channel subscribe) replaces
        // the record, but what their app told us it supports is still true, so
        // it is carried over unless the new record brings its own.
        var merged = contact
        if merged.caps == nil {
            merged.caps = contacts.first { $0.fingerprint == contact.fingerprint }?.caps
        }
        contacts.removeAll { $0.fingerprint == contact.fingerprint }
        contacts.append(merged)
        persist()
    }

    func remove(_ fingerprint: Fingerprint) {
        contacts.removeAll { $0.fingerprint == fingerprint }
        persist()
    }

    func removeAll() {
        contacts.removeAll()
        persist()
    }

    /// Promote a contact to verified (the user compared the safety number
    /// out-of-band, or paired in person).
    func markVerified(_ fingerprint: Fingerprint) {
        guard let idx = contacts.firstIndex(where: { $0.fingerprint == fingerprint }) else { return }
        contacts[idx].trust = .verified
        persist()
    }

    /// Set the name a peer told us about themselves (arrives via pairing or an
    /// encrypted profile message). Does not touch a local nickname.
    func setName(_ fingerprint: Fingerprint, name: String?) {
        guard let idx = contacts.firstIndex(where: { $0.fingerprint == fingerprint }) else { return }
        let trimmed = name?.trimmingCharacters(in: .whitespacesAndNewlines)
        contacts[idx].name = (trimmed?.isEmpty == false) ? trimmed : nil
        persist()
    }

    /// Set your local nickname for a contact. Overrides whatever name they sent.
    func setNickname(_ fingerprint: Fingerprint, nickname: String?) {
        guard let idx = contacts.firstIndex(where: { $0.fingerprint == fingerprint }) else { return }
        let trimmed = nickname?.trimmingCharacters(in: .whitespacesAndNewlines)
        contacts[idx].nickname = (trimmed?.isEmpty == false) ? trimmed : nil
        persist()
    }

    /// Record what a contact's app says it supports (arrives in an invite, or
    /// in an encrypted profile or caps message from them).
    func setCaps(_ fingerprint: Fingerprint, caps: [String]?) {
        guard let idx = contacts.firstIndex(where: { $0.fingerprint == fingerprint }) else { return }
        let cleaned = PairingCaps.normalized(caps)
        guard contacts[idx].caps != cleaned else { return }
        contacts[idx].caps = cleaned
        persist()
    }

    // MARK: - Lookups

    func contact(_ fingerprint: Fingerprint) -> Contact? {
        contacts.first { $0.fingerprint == fingerprint }
    }

    /// Raw (binary) public key bytes for a fingerprint, dearmored from the stored
    /// armored key. This is what the crypto engine's publicKeyData resolver wants.
    func publicKeyData(_ fingerprint: Fingerprint) -> Data? {
        guard let contact = contact(fingerprint) else { return nil }
        return PGPArmor.dearmor(contact.publicKey.armored)
    }

    // MARK: - Persistence

    private func load() {
        // A missing or unreadable file means this account has no contacts yet;
        // clear so the previous account's contacts don't linger after a switch.
        guard let data = try? Data(contentsOf: fileURL),
              let records = try? JSONDecoder().decode([Record].self, from: data) else {
            contacts = []
            return
        }
        contacts = records.compactMap { record in
            guard let fingerprint = Fingerprint(record.fingerprint) else { return nil }
            return Contact(
                fingerprint: fingerprint,
                publicKey: PublicKey(fingerprint: fingerprint, armored: record.armored),
                name: record.name,
                trust: TrustLevel(rawValue: record.trust ?? "unverified") ?? .unverified,
                nickname: record.nickname,
                caps: record.caps?.caps
            )
        }
    }

    private func persist() {
        let records = contacts.map {
            Record(fingerprint: $0.fingerprint.hex, armored: $0.publicKey.armored, name: $0.name, trust: $0.trust.rawValue, nickname: $0.nickname, caps: PairingCaps.Stated($0.caps))
        }
        guard let data = try? JSONEncoder().encode(records) else { return }
        // Deliberately not .completeFileProtection. Opening an incoming message
        // needs the sender's public key from this file, and a push-triggered
        // background refresh can run while the device is locked, where complete
        // protection makes the file unreadable and every message fails to open.
        // This matches the identity Keychain's kSecAttrAccessibleAfterFirstUnlock
        // posture; the file holds only public keys and names.
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}
