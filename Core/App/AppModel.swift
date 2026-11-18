import Foundation
import Observation
import NorseHorsePGPCore

enum IdentityCreationError: Error {
    case invalidFingerprint
}

/// What came of adding a contact from a public key (AppModel.addContactByKey).
enum AddByKeyResult {
    /// Added, and a contact request is on its way to them.
    case added(Contact)
    /// This person is already a contact; nothing changed.
    case alreadyContact(Contact)
    case notReady
    case ownKey
    case secretKey
    case notAKey
    case unsupported
    /// Nobody with this key has an account on the relay this app uses.
    case notOnRelay
    /// The request could not be sent (offline, relay down). Nothing was added.
    case couldNotSend
}

enum PairingError: LocalizedError {
    case notReady
    case malformedInvite
    case keyMismatch
    case peerNeedsUpdate

    var errorDescription: String? {
        switch self {
        case .peerNeedsUpdate: return "This contact is on an older CarrierPony. Ask them to update to version 4.0 or later, then pair again."
        case .notReady:       return "You need an identity before you can pair."
        case .malformedInvite: return "That doesn't look like a CarrierPony invite."
        case .keyMismatch:    return "The key the relay returned doesn't match the invite. Pairing was refused to keep you safe."
        }
    }
}

// The composition root. Owns the identity and contact stores, and once an
// identity exists, builds the real crypto engine, relay client, and ChatStore
// and wires them together. The UI observes this to know whether to show the
// inbox or onboarding, and drives polling lifecycle through start()/stop().
//
// This is the one place the concrete PGPonyCryptoEngine, RelayClient, and
// ChatStore are constructed; everything above codes against ChatStore and the
// stores here.

@MainActor
@Observable
final class AppModel {

    private(set) var identity: Identity?
    private(set) var profileName: String?
    private(set) var store: ChatStore?
    private(set) var relay: RelayClient?
    let contactStore = ContactStore()
    /// Requests from people who added this identity by its public key.
    let contactRequests = ContactRequestStore()
    let appLock = LockManager()

    /// LAN-direct discovery (2.1 M2): advertises this device on the local
    /// network and browses for other CarrierPony nodes so the switcher/settings
    /// can show how many are nearby. Discovery only; no envelopes move yet.
    let lanDiscovery = LanDiscovery()

    var lastError: String?

    /// Unread counts for accounts other than the active one, refreshed by the
    /// background poll so the switcher can flag which accounts have messages waiting.
    private(set) var accountUnread: [String: Int] = [:]

    /// WAN-direct (2.2 M1) signaling test surface: how many webrtc-* control ops
    /// this device has received from peers, and a short label for the last one.
    private(set) var wanSignalsReceived: Int = 0
    private(set) var lastWanSignal: String?
    /// Number of contacts currently reachable over a direct WAN path (2.2 M2).
    private(set) var wanConnectedCount: Int = 0
    /// Bridges CarrierPony signaling + pair keys to the PonyDirect WAN transport.
    let wanBridge = WanDirectBridge()
    /// Holds the Nostr relay connections for the store-and-forward Nostr transport (2.3).
    let nostrManager = NostrTransportManager()
    private var otherPollTask: Task<Void, Never>?

    /// Pairing offers created here that haven't been accepted yet. Persisted per
    /// identity and swept on every inbox refresh, so an invite keeps working
    /// after its screen — or the app — is closed.
    private(set) var pendingInvites: [PendingInvite] = []
    private var completedInviteContacts: [String: Contact] = [:]
    private var lastPendingSweep = Date.distantPast

    private let identityStore = IdentityStore()

    init() {
        appLanguage = UserDefaults.standard.string(forKey: "cp.lang") ?? "en"
        onboardingComplete = UserDefaults.standard.bool(forKey: "cp.onboarded")
        do {
            if let existing = try identityStore.load() {
                identity = existing
                onboardingComplete = true   // existing users have already set up
                loadProfileName()
                loadPendingInvites()
                buildStore(for: existing)
            }
        } catch {
            lastError = "identity load failed"
        }
    }

    // MARK: - Onboarding

    private(set) var onboardingComplete: Bool
    private(set) var appLanguage: String

    func completeOnboarding() {
        onboardingComplete = true
        UserDefaults.standard.set(true, forKey: "cp.onboarded")
        // A freshly created identity hasn't registered with the relay yet (the
        // launch-time .task ran before it existed). Register the device and push
        // token now so the identity can receive messages and notifications
        // without needing an app relaunch. start() handles push registration
        // itself, in the right order.
        Task { await start() }
    }

    func setLanguage(_ code: String) {
        appLanguage = code
        UserDefaults.standard.set(code, forKey: "cp.lang")
    }

    /// Replay the first-run flow without wiping anything.
    func resetOnboarding() {
        onboardingComplete = false
        UserDefaults.standard.set(false, forKey: "cp.onboarded")
    }

    /// Factory reset: wipe the identity, contacts, conversations, attachments,
    /// stored passphrase, and all preferences. Returns to onboarding.
    func resetApp() {
        signOut()                                   // identity, conversations, attachments, vault, session
        contactStore.removeAll()
        try? FileManager.default.removeItem(at: AttachmentStore.directory)

        let defaults = UserDefaults.standard
        for key in defaults.dictionaryRepresentation().keys where key.hasPrefix("cp.") {
            defaults.removeObject(forKey: key)
        }
        appLock.appLockEnabled = false
        appLanguage = "en"
        onboardingComplete = false
    }

    var isReady: Bool { store != nil }

    // MARK: - Identity

    /// Install a new identity (from onboarding, import, or pairing), persist it,
    /// and stand up the messaging stack around it.
    func setIdentity(_ identity: Identity) {
        // Stop the previous account's poll loop before switching the stack over.
        store?.stop()
        do {
            try identityStore.save(identity)
        } catch {
            lastError = "identity save failed"
        }
        self.identity = identity
        // A fresh/unprotected identity must not inherit the previous account's
        // session passphrase; a protected one (import/restore) had its passphrase
        // set by the caller before this call.
        if !identity.protected { appLock.clearSessionPassphrase() }
        loadProfileName()
        loadPendingInvites()
        buildStore(for: identity)
        // Adding an account happens past onboarding, so bring the new account live
        // now. During first-run this stays false until completeOnboarding() starts it.
        if onboardingComplete { Task { await start() } }
    }

    // MARK: - Profile

    private func profileKey(_ identity: Identity) -> String {
        "cp.profile.\(identity.fingerprint.hex)"
    }

    private func loadProfileName() {
        guard let identity else { profileName = nil; return }
        profileName = UserDefaults.standard.string(forKey: profileKey(identity))
    }

    /// Set your own display name (nil/empty = anonymous). Persists per-identity
    /// and pushes the change to existing contacts as an encrypted profile message.
    func setProfileName(_ name: String?) {
        guard let identity else { return }
        let trimmed = name?.trimmingCharacters(in: .whitespacesAndNewlines)
        let value = (trimmed?.isEmpty == false) ? trimmed : nil
        profileName = value
        if let value {
            UserDefaults.standard.set(value, forKey: profileKey(identity))
        } else {
            UserDefaults.standard.removeObject(forKey: profileKey(identity))
        }
        let toNotify = contactStore.contacts
        Task { [weak self] in
            for contact in toNotify {
                await self?.store?.sendProfile(name: value, to: contact)
            }
        }
    }

    /// Generate a fresh identity, persist it, and go live. From 4.0 a new
    /// identity is OpenPGP v6: an Ed25519 primary key that certifies and signs,
    /// and one ML-KEM-768 + X25519 subkey for encryption. Identities made
    /// before 4.0 stay v4 and keep working. Key generation runs off the main
    /// actor; the resulting identity is installed on the main actor.
    func createIdentity(name: String, email: String) async throws {
        let generated = try await Task.detached(priority: .userInitiated) {
            try OpenPGPKeyGenerator.generateV6Identity(name: name, email: email)
        }.value
        guard let fingerprint = Fingerprint(generated.fingerprint) else {
            throw IdentityCreationError.invalidFingerprint
        }
        setIdentity(Identity(
            fingerprint: fingerprint,
            secretKey: generated.secretKey,
            armoredPublicKey: generated.armoredPublicKey
        ))
        setProfileName(name)
    }

    // MARK: - Multiple accounts

    struct AccountSummary: Identifiable {
        let fingerprint: Fingerprint
        let name: String?
        var id: String { fingerprint.hex }
    }

    /// Fingerprint and display name for each stored account, for the switcher.
    func accounts() -> [AccountSummary] {
        identityStore.list().compactMap { hex in
            Fingerprint(hex).map { AccountSummary(fingerprint: $0, name: UserDefaults.standard.string(forKey: "cp.profile.\(hex)")) }
        }
    }

    var activeFingerprintHex: String? { identity?.fingerprint.hex }

    /// Switch the active account, rebuilding the messaging stack around it.
    func switchAccount(_ fprHex: String) {
        guard fprHex != identity?.fingerprint.hex else { return }
        let next: Identity?
        do { next = try identityStore.load(fprHex) } catch { next = nil }
        guard let next else { return }
        store?.stop()
        identityStore.setSelected(fprHex)
        identity = next
        // Drop the previous account's session passphrase.
        appLock.clearSessionPassphrase()
        loadProfileName()
        loadPendingInvites()
        buildStore(for: next)
        // A protected account under App Lock keeps its passphrase behind
        // biometrics, so present the lock screen to re-authenticate before its
        // key is used; otherwise start now (unprotected, or lock off, where
        // start() reloads the passphrase silently).
        if next.protected && appLock.appLockEnabled {
            appLock.lockNow()
        } else {
            Task { await start() }
        }
    }

    /// Remove an account and erase its local data (messages, contacts, sealed
    /// keys, pending invites, profile, wake token). If it was the active account,
    /// switch to the next remaining one; if none remain, return to onboarding.
    func removeAccount(_ fprHex: String) {
        let isActive = fprHex == identity?.fingerprint.hex
        if isActive {
            // The live store owns this identity's sealed keys and conversations;
            // purge() wipes them (using the currently-active sealed scope).
            store?.stop()
            store?.purge()
        } else {
            // A non-active account has no live store, so purge its own sealed store.
            SealedKeyStore(identityHex: fprHex).purge()
            let dir = (try? FileManager.default.url(
                for: .applicationSupportDirectory, in: .userDomainMask,
                appropriateFor: nil, create: true
            )) ?? FileManager.default.temporaryDirectory
            try? FileManager.default.removeItem(at: dir.appendingPathComponent("carrierpony-conversations-\(fprHex).json"))
        }
        contactStore.deleteFile(fprHex)
        contactRequests.deleteFile(fprHex)
        PassphraseVault.delete(fingerprint: fprHex)
        UserDefaults.standard.removeObject(forKey: "cp.profile.\(fprHex)")
        UserDefaults.standard.removeObject(forKey: "cp.pendinginvites.\(fprHex)")
        AppConfig.setStoredWakeToken(nil, for: fprHex)
        let newSelected = identityStore.delete(fprHex)
        guard isActive else { return }
        if let newSelected, let next = try? identityStore.load(newSelected) {
            identity = next
            appLock.clearSessionPassphrase()
            loadProfileName()
            loadPendingInvites()
            buildStore(for: next)
            if next.protected && appLock.appLockEnabled {
                appLock.lockNow()
            } else {
                Task { await start() }
            }
        } else {
            appLock.clearSessionPassphrase()
            resetToOnboardingState()
        }
    }

    private func resetToOnboardingState() {
        onboardingComplete = false
        UserDefaults.standard.set(false, forKey: "cp.onboarded")
        identity = nil
        store = nil
        relay = nil
        profileName = nil
        pendingInvites = []
        completedInviteContacts = [:]
    }

    func signOut() {
        if let identity, identity.protected {
            PassphraseVault.delete(fingerprint: identity.fingerprint.hex)
        }
        store?.stop()
        store?.purge()
        identityStore.deleteAll()
        appLock.clearSessionPassphrase()
        if let identity {
            UserDefaults.standard.removeObject(forKey: pendingInvitesKey(identity))
        }
        pendingInvites = []
        completedInviteContacts = [:]
        identity = nil
        store = nil
        relay = nil
    }

    // MARK: - Import an existing key

    /// Adopt an imported identity. A protected key keeps its passphrase behind the
    /// biometric vault and turns on the app lock; the passphrase is held for this
    /// session so messaging works immediately.
    func adoptImportedIdentity(_ identity: Identity, passphrase: String?) async throws {
        if identity.protected, let passphrase, !passphrase.isEmpty {
            guard PassphraseVault.store(passphrase, fingerprint: identity.fingerprint.hex) else {
                throw KeyImportError.malformed
            }
            appLock.setSessionPassphrase(passphrase)
            appLock.appLockEnabled = true
        }
        setIdentity(identity)
        // Seed the display name from the key's User ID so an imported identity
        // isn't anonymous by default (mirrors how a generated identity takes the
        // onboarding name). The user can still edit or clear it later.
        if profileName == nil, let uidName = KeyImport.userIDName(fromSecretKey: identity.secretKey) {
            setProfileName(uidName)
        }
    }

    // MARK: - App lock

    // MARK: - Push

    /// Register for contentless push: hand any APNs token to the relay, and ask
    /// the system for permission. Safe to call repeatedly.
    ///
    /// Call this only after the device is registered with the relay (see start()).
    /// register-push is keyed by device_id, so submitting a token for a device the
    /// relay has never seen fails, and the failure used to be swallowed with no
    /// retry until the next launch.
    func enablePush() {
        PushService.shared.onToken = { [weak self] token in
            Task { [weak self] in await self?.submitPushToken(token) }
        }
        PushService.shared.onPush = { [weak self] in
            await self?.store?.refresh()
        }
        let wantPush = !AppConfig.usingCustomRelay || AppConfig.gatewayPushEnabled
        if wantPush {
            if let token = PushService.shared.token {
                Task { await submitPushToken(token) }
            }
            PushService.shared.requestAndRegister()
        }
    }

    /// Hand a token to the relay, surfacing a failure instead of discarding it.
    /// A silently dropped registration means no notifications for the life of the
    /// install, with nothing anywhere to say so.
    private func submitPushToken(_ token: String) async {
        // On a custom relay the gateway is the user's own opt-in choice, so their
        // token never reaches the default gateway unasked.
        if AppConfig.usingCustomRelay {
            if AppConfig.gatewayPushEnabled {
                await registerWithGateway(token: token)
            }
            return
        }
        // Default relay: every device registers with the gateway so it gets a
        // sealed wake token and can be woken in the background (the relay can't
        // push a sealed message itself). Also keep the fingerprint-keyed push for
        // any remaining legacy delivery.
        await registerWithGateway(token: token)
        guard let relay else { return }
        do {
            try await relay.registerPush(token: token)
        } catch {
            // Push registration retries on the next foreground; polling covers
            // delivery meanwhile, so don't raise the inbox banner.
        }
    }

    /// Register the push token with the gateway, store the wake token it returns,
    /// and hand that wake token to the custom relay so it can nudge the gateway.
    private func registerWithGateway(token: String) async {
        guard let relay else { return }
        do {
            // Register the ACTIVE account's sealed device with the gateway, so each
            // account gets its OWN wake token; a shared token would let the relay
            // link the accounts.
            let wake = try await GatewayClient.registerPush(
                deviceID: store?.sealedDeviceId() ?? AppConfig.deviceID, token: token, platform: "apns"
            )
            AppConfig.setStoredWakeToken(wake, for: identity?.fingerprint.hex)
            try await relay.registerWake(wakeToken: wake)
            // Attach the wake token to the sealed device now, rather than waiting
            // for the next app start, so background sealed pushes work from the
            // first session (the token arrives async, after the sealed device was
            // first registered with an empty token).
            await store?.sealedReregisterDevice()
        } catch {
            // Gateway registration retries on the next foreground; no banner.
        }
    }

    /// Turn gateway push on or off (the custom-relay opt-in). On enable it
    /// registers the current token (or requests one); on disable it deregisters
    /// from the gateway and clears the wake token on the relay.
    func setGatewayPush(_ on: Bool) {
        AppConfig.gatewayPushEnabled = on
        if on {
            if let token = PushService.shared.token {
                Task { await submitPushToken(token) }
            } else {
                PushService.shared.requestAndRegister()
            }
        } else {
            Task { await disableGateway() }
        }
    }

    private func disableGateway() async {
        let fpr = identity?.fingerprint.hex
        let wake = AppConfig.storedWakeToken(for: fpr)
        AppConfig.setStoredWakeToken(nil, for: fpr)
        if let wake { await GatewayClient.deregister(wakeToken: wake) }
        try? await relay?.registerWake(wakeToken: "")
    }

    private func describePush(_ error: Error) -> String {
        if let relayError = error as? RelayError {
            return "relay \(relayError.status)\(relayError.code.map { ": \($0)" } ?? "")"
        }
        return error.localizedDescription
    }

    func lockForBackground() {
        appLock.lockIfEnabled()
    }

    /// Attempt to unlock (biometrics/passcode). Returns true on success.
    @discardableResult
    func unlock() async -> Bool {
        await appLock.unlock(
            fingerprint: identity?.fingerprint.hex,
            protected: identity?.protected ?? false
        )
    }

    // MARK: - Backup / restore

    /// Produce an armored, passphrase-protected backup of the current identity.
    func exportBackup(passphrase: String) async throws -> String {
        guard let identity else { throw BackupError.noIdentity }
        return try await Task.detached(priority: .userInitiated) {
            try IdentityBackup.export(identity, passphrase: passphrase)
        }.value
    }

    /// Restore an identity from a passphrase-protected backup blob and adopt it.
    func importBackup(_ blob: String, passphrase: String) async throws {
        let restored = try await Task.detached(priority: .userInitiated) {
            try IdentityBackup.restore(blob, passphrase: passphrase)
        }.value
        setIdentity(restored)
    }

    // MARK: - Pairing (over the relay)

    /// Publish a pairing offer and return an invite to share out-of-band. The
    /// invite carries your display name (if set) so the other side sees it.
    /// App Review demo: create a simulated local contact and seed a welcome
    /// message. Uses no network. See DemoMode.
    func startDemo() -> Contact? {
        guard let identity else { return nil }
        let contact = Contact(
            fingerprint: DemoMode.fingerprint,
            publicKey: PublicKey(fingerprint: DemoMode.fingerprint, armored: identity.armoredPublicKey),
            name: DemoMode.peerName,
            trust: .verified
        )
        contactStore.add(contact)
        store?.injectDemoIncoming(text: "Welcome to the CarrierPony demo. Send me a message, or attach a file, and I'll reply. Everything here is encrypted and decrypted on this device. You can also open the ••• menu to try Report and Block.")
        return contact
    }

    /// Publish a pairing offer and remember it, so acceptance completes on this
    /// side even after the invite screen closes: the pending list is swept on
    /// every inbox refresh and at the next launch. Both the in-person live QR
    /// (inPerson: true, completes verified) and the remote invite use this, so
    /// the offerer never half-pairs by dismissing before the peer's scan lands.
    func createRememberedInvite(inPerson: Bool = false) async throws -> (invite: Invite, expiresAt: Date?) {
        guard let identity, let relay else { throw PairingError.notReady }
        let response = try await relay.pairOffer(pubkey: identity.armoredPublicKey)
        let expiresAt: Date? = response.expiresIn > 0
            ? Date(timeIntervalSinceNow: TimeInterval(response.expiresIn))
            : nil
        pendingInvites.append(PendingInvite(
            token: response.token,
            name: profileName,
            createdAt: Date(),
            expiresAt: expiresAt,
            inPerson: inPerson
        ))
        savePendingInvites()
        return (Invite(token: response.token, fingerprint: identity.fingerprint, name: profileName), expiresAt)
    }

    /// Poll an outstanding invite this identity created. Returns the newly paired
    /// contact once the peer accepts, or nil while still waiting.
    func pollInvite(_ invite: Invite) async throws -> Contact? {
        if let already = completedInviteContacts[invite.t] { return already }
        guard let relay else { throw PairingError.notReady }
        let status = try await relay.pairStatus(token: invite.t)
        guard status.state == "accepted",
              let responderFpr = status.responderFpr,
              let responderPubkey = status.responderPubkey else {
            if status.state == "expired" { forgetPendingInvite(token: invite.t) }
            return nil
        }
        return try await finishAcceptedInvite(token: invite.t, responderFpr: responderFpr, responderPubkey: responderPubkey)
    }

    /// Complete this (the offerer's) side of an accepted invite exactly once:
    /// add the responder, drop the pending entry, and send our profile. Keyed by
    /// token so the on-screen poll loop and the background sweep can't both act
    /// on the same acceptance; everything before the await runs as one main-actor
    /// block, so a second caller sees the completed entry and returns early.
    private func finishAcceptedInvite(token: String, responderFpr: String, responderPubkey: String) async throws -> Contact? {
        if let already = completedInviteContacts[token] { return already }
        // An in-person live invite was exchanged face to face, so the responder's
        // key is trusted and the contact is added verified. A remote invite has no
        // out-of-band anchor for the responder's key on this side, so it is
        // trust-on-first-use: added unverified, upgraded later by safety number.
        let inPerson = pendingInvites.first { $0.token == token }?.inPerson ?? false
        let trust: TrustLevel = inPerson ? .verified : .unverified
        guard let contact = Self.consistentContact(fprHex: responderFpr, armoredPub: responderPubkey, trust: trust) else {
            forgetPendingInvite(token: token)
            throw PairingError.keyMismatch
        }
        completedInviteContacts[token] = contact
        contactStore.add(contact)
        if inPerson { contactStore.markVerified(contact.fingerprint) }
        forgetPendingInvite(token: token)
        await store?.sendCaps(to: contact)
        await store?.sendProfile(name: profileName, to: contact)
        return contact
    }

    // MARK: - Telling contacts what this app supports

    @ObservationIgnored private var capsAnnouncing = false

    private func capsAnnouncedKey(_ identity: Identity) -> String {
        "cp.capsannounced.\(identity.fingerprint.hex).\(PairingCaps.current.joined(separator: "+"))"
    }

    /// Contacts paired before this build never heard what it supports: caps
    /// travel in invites and at pairing, and theirs came from an older app. So
    /// each contact is told once, in a silent control message an older app
    /// ignores. Runs with the inbox refresh, so it only happens while online.
    /// A contact whose message could not be handed off is tried again on a
    /// later refresh; the ones already told are remembered and not told twice.
    /// The key includes the caps, so a later build that supports more
    /// announces again.
    private func announceCapsIfNeeded(_ identity: Identity) async {
        let key = capsAnnouncedKey(identity)
        let told = Set(UserDefaults.standard.stringArray(forKey: key) ?? [])
        let pending = contactStore.contacts.filter { !told.contains($0.fingerprint.hex) }
        guard !pending.isEmpty, let store, !capsAnnouncing else { return }
        capsAnnouncing = true
        defer { capsAnnouncing = false }
        var nowTold = told
        for contact in pending {
            if await store.sendCaps(to: contact) { nowTold.insert(contact.fingerprint.hex) }
        }
        // Only if this is still the active account: its contact list is the one that was read.
        if nowTold.count != told.count, self.identity?.fingerprint == identity.fingerprint {
            UserDefaults.standard.set(Array(nowTold).sorted(), forKey: key)
        }
    }

    /// Check every remembered invite against the relay. Runs from the inbox
    /// refresh cycle, before messages are processed, so a new contact's first
    /// messages open cleanly on the same pass that discovers their acceptance.
    /// Throttled: pending invites can outlive a session by days, and each check
    /// costs a challenge round trip per invite.
    func sweepPendingInvites() async {
        guard let identity, relay != nil else { return }
        await announceCapsIfNeeded(identity)
        guard !pendingInvites.isEmpty else { return }
        guard Date().timeIntervalSince(lastPendingSweep) >= 30 else { return }
        lastPendingSweep = Date()
        for pending in pendingInvites {
            // Past its expiry an offer may still have been ACCEPTED while this app
            // was closed, so keep asking the relay (which keeps accepted offers for
            // a completion window) and only give up after the grace period.
            if PairingRetention.isStale(pending) {
                forgetPendingInvite(token: pending.token)
                continue
            }
            if pending.relayGone ?? false { continue }
            do {
                _ = try await pollInvite(pending.invite(fingerprint: identity.fingerprint))
            } catch let error as RelayError where (400..<500).contains(error.status) {
                // The relay no longer knows the token. Stop polling but keep it for
                // the grace window: the responder's pair-complete op can still
                // finish the pairing from the inbox.
                markPendingRelayGone(token: pending.token)
            } catch is PairingError {
                // A mismatched key can never become valid for this token.
                forgetPendingInvite(token: pending.token)
            } catch {
                // Transient (offline, relay 5xx): keep the invite for next sweep.
            }
        }
    }

    private func pendingInvitesKey(_ identity: Identity) -> String {
        "cp.pendinginvites.\(identity.fingerprint.hex)"
    }

    private func loadPendingInvites() {
        guard let identity else { pendingInvites = []; return }
        if let data = UserDefaults.standard.data(forKey: pendingInvitesKey(identity)),
           let stored = try? JSONDecoder().decode([PendingInvite].self, from: data) {
            pendingInvites = stored
        } else {
            pendingInvites = []
        }
    }

    private func savePendingInvites() {
        guard let identity else { return }
        if pendingInvites.isEmpty {
            UserDefaults.standard.removeObject(forKey: pendingInvitesKey(identity))
        } else if let data = try? JSONEncoder().encode(pendingInvites) {
            UserDefaults.standard.set(data, forKey: pendingInvitesKey(identity))
        }
    }

    private func forgetPendingInvite(token: String) {
        guard pendingInvites.contains(where: { $0.token == token }) else { return }
        pendingInvites.removeAll { $0.token == token }
        savePendingInvites()
    }

    private func markPendingRelayGone(token: String) {
        guard let i = pendingInvites.firstIndex(where: { $0.token == token }),
              !(pendingInvites[i].relayGone ?? false) else { return }
        pendingInvites[i].relayGone = true
        savePendingInvites()
    }

    /// Offerer side, from the responder's pair-complete op (ChatStore's
    /// decrypt-only bootstrap). Adds the contact only for a token this identity
    /// issued and still holds, with the same trust the relay path would give.
    /// Called synchronously from inside the store's receive path, so the profile
    /// reply is sent from a Task rather than awaited here.
    func completeInviteFromPeer(token: String, responderPubkey: String) -> Bool {
        guard let identity,
              let pending = pendingInvites.first(where: { $0.token == token }),
              let fpr = OpenPGPKeyID.primaryFingerprint(armoredPublicKey: responderPubkey) else { return false }
        let inPerson = pending.inPerson ?? false
        guard let contact = Self.consistentContact(fprHex: fpr, armoredPub: responderPubkey, trust: inPerson ? .verified : .unverified),
              contact.fingerprint != identity.fingerprint else { return false }
        completedInviteContacts[token] = contact
        contactStore.add(contact)
        if inPerson { contactStore.markVerified(contact.fingerprint) }
        forgetPendingInvite(token: token)
        let name = profileName
        Task { [weak self] in
            await self?.store?.sendCaps(to: contact)
            await self?.store?.sendProfile(name: name, to: contact)
        }
        return true
    }

    /// Accept an invite: fetch the offerer's key and require it to match the
    /// fingerprint carried in the invite before adding the contact. A mismatch is
    /// a hard failure — we never add a contact whose key doesn't match.
    func acceptInvite(_ invite: Invite, trust: TrustLevel = .unverified) async throws -> Contact {
        guard let identity, let relay else { throw PairingError.notReady }
        guard let invitedFpr = invite.fingerprint else { throw PairingError.malformedInvite }
        // Checked before the relay is asked, so a refused invite keeps its
        // one-time token and still works once the other person has updated.
        guard PairingCaps.canPair(mine: identity.fingerprint, peer: invitedFpr, peerCaps: invite.c) else {
            throw PairingError.peerNeedsUpdate
        }
        let response = try await relay.pairAccept(token: invite.t, pubkey: identity.armoredPublicKey)
        guard response.offererFpr.uppercased() == invitedFpr.hex,
              let contact = Self.consistentContact(fprHex: invitedFpr.hex, armoredPub: response.offererPubkey, trust: trust) else {
            throw PairingError.keyMismatch
        }
        var named = contact
        named.name = invite.n
        // The invite says what the offerer's app supports; keep it with the contact.
        named.caps = invite.c
        contactStore.add(named)
        store?.setAwaiting(named.fingerprint, true)
        // The offerer only learns of this accept when its app next sweeps the
        // relay; the pair-complete op also lets it finish from its inbox. Sent
        // first so it is processed before the profile and any message after it.
        await store?.sendPairComplete(token: invite.t, to: named)
        await store?.sendCaps(to: named)
        await store?.sendProfile(name: profileName, to: named)
        return named
    }

    /// Add a contact from a public key they handed over as text or as a file,
    /// and ask them to add this identity back.
    ///
    /// The request is sent before anything is stored. The relay refuses a
    /// deposit to a fingerprint with no account, which is the only way to learn
    /// that the key belongs to nobody on this relay, and a contact who can
    /// never be reached is not worth keeping. The contact is added unverified:
    /// the key arrived over whatever channel the text did, so the safety number
    /// is what confirms it. Until they accept, they are shown as waiting.
    func addContactByKey(_ input: Data) async -> AddByKeyResult {
        guard let identity, let store else { return .notReady }
        let key: ContactKey.Usable
        switch ContactKey.inspect(input) {
        case .usable(let usable): key = usable
        case .secretKey: return .secretKey
        case .notAKey: return .notAKey
        case .unsupported: return .unsupported
        }
        guard var contact = Self.consistentContact(fprHex: key.fingerprint.hex, armoredPub: key.armoredPublicKey, trust: .unverified) else {
            return .notAKey
        }
        contact.name = key.name
        if contact.fingerprint == identity.fingerprint { return .ownKey }
        if let existing = contactStore.contact(contact.fingerprint) { return .alreadyContact(existing) }
        // Adding someone's key yourself overrides having declined them, and if
        // their request is already waiting here, this is the same as accepting it.
        contactRequests.clearDeclined(contact.fingerprint)
        if let waiting = contactRequests.requests.first(where: { $0.fingerprint == contact.fingerprint }) {
            do {
                return .added(try await acceptContactRequest(waiting))
            } catch PairingError.peerNeedsUpdate {
                return .unsupported
            } catch {
                return .notReady
            }
        }
        do {
            try await store.sendContactRequest(name: profileName, to: contact)
        } catch let error as RelayError {
            return error.status == 404 ? .notOnRelay : .couldNotSend
        } catch {
            return .couldNotSend
        }
        // Still the same account as when the request went out.
        guard self.identity?.fingerprint == identity.fingerprint else { return .notReady }
        contactStore.add(contact)
        store.setAwaiting(contact.fingerprint, true)
        await store.sendCaps(to: contact)
        await store.sendProfile(name: profileName, to: contact)
        return .added(contact)
    }

    /// Accept a contact request: add the person, unverified, and tell them
    /// about this app and this identity's name. Their first envelope that opens
    /// clears the waiting mark on their side. A v6 identity holds the same line
    /// as when pairing: it does not add someone whose app could not add it
    /// back. The request says what their app supports.
    @discardableResult
    func acceptContactRequest(_ request: ContactRequest) async throws -> Contact {
        guard let identity else { throw PairingError.notReady }
        guard PairingCaps.canPair(mine: identity.fingerprint, peer: request.fingerprint, peerCaps: request.caps) else {
            throw PairingError.peerNeedsUpdate
        }
        guard var contact = Self.consistentContact(fprHex: request.fingerprint.hex, armoredPub: request.armoredPublicKey, trust: .unverified) else {
            contactRequests.remove(request.fingerprint)
            throw PairingError.keyMismatch
        }
        contact.name = request.name
        contact.caps = request.caps
        contactStore.add(contact)
        contactRequests.remove(request.fingerprint)
        await store?.sendCaps(to: contact)
        await store?.sendProfile(name: profileName, to: contact)
        // What they sent while waiting could not open; it does now that they are a contact.
        Task { [weak self] in await self?.store?.refresh() }
        return contact
    }

    /// Decline a contact request. Nothing is sent; the same person asking
    /// again is ignored from now on.
    func declineContactRequest(_ request: ContactRequest) {
        contactRequests.decline(request.fingerprint)
    }

    /// Build a Contact only if the armored key actually hashes to the claimed
    /// fingerprint. Returns nil on a malformed key or any mismatch.
    private static func consistentContact(fprHex: String, armoredPub: String, trust: TrustLevel) -> Contact? {
        guard let fingerprint = Fingerprint(fprHex),
              let computed = OpenPGPKeyID.primaryFingerprint(armoredPublicKey: armoredPub),
              computed.uppercased() == fingerprint.hex else {
            return nil
        }
        return Contact(
            fingerprint: fingerprint,
            publicKey: PublicKey(fingerprint: fingerprint, armored: armoredPub),
            name: nil,
            trust: trust
        )
    }

    // MARK: - Assembly

    private func buildStore(for identity: Identity) {
        // A per-account sealed store: its device and pair state are namespaced by
        // this identity (migrating the pre-account state on first run).
        let sealedKeys = SealedKeyStore(identityHex: identity.fingerprint.hex)
        // Load this identity's contacts (per-account file).
        self.contactStore.activate(identity.fingerprint.hex)
        self.contactRequests.activate(identity.fingerprint.hex)
        let contactStore = self.contactStore
        let crypto = PGPonyCryptoEngine(
            fingerprint: identity.fingerprint,
            secretKey: identity.secretKey,
            armoredPublicKey: identity.armoredPublicKey,
            publicKeyData: { fingerprint in
                // Runs on the main actor (the store invokes crypto synchronously
                // from its own @MainActor methods); make that explicit so it holds
                // under strict concurrency. Resolve our own key for self-copy
                // verification, else a contact.
                MainActor.assumeIsolated {
                    if fingerprint == identity.fingerprint {
                        return PGPArmor.dearmor(identity.armoredPublicKey)
                    }
                    return contactStore.publicKeyData(fingerprint)
                }
            },
            passphrase: { [weak self] in
                // Only a protected key needs a passphrase; handing a stale one to
                // an unprotected key (e.g. a freshly created second account) makes
                // the OpenPGP core reject it and breaks signing/pairing.
                MainActor.assumeIsolated { identity.protected ? self?.appLock.sessionPassphrase : nil }
            },
            signerKeys: {
                MainActor.assumeIsolated {
                    (contactStore.contacts.map(\.publicKey.armored) + [identity.armoredPublicKey])
                        .compactMap { PGPArmor.dearmor($0) }
                }
            }
        )
        let relay = RelayClient(
            baseURL: AppConfig.relayBaseURL,
            crypto: crypto,
            deviceID: AppConfig.deviceID
        )
        self.relay = relay
        store = ChatStore(
            identity: identity.fingerprint,
            relay: relay,
            crypto: crypto,
            sealedKeys: sealedKeys,
            contacts: { contactStore.contacts },
            pairingSweep: { [weak self] in await self?.sweepPendingInvites() },
            updatePeerName: { fingerprint, name in
                MainActor.assumeIsolated {
                    contactStore.setName(fingerprint, name: name)
                }
            },
            updatePeerCaps: { fingerprint, caps in
                MainActor.assumeIsolated {
                    contactStore.setCaps(fingerprint, caps: caps)
                }
            },
            addContact: { contact in
                MainActor.assumeIsolated { contactStore.add(contact) }
            },
            lanTransport: LanDirectTransport(discovery: lanDiscovery),
            wanTransport: WanDirectTransport(bridge: wanBridge),
            nostrTransport: NostrTransport(manager: nostrManager),
            nostrSubscribe: { [weak self] addresses in
                Task { @MainActor in self?.nostrManager.subscribe(addresses: addresses) }
            },
            pairComplete: { [weak self] token, pubkey in
                MainActor.assumeIsolated { self?.completeInviteFromPeer(token: token, responderPubkey: pubkey) ?? false }
            },
            contactRequest: { [weak self] fingerprint, armored, name, caps in
                MainActor.assumeIsolated {
                    self?.contactRequests.add(ContactRequest(
                        fingerprint: fingerprint, armoredPublicKey: armored, name: name, caps: caps,
                        receivedAt: Int(Date().timeIntervalSince1970)
                    )) ?? false
                }
            }
        )
        store?.onSignal = { [weak self] peerHex, op, sdp, candidate in
            guard let self else { return }
            self.wanSignalsReceived += 1
            let shortHex = String(peerHex.suffix(8))
            self.lastWanSignal = "\(op) from \(shortHex)"
            self.wanBridge.handleIncoming(peerHex: peerHex, op: op, sdp: sdp, candidate: candidate)
        }
        wanBridge.sendOp = { [weak self] op, peer, sdp, candidate in
            Task { @MainActor in
                await self?.store?.sendWanSignal(op: op, toPeerHex: peer, sdp: sdp, candidate: candidate)
            }
        }
        wanBridge.onConnectedChange = { [weak self] count in
            Task { @MainActor in self?.wanConnectedCount = count }
        }
        wanBridge.onPayload = { [weak self] _, data in
            Task { @MainActor in self?.store?.ingestLanEnvelope(data) }
        }
        nostrManager.onNostrEvent = { [weak self] mailbox, content in
            Task { @MainActor in self?.store?.ingestNostrEnvelope(mailbox: mailbox, content: content) }
        }
    }

    // MARK: - Lifecycle

    /// Bring the messaging stack up. Push registration runs last and only after
    /// store.start() has registered this device with the relay, since register-push
    /// is rejected for an unknown device_id. This also gives push registration a
    /// retry on every foreground, which it previously never had.
    func start() async {
        #if DEBUG
        // Screenshot demo data (DemoSeed) never touches a relay.
        if DemoSeed.isActive { return }
        #endif
        loadSessionPassphraseIfLockDisabled()
        await store?.start()
        guard identity != nil, onboardingComplete else { return }
        enablePush()
        startOtherAccountPolling()
        lanDiscovery.keyProvider = { [weak self] in self?.store?.lanContactKeys() ?? [:] }
        lanDiscovery.onEnvelope = { [weak self] data in self?.store?.ingestLanEnvelope(data) }
        lanDiscovery.start()
        // Bring up WAN direct if it was left enabled: the toggle's onChange is the only
        // other caller, so without this an app that launches (or updates) with the
        // switch already on never sets up the transport. Idempotent on each foreground.
        if AppConfig.wanDirectEnabled { setWanDirectEnabled(true) }
        if AppConfig.nostrEnabled { setNostrEnabled(true) }
    }

    /// For a protected identity with App Lock off, there is no unlock moment to
    /// load the passphrase, so read it silently at launch. The vault entry is
    /// stored without user-presence in that posture, so this needs no prompt.
    private func loadSessionPassphraseIfLockDisabled() {
        guard let identity, identity.protected,
              !appLock.appLockEnabled, appLock.sessionPassphrase == nil else { return }
        appLock.setSessionPassphrase(PassphraseVault.readSilently(fingerprint: identity.fingerprint.hex))
    }

    /// Route the App Lock toggle through here so the vault entry's access policy
    /// tracks the lock state: user-presence when on, silent-readable when off.
    /// Turning off also loads the passphrase now, since no unlock will follow.
    /// Toggle LAN-direct (2.1). Off by default; on lets the app identify known
    /// contacts on the local network (and, once M3b lands, deliver to them
    /// directly, exposing this device's IP to that contact).
    func setLanDirectEnabled(_ enabled: Bool) {
        AppConfig.lanDirectEnabled = enabled
        lanDiscovery.lanDidToggle()
    }

    /// Toggle WAN-direct (2.2). M1: enabling it fires a synthetic signaling round
    /// trip to each sealed-capable contact so the offer/answer/ice control-op path
    /// can be verified over the relay before the WebRTC dependency lands.
    func setWanDirectEnabled(_ enabled: Bool) {
        AppConfig.wanDirectEnabled = enabled
        guard enabled else {
            wanBridge.disable()
            wanConnectedCount = 0
            return
        }
        guard let store, let identity else { return }
        let keys = store.lanContactKeys()
        wanBridge.updateKeys(keys)
        wanBridge.selfHex = identity.fingerprint.hex.lowercased()
        let host = AppConfig.wanStunHost.isEmpty
            ? (URLComponents(string: AppConfig.relayBaseURL)?.host ?? "")
            : AppConfig.wanStunHost
        guard !host.isEmpty,
              wanBridge.enable(stunHost: host, stunPort: UInt16(AppConfig.wanStunPort)) else { return }
        // The transport is up and can answer incoming offers. Outbound paths open
        // lazily on first activity with a peer (WanDirectBridge.canReach), so we do
        // not fan out a handshake to every contact the moment WAN is enabled.
    }

    /// Toggle the Nostr transport (2.3). Off by default. When on, connect to the
    /// configured Nostr relays so each message is also posted to the peer's sealed
    /// mailbox address there, giving delivery a path independent of the CarrierPony
    /// relay. Third-party relays see opaque content under a rotating tag and this
    /// device's IP.
    func setNostrEnabled(_ enabled: Bool) {
        AppConfig.nostrEnabled = enabled
        if enabled {
            nostrManager.start(relayURLs: AppConfig.nostrRelayURLs)
        } else {
            nostrManager.stop()
        }
    }

    /// Persist a new Nostr relay set. If Nostr is on, restart the manager on the new
    /// set (an empty set stops it, since there is nowhere to post).
    func setNostrRelays(_ relays: [String]) {
        AppConfig.nostrRelays = relays
        if AppConfig.nostrEnabled {
            if relays.isEmpty {
                nostrManager.stop()
            } else {
                nostrManager.start(relayURLs: AppConfig.nostrRelayURLs)
            }
        }
    }

    /// Recover sealed delivery if it desynced (e.g. a contact reinstalled): regenerate
    /// this account's sealed keys and re-sync with contacts.
    func resyncSealed() {
        Task { await store?.resyncSealedKeys() }
    }

    /// Same recovery as resyncSealed, awaited so the caller can show progress and a
    /// result. Suspends until the regenerate, window refresh and inbox poll finish.
    func resyncSealedAwait() async {
        await store?.resyncSealedKeys()
    }

    func setAppLockEnabled(_ enabled: Bool) {
        appLock.appLockEnabled = enabled
        guard let identity, identity.protected else { return }
        if appLock.sessionPassphrase == nil {
            appLock.setSessionPassphrase(PassphraseVault.readSilently(fingerprint: identity.fingerprint.hex))
        }
        if let passphrase = appLock.sessionPassphrase {
            _ = PassphraseVault.store(passphrase, fingerprint: identity.fingerprint.hex, requireUserPresence: enabled)
        }
    }

    func stop() {
        store?.stop()
        otherPollTask?.cancel()
        otherPollTask = nil
        lanDiscovery.stop()
    }

    // MARK: - Background delivery for non-active accounts

    /// While foreground, poll every OTHER account's inbox on a slow cadence so a
    /// message to a non-active account is received (persisted to that account's
    /// conversations) and its unread count surfaces in the switcher, and its
    /// outstanding pairing offers complete, without switching to it first.
    private func startOtherAccountPolling() {
        otherPollTask?.cancel()
        guard identityStore.list().count > 1 else { accountUnread = [:]; return }
        otherPollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.pollOtherAccounts()
                try? await Task.sleep(nanoseconds: 20_000_000_000)
            }
        }
    }

    private func pollOtherAccounts() async {
        let activeHex = identity?.fingerprint.hex
        let others = identityStore.list().filter { $0 != activeHex }
        guard !others.isEmpty else { accountUnread = [:]; return }
        var unread: [String: Int] = [:]
        for fprHex in others {
            guard let id = try? identityStore.load(fprHex) else { continue }
            // A protected account needs a passphrase we don't hold in the
            // background, so skip it; it syncs when the user switches to it.
            if id.protected { continue }
            if let count = await pollAccountOnce(id) { unread[fprHex] = count }
        }
        accountUnread = unread
    }

    /// Build a throwaway stack for one account, finish its pending pairing offers,
    /// poll its inbox once (receiving and persisting new messages, keeping its
    /// sealed mailboxes registered so senders reach it while backgrounded), and
    /// return its unread count.
    private func pollAccountOnce(_ id: Identity) async -> Int? {
        let tContacts = ContactStore()
        tContacts.activate(id.fingerprint.hex)
        let sealedKeys = SealedKeyStore(identityHex: id.fingerprint.hex)
        let crypto = PGPonyCryptoEngine(
            fingerprint: id.fingerprint,
            secretKey: id.secretKey,
            armoredPublicKey: id.armoredPublicKey,
            publicKeyData: { fingerprint in
                MainActor.assumeIsolated {
                    if fingerprint == id.fingerprint { return PGPArmor.dearmor(id.armoredPublicKey) }
                    return tContacts.publicKeyData(fingerprint)
                }
            },
            passphrase: { nil },
            signerKeys: {
                MainActor.assumeIsolated {
                    (tContacts.contacts.map(\.publicKey.armored) + [id.armoredPublicKey])
                        .compactMap { PGPArmor.dearmor($0) }
                }
            }
        )
        let relay = RelayClient(baseURL: AppConfig.relayBaseURL, crypto: crypto, deviceID: AppConfig.deviceID)
        let store = ChatStore(
            identity: id.fingerprint,
            relay: relay,
            crypto: crypto,
            sealedKeys: sealedKeys,
            contacts: { tContacts.contacts },
            pairingSweep: nil,
            updatePeerName: { fingerprint, name in
                MainActor.assumeIsolated { tContacts.setName(fingerprint, name: name) }
            },
            updatePeerCaps: { fingerprint, caps in
                MainActor.assumeIsolated { tContacts.setCaps(fingerprint, caps: caps) }
            },
            addContact: { contact in
                MainActor.assumeIsolated { tContacts.add(contact) }
            },
            pairComplete: { token, pubkey in
                MainActor.assumeIsolated { Self.completeBackgroundInvite(id, contacts: tContacts, token: token, pubkey: pubkey) }
            }
        )
        await sweepBackgroundInvites(id, contacts: tContacts, relay: relay, store: store)
        await store.refresh()
        let unread = store.conversations.values.reduce(0) { $0 + $1.unreadCount }
        store.stop()
        return unread
    }

    /// Background account: finish a pairing offer from the responder's
    /// pair-complete op, matching the token against the persisted pending list.
    private static func completeBackgroundInvite(_ id: Identity, contacts: ContactStore, token: String, pubkey: String) -> Bool {
        let key = "cp.pendinginvites.\(id.fingerprint.hex)"
        guard let data = UserDefaults.standard.data(forKey: key),
              var pending = try? JSONDecoder().decode([PendingInvite].self, from: data),
              let index = pending.firstIndex(where: { $0.token == token }),
              let fpr = OpenPGPKeyID.primaryFingerprint(armoredPublicKey: pubkey) else { return false }
        let inPerson = pending[index].inPerson ?? false
        guard let contact = consistentContact(fprHex: fpr, armoredPub: pubkey, trust: inPerson ? .verified : .unverified),
              contact.fingerprint != id.fingerprint else { return false }
        contacts.add(contact)
        if inPerson { contacts.markVerified(contact.fingerprint) }
        pending.remove(at: index)
        if pending.isEmpty { UserDefaults.standard.removeObject(forKey: key) }
        else if let d = try? JSONEncoder().encode(pending) { UserDefaults.standard.set(d, forKey: key) }
        return true
    }

    /// Complete a background account's outstanding pairing OFFERS from the relay
    /// without making it active (mirrors sweepPendingInvites/finishAcceptedInvite
    /// off the persisted list and the throwaway stack), so pairing an account you
    /// have since switched away from still finishes on its side.
    private func sweepBackgroundInvites(_ id: Identity, contacts: ContactStore, relay: RelayClient, store: ChatStore) async {
        let key = "cp.pendinginvites.\(id.fingerprint.hex)"
        guard let data = UserDefaults.standard.data(forKey: key),
              let pending = try? JSONDecoder().decode([PendingInvite].self, from: data),
              !pending.isEmpty else { return }
        var changed = false
        var keep: [PendingInvite] = []
        for p in pending {
            if PairingRetention.isStale(p) { changed = true; continue }
            if p.relayGone ?? false { keep.append(p); continue }
            do {
                let status = try await relay.pairStatus(token: p.token)
                if status.state == "accepted", let rFpr = status.responderFpr, let rPub = status.responderPubkey {
                    let trust: TrustLevel = (p.inPerson ?? false) ? .verified : .unverified
                    if let contact = Self.consistentContact(fprHex: rFpr, armoredPub: rPub, trust: trust) {
                        contacts.add(contact)
                        if p.inPerson ?? false { contacts.markVerified(contact.fingerprint) }
                        await store.sendProfile(name: UserDefaults.standard.string(forKey: "cp.profile.\(id.fingerprint.hex)"), to: contact)
                    }
                    changed = true
                } else if status.state == "expired" {
                    changed = true
                } else {
                    keep.append(p)
                }
            } catch let error as RelayError where (400..<500).contains(error.status) {
                // The relay forgot the offer. Keep the token for the grace window so
                // the responder's pair-complete op can still finish it from the inbox.
                var gone = p
                gone.relayGone = true
                keep.append(gone)
                changed = true
            } catch {
                keep.append(p)
            }
        }
        if changed {
            if keep.isEmpty { UserDefaults.standard.removeObject(forKey: key) }
            else if let d = try? JSONEncoder().encode(keep) { UserDefaults.standard.set(d, forKey: key) }
        }
    }
}
