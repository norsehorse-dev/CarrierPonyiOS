import Foundation
import Observation
import CryptoKit

@MainActor
@Observable
final class ChatStore {

    private let identity: Fingerprint
    private let relay: RelayClient
    private let crypto: CryptoEngine
    private let sealedKeys: SealedKeyStore
    private let transports: [Transport]
    /// Optional best-effort direct transport (LAN). The relay stays authoritative;
    /// this only accelerates delivery when the peer is reachable on this network.
    private let lanTransport: Transport?
    /// Optional best-effort direct transport (WAN, PonyDirect hole-punch). Concurrent
    /// with the relay; can also carry the whole message when the relay is unreachable.
    private let wanTransport: Transport?
    /// Optional best-effort store-and-forward transport over Nostr relays (2.3).
    /// Concurrent with the relay; posts to the peer's sealed mailbox address.
    private let nostrTransport: Transport?
    /// Push the current inbound mailbox-address window to the Nostr transport so it
    /// subscribes for events posted to us there. Wired by AppModel.
    private let nostrSubscribe: (([String]) -> Void)?

    /// WAN-direct (2.2) signaling hook: called when a webrtc-offer/answer/ice control
    /// op arrives from a peer, with (peerHex, op, sdp, candidate). AppModel wires it
    /// to the WebRTC layer (M2); in M1 it just drives a received-count for the test.
    var onSignal: ((String, String, String?, String?) -> Void)?
    private let factory: EnvelopeFactory
    private let contacts: () -> [Contact]
    private let multiDevice: Bool
    private let defaultTTL: Int
    private let pairingSweep: (() async -> Void)?
    private let updatePeerName: (Fingerprint, String?) -> Void
    // Record what a contact's app says it supports, from a profile or caps op.
    // Wired to ContactStore.setCaps.
    private let updatePeerCaps: (Fingerprint, [String]) -> Void
    // Keep a contact request whose envelope checked out against the key it
    // carries: (fingerprint, armored key, name, caps). Returns false when it
    // was not kept. Nil on a store that has nowhere to put one; such a store
    // leaves the envelope for the next real one.
    private let contactRequest: ((Fingerprint, String, String?, [String]?) -> Bool)?
    // Add or replace a contact (channel subscribe: admin adds a subscriber, the
    // subscriber adds the channel admin). Wired to ContactStore.
    private let addContact: (Contact) -> Void
    // Completes a pairing offer this identity created, from the responder's own
    // pair-complete control op: (invite token, responder armored public key), true
    // when the token matched an offer we issued and the contact was added. The
    // relay's pair/status record is the primary path; this one keeps working when
    // the offerer's app was closed until that record was gone. Wired by AppModel.
    private let pairComplete: ((String, String) -> Bool)?

    private(set) var conversations: [String: Conversation] = [:]
    private(set) var groups: [String: ChatGroup] = [:]
    private(set) var groupMessages: [String: [ChatMessage]] = [:]
    private(set) var lastError: String?
    /// Inbox envelopes that keep failing to open (usually a sender whose pairing
    /// has not finished on this device). They stay on the relay and are retried
    /// every poll; the count drives the "messages waiting" banner.
    private(set) var heldCount = 0
    /// Contacts added by accepting THEIR invite whose side has not confirmed yet
    /// (nothing from them has opened here). Fingerprint hex, persisted per identity.
    private(set) var awaitingPeers: Set<String> = []
    private static let heldAfterAttempts = 4

    private var seenMessageIDs: Set<String> = []
    private var failedOpenCounts: [String: Int] = [:]
    /// Polls of the fingerprint inbox so far. An envelope that failed to open 3
    /// times is only tried again on every 12th poll (about a minute): each failed
    /// open is up to four decrypts on the main actor, and retrying a stuck one
    /// every 5 seconds made the whole app stutter.
    @ObservationIgnored private var legacyPollCount = 0
    /// The envelopes the waiting banner is counting right now.
    @ObservationIgnored private var heldIDs: Set<String> = []
    private var dismissedHeldKey: String { "cp.heldDismissed." + identity.hex }
    private func dismissedHeld() -> Set<String> {
        Set(UserDefaults.standard.stringArray(forKey: dismissedHeldKey) ?? [])
    }

    /// Hide the waiting banner for the envelopes it counts now. They stay on the
    /// relay and still open by themselves if pairing finishes. The banner comes
    /// back only when a different envelope gets stuck.
    func dismissHeld() {
        let dismissed = dismissedHeld().union(heldIDs)
        UserDefaults.standard.set(Array(dismissed), forKey: dismissedHeldKey)
        heldCount = 0
    }
    /// Nostr events that already opened in this run of the app (see
    /// ingestNostrEnvelope). Memory only.
    @ObservationIgnored private var nostrOpened: Set<String> = []
    // Cap envelopes decrypted per refresh. The PGP decrypt runs on the main
    // actor, so a large backlog (app offline for a while) would otherwise block
    // the UI in one pass; a bounded batch + a yield per item keeps the run loop
    // responsive and drains the queue over successive polls. Un-acked overflow
    // returns on the next refresh.
    private let maxPerRefresh = 50
    private var pollTask: Task<Void, Never>?
    private let fileURL: URL
    /// Text typed but not sent, per conversation, so it survives leaving the
    /// thread and the app being ended in the background. Keyed by draftKey /
    /// groupDraftKey. Not observed: typing must not redraw every view of the store.
    @ObservationIgnored private var drafts: [String: String] = [:]
    @ObservationIgnored private var draftsSaveTask: Task<Void, Never>?
    private let draftsURL: URL

    init(
        identity: Fingerprint,
        relay: RelayClient,
        crypto: CryptoEngine,
        sealedKeys: SealedKeyStore,
        contacts: @escaping () -> [Contact],
        multiDevice: Bool = true,
        defaultTTL: Int = 30 * 86400,
        pairingSweep: (() async -> Void)? = nil,
        updatePeerName: @escaping (Fingerprint, String?) -> Void = { _, _ in },
        updatePeerCaps: @escaping (Fingerprint, [String]) -> Void = { _, _ in },
        addContact: @escaping (Contact) -> Void = { _ in },
        lanTransport: Transport? = nil,
        wanTransport: Transport? = nil,
        nostrTransport: Transport? = nil,
        nostrSubscribe: (([String]) -> Void)? = nil,
        pairComplete: ((String, String) -> Bool)? = nil,
        contactRequest: ((Fingerprint, String, String?, [String]?) -> Bool)? = nil
    ) {
        self.identity = identity
        self.relay = relay
        self.crypto = crypto
        self.sealedKeys = sealedKeys
        self.transports = [RelayTransport(relay: relay)]
        self.lanTransport = lanTransport
        self.wanTransport = wanTransport
        self.nostrTransport = nostrTransport
        self.nostrSubscribe = nostrSubscribe
        self.factory = EnvelopeFactory(crypto: crypto)
        self.contacts = contacts
        self.multiDevice = multiDevice
        self.defaultTTL = defaultTTL
        self.pairingSweep = pairingSweep
        self.updatePeerName = updatePeerName
        self.updatePeerCaps = updatePeerCaps
        self.contactRequest = contactRequest
        self.addContact = addContact
        self.pairComplete = pairComplete

        let dir = (try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        )) ?? FileManager.default.temporaryDirectory
        self.fileURL = dir.appendingPathComponent("carrierpony-conversations-\(identity.hex).json")
        self.draftsURL = dir.appendingPathComponent("carrierpony-drafts-\(identity.hex).json")
        load()
        loadDrafts()
        awaitingPeers = Set(UserDefaults.standard.stringArray(forKey: awaitingKey) ?? [])
    }

    // Sealed sender: this device's auth key (minted once), the current
    // address->(peer,counter) map for the registered receive windows, and when
    // the windows were last re-registered.
    private var sealedDeviceKey: String { sealedKeys.deviceKey() }
    private var sealedDeviceID: String { sealedKeys.deviceID() }
    /// This account's sealed device id, for per-account gateway registration.
    func sealedDeviceId() -> String { sealedKeys.deviceID() }
    private var sealedAddressMap: [String: SealedRoute] = [:]
    private var lastSealedWindowRefresh: Date = .distantPast
    /// Receive addresses the relay already holds for this device (this session), so
    /// window upkeep only sends new ones instead of the whole window every 30s.
    private var sealedRegistered: Set<String> = []
    /// Last full re-registration, which also pushes every mailbox's expiry forward.
    private var lastSealedFullRegistration: Date = .distantPast
    private let sealedFullRegistrationInterval: TimeInterval = 6 * 3600
    /// Last time we retried sending our inbound key to contacts that lack it.
    private var lastSealedHandshake: Date = .distantPast
    /// A high-water mark moved, so the window should slide on the next upkeep.
    private var sealedWindowsDirty = false
    /// Sealed envelopes that failed to open, by relay message id. Ones that keep
    /// failing are skipped on most polls so they can't crowd out new messages.
    private var sealedFailCounts: [String: Int] = [:]
    private var sealedPollCount = 0
    /// Single-flight refresh: the pass running now and at most one queued follow-up.
    private var refreshTask: Task<Void, Never>?
    private var refreshTaskSerial = 0
    private var refreshFollowUp: Task<Void, Never>?

    // MARK: - Lifecycle

    func start(pollIntervalSeconds: UInt64 = 5) async {
        do {
            try await relay.registerDevice(label: "ios")
        } catch {
            // Transient: polling retries; don't flash the inbox banner on start.
        }
        await sealedEnsureDevice()
        await refresh()
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: pollIntervalSeconds * 1_000_000_000)
                await self?.refresh()
            }
        }
    }

    func stop() {
        pollTask?.cancel()
        pollTask = nil
    }

    /// Clear all conversations from memory and disk. Used on sign-out so a
    /// device doesn't keep plaintext message history after its identity is gone.
    func purge() {
        for conversation in conversations.values {
            for message in conversation.messages {
                for attachment in message.attachments {
                    AttachmentStore.delete(attachment.localPath)
                }
            }
        }
        for (gid, group) in groups { GroupKeyStore.deleteGroup(groupID: gid, throughEpoch: group.epoch) }
        sealedKeys.purge()
        conversations = [:]
        groups = [:]
        groupMessages = [:]
        seenMessageIDs = []
        try? FileManager.default.removeItem(at: fileURL)
        draftsSaveTask?.cancel()
        draftsSaveTask = nil
        drafts = [:]
        try? FileManager.default.removeItem(at: draftsURL)
        awaitingPeers = []
        heldCount = 0
        UserDefaults.standard.removeObject(forKey: awaitingKey)
    }

    func clearError() {
        lastError = nil
    }

    // MARK: - Receive

    /// Fetch and open everything waiting. Single-flight: a call made while a pass is
    /// running (a push landing mid-poll) waits for one follow-up pass instead of
    /// starting a second concurrent one, and returns when that pass is done, so a
    /// background push's completion handler still fires after the fetch.
    func refresh() async {
        if let follow = refreshFollowUp {
            await follow.value
            return
        }
        if let running = refreshTask {
            let follow = Task { [weak self] in
                await running.value
                guard let self else { return }
                self.refreshFollowUp = nil
                await self.runRefreshPass()
            }
            refreshFollowUp = follow
            await follow.value
            return
        }
        await runRefreshPass()
    }

    private func runRefreshPass() async {
        refreshTaskSerial &+= 1
        let serial = refreshTaskSerial
        let task = Task { [weak self] in
            guard let self else { return }
            await self.refreshPass()
        }
        refreshTask = task
        await task.value
        if refreshTaskSerial == serial { refreshTask = nil }
    }

    private func refreshPass() async {
        // Sealed inbox first. It is where 1:1 and group messages land, and the push
        // that woke us was almost always for one of them, so nothing slow (pairing
        // sweep, legacy challenge round trips, window upkeep) may run ahead of it.
        // The address map is pure HMAC, built locally when it isn't there yet.
        if sealedAddressMap.isEmpty { sealedBuildWindows() }
        await sealedPollInbox()

        // Settle any pending pairing offers first, so a brand-new contact's
        // first messages open on this same pass instead of burning open retries
        // against a sender we haven't stored yet.
        await pairingSweep?()
        do {
            let inbox = try await relay.inbox()
            var ackIDs: [String] = []
            legacyPollCount &+= 1
            let retryHeld = legacyPollCount % 12 == 0
            for item in inbox.prefix(maxPerRefresh) {
                if !retryHeld, (failedOpenCounts[item.messageId] ?? 0) >= 3 { continue }
                await Task.yield()
                guard let envelope = Data(base64Encoded: item.envelope) else {
                    // Malformed base64 is not retryable; ack so it stops recurring.
                    ackIDs.append(item.messageId)
                    continue
                }
                if envelope.starts(with: Self.groupMagic) {
                    if handleGroup(payload: Data(envelope.dropFirst(Self.groupMagic.count))) {
                        ackIDs.append(item.messageId)
                        failedOpenCounts[item.messageId] = nil
                    } else {
                        failedOpenCounts[item.messageId] = (failedOpenCounts[item.messageId] ?? 0) + 1
                    }
                    continue
                }
                if handle(envelope: envelope) {
                    ackIDs.append(item.messageId)
                    failedOpenCounts[item.messageId] = nil
                } else {
                    // Open failed (often a pairing race, sometimes a key we can't
                    // resolve yet). Never ack: acking tells the relay to delete the
                    // only copy, so a recoverable failure would destroy the message
                    // permanently. Leave it on the relay and retry on later
                    // refreshes; its own expires_at bounds how long it can linger,
                    // so nothing accumulates forever. The attempt count is kept
                    // only so the error text can say how long this has been stuck.
                    failedOpenCounts[item.messageId] = (failedOpenCounts[item.messageId] ?? 0) + 1
                }
            }
            if !ackIDs.isEmpty {
                try await relay.ack(messageIDs: ackIDs)
            }
            let present = Set(inbox.prefix(maxPerRefresh).map(\.messageId))
            // Assign only on change: every write to an observed property re-renders
            // the views that read it, and this ran on every 5-second poll.
            let stuck = Set(failedOpenCounts.filter { present.contains($0.key) && $0.value >= Self.heldAfterAttempts }.keys)
            heldIDs = stuck
            // Dismissing the banner hides the ones it counted, nothing more. Forget
            // a dismissed one once the relay no longer holds it, so the list stays
            // small.
            var dismissed = dismissedHeld()
            let onRelay = Set(inbox.map(\.messageId))
            if !dismissed.isSubset(of: onRelay) {
                dismissed.formIntersection(onRelay)
                UserDefaults.standard.set(Array(dismissed), forKey: dismissedHeldKey)
            }
            let held = stuck.subtracting(dismissed).count
            if held != heldCount { heldCount = held }
            pruneExpired()
        } catch {
            // Transient poll failure; retried on the next refresh, no banner.
        }
        await sealedMaintain()
    }

    @discardableResult
    private func handle(envelope: Data, viaLan: Bool = false) -> Bool {
        let incoming: IncomingMessage
        let openStarted = Date()
        do {
            incoming = try factory.open(envelope)
            Self.logSlow("open", since: openStarted, bytes: envelope.count)
        } catch {
            Self.logSlow("open-failed", since: openStarted, bytes: envelope.count)
            // Before giving up: an un-verifiable envelope may be a self-authenticating
            // channel-subscribe from a stranger (decrypt-only, no signer to verify yet).
            if tryChannelSubscribe(envelope) { return true }
            // Or the responder of a pairing offer we created, announcing itself
            // before this device has its key.
            if tryPairComplete(envelope) { return true }
            // Or someone who added this identity by its public key, asking to be
            // added back.
            if tryContactRequest(envelope) { return true }
            // A common cause is the sender not being paired on this device yet, so
            // their signature can't be verified. Report false so refresh() retries
            // rather than losing a message that races pairing. Name the underlying
            // failure: "no valid signature" and "decryption failed" have completely
            // different causes and used to be indistinguishable from the UI.
            // Usually a message racing pairing; refresh() retries it instead of
            // raising a banner on every poll.
            return false
        }
        let manifest = incoming.manifest

        guard !seenMessageIDs.contains(manifest.messageID) else { return true }
        if manifest.expiresAt <= now {
            seenMessageIDs.insert(manifest.messageID)
            return true
        }

        let senderIsSelf = incoming.sender == identity
        if !senderIsSelf, awaitingPeers.contains(incoming.sender.hex) { setAwaiting(incoming.sender, false) }
        switch (senderIsSelf, manifest.type) {
        case (_, "group-key"):
            applyGroupKey(incoming)
        case (true, "control"):
            applyControl(incoming)
        case (true, "message"):
            // Self-copy of one of my own sent messages, synced from another device.
            if let peer = resolvePeer(for: incoming, senderIsSelf: true) {
                file(incoming, peer: peer, direction: .outgoing)
            } else {
                return true
            }
        case (false, "message"):
            file(incoming, peer: incoming.sender, direction: .incoming, viaLan: viaLan)
        case (false, "control"):
            // A peer may send a profile update (display name) or a sealed-sender
            // mailbox-key handshake. Both only affect our view of them.
            applyPeerControl(incoming)
        default:
            // Others cannot control my state; anything else is rejected.
            return true
        }
        seenMessageIDs.insert(manifest.messageID)
        return true
    }

    private func resolvePeer(for incoming: IncomingMessage, senderIsSelf: Bool) -> Fingerprint? {
        if senderIsSelf, let to = incoming.manifest.to, let peer = Fingerprint(to), peer != identity {
            return peer
        }
        // Fallback: match the thread against known contacts.
        let thread = incoming.manifest.threadID
        for contact in contacts() where Threading.pairwise(identity.hex, contact.fingerprint.hex) == thread {
            return contact.fingerprint
        }
        return nil
    }

    private func file(_ incoming: IncomingMessage, peer: Fingerprint, direction: MessageDirection, viaLan: Bool = false) {
        let manifest = incoming.manifest
        let message = ChatMessage(
            id: manifest.messageID,
            threadID: manifest.threadID,
            peer: peer,
            direction: direction,
            text: incoming.text,
            attachments: incoming.files.map { file in
                let mime = file.part.mime ?? "application/octet-stream"
                let filename = file.part.filename ?? "file"
                let localPath = AttachmentStore.save(file.data, suggestedName: filename)
                return ChatMessage.Attachment(
                    id: UUID().uuidString,
                    filename: filename,
                    mime: mime,
                    size: file.data.count,
                    localPath: localPath
                )
            },
            sentAt: manifest.sentAt,
            expiresAt: manifest.expiresAt,
            isRead: direction == .outgoing,
            viaLan: viaLan
        )
        appendToConversation(message, peer: peer)
    }

    /// Whether messages to this peer are sealed (roster-hidden) yet. False until
    /// the mailbox-key handshake has completed both ways, or for a pre-2.0 peer.
    /// Drives the pair-state indicator so the honest limit is visible.
    func isSealed(with peer: Fingerprint) -> Bool {
        sealedKeys.pair(peer.hex)?.canSend ?? false
    }

    // MARK: - Send

    func send(text: String?, attachments: [OutgoingMessage.Attachment] = [], to contact: Contact, ttl: Int? = nil) async {
        let totalBytes = attachments.reduce(0) { $0 + $1.data.count }
        if totalBytes > AppConfig.maxAttachmentBytes {
            let mb = AppConfig.maxAttachmentBytes / (1024 * 1024)
            lastError = "That attachment is too large to send (limit \(mb) MB)."
            return
        }

        let threadID = Threading.pairwise(identity.hex, contact.fingerprint.hex)
        let expiresAt = now + (ttl ?? defaultTTL)
        let messageID = UUID().uuidString
        let outgoing = OutgoingMessage(threadID: threadID, text: text, attachments: attachments, expiresAt: expiresAt)

        // Persist attachment bytes to disk for the local echo (kept out of the
        // conversation store and out of memory).
        let storedAttachments = attachments.map { attachment -> ChatMessage.Attachment in
            let localPath = AttachmentStore.save(attachment.data, suggestedName: attachment.filename)
            return ChatMessage.Attachment(
                id: UUID().uuidString,
                filename: attachment.filename,
                mime: attachment.mime,
                size: attachment.data.count,
                localPath: localPath
            )
        }

        // Show immediately on this device.
        let local = ChatMessage(
            id: messageID,
            threadID: threadID,
            peer: contact.fingerprint,
            direction: .outgoing,
            text: text,
            attachments: storedAttachments,
            sentAt: now,
            expiresAt: expiresAt,
            isRead: true
        )
        seenMessageIDs.insert(messageID)
        appendToConversation(local, peer: contact.fingerprint, peerName: contact.name)

        if contact.fingerprint == DemoMode.fingerprint {
            await demoAutoReply(hadAttachment: !attachments.isEmpty)
            return
        }

        do {
            let envelope = try factory.build(outgoing, to: contact.publicKey, messageID: messageID)
            try await deliverToPeer(envelope, to: contact.fingerprint, expiresAt: expiresAt, silent: false)

            if multiDevice {
                try await sendSelfCopy(outgoing, messageID: messageID)
            }
        } catch {
            lastError = describe(error)
        }
    }

    // MARK: - Reporting

    /// Text of recent messages received from a peer, oldest-first, for an abuse
    /// report. Only incoming text is included; attachment bytes are never shared.
    func recentIncomingText(for peer: Fingerprint, limit: Int = 20) -> String? {
        let texts = conversations.values
            .flatMap { $0.messages }
            .filter { $0.peer == peer && $0.direction == .incoming }
            .sorted { $0.sentAt > $1.sentAt }
            .prefix(limit)
            .compactMap { message -> String? in
                let t = message.text?.trimmingCharacters(in: .whitespacesAndNewlines)
                return (t?.isEmpty == false) ? t : nil
            }
        return texts.isEmpty ? nil : texts.reversed().joined(separator: "\n")
    }

    func submitReport(contact: Contact, category: String, description: String?, includeContent: Bool) async throws {
        let content = includeContent ? recentIncomingText(for: contact.fingerprint) : nil
        try await relay.submitReport(
            reportedFingerprint: contact.fingerprint,
            category: category,
            description: description,
            content: content
        )
    }

    // MARK: - Demo mode (App Review)

    /// Inject a message that appears to come from the simulated demo contact.
    func injectDemoIncoming(text: String, attachment: ChatMessage.Attachment? = nil) {
        let threadID = Threading.pairwise(identity.hex, DemoMode.fingerprint.hex)
        let message = ChatMessage(
            id: UUID().uuidString,
            threadID: threadID,
            peer: DemoMode.fingerprint,
            direction: .incoming,
            text: text,
            attachments: attachment.map { [$0] } ?? [],
            sentAt: now,
            expiresAt: now + defaultTTL,
            isRead: false
        )
        appendToConversation(message, peer: DemoMode.fingerprint, peerName: DemoMode.peerName)
    }

    private func demoAutoReply(hadAttachment: Bool) async {
        try? await Task.sleep(nanoseconds: 1_200_000_000)
        if hadAttachment {
            let data = Data("This file came back from the CarrierPony demo contact. It was delivered the same encrypted way your file was.".utf8)
            let path = AttachmentStore.save(data, suggestedName: "demo-reply.txt")
            let attachment = ChatMessage.Attachment(
                id: UUID().uuidString,
                filename: "demo-reply.txt",
                mime: "text/plain",
                size: data.count,
                localPath: path
            )
            injectDemoIncoming(
                text: "Got your file. It was encrypted on your device and decrypted here. Here's one back so you can see file transfer both ways.",
                attachment: attachment
            )
        } else {
            injectDemoIncoming(text: "Received and decrypted on-device. In a real conversation this reply would come from the person you paired with. Try attaching a file next, or open the ••• menu to see Report and Block.")
        }
    }

    private func sendSelfCopy(_ outgoing: OutgoingMessage, messageID: String) async throws {
        guard let selfKey = ownPublicKey() else { return }
        let envelope = try factory.build(outgoing, to: selfKey, messageID: messageID)
        _ = try await relay.send(envelope: envelope, to: identity, expiresAt: outgoing.expiresAt, silent: true)
    }

    // MARK: - Read / control

    func markRead(threadID: String) async {
        guard var conversation = conversations[threadID] else { return }
        let unread = conversation.messages.filter { $0.direction == .incoming && !$0.isRead }
        guard !unread.isEmpty else { return }
        for index in conversation.messages.indices {
            conversation.messages[index].isRead = true
        }
        conversations[threadID] = conversation
        persist()
        if multiDevice {
            for message in unread {
                await emitControl(op: "read", targetMessageID: message.id, threadID: threadID)
            }
        }
    }

    /// Mark every incoming message in a group thread read on this device. Local
    /// only; group read receipts are not fanned out to the whole group.
    func markGroupRead(groupID: String) {
        guard var messages = groupMessages[groupID] else { return }
        guard messages.contains(where: { $0.direction == .incoming && !$0.isRead }) else { return }
        for index in messages.indices where messages[index].direction == .incoming && !messages[index].isRead {
            messages[index].isRead = true
        }
        groupMessages[groupID] = messages
        persist()
    }

    // MARK: - Deletion

    /// Remove a message from this device only. The peer and any other devices
    /// keep their copies.
    func deleteLocally(messageID: String) {
        deleteMessage(id: messageID)
    }

    /// Retract a message everywhere: ask the peer to delete their copy (and, on
    /// multi-device, my other devices), then remove it here. Meaningful only for
    /// your own outgoing messages.
    func deleteForEveryone(messageID: String, to contact: Contact) async {
        await sendControlToPeer(op: "delete", targetMessageID: messageID, to: contact)
        if multiDevice {
            let threadID = Threading.pairwise(identity.hex, contact.fingerprint.hex)
            await emitControl(op: "delete", targetMessageID: messageID, threadID: threadID)
        }
        deleteMessage(id: messageID)
    }

    /// Clear every message in a thread on this device, keeping the contact and
    /// pairing intact. Local only.
    func clearHistory(threadID: String) {
        guard var conversation = conversations[threadID] else { return }
        for message in conversation.messages {
            for attachment in message.attachments {
                AttachmentStore.delete(attachment.localPath)
            }
        }
        conversation.messages.removeAll()
        conversations[threadID] = conversation
        persist()
    }

    /// Remove a whole conversation from the list (and its messages) on this
    /// device. The contact stays paired, unlike unpairing.
    func deleteConversation(threadID: String) {
        guard let conversation = conversations[threadID] else { return }
        for message in conversation.messages {
            for attachment in message.attachments {
                AttachmentStore.delete(attachment.localPath)
            }
        }
        conversations[threadID] = nil
        persist()
        setDraft("", for: Self.draftKey(peer: conversation.peer))
    }

    // MARK: - Drafts

    static func draftKey(peer: Fingerprint) -> String { "p:" + peer.hex }
    static func groupDraftKey(_ groupID: String) -> String { "g:" + groupID }

    /// The unsent text for a conversation, or "" when there is none.
    func draft(for key: String) -> String { drafts[key] ?? "" }

    /// Remember the unsent text for a conversation. An empty text removes it.
    /// Written to disk shortly after typing stops; saveDraftsNow() writes at once.
    func setDraft(_ text: String, for key: String) {
        if text.isEmpty {
            guard drafts.removeValue(forKey: key) != nil else { return }
        } else {
            guard drafts[key] != text else { return }
            drafts[key] = text
        }
        draftsSaveTask?.cancel()
        draftsSaveTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(700))
            guard !Task.isCancelled else { return }
            self?.draftsSaveTask = nil
            self?.persistDrafts()
        }
    }

    /// Write drafts to disk now. Called when a thread closes and when the app
    /// goes to the background.
    func saveDraftsNow() {
        guard let waiting = draftsSaveTask else { return }
        waiting.cancel()
        draftsSaveTask = nil
        persistDrafts()
    }

    private func persistDrafts() {
        if drafts.isEmpty {
            try? FileManager.default.removeItem(at: draftsURL)
            return
        }
        guard let data = try? JSONEncoder().encode(drafts) else { return }
        try? data.write(to: draftsURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    private func loadDrafts() {
        guard let data = try? Data(contentsOf: draftsURL),
              let saved = try? JSONDecoder().decode([String: String].self, from: data) else { return }
        drafts = saved
    }

    /// Send a control op (e.g. "delete") to the peer over the relay.
    private func sendControlToPeer(op: String, targetMessageID: String, to contact: Contact) async {
        let threadID = Threading.pairwise(identity.hex, contact.fingerprint.hex)
        let body = ControlOp(op: op, targetMessageID: targetMessageID, at: now)
        guard let json = try? JSONEncoder().encode(body) else { return }
        let controlMessage = OutgoingMessage(
            threadID: threadID,
            text: nil,
            attachments: [OutgoingMessage.Attachment(filename: "control", mime: "application/json", data: json)],
            expiresAt: now + 86400
        )
        do {
            let messageID = UUID().uuidString
            seenMessageIDs.insert(messageID)
            let envelope = try buildControl(controlMessage, to: contact.publicKey, messageID: messageID)
            try await deliverToPeer(envelope, to: contact.fingerprint, expiresAt: controlMessage.expiresAt, silent: true)
        } catch {
            // Background control op; retried later, no banner.
        }
    }

    /// WAN-direct (2.2): send a signaling control op (webrtc-offer/answer/ice) to a
    /// peer over the sealed relay path, exactly like any other control op, so the
    /// relay only ever sees opaque mailbox traffic.
    private func sendSignal(op: String, to contact: Contact, sdp: String?, candidate: String?) async {
        let threadID = Threading.pairwise(identity.hex, contact.fingerprint.hex)
        var body = ControlOp(op: op, targetMessageID: "", at: now)
        body.sdp = sdp
        body.candidate = candidate
        guard let json = try? JSONEncoder().encode(body) else { return }
        let controlMessage = OutgoingMessage(
            threadID: threadID,
            text: nil,
            attachments: [OutgoingMessage.Attachment(filename: "control", mime: "application/json", data: json)],
            expiresAt: now + 86400
        )
        do {
            let messageID = UUID().uuidString
            seenMessageIDs.insert(messageID)
            let envelope = try buildControl(controlMessage, to: contact.publicKey, messageID: messageID)
            try await deliverToPeer(envelope, to: contact.fingerprint, expiresAt: controlMessage.expiresAt, silent: true)
        } catch {
            // Background signaling op; retried by the WebRTC layer, no banner.
        }
    }

    /// WAN-direct (2.2) public signaling send, addressed by peer fingerprint hex.
    func sendWanSignal(op: String, toPeerHex peerHex: String, sdp: String?, candidate: String?) async {
        guard let contact = contacts().first(where: { $0.fingerprint.hex.lowercased() == peerHex.lowercased() }) else { return }
        await sendSignal(op: op, to: contact, sdp: sdp, candidate: candidate)
    }

    /// M1 test only: exercise the signaling round-trip by sending a synthetic offer
    /// and ice candidate to every sealed-capable contact. Replaced in M2 by real
    /// WebRTC offer generation.
    func sendTestWanSignals() async {
        for contact in contacts() {
            guard let st = sealedKeys.pair(contact.fingerprint.hex), st.peerInboundKey != nil else { continue }
            await sendSignal(op: "webrtc-offer", to: contact, sdp: "m1-test-offer", candidate: nil)
            await sendSignal(op: "webrtc-ice", to: contact, sdp: nil, candidate: "m1-test-candidate")
        }
    }

    private func applyControl(_ incoming: IncomingMessage) {
        guard let payload = incoming.files.first?.data ?? incoming.text.map({ Data($0.utf8) }),
              let control = try? JSONDecoder().decode(ControlOp.self, from: payload) else {
            return
        }
        switch control.op {
        case "read":
            setRead(messageID: control.targetMessageID)
        case "delete":
            deleteMessage(id: control.targetMessageID)
        default:
            break
        }
    }

    // MARK: - Profile (display name exchange)

    /// Send my current display name to a contact as an encrypted control message.
    /// If the name is nil/empty (anonymous), nothing is sent.
    func sendProfile(name: String?, to contact: Contact) async {
        let trimmed = name?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let displayName = trimmed, !displayName.isEmpty else { return }
        let threadID = Threading.pairwise(identity.hex, contact.fingerprint.hex)
        var body = ControlOp(op: "profile", targetMessageID: "", at: now, name: displayName)
        body.caps = PairingCaps.Stated(PairingCaps.current)
        guard let json = try? JSONEncoder().encode(body) else { return }
        let controlMessage = OutgoingMessage(
            threadID: threadID,
            text: nil,
            attachments: [OutgoingMessage.Attachment(filename: "control", mime: "application/json", data: json)],
            expiresAt: now + 86400
        )
        do {
            let messageID = UUID().uuidString
            seenMessageIDs.insert(messageID)
            let envelope = try buildControl(controlMessage, to: contact.publicKey, messageID: messageID)
            try await deliverToPeer(envelope, to: contact.fingerprint, expiresAt: controlMessage.expiresAt, silent: true)
        } catch {
            // Background control op; retried later, no banner.
        }
    }

    /// Tell a contact what this app supports (PairingCaps). Its own op, because
    /// the profile op is only sent by someone who has set a display name, and an
    /// app before 4.0 ignores an op it does not know. Returns false if it could
    /// not be handed off, so the caller can try again later.
    @discardableResult
    func sendCaps(to contact: Contact) async -> Bool {
        let threadID = Threading.pairwise(identity.hex, contact.fingerprint.hex)
        var body = ControlOp(op: "caps", targetMessageID: "", at: now)
        body.caps = PairingCaps.Stated(PairingCaps.current)
        guard let json = try? JSONEncoder().encode(body) else { return false }
        let controlMessage = OutgoingMessage(
            threadID: threadID,
            text: nil,
            attachments: [OutgoingMessage.Attachment(filename: "control", mime: "application/json", data: json)],
            expiresAt: now + defaultTTL
        )
        do {
            let messageID = UUID().uuidString
            seenMessageIDs.insert(messageID)
            let envelope = try buildControl(controlMessage, to: contact.publicKey, messageID: messageID)
            try await deliverToPeer(envelope, to: contact.fingerprint, expiresAt: controlMessage.expiresAt, silent: true)
            return true
        } catch {
            return false
        }
    }

    /// Ask someone whose public key I added to add me back. The envelope is
    /// encrypted to them and signed by a key they do not hold yet, so the op
    /// carries that key; their app checks the signature against it before it
    /// shows the request. Also carries my name, if I have set one, and what
    /// this app supports. Throws if it could not be handed off, so the caller
    /// can tell "not on this relay" (RelayError 404) from being offline.
    func sendContactRequest(name: String?, to contact: Contact) async throws {
        let mine = try crypto.armoredPublicKey()
        let threadID = Threading.pairwise(identity.hex, contact.fingerprint.hex)
        var body = ControlOp(op: "contact-request", targetMessageID: "", at: now)
        let trimmed = name?.trimmingCharacters(in: .whitespacesAndNewlines)
        body.name = (trimmed?.isEmpty == false) ? trimmed : nil
        body.pubkey = mine
        body.caps = PairingCaps.Stated(PairingCaps.current)
        let json = try JSONEncoder().encode(body)
        let controlMessage = OutgoingMessage(
            threadID: threadID,
            text: nil,
            attachments: [OutgoingMessage.Attachment(filename: "control", mime: "application/json", data: json)],
            expiresAt: now + defaultTTL
        )
        let messageID = UUID().uuidString
        seenMessageIDs.insert(messageID)
        let envelope = try buildControl(controlMessage, to: contact.publicKey, messageID: messageID)
        // Straight to the relay by fingerprint: there is no sealed address or
        // direct path to someone who is not a contact yet, and this is the call
        // that can say the deposit is a contact request.
        _ = try await relay.send(envelope: envelope, to: contact.fingerprint,
                                 expiresAt: controlMessage.expiresAt, silent: false, kind: "request")
    }

    /// Responder side of remote pairing: tell the offerer we accepted, carrying our
    /// own key and the invite token. The offerer usually learns this from the
    /// relay's pair/status record, but only while its app sweeps before that
    /// record is gone; this op lets the offerer finish from its inbox instead.
    /// Sent before the profile so it is processed first.
    func sendPairComplete(token: String, to contact: Contact) async {
        guard let mine = try? crypto.armoredPublicKey() else { return }
        let threadID = Threading.pairwise(identity.hex, contact.fingerprint.hex)
        var body = ControlOp(op: "pair-complete", targetMessageID: "", at: now)
        body.pubkey = mine
        body.token = token
        guard let json = try? JSONEncoder().encode(body) else { return }
        let controlMessage = OutgoingMessage(
            threadID: threadID,
            text: nil,
            attachments: [OutgoingMessage.Attachment(filename: "control", mime: "application/json", data: json)],
            expiresAt: now + defaultTTL
        )
        do {
            let messageID = UUID().uuidString
            seenMessageIDs.insert(messageID)
            let envelope = try buildControl(controlMessage, to: contact.publicKey, messageID: messageID)
            try await deliverToPeer(envelope, to: contact.fingerprint, expiresAt: controlMessage.expiresAt, silent: true)
        } catch {
            // Best effort: the relay's pair/status record is the primary path.
        }
    }

    // MARK: - Awaiting the peer's side of pairing

    private var awaitingKey: String { "cp.awaitingpeers.\(identity.hex)" }

    /// Mark a contact we paired with by accepting their invite as not yet
    /// confirmed on their side. Cleared by the first envelope from them that opens.
    func setAwaiting(_ fingerprint: Fingerprint, _ waiting: Bool) {
        let next = waiting ? awaitingPeers.union([fingerprint.hex]) : awaitingPeers.subtracting([fingerprint.hex])
        guard next != awaitingPeers else { return }
        awaitingPeers = next
        UserDefaults.standard.set(Array(next), forKey: awaitingKey)
    }

    private func applyContactProfile(_ incoming: IncomingMessage) {
        guard let payload = incoming.files.first?.data ?? incoming.text.map({ Data($0.utf8) }),
              let control = try? JSONDecoder().decode(ControlOp.self, from: payload),
              control.op == "profile" else {
            return
        }
        let name = control.name?.trimmingCharacters(in: .whitespacesAndNewlines)
        // Update the stored contact (source of truth for names).
        updatePeerName(incoming.sender, (name?.isEmpty == false) ? name : nil)
        // Reflect immediately on any existing thread.
        let threadID = Threading.pairwise(identity.hex, incoming.sender.hex)
        if var conversation = conversations[threadID] {
            conversation.peerName = (name?.isEmpty == false) ? name : conversation.peerName
            conversations[threadID] = conversation
            persist()
        }
    }

    // MARK: - Groups

    /// Create a group, generate the epoch-0 key, and distribute the key + roster to
    /// every member. The creator is the first admin.
    /// The names of the roster's members who must update to 4.0 before it can
    /// be a group (GroupRules). Empty when the roster is fine.
    private func rosterNeedingUpdate(_ roster: [GroupMember]) -> [String] {
        let known = Dictionary(contacts().map { ($0.fingerprint, $0) }, uniquingKeysWith: { first, _ in first })
        let members = roster.map { member -> GroupRules.Member in
            if member.fingerprint == identity {
                return GroupRules.Member(fingerprint: identity, caps: PairingCaps.current, label: "")
            }
            let contact = known[member.fingerprint]
            let label = contact?.displayName ?? member.name ?? String(member.fingerprint.hex.suffix(8))
            return GroupRules.Member(fingerprint: member.fingerprint, caps: contact?.caps, label: label)
        }
        return GroupRules.needingUpdate(members).map(\.label)
    }

    /// Who must update before a group of me and `members` can be made. Screens
    /// ask this first so they can say why; createGroup checks again.
    func membersNeedingUpdate(forNewGroupWith members: [Contact]) -> [String] {
        rosterNeedingUpdate(
            [GroupMember(fingerprint: identity, armoredPublicKey: "", name: nil, isAdmin: true)]
                + members.map { GroupMember(fingerprint: $0.fingerprint, armoredPublicKey: $0.publicKey.armored,
                                            name: $0.name, isAdmin: false) }
        )
    }

    /// Who must update before `contacts` can join the group: anyone already in
    /// it or being added. Screens ask this first; addMembers checks again.
    func membersNeedingUpdate(adding contacts: [Contact], toGroup groupID: String) -> [String] {
        guard let group = groups[groupID] else { return [] }
        let present = Set(group.members.map { $0.fingerprint.hex })
        let additions = contacts
            .filter { !present.contains($0.fingerprint.hex) }
            .map { GroupMember(fingerprint: $0.fingerprint, armoredPublicKey: $0.publicKey.armored,
                               name: $0.name, isAdmin: false) }
        guard !additions.isEmpty else { return [] }
        return rosterNeedingUpdate(group.members + additions)
    }

    /// Create a group. Returns the names of anyone who must update first, in
    /// which case nothing was created; an empty list means it went ahead.
    @discardableResult
    func createGroup(name: String, members: [Contact]) async -> [String] {
        let blocked = membersNeedingUpdate(forNewGroupWith: members)
        guard blocked.isEmpty else { return blocked }
        guard let mine = ownPublicKey() else { return [] }
        var roster: [GroupMember] = [
            GroupMember(fingerprint: identity, armoredPublicKey: mine.armored,
                        name: contactName(for: identity), isAdmin: true)
        ]
        for c in members {
            roster.append(GroupMember(fingerprint: c.fingerprint,
                                      armoredPublicKey: c.publicKey.armored,
                                      name: c.name, isAdmin: false))
        }
        let groupID = ChatGroup.newID()
        let key = GroupKeyStore.newKey()
        GroupKeyStore.store(key, groupID: groupID, epoch: 0)
        let group = ChatGroup(groupID: groupID, name: name, members: roster, epoch: 0, createdAt: now)
        groups[groupID] = group
        persist()
        await distributeGroupKey(group, key: key)
        return []
    }

    /// Create a broadcast channel: like a group, but the creator is the sole admin
    /// (broadcaster) and everyone else is a subscriber (receive-only).
    func createChannel(name: String, subscribers: [Contact]) async {
        guard let mine = ownPublicKey() else { return }
        var roster: [GroupMember] = [
            GroupMember(fingerprint: identity, armoredPublicKey: mine.armored,
                        name: contactName(for: identity), isAdmin: true)
        ]
        for c in subscribers {
            roster.append(GroupMember(fingerprint: c.fingerprint,
                                      armoredPublicKey: c.publicKey.armored,
                                      name: c.name, isAdmin: false))
        }
        let groupID = ChatGroup.newID()
        let key = GroupKeyStore.newKey()
        GroupKeyStore.store(key, groupID: groupID, epoch: 0)
        let group = ChatGroup(groupID: groupID, name: name, members: roster, epoch: 0, isChannel: true, createdAt: now)
        groups[groupID] = group
        NSLog("CPCHAN created channel=%@ subs=%d groupsNow=%d", String(groupID.suffix(8)), subscribers.count, groups.count)
        persist()
        await distributeGroupKey(group, key: key)
    }

    /// Admin only: add subscribers to a channel WITHOUT a rekey. The current epoch key
    /// goes to the new subscribers only, with the admins-only roster.
    func addSubscribers(_ contacts: [Contact], toChannel groupID: String) async {
        guard var group = groups[groupID], group.isChannel, group.isAdmin(identity),
              let key = GroupKeyStore.key(groupID: groupID, epoch: group.epoch) else { return }
        let present = Set(group.members.map { $0.fingerprint.hex })
        let additions = contacts
            .filter { !present.contains($0.fingerprint.hex) }
            .map { GroupMember(fingerprint: $0.fingerprint, armoredPublicKey: $0.publicKey.armored,
                               name: $0.name, isAdmin: false) }
        guard !additions.isEmpty else { return }
        group.members.append(contentsOf: additions)
        groups[groupID] = group
        persist()
        let payload = GroupKeyPayload(
            groupID: groupID, epoch: group.epoch,
            keyB64: key.withUnsafeBytes { Data($0) }.base64EncodedString(),
            name: group.name, members: group.admins, isChannel: true
        )
        for member in additions {
            await sendGroupKey(payload, to: member.publicKey, recipient: member.fingerprint)
        }
    }

    var identityFingerprint: Fingerprint { identity }

    func amGroupAdmin(_ groupID: String) -> Bool {
        groups[groupID]?.isAdmin(identity) ?? false
    }

    /// Admin only: add paired contacts to a group, rekey, and redistribute to all.
    @discardableResult
    func addMembers(_ contacts: [Contact], toGroup groupID: String) async -> [String] {
        guard var group = groups[groupID], group.isAdmin(identity) else { return [] }
        let present = Set(group.members.map { $0.fingerprint.hex })
        let additions = contacts
            .filter { !present.contains($0.fingerprint.hex) }
            .map { GroupMember(fingerprint: $0.fingerprint, armoredPublicKey: $0.publicKey.armored,
                               name: $0.name, isAdmin: false) }
        guard !additions.isEmpty else { return [] }
        // Anyone, already in the group or being added, who must update first:
        // nothing changes until they have.
        let blocked = rosterNeedingUpdate(group.members + additions)
        guard blocked.isEmpty else { return blocked }
        group.members.append(contentsOf: additions)
        group.epoch += 1
        let key = GroupKeyStore.newKey()
        GroupKeyStore.store(key, groupID: groupID, epoch: group.epoch)
        groups[groupID] = group
        persist()
        await distributeGroupKey(group, key: key)
        return []
    }

    /// Admin only: remove a member (not yourself), rekey, and redistribute to the
    /// remaining members. The removed member never receives the new epoch key.
    func removeMember(_ fingerprint: Fingerprint, fromGroup groupID: String) async {
        guard var group = groups[groupID], group.isAdmin(identity), fingerprint != identity else { return }
        group.members.removeAll { $0.fingerprint == fingerprint }
        group.epoch += 1
        let key = GroupKeyStore.newKey()
        GroupKeyStore.store(key, groupID: groupID, epoch: group.epoch)
        groups[groupID] = group
        persist()
        await distributeGroupKey(group, key: key)
    }

    /// Admin only: rename a group (no rekey; same epoch key, new name).
    func renameGroup(_ groupID: String, to name: String) async {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, var group = groups[groupID], group.isAdmin(identity),
              let key = GroupKeyStore.key(groupID: groupID, epoch: group.epoch) else { return }
        group.name = trimmed
        groups[groupID] = group
        persist()
        await distributeGroupKey(group, key: key)
    }

    /// Leave a group. If you are an admin, remove yourself and rekey the remaining
    /// members first, so your departure cuts you off cryptographically. Then delete
    /// the group and its keys locally.
    func leaveGroup(_ groupID: String) async {
        guard let group = groups[groupID] else { return }
        if group.isAdmin(identity) {
            var remaining = group
            remaining.members.removeAll { $0.fingerprint == identity }
            if !remaining.members.isEmpty {
                remaining.epoch += 1
                let key = GroupKeyStore.newKey()
                GroupKeyStore.store(key, groupID: groupID, epoch: remaining.epoch)
                await distributeGroupKey(remaining, key: key, includeSelf: false)
            }
        }
        GroupKeyStore.deleteGroup(groupID: groupID, throughEpoch: group.epoch + 1)
        sealedKeys.deleteGroupState(groupID)
        groups[groupID] = nil
        groupMessages[groupID] = nil
        persist()
        setDraft("", for: Self.groupDraftKey(groupID))
    }

    private func distributeGroupKey(_ group: ChatGroup, key: SymmetricKey, includeSelf: Bool = true) async {
        let keyB64 = key.withUnsafeBytes { Data($0) }.base64EncodedString()
        // In a channel, a subscriber receives the admins-only roster (enough to verify
        // who may post) and never the other subscribers.
        func payloadFor(_ recipient: Fingerprint) -> GroupKeyPayload {
            let roster = (group.isChannel && !group.isAdmin(recipient)) ? group.admins : group.members
            return GroupKeyPayload(groupID: group.groupID, epoch: group.epoch, keyB64: keyB64,
                                   name: group.name, members: roster, isChannel: group.isChannel)
        }
        NSLog("CPCHAN distribute group=%@ members=%d isChannel=%@ multiDevice=%@", String(group.groupID.suffix(8)), group.members.count, group.isChannel ? "1" : "0", multiDevice ? "1" : "0")
        for member in group.members where member.fingerprint != identity {
            await sendGroupKey(payloadFor(member.fingerprint), to: member.publicKey, recipient: member.fingerprint)
        }
        if multiDevice, includeSelf, let mine = ownPublicKey() {
            await sendGroupKey(payloadFor(identity), to: mine, recipient: identity)
        }
    }

    /// Send a group-key envelope (PGP-encrypted to one recipient), silent so it
    /// syncs without a banner.
    private func sendGroupKey(_ payload: GroupKeyPayload, to publicKey: PublicKey, recipient: Fingerprint) async {
        NSLog("CPCHAN key-send-enter to=%@ group=%@", String(recipient.hex.suffix(8)), String(payload.groupID.suffix(8)))
        guard let json = try? JSONEncoder().encode(payload) else {
            NSLog("CPCHAN key-send-FAIL to=%@ err=encode", String(recipient.hex.suffix(8)))
            return
        }
        let outgoing = OutgoingMessage(
            threadID: payload.groupID, text: nil,
            attachments: [OutgoingMessage.Attachment(filename: "group-key", mime: "application/json", data: json)],
            expiresAt: now + defaultTTL
        )
        do {
            let messageID = UUID().uuidString
            seenMessageIDs.insert(messageID)
            let envelope = try buildGroupEnvelope(outgoing, type: "group-key",
                                                  groupID: payload.groupID, epoch: payload.epoch,
                                                  to: publicKey, messageID: messageID)
            // Deliver over the same sealed-first path as messages: it posts to the
            // recipient's sealed mailbox (no relay identity auth, sender hidden) and
            // fires the Nostr/direct accelerators, falling back to the legacy
            // fingerprint-routed relay send only when the pair is not sealed yet.
            try await deliverToPeer(envelope, to: recipient, expiresAt: outgoing.expiresAt, silent: true)
            NSLog("CPCHAN key-send group=%@ to=%@ isChannel=%@", String(payload.groupID.suffix(8)), String(recipient.hex.suffix(8)), payload.isChannel ? "1" : "0")
        } catch {
            NSLog("CPCHAN key-send-FAIL to=%@ err=%@", String(recipient.hex.suffix(8)), String(describing: error))
        }
    }

    /// A group control/key envelope: CPN1 with a group manifest type, PGP
    /// sign+encrypted to the recipient. Mirrors buildControl but carries groupID
    /// and epoch and a caller-chosen type.
    private func buildGroupEnvelope(_ message: OutgoingMessage, type: String, groupID: String,
                                    epoch: Int, to recipient: PublicKey, messageID: String) throws -> Data {
        var meta: [Manifest.Part] = [Manifest.Part(kind: "control", mime: "application/json", filename: nil, size: nil)]
        let parts = message.attachments.map { $0.data }
        meta[0].size = parts.first?.count
        var manifest = Manifest(
            v: 1, type: type, messageID: messageID, threadID: message.threadID,
            sentAt: now, expiresAt: message.expiresAt, parts: meta
        )
        manifest.groupID = groupID
        manifest.epoch = epoch
        let container = CPN1.encode(manifest: try manifest.encoded(), parts: parts)
        return try crypto.signAndEncrypt(container, to: recipient)
    }

    /// Apply a received group-key envelope: store the epoch key and roster. A new
    /// group is accepted only from a creator listed as admin; an existing group
    /// only from a current admin, and only for an epoch at least as new as ours.
    private func applyGroupKey(_ incoming: IncomingMessage) {
        guard let data = incoming.files.first?.data ?? incoming.text.map({ Data($0.utf8) }),
              let payload = try? JSONDecoder().decode(GroupKeyPayload.self, from: data),
              let keyData = Data(base64Encoded: payload.keyB64) else {
            return
        }
        let senderIsSelf = incoming.sender == identity
        NSLog("CPCHAN key-recv group=%@ isChannel=%@ from=%@ known=%@", String(payload.groupID.suffix(8)), payload.isChannel ? "1" : "0", String(incoming.sender.hex.suffix(8)), groups[payload.groupID] != nil ? "1" : "0")
        if let existing = groups[payload.groupID] {
            guard senderIsSelf || existing.isAdmin(incoming.sender) else { return }
            guard payload.epoch >= existing.epoch else { return }
        } else {
            guard senderIsSelf
                || payload.members.contains(where: { $0.fingerprint == incoming.sender && $0.isAdmin }) else { return }
        }
        let priorEpoch = groups[payload.groupID]?.epoch
        let priorCreatedAt = groups[payload.groupID]?.createdAt
        GroupKeyStore.store(SymmetricKey(data: keyData), groupID: payload.groupID, epoch: payload.epoch)
        groups[payload.groupID] = ChatGroup(groupID: payload.groupID, name: payload.name,
                                            members: payload.members, epoch: payload.epoch, isChannel: payload.isChannel,
                                            createdAt: priorCreatedAt ?? now)
        NSLog("CPCHAN key-stored group=%@ isChannel=%@", String(payload.groupID.suffix(8)), payload.isChannel ? "1" : "0")
        // A newly joined group/channel (or a rekey) means our receive window for
        // this group's sealed address is not registered on the relay yet, and the
        // relay drops deposits to unregistered mailboxes. Force the next maintain
        // pass to re-register now instead of waiting up to 30s, so the admin's
        // first message is not lost to an unregistered mailbox.
        if priorEpoch == nil || payload.epoch > priorEpoch! { lastSealedWindowRefresh = .distantPast }
        persist()
    }

    static let groupMagic = Array("CPG1".utf8)

    /// Send a text message to a group: seal it once, fan out the identical payload
    /// to every member, plus a silent self-copy for my other devices.
    func sendGroupMessage(groupID: String, text: String, attachments: [OutgoingMessage.Attachment] = []) async {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (!trimmed.isEmpty || !attachments.isEmpty), let group = groups[groupID],
              let key = GroupKeyStore.key(groupID: groupID, epoch: group.epoch) else { return }
        if group.isChannel && !group.isAdmin(identity) { return }
        let messageID = UUID().uuidString
        let expiresAt = now + defaultTTL
        let container: Data
        do {
            container = try buildGroupContainer(text: trimmed.isEmpty ? nil : trimmed, attachments: attachments,
                                                groupID: groupID, epoch: group.epoch, messageID: messageID, expiresAt: expiresAt)
        } catch { lastError = describe(error); return }

        let storedAttachments = attachments.map { attachment -> ChatMessage.Attachment in
            let localPath = AttachmentStore.save(attachment.data, suggestedName: attachment.filename)
            return ChatMessage.Attachment(id: UUID().uuidString, filename: attachment.filename,
                                          mime: attachment.mime, size: attachment.data.count, localPath: localPath)
        }
        let local = ChatMessage(id: messageID, threadID: groupID, peer: identity, direction: .outgoing,
                                text: trimmed.isEmpty ? nil : trimmed, attachments: storedAttachments,
                                sentAt: now, expiresAt: expiresAt, isRead: true)
        seenMessageIDs.insert(messageID)
        appendGroupMessage(local, groupID: groupID)

        do {
            let box = try GroupCrypto.seal(container: container, groupID: groupID, sender: identity,
                                           epoch: group.epoch, key: key, crypto: crypto)
            var payload = Data(Self.groupMagic)
            payload.append(box)
            var recipients = group.members.map { $0.fingerprint }.filter { $0 != identity }
            if multiDevice { recipients.append(identity) }
            NSLog("CPCHAN send group=%@ isChannel=%@ recipients=%d", String(groupID.suffix(8)), group.isChannel ? "1" : "0", recipients.count)
            for recipient in recipients {
                let silent = recipient == identity
                // A member not yet known to be listening on its group address gets
                // the message by the per-contact path instead (GroupDelivery).
                // Decided before a group address is taken, so none is used up on a
                // member who cannot be listening. My own other devices are left as
                // they were.
                if recipient != identity, groupMemberUsesPeerPath(groupID: groupID, epoch: group.epoch, member: recipient) {
                    do {
                        try await deliverToPeer(payload, to: recipient, expiresAt: expiresAt, silent: silent)
                    } catch { lastError = describe(error) }
                    continue
                }
                if let address = sealedGroupSendAddress(groupID: groupID, epoch: group.epoch, recipient: recipient) {
                    // Relay is authoritative; Nostr and the direct transports run as
                    // best-effort accelerators so a channel/group message still lands
                    // when the relay is down or unreachable, the same model 1:1 and
                    // group-key delivery already use. Each transport is isolated so one
                    // failing does not skip the others or abort the remaining recipients.
                    _ = try? await relay.sealedSend(mailbox: address, envelope: payload, expiresAt: expiresAt, silent: silent)
                    let directs: [Transport] = [lanTransport, wanTransport].compactMap { $0 }.filter { $0.canReach(recipient) }
                    for d in directs { _ = try? await d.send(payload, to: recipient, mailbox: nil, expiresAt: expiresAt, silent: silent) }
                    if let nostr = nostrTransport, nostr.canReach(recipient) {
                        _ = try? await nostr.send(payload, to: recipient, mailbox: address, expiresAt: expiresAt, silent: silent)
                    }
                } else {
                    // No sealed group stream for this recipient yet: fall back to the
                    // shared per-peer delivery path instead of a relay-only send.
                    try? await deliverToPeer(payload, to: recipient, expiresAt: expiresAt, silent: silent)
                }
            }
        } catch { lastError = describe(error) }
    }

    private func buildGroupContainer(text: String?, attachments: [OutgoingMessage.Attachment], groupID: String,
                                     epoch: Int, messageID: String, expiresAt: Int) throws -> Data {
        var parts: [Data] = []
        var meta: [Manifest.Part] = []
        if let text {
            parts.append(Data(text.utf8))
            meta.append(Manifest.Part(kind: "text", mime: "text/plain; charset=utf-8", filename: nil, size: nil))
        }
        for attachment in attachments {
            parts.append(attachment.data)
            meta.append(Manifest.Part(kind: "file", mime: attachment.mime, filename: attachment.filename, size: attachment.data.count))
        }
        var manifest = Manifest(v: 1, type: "group-msg", messageID: messageID, threadID: groupID,
                                sentAt: now, expiresAt: expiresAt, parts: meta)
        manifest.groupID = groupID
        manifest.epoch = epoch
        return CPN1.encode(manifest: try manifest.encoded(), parts: parts)
    }

    /// Open a received group message: pick the group, decrypt with the epoch key,
    /// verify the sender against the roster, and file it. Returns false only when
    /// the failure is recoverable (a rekey we have not received yet), so the relay
    /// keeps the message for a retry.
    private func handleGroup(payload: Data) -> Bool {
        guard let box = try? JSONDecoder().decode(GroupSealedBox.self, from: payload) else {
            return true
        }
        guard let group = groups[box.groupID] else {
            // Group not known yet: its key envelope may not have arrived. Keep it on
            // the relay and retry, bounded by the message's own expiry.
            return false
        }
        let opened: (sender: Fingerprint, container: Data)
        do {
            opened = try GroupCrypto.open(payload: payload, group: group,
                                          keyFor: { GroupKeyStore.key(groupID: box.groupID, epoch: $0) },
                                          crypto: crypto)
        } catch {
            if case GroupCryptoError.noKey = error { return false }
            return true
        }
        guard let (manifestData, parts) = try? CPN1.decode(opened.container),
              let manifest = try? Manifest.decode(manifestData) else { return true }
        // A message from a member in the current epoch shows they hold its key
        // and are listening, so later messages to them need only the group address.
        if opened.sender != identity, manifest.epoch == group.epoch {
            noteGroupMemberHeard(groupID: box.groupID, epoch: group.epoch, member: opened.sender)
        }
        guard !seenMessageIDs.contains(manifest.messageID) else { return true }
        if manifest.expiresAt <= now { seenMessageIDs.insert(manifest.messageID); return true }
        NSLog("CPCHAN msg-recv group=%@ isChannel=%@ from=%@ adminOK=%@", String(box.groupID.suffix(8)), group.isChannel ? "1" : "0", String(opened.sender.hex.suffix(8)), group.isAdmin(opened.sender) ? "1" : "0")
        if group.isChannel && opened.sender != identity && !group.isAdmin(opened.sender) {
            // Channel: only admins may post. Drop anything else.
            seenMessageIDs.insert(manifest.messageID)
            return true
        }

        var text: String?
        var atts: [ChatMessage.Attachment] = []
        for (i, part) in manifest.parts.enumerated() where i < parts.count {
            switch part.kind {
            case "text":
                text = String(data: parts[i], encoding: .utf8)
            case "file":
                let filename = part.filename ?? "file"
                let localPath = AttachmentStore.save(parts[i], suggestedName: filename)
                atts.append(ChatMessage.Attachment(id: UUID().uuidString, filename: filename,
                                                   mime: part.mime ?? "application/octet-stream",
                                                   size: parts[i].count, localPath: localPath))
            default:
                break
            }
        }
        let message = ChatMessage(id: manifest.messageID, threadID: box.groupID, peer: opened.sender,
                                  direction: opened.sender == identity ? .outgoing : .incoming,
                                  text: text, attachments: atts, sentAt: manifest.sentAt,
                                  expiresAt: manifest.expiresAt, isRead: opened.sender == identity)
        seenMessageIDs.insert(manifest.messageID)
        appendGroupMessage(message, groupID: box.groupID)
        return true
    }

    /// Whether a group message to `member` goes by the per-contact path for
    /// now, recording when I first sent to them in this epoch.
    private func groupMemberUsesPeerPath(groupID: String, epoch: Int, member: Fingerprint) -> Bool {
        var state = sealedKeys.group(groupID) ?? SealedGroupState(epoch: epoch, sendCounters: [:], recvHighs: [:])
        if state.epoch != epoch { state = SealedGroupState(epoch: epoch, sendCounters: [:], recvHighs: [:]) }
        guard GroupDelivery.usePeerPath(state, member: member.hex, now: now) else { return false }
        if state.since[member.hex] == nil {
            state.since[member.hex] = now
            sealedKeys.setGroup(groupID, state)
        }
        return true
    }

    private func noteGroupMemberHeard(groupID: String, epoch: Int, member: Fingerprint) {
        var state = sealedKeys.group(groupID) ?? SealedGroupState(epoch: epoch, sendCounters: [:], recvHighs: [:])
        if state.epoch != epoch { state = SealedGroupState(epoch: epoch, sendCounters: [:], recvHighs: [:]) }
        if state.heard.insert(member.hex).inserted { sealedKeys.setGroup(groupID, state) }
    }

    private func appendGroupMessage(_ message: ChatMessage, groupID: String) {
        var list = groupMessages[groupID] ?? []
        guard !list.contains(where: { $0.id == message.id }) else { return }
        list.append(message)
        list.sort { $0.sentAt < $1.sentAt }
        groupMessages[groupID] = list
        persist()
    }

    private func emitControl(op: String, targetMessageID: String, threadID: String) async {
        guard let selfKey = ownPublicKey() else { return }
        let body = ControlOp(op: op, targetMessageID: targetMessageID, at: now)
        guard let json = try? JSONEncoder().encode(body) else { return }
        let controlMessage = OutgoingMessage(
            threadID: threadID,
            text: nil,
            attachments: [OutgoingMessage.Attachment(filename: "control", mime: "application/json", data: json)],
            expiresAt: now + 86400
        )
        do {
            let messageID = UUID().uuidString
            seenMessageIDs.insert(messageID)
            let envelope = try buildControl(controlMessage, to: selfKey, messageID: messageID)
            _ = try await relay.send(envelope: envelope, to: identity, expiresAt: controlMessage.expiresAt, silent: true)
        } catch {
            // Background self-copy op; retried later, no banner.
        }
    }

    private func buildControl(_ message: OutgoingMessage, to recipient: PublicKey, messageID: String) throws -> Data {
        // A control message is a normal envelope with manifest.type == "control".
        var meta: [Manifest.Part] = [Manifest.Part(kind: "control", mime: "application/json", filename: nil, size: nil)]
        let parts = message.attachments.map { $0.data }
        meta[0].size = parts.first?.count
        let manifest = Manifest(
            v: 1,
            type: "control",
            messageID: messageID,
            threadID: message.threadID,
            to: recipient.fingerprint.hex,
            sentAt: now,
            expiresAt: message.expiresAt,
            parts: meta
        )
        let container = CPN1.encode(manifest: try manifest.encoded(), parts: parts)
        return try crypto.signAndEncrypt(container, to: recipient)
    }

    struct ControlOp: Codable {
        let op: String
        let targetMessageID: String
        let at: Int
        var name: String?
        var mailboxKey: String?
        // WAN-direct (2.2) signaling: SDP for webrtc-offer/answer, candidate for webrtc-ice.
        var sdp: String?
        var candidate: String?
        // Broadcast-channel subscribe/unsubscribe (2.x Phase 2).
        var channelId: String?
        var pubkey: String?     // subscriber armored public key (channel-subscribe)
        var token: String?      // optional invite token (gated channels)
        // What the sender's app supports; on "profile" and "caps".
        var caps: PairingCaps.Stated?

        enum CodingKeys: String, CodingKey {
            case op
            case targetMessageID = "target_message_id"
            case at
            case name
            case mailboxKey = "mailbox_key"
            case sdp
            case candidate
            case channelId = "channel_id"
            case pubkey
            case token
            case caps
        }
    }

    // MARK: - Helpers

    private func appendToConversation(_ message: ChatMessage, peer: Fingerprint, peerName: String? = nil) {
        if var conversation = conversations[message.threadID] {
            guard !conversation.messages.contains(where: { $0.id == message.id }) else { return }
            conversation.messages.append(message)
            if let peerName { conversation.peerName = peerName }
            conversations[message.threadID] = conversation
            persist()
        } else {
            conversations[message.threadID] = Conversation(
                threadID: message.threadID,
                peer: peer,
                peerName: peerName ?? contactName(for: peer),
                messages: [message]
            )
            persist()
        }
    }

    private func setRead(messageID: String) {
        for (threadID, var conversation) in conversations {
            if let index = conversation.messages.firstIndex(where: { $0.id == messageID }) {
                conversation.messages[index].isRead = true
                conversations[threadID] = conversation
                persist()
                return
            }
        }
    }

    private func deleteMessage(id: String) {
        for (threadID, var conversation) in conversations {
            for message in conversation.messages where message.id == id {
                for attachment in message.attachments {
                    AttachmentStore.delete(attachment.localPath)
                }
            }
            conversation.messages.removeAll { $0.id == id }
            conversations[threadID] = conversation
        }
        persist()
    }

    private func pruneExpired() {
        let cutoff = now
        var changed = false
        for (threadID, var conversation) in conversations {
            let before = conversation.messages.count
            conversation.messages.removeAll { $0.expiresAt <= cutoff }
            if conversation.messages.count != before {
                conversations[threadID] = conversation
                changed = true
            }
        }
        // Runs on every poll. Writing the whole history to disk on the main actor
        // every 5 seconds, whether or not anything expired, was a steady stutter.
        if changed { persist() }
    }

    // MARK: - Persistence
    //
    // Conversations and messages are kept on disk so threads survive relaunch.
    // Stored per-identity (the filename carries the identity fingerprint), so a
    // different identity on the same device sees its own history and never the
    // previous one's. The domain value types aren't Codable, so we map to a small
    // Codable snapshot the way ContactStore does.

    private struct StoredAttachment: Codable {
        let id: String
        let filename: String
        let mime: String
        let size: Int
        let localPath: String
    }
    private struct StoredMessage: Codable {
        let id: String
        let threadID: String
        let peer: String
        let direction: String
        let text: String?
        let attachments: [StoredAttachment]
        let sentAt: Int
        let expiresAt: Int
        let isRead: Bool
        let viaLan: Bool?
    }
    private struct StoredConversation: Codable {
        let threadID: String
        let peer: String
        let peerName: String?
        let messages: [StoredMessage]
    }
    private struct Snapshot: Codable {
        let conversations: [StoredConversation]
        let seen: [String]
        let groups: [ChatGroup]?
        let groupThreads: [StoredGroupThread]?
    }

    private struct StoredGroupThread: Codable {
        let groupID: String
        let messages: [StoredMessage]
    }

    /// Anything on the main actor that took 50 ms or more, so a stutter can be
    /// traced in Console (filter CPPERF). Sizes and times only.
    private static func logSlow(_ what: String, since start: Date, bytes: Int = 0) {
        let ms = Int(Date().timeIntervalSince(start) * 1000)
        if ms >= 50 { NSLog("CPPERF %@ %dms bytes=%d", what, ms, bytes) }
    }

    private func persist() {
        let persistStarted = Date()
        let stored = conversations.values.map { convo in
            StoredConversation(
                threadID: convo.threadID,
                peer: convo.peer.hex,
                peerName: convo.peerName,
                messages: convo.messages.map { message in
                    StoredMessage(
                        id: message.id,
                        threadID: message.threadID,
                        peer: message.peer.hex,
                        direction: message.direction == .incoming ? "in" : "out",
                        text: message.text,
                        attachments: message.attachments.map {
                            StoredAttachment(id: $0.id, filename: $0.filename, mime: $0.mime, size: $0.size, localPath: $0.localPath)
                        },
                        sentAt: message.sentAt,
                        expiresAt: message.expiresAt,
                        isRead: message.isRead,
                        viaLan: message.viaLan
                    )
                }
            )
        }
        let storedGroupThreads = groupMessages.map { gid, msgs in
            StoredGroupThread(groupID: gid, messages: msgs.map { message in
                StoredMessage(
                    id: message.id, threadID: message.threadID, peer: message.peer.hex,
                    direction: message.direction == .incoming ? "in" : "out",
                    text: message.text,
                    attachments: message.attachments.map {
                        StoredAttachment(id: $0.id, filename: $0.filename, mime: $0.mime, size: $0.size, localPath: $0.localPath)
                    },
                    sentAt: message.sentAt, expiresAt: message.expiresAt, isRead: message.isRead, viaLan: message.viaLan
                )
            })
        }
        let snapshot = Snapshot(conversations: stored, seen: Array(seenMessageIDs), groups: Array(groups.values), groupThreads: storedGroupThreads)
        guard let data = try? JSONEncoder().encode(snapshot) else { return }
        // This file holds decrypted message history, so it was the least protected
        // thing on disk while contacts had file protection. Match the identity
        // Keychain's posture (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        // rather than .completeFileProtection: a push-triggered background refresh
        // can run while the device is locked, and complete protection would fail
        // the write and silently lose the message.
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        Self.logSlow("persist", since: persistStarted, bytes: data.count)
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let snapshot = try? JSONDecoder().decode(Snapshot.self, from: data) else {
            return
        }
        var restored: [String: Conversation] = [:]
        for stored in snapshot.conversations {
            guard let peer = Fingerprint(stored.peer) else { continue }
            let messages: [ChatMessage] = stored.messages.compactMap { message in
                guard let messagePeer = Fingerprint(message.peer) else { return nil }
                return ChatMessage(
                    id: message.id,
                    threadID: message.threadID,
                    peer: messagePeer,
                    direction: message.direction == "in" ? .incoming : .outgoing,
                    text: message.text,
                    attachments: message.attachments.map {
                        ChatMessage.Attachment(
                            id: $0.id,
                            filename: $0.filename,
                            mime: $0.mime,
                            size: $0.size,
                            localPath: $0.localPath
                        )
                    },
                    sentAt: message.sentAt,
                    expiresAt: message.expiresAt,
                    isRead: message.isRead,
                    viaLan: message.viaLan ?? false
                )
            }
            restored[stored.threadID] = Conversation(
                threadID: stored.threadID,
                peer: peer,
                peerName: stored.peerName,
                messages: messages
            )
        }
        conversations = restored
        seenMessageIDs = Set(snapshot.seen)
        for stored in snapshot.groups ?? [] {
            groups[stored.groupID] = stored
        }
        for thread in snapshot.groupThreads ?? [] {
            groupMessages[thread.groupID] = thread.messages.compactMap { message in
                guard let messagePeer = Fingerprint(message.peer) else { return nil }
                return ChatMessage(
                    id: message.id, threadID: message.threadID, peer: messagePeer,
                    direction: message.direction == "in" ? .incoming : .outgoing,
                    text: message.text,
                    attachments: message.attachments.map {
                        ChatMessage.Attachment(id: $0.id, filename: $0.filename, mime: $0.mime, size: $0.size, localPath: $0.localPath)
                    },
                    sentAt: message.sentAt, expiresAt: message.expiresAt, isRead: message.isRead, viaLan: message.viaLan ?? false
                )
            }
        }
    }

    private func ownPublicKey() -> PublicKey? {
        if let armored = try? crypto.armoredPublicKey() {
            return PublicKey(fingerprint: identity, armored: armored)
        }
        return nil
    }

    private func contactName(for fingerprint: Fingerprint) -> String? {
        contacts().first { $0.fingerprint == fingerprint }?.name
    }

    private var now: Int { Int(Date().timeIntervalSince1970) }

    private func describe(_ error: Error) -> String {
        if let relayError = error as? RelayError {
            return "relay \(relayError.status)\(relayError.code.map { ": \($0)" } ?? "")"
        }
        // The crypto and envelope errors carry no useful localizedDescription, so
        // name them here. Which one fired is the whole diagnosis: a signature
        // failure means we can't resolve the sender's key, a decryption failure
        // means the envelope wasn't for this identity.
        if let cryptoError = error as? CryptoError {
            switch cryptoError {
            case .noValidSignature: return "sender's key missing or signature invalid"
            case .decryptionFailed: return "not encrypted to this identity"
            case .notImplemented:   return "unsupported key type"
            }
        }
        if let envelopeError = error as? CPN1Error {
            switch envelopeError {
            case .badMagic:  return "not a CarrierPony envelope"
            case .truncated: return "envelope truncated"
            }
        }
        return error.localizedDescription
    }
}

#if DEBUG
// A self-contained preview engine so this file has no dependency on any
// preview/test helper that may not be in the app target. Frames the sender
// fingerprint ahead of the plaintext; no real cryptography. Previews only.
private final class PreviewCryptoEngine: CryptoEngine {
    let fingerprint: Fingerprint
    init(fingerprint: Fingerprint) { self.fingerprint = fingerprint }
    func armoredPublicKey() throws -> String { "" }
    func detachedSignature(over data: Data) throws -> String { "" }
    func signAndEncrypt(_ plaintext: Data, to recipient: PublicKey) throws -> Data {
        var out = Data()
        out.append(Data(fingerprint.hex.utf8))
        out.append(0x00)
        out.append(plaintext)
        return out
    }
    func decryptAndVerify(_ message: Data) throws -> VerifiedMessage {
        guard let separator = message.firstIndex(of: 0x00) else { throw CryptoError.decryptionFailed }
        let senderHex = String(data: Data(message[message.startIndex..<separator]), encoding: .utf8) ?? ""
        guard let sender = Fingerprint(senderHex) else { throw CryptoError.noValidSignature }
        return VerifiedMessage(sender: sender, plaintext: Data(message[message.index(after: separator)...]))
    }
    func decryptOnly(_ message: Data) throws -> Data {
        guard let separator = message.firstIndex(of: 0x00) else { throw CryptoError.decryptionFailed }
        return Data(message[message.index(after: separator)...])
    }
    func verifyDetached(signature: String, over data: Data, signerPublicKey: PublicKey) throws -> Bool { true }
}

extension ChatStore {

    /// Build a store wired to an inline preview engine and an unused relay,
    /// seeded with conversations, for SwiftUI previews. Never touches the network.
    static func preview(identity: Fingerprint, seeded: [Conversation] = []) -> ChatStore {
        let engine = PreviewCryptoEngine(fingerprint: identity)
        let store = ChatStore(
            identity: identity,
            relay: RelayClient(baseURL: "https://preview.invalid", crypto: engine, deviceID: "preview"),
            crypto: engine,
            sealedKeys: SealedKeyStore(identityHex: identity.hex),
            contacts: { [] },
            multiDevice: false
        )
        for convo in seeded {
            store.conversations[convo.threadID] = convo
        }
        return store
    }
}
#endif

// MARK: - Sealed sender wiring

// Roster-hiding delivery layered onto the existing 1:1 path. A pair becomes
// sealed once both sides have exchanged inbound mailbox keys (a control op sent
// over the legacy path, which also upgrades pairs made before 2.0). Sends then
// address an opaque rotating mailbox instead of a fingerprint; the inbox is
// polled by mailbox and mapped back to the peer. Self-copies and groups stay on
// the legacy path for now. See CarrierPony-2.0-SealedSender-Design.md.
extension ChatStore {

    /// Register this device on the relay's sealed side. Best-effort.
    /// Re-register the sealed device with the relay (e.g. once the gateway wake
    /// token is obtained), so its wake_token is attached without waiting for the
    /// next app start.
    func sealedReregisterDevice() async {
        await sealedEnsureDevice()
    }

    private func sealedEnsureDevice() async {
        do {
            try await relay.sealedRegisterDevice(sealedDeviceID: sealedDeviceID, deviceKey: sealedDeviceKey, wakeToken: AppConfig.storedWakeToken(for: identity.hex))
        } catch let error as RelayError where error.status == 401 {
            // The relay already first-claimed this sealed device_id under a key we
            // no longer hold (keychain reset, or a restore that split the id from
            // the key). Mint a fresh sealed identity and re-register; the old one
            // is orphaned and reaped. Clear the window map so it rebuilds under
            // the new id on the next refresh.
            sealedKeys.rotateDeviceIdentity()
            sealedAddressMap.removeAll()
            sealedRegistered.removeAll()
            lastSealedFullRegistration = .distantPast
            try? await relay.sealedRegisterDevice(sealedDeviceID: sealedDeviceID, deviceKey: sealedDeviceKey, wakeToken: AppConfig.storedWakeToken(for: identity.hex))
        } catch {
            // best-effort; sealed delivery just waits for the next refresh
        }
    }

    /// Window upkeep, after the poll: slide the windows, register what's new, retry
    /// the key handshake. Throttled, except right after a high-water mark moved.
    private func sealedMaintain() async {
        guard sealedAddressMap.isEmpty || sealedWindowsDirty
            || Date().timeIntervalSince(lastSealedWindowRefresh) > 30 else { return }
        sealedWindowsDirty = false
        lastSealedWindowRefresh = Date()
        await sealedRefreshWindows()
    }

    /// Route a peer-bound envelope: sealed when the pair is capable, else legacy.
    /// LAN-direct (2.1): the per-pair LAN key for each sealed-capable contact of
    /// this identity, keyed by lowercased fingerprint hex. A pair with no peer
    /// inbound key is not sealed-capable and is omitted (it stays relay-only).
    /// Used by the LAN identify handshake so a nearby random node can be matched
    /// to a known contact without revealing anything to a non-contact.
    func lanContactKeys() -> [String: Data] {
        var out: [String: Data] = [:]
        for c in contacts() {
            guard let st = sealedKeys.pair(c.fingerprint.hex),
                  let peer = st.peerInboundKey else { continue }
            out[c.fingerprint.hex.lowercased()] = LanCrypto.pairKey(myInbound: st.myInboundKey, peerInbound: peer)
        }
        return out
    }

    private func deliverToPeer(_ envelope: Data, to peer: Fingerprint, expiresAt: Int, silent: Bool) async throws {
        // The direct transports (LAN, then WAN) that can reach this peer right now.
        let directs: [Transport] = [lanTransport, wanTransport].compactMap { $0 }.filter { $0.canReach(peer) }

        // Direct-only mode (opt-in): deliver over a direct path and skip the relay
        // entirely. Fall back to the relay only if no direct path actually delivered,
        // so a message is never lost. The user accepted the cost (the peer's other
        // devices and offline delivery won't get it) by enabling it.
        if AppConfig.lanDirectSkipRelay, !directs.isEmpty {
            for d in directs {
                if (try? await d.send(envelope, to: peer, mailbox: nil, expiresAt: expiresAt, silent: silent)) == true { return }
            }
            // No direct path delivered: fall back to the relay, computing the sealed
            // address now so the counter only advances when a mailbox send happens.
            let mailbox = nextSealedAddress(for: peer)
            for transport in transports where transport.canReach(peer) {
                if try await transport.send(envelope, to: peer, mailbox: mailbox, expiresAt: expiresAt, silent: silent) { return }
            }
            return
        }

        // The relay is authoritative (store-and-forward, the peer's other devices,
        // offline delivery). The direct transports and Nostr run concurrently as
        // best-effort accelerators: all fire, the receiver dedupes by message id, and a
        // relay failure is tolerated only if an accelerator delivered - so a message
        // still lands when the relay is down but a direct path or Nostr is up. On relay
        // success the accelerators continue in the background (a WAN ARQ or a Nostr OK
        // can take seconds), so the send does not block on them. The sealed mailbox
        // address is computed once here and shared by the relay and Nostr, so both post
        // to the same slot and the send counter advances a single step.
        let mailbox = nextSealedAddress(for: peer)
        let directTask = Task { () -> Bool in
            for d in directs {
                if (try? await d.send(envelope, to: peer, mailbox: nil, expiresAt: expiresAt, silent: silent)) == true { return true }
            }
            return false
        }
        let nostrTask: Task<Bool, Never>? = {
            guard let nostr = nostrTransport, nostr.canReach(peer) else { return nil }
            return Task { (try? await nostr.send(envelope, to: peer, mailbox: mailbox, expiresAt: expiresAt, silent: silent)) == true }
        }()
        do {
            for transport in transports where transport.canReach(peer) {
                if try await transport.send(envelope, to: peer, mailbox: mailbox, expiresAt: expiresAt, silent: silent) { return }
            }
            _ = await directTask.value
            if let nostrTask { _ = await nostrTask.value }
        } catch {
            if await directTask.value { return }
            if let nostrTask, await nostrTask.value { return }
            throw error
        }
    }

    /// Next sealed mailbox address for a peer, advancing the shared send counter once.
    /// nil when the pair is not sealed-capable yet (no peer inbound key), so callers
    /// fall back to the legacy fingerprint-routed relay send.
    private func nextSealedAddress(for peer: Fingerprint) -> String? {
        guard var st = sealedKeys.pair(peer.hex), let peerKey = st.peerInboundKey else { return nil }
        let address = MailboxCrypto.address(key: peerKey, counter: st.sendCounter)
        st.sendCounter &+= 1
        sealedKeys.setPair(peer.hex, st)
        return address
    }

    /// Ingest one sealed envelope received over a direct transport (LAN), running
    /// it through the same open path as a relay-fetched envelope. Dedupe by
    /// message id is automatic, so a message that also arrives via the relay is
    /// filed once. No ack: there is no relay message to acknowledge.
    func ingestLanEnvelope(_ envelope: Data) {
        if envelope.starts(with: Self.groupMagic) {
            _ = handleGroup(payload: Data(envelope.dropFirst(Self.groupMagic.count)))
        } else {
            _ = handle(envelope: envelope, viaLan: true)
        }
    }

    /// Ingest one sealed event received over Nostr. Its mailbox address (the event's
    /// `t` tag) maps to the peer/counter through the same window the relay uses, so it
    /// opens through the normal path and advances the high-water mark exactly like a
    /// relay-fetched item - minus the ack, since Nostr has no message to acknowledge.
    /// Dedupe by message id is automatic, so a copy that also arrives via the relay is
    /// filed once.
    func ingestNostrEnvelope(mailbox: String, content: String) {
        // Nostr relays keep events and send them again on every subscribe and
        // reconnect, and each relay sends its own copy. One that already opened
        // is dropped here, before any decrypting. One that did not open is not
        // remembered, so it is tried again when it next arrives.
        let seenKey = "\(content.count):\(content.hashValue)"
        if nostrOpened.contains(seenKey) { return }
        guard let route = sealedAddressMap[mailbox],
              let envelope = Data(base64Encoded: content) else {
            NSLog("CPNOSTR INGEST mailbox=%@ mapped=no", String(mailbox.suffix(8)))
            return
        }
        let before = seenMessageIDs.count
        let opened: Bool
        if envelope.starts(with: Self.groupMagic) {
            opened = handleGroup(payload: Data(envelope.dropFirst(Self.groupMagic.count)))
        } else {
            opened = handle(envelope: envelope)
        }
        NSLog("CPNOSTR INGEST mailbox=%@ opened=%@ newlyFiled=%@", String(mailbox.suffix(8)), opened ? "YES" : "no", seenMessageIDs.count > before ? "YES" : "no")
        guard opened else { return }
        if nostrOpened.count >= 5000 { nostrOpened.removeAll(keepingCapacity: true) }
        nostrOpened.insert(seenKey)
        switch route {
        case .pair(let peer, let counter):
            if var st = sealedKeys.pair(peer.hex), counter > st.receiveHigh {
                st.receiveHigh = counter
                sealedKeys.setPair(peer.hex, st)
            }
        case .group(let groupID, let sender, let counter):
            if var gst = sealedKeys.group(groupID) {
                let cur = gst.recvHighs[sender.hex] ?? 0
                if counter > cur {
                    gst.recvHighs[sender.hex] = counter
                    sealedKeys.setGroup(groupID, gst)
                }
            }
        }
    }

    /// Ensure every contact has per-pair state, share our inbound key once, and
    /// register a rolling window of our receive addresses. Builds the
    /// address->(peer,counter) map the sealed inbox is routed through.
    /// Recover sealed delivery when a pair has desynced (a peer reinstalled before the
    /// self-heal shipped, so counters drifted past the window with no key change left to
    /// trip the realign). Regenerate our inbound key for every contact and reset our
    /// counters; peers see the new key and self-heal to zero, so delivery resumes with no
    /// re-pairing and no lost identity. Best-effort; runs a window refresh immediately.
    func resyncSealedKeys() async {
        for contact in contacts() where contact.fingerprint != DemoMode.fingerprint {
            var st = sealedKeys.pair(contact.fingerprint.hex)
                ?? SealedPairState(myInboundKey: sealedKeys.newPairKey(),
                                   peerInboundKey: nil, sendCounter: 0, receiveHigh: 0, sharedMine: false)
            st.myInboundKey = sealedKeys.newPairKey()
            st.sendCounter = 0
            st.receiveHigh = 0
            st.sharedMine = false
            sealedKeys.setPair(contact.fingerprint.hex, st)
        }
        sealedAddressMap.removeAll()
        NSLog("CPSEAL RESYNC regenerated my inbound keys and zeroed my send counters for all contacts")
        await sealedRefreshWindows()
        await sealedPollInbox()
    }

    /// Make sure every contact has per-pair state and build the address map for the
    /// current receive windows. No network: HMACs only, cheap enough to run before
    /// the first poll. Returns the registration batch for those windows.
    @discardableResult
    private func sealedBuildWindows() -> [[String: Any]] {
        let window: UInt64 = 64
        let expiresAt = now + defaultTTL
        var batch: [[String: Any]] = []
        var map: [String: SealedRoute] = [:]

        for contact in contacts() where contact.fingerprint != DemoMode.fingerprint {
            let st: SealedPairState
            if let existing = sealedKeys.pair(contact.fingerprint.hex) {
                st = existing
            } else {
                st = SealedPairState(myInboundKey: sealedKeys.newPairKey(),
                                     peerInboundKey: nil, sendCounter: 0, receiveHigh: 0, sharedMine: false)
                sealedKeys.setPair(contact.fingerprint.hex, st)
            }
            let low = st.receiveHigh > window ? st.receiveHigh - window : 0
            let high = st.receiveHigh + window
            var m = low
            while m <= high {
                let address = MailboxCrypto.address(key: st.myInboundKey, counter: m)
                batch.append(["mailbox": address, "expires_at": expiresAt])
                map[address] = .pair(contact.fingerprint, m)
                m &+= 1
            }
        }

        // Group streams: an inbound window per co-member per group, so a group
        // fan-out to my per-pair group address is delivered and mapped back.
        for (groupID, group) in groups {
            guard let key = GroupKeyStore.key(groupID: groupID, epoch: group.epoch) else { continue }
            let epochKey = key.withUnsafeBytes { Data($0) }
            var gst = sealedKeys.group(groupID) ?? SealedGroupState(epoch: group.epoch, sendCounters: [:], recvHighs: [:])
            if gst.epoch != group.epoch || sealedKeys.group(groupID) == nil {
                if gst.epoch != group.epoch { gst = SealedGroupState(epoch: group.epoch, sendCounters: [:], recvHighs: [:]) }
                sealedKeys.setGroup(groupID, gst)
            }
            for member in group.members where member.fingerprint != identity {
                let hw = gst.recvHighs[member.fingerprint.hex] ?? 0
                let low = hw > window ? hw - window : 0
                let high = hw + window
                var m = low
                while m <= high {
                    let address = MailboxCrypto.groupAddress(epochKey: epochKey, senderFprHex: member.fingerprint.hex, recipientFprHex: identity.hex, counter: m)
                    batch.append(["mailbox": address, "expires_at": expiresAt])
                    map[address] = .group(groupID, member.fingerprint, m)
                    m &+= 1
                }
            }
        }
        sealedAddressMap = map
        return batch
    }

    /// Window upkeep: rebuild the map, share our inbound key with contacts that
    /// lack it (throttled), and register only addresses the relay doesn't hold yet.
    /// A full re-registration runs every few hours to keep mailbox expiries fresh.
    private func sealedRefreshWindows() async {
        let batch = sealedBuildWindows()
        nostrSubscribe?(Array(sealedAddressMap.keys))

        if Date().timeIntervalSince(lastSealedHandshake) > 30 {
            lastSealedHandshake = Date()
            for contact in contacts() where contact.fingerprint != DemoMode.fingerprint {
                guard let st = sealedKeys.pair(contact.fingerprint.hex), !st.sharedMine else { continue }
                if await sealedSendMyKey(st.myInboundKey, to: contact) {
                    // Re-read after the await so a counter bump made meanwhile is kept.
                    var latest = sealedKeys.pair(contact.fingerprint.hex) ?? st
                    latest.sharedMine = true
                    sealedKeys.setPair(contact.fingerprint.hex, latest)
                }
            }
        }

        let full = Date().timeIntervalSince(lastSealedFullRegistration) > sealedFullRegistrationInterval
        let pending = full ? batch : batch.filter { !sealedRegistered.contains(($0["mailbox"] as? String) ?? "") }
        guard !pending.isEmpty else { return }
        NSLog("CPSEAL REG pending=%d full=%@", pending.count, full ? "yes" : "no")
        var registered: [String] = []
        var allOK = true
        var i = 0
        while i < pending.count {
            let chunk = Array(pending[i..<min(i + 500, pending.count)])
            do {
                _ = try await relay.sealedRegisterMailboxes(sealedDeviceID: sealedDeviceID, deviceKey: sealedDeviceKey, mailboxes: chunk)
                registered.append(contentsOf: chunk.compactMap { $0["mailbox"] as? String })
            } catch {
                allOK = false
                break
            }
            i += 500
        }
        if full && allOK {
            sealedRegistered = Set(registered)
            lastSealedFullRegistration = Date()
        } else {
            sealedRegistered.formUnion(registered)
        }
    }

    /// Send our inbound mailbox key to a peer as an encrypted control op, over the
    /// legacy path (the peer cannot seal to us until they hold it). Also the
    /// upgrade path for pairs created before 2.0.
    private func sealedSendMyKey(_ key: Data, to contact: Contact) async -> Bool {
        let threadID = Threading.pairwise(identity.hex, contact.fingerprint.hex)
        let body = ControlOp(op: "mailbox-key", targetMessageID: "", at: now, mailboxKey: key.base64EncodedString())
        guard let json = try? JSONEncoder().encode(body) else { return false }
        let controlMessage = OutgoingMessage(
            threadID: threadID,
            text: nil,
            attachments: [OutgoingMessage.Attachment(filename: "control", mime: "application/json", data: json)],
            expiresAt: now + 7 * 86400
        )
        do {
            let messageID = UUID().uuidString
            seenMessageIDs.insert(messageID)
            let envelope = try buildControl(controlMessage, to: contact.publicKey, messageID: messageID)
            _ = try await relay.send(envelope: envelope, to: contact.fingerprint, expiresAt: controlMessage.expiresAt, silent: true)
            return true
        } catch {
            return false
        }
    }

    /// Poll the sealed inbox, map each mailbox to its peer, open through the
    /// normal path, ack, and advance the peer's high-water mark.
    private func sealedPollInbox() async {
        // Envelopes that failed to open 3+ times are left out of most polls (every
        // 60th poll, about 5 minutes, retries them), so a stuck backlog can't keep new
        // messages behind it or stall the UI with repeated failing decrypts.
        sealedPollCount &+= 1
        let retryAll = sealedPollCount % 60 == 0
        let skip = retryAll ? [] : Array(sealedFailCounts.filter { $0.value >= 3 }.keys.prefix(200))
        do {
            let messages = try await relay.sealedInbox(sealedDeviceID: sealedDeviceID, deviceKey: sealedDeviceKey, skip: skip)
            NSLog("CPSEAL RX sealedInbox=%d mapSize=%d skip=%d", messages.count, sealedAddressMap.count, skip.count)
            var ackIDs: [String] = []
            for item in messages.prefix(maxPerRefresh) {
                await Task.yield()
                // The relay only stores to mailboxes registered to this device, so an
                // address outside the current map (an older window, a pre-resync key,
                // a previous group epoch) is still ours: open it rather than leaving it
                // to sit unacked until it expires. Only the high-water bump needs a route.
                let route = sealedAddressMap[item.mailbox]
                if route == nil {
                    NSLog("CPSEAL RX unmapped mbox=%@, opening anyway", String(item.mailbox.suffix(6)))
                }
                guard let envelope = Data(base64Encoded: item.envelope) else {
                    ackIDs.append(item.messageId)
                    continue
                }
                let opened: Bool
                if envelope.starts(with: Self.groupMagic) {
                    opened = handleGroup(payload: Data(envelope.dropFirst(Self.groupMagic.count)))
                } else {
                    opened = handle(envelope: envelope)
                }
                guard opened else {
                    sealedFailCounts[item.messageId, default: 0] += 1
                    continue
                }
                ackIDs.append(item.messageId)
                sealedFailCounts[item.messageId] = nil
                switch route {
                case .pair(let peer, let counter)?:
                    if var st = sealedKeys.pair(peer.hex), counter > st.receiveHigh {
                        st.receiveHigh = counter
                        sealedKeys.setPair(peer.hex, st)
                        sealedWindowsDirty = true
                    }
                case .group(let groupID, let sender, let counter)?:
                    if var gst = sealedKeys.group(groupID) {
                        let cur = gst.recvHighs[sender.hex] ?? 0
                        if counter > cur {
                            gst.recvHighs[sender.hex] = counter
                            sealedKeys.setGroup(groupID, gst)
                            sealedWindowsDirty = true
                        }
                    }
                case nil:
                    break
                }
            }
            if !ackIDs.isEmpty {
                _ = try await relay.sealedAck(sealedDeviceID: sealedDeviceID, deviceKey: sealedDeviceKey, messageIDs: ackIDs)
            }
            if sealedFailCounts.count > 500 { sealedFailCounts = sealedFailCounts.filter { $0.value >= 3 } }
        } catch {
            // best-effort; a sealed failure must not break legacy delivery
        }
    }

    /// A peer control op: a profile update or a sealed mailbox-key handshake.
    private func applyPeerControl(_ incoming: IncomingMessage) {
        guard let payload = incoming.files.first?.data ?? incoming.text.map({ Data($0.utf8) }),
              let control = try? JSONDecoder().decode(ControlOp.self, from: payload) else {
            return
        }
        // Whatever the op, a peer that states what its app supports is believed:
        // the envelope was signed by them. The latest statement wins.
        if let caps = control.caps?.caps { updatePeerCaps(incoming.sender, caps) }
        switch control.op {
        case "caps":
            break
        case "contact-request":
            // From someone who is already a contact there is nothing to ask:
            // both sides have each other. Their caps were taken above.
            break
        case "mailbox-key":
            if let b64 = control.mailboxKey, let key = Data(base64Encoded: b64) {
                sealedApplyPeerKey(sender: incoming.sender, key: key)
            }
        case "channel-unsubscribe":
            if let cid = control.channelId, var group = groups[cid], group.isAdmin(identity),
               group.members.contains(where: { $0.fingerprint == incoming.sender }) {
                group.members.removeAll { $0.fingerprint == incoming.sender }
                groups[cid] = group
                persist()
                NSLog("CPCHAN unsubscribe-recv channel=%@ from=%@", String(cid.suffix(8)), String(incoming.sender.hex.suffix(8)))
            }
        case "channel-subscribe":
            // Also reached here (not only via the decrypt-only bootstrap) when the
            // subscriber is already a known contact, so their envelope verifies and
            // opens normally instead of failing.
            if let cid = control.channelId, let pk = control.pubkey {
                applyChannelSubscribe(channelId: cid, subFpr: incoming.sender, subPubkey: pk, token: control.token)
            }
        case "webrtc-offer", "webrtc-answer", "webrtc-ice":
            onSignal?(incoming.sender.hex, control.op, control.sdp, control.candidate)
        default:
            applyContactProfile(incoming)
        }
    }

    // MARK: - Broadcast channel subscribe links (2.x Phase 2)
    //
    // A channel invite is a reusable CPCHAN1 link/QR the admin shares publicly. A
    // stranger who opens it seals a self-authenticating channel-subscribe to the
    // admin (decrypt-only on the admin side, since there is no pairing yet; the
    // payload carries the subscriber's own key and its fingerprint must hash to
    // it). The admin auto-accepts, adds the subscriber as a non-admin member, and
    // returns the admins-only channel key. No epoch rekey on join.

    /// Admin-only: a shareable CPCHAN1 invite for a channel I broadcast.
    func channelInvite(_ groupID: String) -> String? {
        guard let group = groups[groupID], group.isChannel, group.isAdmin(identity),
              let mine = ownPublicKey() else { return nil }
        return ChannelInvite(channelId: groupID, adminFingerprint: identity,
                             adminArmoredKey: mine.armored, token: nil, name: group.name).encoded()
    }

    /// True when this identity is v6 and the channel's admin is on an app from
    /// before 4.0, which could neither read the subscribe request nor be read
    /// by a v6 subscriber. Screens ask this first so they can say why.
    func channelAdminNeedsUpdate(_ invite: ChannelInvite) -> Bool {
        guard let admin = invite.adminFingerprint else { return false }
        return !PairingCaps.canPair(mine: identity, peer: admin, peerCaps: invite.caps)
    }

    /// Subscriber side: subscribe from an invite. Adds the admin as a contact so we
    /// can verify its posts, then seals a channel-subscribe to it. The channel
    /// appears once the admin returns its key.
    @discardableResult
    func subscribeToChannel(_ invite: ChannelInvite) async -> Bool {
        guard let adminFpr = Fingerprint(invite.f),
              let computed = OpenPGPKeyID.primaryFingerprint(armoredPublicKey: invite.k),
              computed == adminFpr.hex, adminFpr != identity,
              !channelAdminNeedsUpdate(invite),
              let mine = ownPublicKey() else { return false }
        let adminKey = PublicKey(fingerprint: adminFpr, armored: invite.k)
        // Only add the admin as a contact if we do not already know them; never
        // overwrite an existing contact (that would clobber their name/trust and
        // rename the existing conversation). The channel name is not their name.
        if !contacts().contains(where: { $0.fingerprint == adminFpr }) {
            addContact(Contact(fingerprint: adminFpr,
                               publicKey: PublicKey(fingerprint: adminFpr, armored: invite.k),
                               name: nil, trust: .unverified, caps: invite.caps))
        }
        let op = ControlOp(op: "channel-subscribe", targetMessageID: "", at: now,
                           channelId: invite.c, pubkey: mine.armored, token: invite.t)
        guard let json = try? JSONEncoder().encode(op) else { return false }
        let outgoing = OutgoingMessage(threadID: invite.c, text: nil,
            attachments: [OutgoingMessage.Attachment(filename: "control", mime: "application/json", data: json)],
            expiresAt: now + defaultTTL)
        do {
            let messageID = UUID().uuidString
            seenMessageIDs.insert(messageID)
            let envelope = try buildControl(outgoing, to: adminKey, messageID: messageID)
            // Deliver over the sealed-first path (sealed mailbox + Nostr) when we
            // already share a session with the admin, so they process it on Nostr
            // arrival instead of their next inbox poll (cuts the join delay). Falls
            // back to the legacy relay send for a brand-new admin contact.
            try await deliverToPeer(envelope, to: adminFpr, expiresAt: outgoing.expiresAt, silent: true)
            NSLog("CPCHAN subscribe-sent channel=%@ to=%@", String(invite.c.suffix(8)), String(adminFpr.hex.suffix(8)))
            return true
        } catch { lastError = describe(error); return false }
    }

    /// Subscriber side: unsubscribe. Best-effort tell each admin to drop us, then
    /// leave the channel locally.
    func unsubscribeFromChannel(_ groupID: String) async {
        guard let group = groups[groupID] else { return }
        if group.isAdmin(identity) { await leaveGroup(groupID); return }
        for adminMember in group.admins where adminMember.fingerprint != identity {
            let op = ControlOp(op: "channel-unsubscribe", targetMessageID: "", at: now, channelId: groupID)
            guard let json = try? JSONEncoder().encode(op) else { continue }
            let outgoing = OutgoingMessage(threadID: groupID, text: nil,
                attachments: [OutgoingMessage.Attachment(filename: "control", mime: "application/json", data: json)],
                expiresAt: now + defaultTTL)
            do {
                let messageID = UUID().uuidString
                seenMessageIDs.insert(messageID)
                let envelope = try buildControl(outgoing, to: adminMember.publicKey, messageID: messageID)
                try await deliverToPeer(envelope, to: adminMember.fingerprint, expiresAt: outgoing.expiresAt, silent: true)
            } catch { lastError = describe(error) }
        }
        GroupKeyStore.deleteGroup(groupID: groupID, throughEpoch: group.epoch + 1)
        sealedKeys.deleteGroupState(groupID)
        groups[groupID] = nil
        groupMessages[groupID] = nil
        persist()
        setDraft("", for: Self.groupDraftKey(groupID))
    }

    /// Admin side: open an un-verifiable envelope as a self-authenticating
    /// channel-subscribe (decrypt-only; the payload carries the subscriber's own
    /// key). Returns true when consumed (valid shape).
    private func tryChannelSubscribe(_ envelope: Data) -> Bool {
        guard let container = try? crypto.decryptOnly(envelope),
              let decoded = try? CPN1.decode(container),
              let manifest = try? Manifest.decode(decoded.manifest),
              manifest.type == "control",
              let part = decoded.parts.first,
              let op = try? JSONDecoder().decode(ControlOp.self, from: part),
              op.op == "channel-subscribe" else { return false }
        if seenMessageIDs.contains(manifest.messageID) { return true }
        guard let channelId = op.channelId, let pubkey = op.pubkey,
              let computed = OpenPGPKeyID.primaryFingerprint(armoredPublicKey: pubkey),
              let subFpr = Fingerprint(computed) else { return true }
        applyChannelSubscribe(channelId: channelId, subFpr: subFpr, subPubkey: pubkey, token: op.token)
        seenMessageIDs.insert(manifest.messageID)
        return true
    }

    /// Decrypt-only bootstrap for a pairing offer's responder. The envelope is
    /// encrypted to us but signed by a key we do not hold yet; the payload carries
    /// that key and the invite token. AppModel adds the contact only if the token is
    /// one this identity issued and the key hashes to a valid fingerprint, the same
    /// trust-on-first-use the relay's pair/status path gives. An op whose token we
    /// never issued is consumed, since it can never open. Mirrors Android.
    private func tryPairComplete(_ envelope: Data) -> Bool {
        guard let container = try? crypto.decryptOnly(envelope),
              let decoded = try? CPN1.decode(container),
              let manifest = try? Manifest.decode(decoded.manifest),
              manifest.type == "control",
              let part = decoded.parts.first,
              let op = try? JSONDecoder().decode(ControlOp.self, from: part),
              op.op == "pair-complete" else { return false }
        if seenMessageIDs.contains(manifest.messageID) { return true }
        seenMessageIDs.insert(manifest.messageID)
        guard let token = op.token, let pubkey = op.pubkey else { return true }
        let matched = pairComplete?(token, pubkey) ?? false
        NSLog("CarrierPony pair-complete token=%@ matched=%@", String(token.suffix(6)), matched ? "yes" : "no")
        if matched {
            lastSealedWindowRefresh = .distantPast
            persist()
        }
        return true
    }

    /// A contact request from someone this device does not know: they added my
    /// public key and ask to be added back. The envelope is encrypted to me and
    /// signed by a key I do not hold, so the op carries that key. Unlike the
    /// two bootstraps above, the op is believed only if the envelope's
    /// signature verifies under the key it carries; otherwise anyone could
    /// send a request that carries somebody else's key and name. Returns true
    /// when the envelope is dealt with for good (kept as a request, or never
    /// going to be one this app accepts), false to leave it for a retry.
    private func tryContactRequest(_ envelope: Data) -> Bool {
        guard let keep = contactRequest,
              let container = try? crypto.decryptOnly(envelope),
              let decoded = try? CPN1.decode(container),
              let manifest = try? Manifest.decode(decoded.manifest),
              manifest.type == "control",
              let part = decoded.parts.first,
              let op = try? JSONDecoder().decode(ControlOp.self, from: part),
              op.op == "contact-request" else { return false }
        if seenMessageIDs.contains(manifest.messageID) { return true }
        seenMessageIDs.insert(manifest.messageID)
        guard manifest.expiresAt > now, let pubkey = op.pubkey,
              case .usable(let key) = ContactKey.inspect(pubkey),
              key.fingerprint != identity else { return true }
        let signer = PublicKey(fingerprint: key.fingerprint, armored: key.armoredPublicKey)
        guard let verified = try? crypto.decryptAndVerify(envelope, signer: signer),
              verified.sender == key.fingerprint else {
            NSLog("CarrierPony contact-request from=%@ refused: not signed by the key it carries", String(key.fingerprint.hex.suffix(8)))
            return true
        }
        let kept = keep(key.fingerprint, key.armoredPublicKey, op.name, op.caps?.caps)
        NSLog("CarrierPony contact-request from=%@ kept=%@", String(key.fingerprint.hex.suffix(8)), kept ? "yes" : "no")
        return true
    }

    /// Admin auto-accept: add the subscriber (non-admin) and send it the admins-only
    /// channel key. No rekey. Idempotent.
    private func applyChannelSubscribe(channelId: String, subFpr: Fingerprint, subPubkey: String, token: String?) {
        guard var group = groups[channelId], group.isChannel, group.isAdmin(identity),
              subFpr != identity,
              OpenPGPKeyID.primaryFingerprint(armoredPublicKey: subPubkey) == subFpr.hex,
              let key = GroupKeyStore.key(groupID: channelId, epoch: group.epoch) else { return }
        let contact = Contact(fingerprint: subFpr,
                              publicKey: PublicKey(fingerprint: subFpr, armored: subPubkey),
                              name: nil, trust: .unverified)
        if !contacts().contains(where: { $0.fingerprint == subFpr }) { addContact(contact) }
        NSLog("CPCHAN subscribe-recv channel=%@ from=%@", String(channelId.suffix(8)), String(subFpr.hex.suffix(8)))
        if !group.members.contains(where: { $0.fingerprint == subFpr }) {
            group.members.append(GroupMember(fingerprint: subFpr, armoredPublicKey: subPubkey, name: nil, isAdmin: false))
            groups[channelId] = group
            persist()
        }
        let payload = GroupKeyPayload(groupID: channelId, epoch: group.epoch,
            keyB64: key.withUnsafeBytes { Data($0) }.base64EncodedString(),
            name: group.name, members: group.admins, isChannel: true)
        Task { await sendGroupKey(payload, to: contact.publicKey, recipient: subFpr) }
    }

    /// The next sealed group address for a recipient, from the epoch key, advancing
    /// this group's per-recipient send counter. Resets on epoch rotation.
    private func sealedGroupSendAddress(groupID: String, epoch: Int, recipient: Fingerprint) -> String? {
        guard let key = GroupKeyStore.key(groupID: groupID, epoch: epoch) else { return nil }
        let epochKey = key.withUnsafeBytes { Data($0) }
        var gst = sealedKeys.group(groupID) ?? SealedGroupState(epoch: epoch, sendCounters: [:], recvHighs: [:])
        if gst.epoch != epoch { gst = SealedGroupState(epoch: epoch, sendCounters: [:], recvHighs: [:]) }
        let counter = gst.sendCounters[recipient.hex] ?? 0
        let address = MailboxCrypto.groupAddress(epochKey: epochKey, senderFprHex: identity.hex, recipientFprHex: recipient.hex, counter: counter)
        gst.sendCounters[recipient.hex] = counter + 1
        sealedKeys.setGroup(groupID, gst)
        return address
    }

    /// Store a peer's inbound key so we can address them with sealed sends.
    private func sealedApplyPeerKey(sender: Fingerprint, key: Data) {
        var st = sealedKeys.pair(sender.hex)
            ?? SealedPairState(myInboundKey: sealedKeys.newPairKey(),
                               peerInboundKey: nil, sendCounter: 0, receiveHigh: 0, sharedMine: false)
        // A changed peer inbound key means the peer reset its sealed state (e.g. a
        // reinstall): its receive window restarted at 0 and it no longer holds our key.
        // Realign both counters to 0 so our sends land in its fresh window, and re-share
        // our own key so it can seal to us again. Without this a reset peer deadlocks -
        // our send counter stays ahead of its window forever.
        let healed = st.peerInboundKey != nil && st.peerInboundKey != key
        if healed {
            st.sendCounter = 0
            st.receiveHigh = 0
            st.sharedMine = false
        }
        st.peerInboundKey = key
        sealedKeys.setPair(sender.hex, st)
        NSLog("CPSEAL KEY peer=%@ healed=%@ (my sendCounter now %d)", String(sender.hex.suffix(8)), healed ? "YES" : "no", Int(st.sendCounter))
    }
}
