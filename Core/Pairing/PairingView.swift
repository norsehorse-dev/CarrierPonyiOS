import SwiftUI
import UIKit
import AVFoundation
import CoreImage.CIFilterBuiltins

// The pairing screen. Two ways in:
//   In person  — show/scan a QR; scanning verifies the key against its claimed
//                fingerprint face to face, so the contact lands verified.
//   Remotely   — create an invite to send over a channel you trust (the invite
//                carries your fingerprint), or enter one you received. Remote
//                pairs immediately but unverified; the safety number upgrades it.

struct PairingView: View {

    let app: AppModel
    var onFinished: (() -> Void)? = nil
    /// A key file another app opened with CarrierPony.
    var incomingKey: IncomingKey? = nil
    @Environment(\.dismiss) private var dismiss
    @State private var answering = false
    @State private var requestNeedsUpdate = false
    @State private var showingIncoming = false

    var body: some View {
        NavigationStack {
            if let identity = app.identity {
                List {
                    if !waitingRequests.isEmpty {
                        Section {
                            ForEach(waitingRequests) { request in
                                ContactRequestRow(
                                    request: request,
                                    enabled: !answering,
                                    onAccept: { accept(request) },
                                    onDecline: { app.declineContactRequest(request) }
                                )
                            }
                            if requestNeedsUpdate {
                                Text("This contact is on an older CarrierPony. Ask them to update to version 4.0 or later, then pair again.")
                                    .font(.footnote).foregroundStyle(.red)
                            }
                        } header: {
                            Text("Contact requests")
                        } footer: {
                            Text("They added you by your public key. Accepting adds them as an unverified contact.")
                        }
                    }

                    Section("In person") {
                        NavigationLink {
                            MyCodeView(app: app, identity: identity, onFinished: finish)
                        } label: {
                            Label("Show my code", systemImage: "qrcode")
                        }
                        NavigationLink {
                            ScanView(app: app, onFinished: finish)
                        } label: {
                            Label("Scan a code", systemImage: "qrcode.viewfinder")
                        }
                    }

                    Section("Remotely") {
                        NavigationLink {
                            InviteCreateView(app: app, onFinished: finish)
                        } label: {
                            Label("Create an invite", systemImage: "envelope")
                        }
                        NavigationLink {
                            InviteEnterView(app: app, onFinished: finish)
                        } label: {
                            Label("Enter an invite", systemImage: "tray.and.arrow.down")
                        }
                        NavigationLink {
                            AddByKeyView(app: app, onFinished: finish)
                        } label: {
                            Label("Add by public key", systemImage: "person.badge.plus")
                        }
                    }

                    Section {
                        Text("Pairing in person verifies you face to face. A remote invite connects you right away; compare the safety number afterward to mark the contact verified.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }

                    #if DEBUG
                    if let other = otherDevIdentity {
                        Section("Debug") {
                            Button {
                                addDevContact(other)
                            } label: {
                                Text("Pair with \(other.name) (dev, no camera)")
                                    .foregroundStyle(CPTheme.accent)
                            }
                        }
                    }
                    #endif
                }
                .navigationDestination(isPresented: $showingIncoming) {
                    AddByKeyView(app: app, onFinished: finish, incoming: incomingKey)
                }
                .onAppear { if incomingKey != nil { showingIncoming = true } }
                .onChange(of: incomingKey) { _, key in
                    if key != nil { showingIncoming = true }
                }
            } else {
                Text("No identity yet.")
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Pair")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button("Done") { dismiss() }.tint(CPTheme.accent)
            }
        }
    }

    // Someone who became a contact some other way no longer needs an answer.
    private var waitingRequests: [ContactRequest] {
        app.contactRequests.requests.filter { request in
            !app.contactStore.contacts.contains { $0.fingerprint == request.fingerprint }
        }
    }

    private func accept(_ request: ContactRequest) {
        requestNeedsUpdate = false
        answering = true
        Task {
            defer { answering = false }
            do {
                try await app.acceptContactRequest(request)
            } catch PairingError.peerNeedsUpdate {
                requestNeedsUpdate = true
            } catch {
                // A request whose key does not check out is dropped by the model.
            }
        }
    }

    private func finish() {
        if let onFinished {
            onFinished()
        } else {
            dismiss()
        }
    }

    #if DEBUG
    private var otherDevIdentity: (name: String, identity: Identity)? {
        guard let me = app.identity, let alice = DevIdentity.alice, let bob = DevIdentity.bob else { return nil }
        if me.fingerprint == alice.fingerprint { return ("Bob", bob) }
        if me.fingerprint == bob.fingerprint { return ("Alice", alice) }
        return nil
    }

    private func addDevContact(_ other: (name: String, identity: Identity)) {
        let contact = Contact(
            fingerprint: other.identity.fingerprint,
            publicKey: PublicKey(fingerprint: other.identity.fingerprint, armored: other.identity.armoredPublicKey),
            name: other.name,
            trust: .verified
        )
        app.contactStore.add(contact)
        dismiss()
    }
    #endif
}

// One waiting contact request: who is asking, the end of their fingerprint to
// tell two people of the same name apart, and the two answers.
private struct ContactRequestRow: View {
    let request: ContactRequest
    let enabled: Bool
    let onAccept: () -> Void
    let onDecline: () -> Void

    private var tail: String {
        let hex = String(request.fingerprint.hex.suffix(8))
        return String(hex.prefix(4)) + " " + String(hex.suffix(4))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("\(request.name ?? tail) wants to connect")
                .font(.body)
            Text("Fingerprint ends in \(tail)")
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
            HStack(spacing: 12) {
                Button("Accept", action: onAccept)
                    .buttonStyle(.borderedProminent)
                    .tint(CPTheme.accent)
                Button("Decline", role: .destructive, action: onDecline)
                    .buttonStyle(.bordered)
            }
            .disabled(!enabled)
        }
        .padding(.vertical, 4)
    }
}

// Shown under a v6 identity's own code or invite: apps before 4.0 cannot use it.
private struct NeedsFourNote: View {
    var body: some View {
        Text("The other person needs CarrierPony 4.0 or later to use this code.")
            .font(.footnote)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .padding(.horizontal, 20)
    }
}

// Copy or share this identity's public key, for someone who will add it with
// Add by public key. Share hands over a file named after the key, so it can be
// saved to Files as well as sent.
private struct MyKeyButtons: View {
    let identity: Identity

    @State private var copied = false
    @State private var fileURL: URL?

    var body: some View {
        HStack(spacing: 12) {
            Button {
                UIPasteboard.general.string = identity.armoredPublicKey
                copied = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
            } label: {
                Label(copied ? LocalizedStringKey("Copied") : LocalizedStringKey("Copy my public key"), systemImage: copied ? "checkmark" : "doc.on.doc")
                    .font(.footnote.weight(.semibold)).multilineTextAlignment(.center).lineLimit(2).minimumScaleFactor(0.85)
                    .frame(maxWidth: .infinity).padding(.vertical, 10).padding(.horizontal, 8)
                    .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Color(.secondarySystemBackground))).foregroundStyle(CPTheme.accent)
            }
            if let fileURL {
                ShareLink(item: fileURL) {
                    Label("Share my public key", systemImage: "square.and.arrow.up")
                        .font(.footnote.weight(.semibold)).multilineTextAlignment(.center).lineLimit(2).minimumScaleFactor(0.85)
                        .frame(maxWidth: .infinity).padding(.vertical, 10).padding(.horizontal, 8)
                        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Color(.secondarySystemBackground))).foregroundStyle(CPTheme.accent)
                }
            }
        }
        .task { fileURL = Self.writeKeyFile(identity) }
    }

    private static func writeKeyFile(_ identity: Identity) -> URL? {
        let name = ContactKey.fileName(armoredPublicKey: identity.armoredPublicKey, fingerprint: identity.fingerprint)
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        do {
            try Data(identity.armoredPublicKey.utf8).write(to: url, options: .atomic)
            return url
        } catch {
            return nil
        }
    }
}

// MARK: - Add by public key

private struct AddByKeyView: View {
    let app: AppModel
    var onFinished: (() -> Void)? = nil
    /// A key file another app opened with CarrierPony. It is checked and shown
    /// in the box; adding it is still the person's own tap.
    var incoming: IncomingKey? = nil

    @State private var text = ""
    @State private var working = false
    @State private var showingFile = false
    @State private var added: Contact?
    @State private var error: LocalizedStringKey?

    private var canAdd: Bool {
        !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !working
    }

    var body: some View {
        Group {
            if let added {
                ScrollView {
                    PairedContactView(
                        app: app,
                        contact: added,
                        subtitle: "Request sent. You can write to them now, and they'll see your messages once they accept. This contact is unverified until you compare the safety number.",
                        onFinished: onFinished
                    )
                    .padding(24)
                }
            } else {
                formView
            }
        }
        .navigationTitle("Add by Public Key")
        .navigationBarTitleDisplayMode(.inline)
        .fileImporter(isPresented: $showingFile, allowedContentTypes: [.item], allowsMultipleSelection: false) { result in
            loadFile(result)
        }
        .task(id: incoming?.id) { loadIncoming() }
    }

    private func loadIncoming() {
        guard let incoming else { return }
        guard let data = incoming.data else {
            error = "Couldn't read that file."
            return
        }
        switch ContactKey.inspect(data) {
        case .usable(let key):
            added = nil
            text = key.armoredPublicKey
            error = nil
        case .secretKey:
            error = "That is a private key. Never give a private key to anyone. Ask the other person for their public key."
        case .notAKey:
            error = "That doesn't look like a public key."
        case .unsupported:
            error = "CarrierPony can't use this kind of key. Ask the other person for the public key from their CarrierPony app."
        }
    }

    private var formView: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Paste the other person's CarrierPony public key, or open it from a file. They get a request to add you back.")
                    .font(.subheadline).foregroundStyle(.secondary)

                if app.identity?.fingerprint.isV6 == true {
                    Text("The other person needs CarrierPony 4.0 or later to see your request.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                TextEditor(text: $text)
                    .font(.system(.footnote, design: .monospaced))
                    .frame(minHeight: 140)
                    .scrollContentBackground(.hidden)
                    .padding(8)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .background(RoundedRectangle(cornerRadius: 10).fill(Color(.secondarySystemBackground)))
                    .onChange(of: text) { error = nil }

                HStack(spacing: 12) {
                    Button {
                        if let pasted = UIPasteboard.general.string {
                            text = pasted
                            error = nil
                        }
                    } label: {
                        Label("Paste", systemImage: "doc.on.clipboard")
                    }
                    Button {
                        showingFile = true
                    } label: {
                        Label("Open a file", systemImage: "folder")
                    }
                    .disabled(working)
                    Spacer()
                    Button("Clear") {
                        text = ""
                        error = nil
                    }
                    .disabled(text.isEmpty)
                }
                .font(.subheadline.weight(.semibold))
                .buttonStyle(.bordered)
                .controlSize(.small)
                .lineLimit(1)
                .tint(CPTheme.accent)

                Button {
                    Task { await add(Data(text.utf8)) }
                } label: {
                    Group {
                        if working {
                            ProgressView().tint(.white)
                        } else {
                            Text("Add contact").font(.body.weight(.semibold))
                        }
                    }
                    .frame(maxWidth: .infinity).padding(.vertical, 14)
                    .background(Capsule().fill(canAdd ? CPTheme.accent : Color(.systemGray4)))
                    .foregroundStyle(.white)
                }
                .disabled(!canAdd)

                if let error {
                    Text(error).font(.footnote).foregroundStyle(.red)
                }
            }
            .padding(24)
        }
    }

    // A key file can be armored text or binary, so it is handed over as bytes
    // and not shown in the box.
    private func loadFile(_ result: Result<[URL], Error>) {
        guard case .success(let urls) = result, let url = urls.first else { return }
        guard let data = ContactKey.read(fileAt: url) else {
            error = "Couldn't read that file."
            return
        }
        Task { await add(data) }
    }

    private func add(_ input: Data) async {
        error = nil
        working = true
        defer { working = false }
        switch await app.addContactByKey(input) {
        case .added(let contact):
            added = contact
        case .alreadyContact(let contact):
            let who = contact.displayName ?? String(contact.fingerprint.hex.suffix(8))
            error = "\(who) is already in your contacts."
        case .secretKey:
            text = ""
            error = "That is a private key. Never give a private key to anyone. Ask the other person for their public key."
        case .notAKey:
            error = "That doesn't look like a public key."
        case .unsupported:
            error = "CarrierPony can't use this kind of key. Ask the other person for the public key from their CarrierPony app."
        case .ownKey:
            error = "That is your own key."
        case .notOnRelay:
            error = "Nobody with this key is on the relay you use. Check that they have set up CarrierPony with this key."
        case .couldNotSend:
            error = "Couldn't send the request. Check your connection and try again."
        case .notReady:
            error = "Couldn't add contact"
        }
    }
}

// MARK: - My code (in person)

private struct MyCodeView: View {
    let app: AppModel
    let identity: Identity
    var onFinished: (() -> Void)? = nil

    @State private var invite: Invite?
    @State private var inviteText: String?
    @State private var paired: Contact?
    @State private var offline = false

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                if let paired {
                    PairedContactView(
                        app: app,
                        contact: paired,
                        subtitle: "Verified in person. You scanned in person and the connection completed, so this contact is confirmed.",
                        onFinished: onFinished
                    )
                } else if let inviteText {
                    liveCode(inviteText)
                } else if offline {
                    staticCode
                } else {
                    ProgressView("Preparing your code…").padding(.top, 40)
                }
            }
            .padding(24)
        }
        .navigationTitle("My Code")
        .navigationBarTitleDisplayMode(.inline)
        .task { await run() }
    }

    private func liveCode(_ text: String) -> some View {
        VStack(spacing: 16) {
            qrCard(text)
            fingerprintBlock
            if identity.fingerprint.isV6 { NeedsFourNote() }
            MyKeyButtons(identity: identity)
            HStack(spacing: 8) {
                ProgressView()
                Text("Waiting for them to scan…").font(.subheadline).foregroundStyle(.secondary)
            }
            .padding(.top, 4)
            Text("Have the other person scan this with Scan a code. When they do, you're both connected and verified — no need to scan theirs.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 20)
        }
    }

    private var staticCode: some View {
        VStack(spacing: 16) {
            if let encoded = staticPayload { qrCard(encoded) }
            fingerprintBlock
            if identity.fingerprint.isV6 { NeedsFourNote() }
            MyKeyButtons(identity: identity)
            Text("You're offline, so this is a static key code. The other person must also show theirs, and you each scan the other's.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 20)
        }
    }

    private func qrCard(_ text: String) -> some View {
        Group {
            if let image = QRImage.make(from: text) {
                Image(uiImage: image)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 240, height: 240)
                    .padding(16)
                    .background(RoundedRectangle(cornerRadius: 20, style: .continuous).fill(.white))
                    .overlay(RoundedRectangle(cornerRadius: 20, style: .continuous).stroke(CPTheme.hairline))
            } else {
                Text("Couldn't generate code")
                    .foregroundStyle(.secondary)
                    .frame(width: 240, height: 240)
            }
        }
    }

    private var fingerprintBlock: some View {
        VStack(spacing: 4) {
            Text("Your fingerprint")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(groupedFingerprint(identity.fingerprint))
                .font(.system(.footnote, design: .monospaced))
                .multilineTextAlignment(.center)
        }
    }

    private var staticPayload: String? {
        PairingPayload(
            fingerprint: identity.fingerprint,
            name: nil,
            armoredPublicKey: identity.armoredPublicKey
        ).encoded()
    }

    private func run() async {
        // Persist the offer (inPerson) so the offerer's side still completes from
        // the background sweep if this screen closes before the on-screen poll
        // catches the scan. Otherwise the shower silently half-pairs: the scanner
        // gets our key from pair/accept, but we never collect theirs.
        let created: Invite
        do {
            (created, _) = try await app.createRememberedInvite(inPerson: true)
        } catch {
            // Only a failure to CREATE the offer means we're offline: fall back to
            // a static key QR, which requires each person to scan the other.
            offline = true
            return
        }
        invite = created
        inviteText = created.encoded()
        while paired == nil && !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            if Task.isCancelled { break }
            // A transient poll failure (network blip, or the offer already
            // completed by the background sweep) must not drop the live code to
            // the offline fallback; swallow it and retry on the next tick.
            if let contact = try? await app.pollInvite(created) {
                // They scanned in person and the relay round trip completed:
                // upgrade to verified on this (the shower's) side.
                app.contactStore.markVerified(contact.fingerprint)
                var verified = contact
                verified.trust = .verified
                paired = verified
                break
            }
        }
    }
}

// MARK: - Scan (in person)

private struct ScanView: View {
    let app: AppModel
    var onFinished: (() -> Void)? = nil
    @Environment(\.dismiss) private var dismiss
    @State private var result: ScanResult?

    enum ScanResult: Identifiable {
        case added(String)
        case invalid
        case needsUpdate
        var id: String {
            switch self {
            case .added(let who): return "added-\(who)"
            case .invalid: return "invalid"
            case .needsUpdate: return "needs-update"
            }
        }
    }

    var body: some View {
        ScanTab(onScan: handleScan)
            .ignoresSafeArea(edges: .bottom)
            .navigationTitle("Scan")
            .navigationBarTitleDisplayMode(.inline)
            .alert(item: $result) { result in
                switch result {
                case .added(let who):
                    return Alert(
                        title: Text("Verified contact added"),
                        message: Text("\(who) is now in your contacts, verified. Start a message from the compose button."),
                        dismissButton: .default(Text("OK")) {
                            if let onFinished { onFinished() } else { dismiss() }
                        }
                    )
                case .invalid:
                    return Alert(
                        title: Text("Couldn't add contact"),
                        message: Text("That QR code isn't a valid CarrierPony key, or its fingerprint doesn't match its key."),
                        dismissButton: .default(Text("OK"))
                    )
                case .needsUpdate:
                    return Alert(
                        title: Text("Couldn't add contact"),
                        message: Text("This contact is on an older CarrierPony. Ask them to update to version 4.0 or later, then pair again."),
                        dismissButton: .default(Text("OK"))
                    )
                }
            }
    }

    private func handleScan(_ code: String) {
        // A live invite QR (one-scan in-person pairing): accept it, verified,
        // since the fingerprint travelled physically via the scan.
        if let invite = Invite.decode(code) {
            Task {
                do {
                    let contact = try await app.acceptInvite(invite, trust: .verified)
                    result = .added(contact.displayName ?? shortFingerprint(contact.fingerprint))
                } catch PairingError.peerNeedsUpdate {
                    result = .needsUpdate
                } catch {
                    result = .invalid
                }
            }
            return
        }
        // Otherwise a static key QR: add as verified (also scanned in person).
        guard let payload = PairingPayload.decode(code),
              var contact = payload.verifiedContact() else {
            result = .invalid
            return
        }
        // The code says what their app supports; keep it with the contact.
        contact.caps = payload.caps
        // The same rule as for an invite: a v6 identity does not add a contact
        // whose app could not add it back.
        if let mine = app.identity?.fingerprint,
           !PairingCaps.canPair(mine: mine, peer: contact.fingerprint, peerCaps: payload.caps) {
            result = .needsUpdate
            return
        }
        app.contactStore.add(contact)
        result = .added(contact.displayName ?? shortFingerprint(contact.fingerprint))
    }
}

// MARK: - Create invite (remote)

private struct InviteCreateView: View {
    let app: AppModel
    var onFinished: (() -> Void)? = nil

    @State private var invite: Invite?
    @State private var inviteText: String?
    @State private var paired: Contact?
    @State private var error: String?
    @State private var copied = false
    @State private var expiresAt: Date?

    var body: some View {
        ScrollView {
            VStack(spacing: 18) {
                if let paired {
                    PairedContactView(app: app, contact: paired, subtitle: "This contact is unverified. To be sure no one is in the middle, compare the safety number with them.", onFinished: onFinished)
                } else if let error {
                    VStack(spacing: 12) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 40)).foregroundStyle(.orange)
                        Text(error).font(.subheadline).foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .padding(.top, 30)
                } else if let inviteText, let invite {
                    waitingView(inviteText, invite)
                } else {
                    ProgressView("Creating your invite…").padding(.top, 40)
                }
            }
            .padding(24)
        }
        .navigationTitle("Create an Invite")
        .navigationBarTitleDisplayMode(.inline)
        .task { await run() }
    }

    private func waitingView(_ text: String, _ invite: Invite) -> some View {
        VStack(spacing: 16) {
            if let img = QRImage.make(from: text) {
                Image(uiImage: img)
                    .interpolation(.none).resizable().scaledToFit()
                    .frame(width: 200, height: 200)
                    .padding(14)
                    .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(.white))
                    .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(CPTheme.hairline))
            }

            Text("Send this invite to the other person over a channel you trust. It works as a link they paste, or a code they scan.")
                .font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)

            if app.identity?.fingerprint.isV6 == true { NeedsFourNote() }

            ScrollView {
                Text(text)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
            }
            .frame(maxHeight: 120)
            .background(RoundedRectangle(cornerRadius: 10).fill(Color(.secondarySystemBackground)))

            HStack(spacing: 12) {
                Button {
                    UIPasteboard.general.string = text
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                } label: {
                    Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                        .font(.body.weight(.semibold)).frame(maxWidth: .infinity).padding(.vertical, 12)
                        .background(Capsule().fill(Color(.secondarySystemBackground))).foregroundStyle(CPTheme.accent)
                }
                ShareLink(item: text) {
                    Label("Share", systemImage: "square.and.arrow.up")
                        .font(.body.weight(.semibold)).frame(maxWidth: .infinity).padding(.vertical, 12)
                        .background(Capsule().fill(Color(.secondarySystemBackground))).foregroundStyle(CPTheme.accent)
                }
            }

            HStack(spacing: 8) {
                ProgressView()
                Text("Waiting for them to accept…").font(.subheadline).foregroundStyle(.secondary)
            }
            .padding(.top, 6)

            VStack(spacing: 6) {
                Text("You can close this screen. When they accept, they'll show up in your contacts.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                if let expiresAt {
                    Text("This invite expires \(expiresAt.formatted(.relative(presentation: .named))).")
                        .font(.footnote)
                        .foregroundStyle(.tertiary)
                        .multilineTextAlignment(.center)
                }
            }
        }
    }

    private func run() async {
        let created: Invite
        let expiry: Date?
        do {
            (created, expiry) = try await app.createRememberedInvite()
        } catch let e as PairingError {
            error = e.errorDescription
            return
        } catch {
            self.error = "Couldn't reach the relay. Check your connection and try again."
            return
        }
        invite = created
        inviteText = created.encoded()
        expiresAt = expiry
        while paired == nil && !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            if Task.isCancelled { break }
            // A transient poll failure (or the offer already completed by the
            // background sweep) must not surface as a create error; retry quietly.
            if let contact = try? await app.pollInvite(created) {
                paired = contact
                break
            }
        }
    }
}

// MARK: - Enter invite (remote)

private struct InviteEnterView: View {
    let app: AppModel
    var onFinished: (() -> Void)? = nil

    @State private var text = ""
    @State private var scanning = false
    @State private var working = false
    @State private var paired: Contact?
    @State private var error: String?
    @State private var needsUpdate = false

    private var canPair: Bool {
        !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !working
    }

    var body: some View {
        Group {
            if let paired {
                ScrollView {
                    PairedContactView(app: app, contact: paired, subtitle: "This contact is unverified. Compare the safety number with them to be sure the connection is secure.", onFinished: onFinished)
                }
                .scrollDismissesKeyboard(.interactively)
            } else if scanning {
                ScanTab(onScan: { code in
                    scanning = false
                    text = code
                    Task { await accept() }
                })
                .ignoresSafeArea(edges: .bottom)
            } else {
                formView
            }
        }
        .navigationTitle("Enter an Invite")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var formView: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Paste an invite you received, or scan the sender's code.")
                    .font(.subheadline).foregroundStyle(.secondary)

                ScrollView {
                    TextEditor(text: $text)
                        .font(.system(.footnote, design: .monospaced))
                        .frame(minHeight: 120)
                        .scrollContentBackground(.hidden)
                        .padding(8)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .keyboardType(.asciiCapable)
                }
                .frame(maxHeight: 160)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color(.secondarySystemBackground)))
                .overlay(alignment: .topLeading) {
                    if text.isEmpty {
                        Text("CPPAIR1:…").font(.system(.footnote, design: .monospaced))
                            .foregroundStyle(.tertiary).padding(16).allowsHitTesting(false)
                    }
                }

                HStack {
                    Button {
                        if let clip = UIPasteboard.general.string { text = clip }
                    } label: {
                        Label("Paste", systemImage: "doc.on.clipboard")
                    }
                    Spacer()
                    Button(role: .destructive) {
                        text = ""
                        error = nil
                    } label: {
                        Label("Clear", systemImage: "xmark.circle")
                    }
                    .disabled(text.isEmpty)
                }
                .font(.subheadline.weight(.semibold))

                Button { Task { await accept() } } label: {
                    Group {
                        if working { ProgressView().tint(.white) }
                        else { Text("Pair").font(.body.weight(.semibold)) }
                    }
                    .foregroundStyle(.white).frame(maxWidth: .infinity).padding(.vertical, 13)
                    .background(Capsule().fill(CPTheme.send)).opacity(canPair ? 1 : 0.5)
                }
                .disabled(!canPair)

                Button { scanning = true } label: {
                    Label("Scan a code instead", systemImage: "qrcode.viewfinder")
                        .font(.subheadline.weight(.semibold)).foregroundStyle(CPTheme.accent)
                }
                .frame(maxWidth: .infinity)

                if needsUpdate {
                    Text("This contact is on an older CarrierPony. Ask them to update to version 4.0 or later, then pair again.")
                        .font(.footnote).foregroundStyle(.red)
                } else if let error {
                    Text(error).font(.footnote).foregroundStyle(.red)
                }
            }
            .padding(24)
        }
    }

    private func accept() async {
        error = nil
        needsUpdate = false
        working = true
        defer { working = false }
        if DemoMode.matches(text) {
            if let contact = app.startDemo() {
                paired = contact
            } else {
                error = "Create an identity first, then try the demo code again."
            }
            return
        }
        guard let invite = Invite.decode(text) else {
            error = PairingError.malformedInvite.errorDescription
            return
        }
        do {
            paired = try await app.acceptInvite(invite)
        } catch PairingError.peerNeedsUpdate {
            needsUpdate = true
        } catch let e as PairingError {
            error = e.errorDescription
        } catch {
            self.error = "Couldn't pair. Check the invite and your connection."
        }
    }
}

// MARK: - Safety number / verify

private struct PairedContactView: View {
    let app: AppModel
    let contact: Contact
    let subtitle: String
    var onFinished: (() -> Void)? = nil

    @State private var nickname: String = ""
    @State private var prefilled = false

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle.fill").font(.system(size: 52)).foregroundStyle(CPTheme.accent)
            Text("Paired with \(contact.displayName ?? shortFingerprint(contact.fingerprint))")
                .font(.title3.bold()).multilineTextAlignment(.center)

            VStack(alignment: .leading, spacing: 6) {
                Text("Name this contact").font(.subheadline.weight(.medium))
                TextField("Name (optional)", text: $nickname)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.words)
                    .autocorrectionDisabled()
                    .submitLabel(.done)
                Text("A private label only you see. You know who you just paired with, so give them a name.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(.top, 2)

            Text(LocalizedStringKey(subtitle))
                .font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)

            NavigationLink {
                SafetyNumberView(app: app, contact: contact, onFinished: onFinished)
            } label: {
                Text("Verify with safety number")
                    .font(.body.weight(.semibold)).foregroundStyle(.white)
                    .frame(maxWidth: .infinity).padding(.vertical, 13)
                    .background(Capsule().fill(CPTheme.send))
            }
            .simultaneousGesture(TapGesture().onEnded { commit() })

            Button("Done") { commit(); onFinished?() }
                .font(.body.weight(.semibold)).foregroundStyle(CPTheme.accent)
        }
        .padding(.top, 20)
        .padding(.horizontal, 24)
        .onAppear {
            if !prefilled { nickname = contact.displayName ?? ""; prefilled = true }
        }
        .onDisappear { commit() }
    }

    private func commit() {
        app.contactStore.setNickname(contact.fingerprint, nickname: nickname)
    }

    private func shortFingerprint(_ fp: Fingerprint) -> String {
        let hex = fp.hex
        guard hex.count >= 8 else { return hex }
        let tail = String(hex.suffix(8))
        return stride(from: 0, to: tail.count, by: 4)
            .map { String(tail[tail.index(tail.startIndex, offsetBy: $0)..<tail.index(tail.startIndex, offsetBy: min($0 + 4, tail.count))]) }
            .joined(separator: " ")
    }
}


struct SafetyNumberView: View {
    let app: AppModel
    let contact: Contact
    var onFinished: (() -> Void)? = nil
    @Environment(\.dismiss) private var dismiss
    @State private var verified = false

    var body: some View {
        ScrollView {
            VStack(spacing: 18) {
                Text("Safety number")
                    .font(.headline)
                Text("Compare this number with \(contact.displayName ?? "your contact") over a call or in person. If it matches on both devices, no one is intercepting your messages.")
                    .font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)

                if let me = app.identity {
                    Text(SafetyNumber.grouped(me.fingerprint, contact.fingerprint))
                        .font(.system(.title3, design: .monospaced))
                        .multilineTextAlignment(.center)
                        .padding(18)
                        .frame(maxWidth: .infinity)
                        .background(RoundedRectangle(cornerRadius: 14).fill(Color(.secondarySystemBackground)))
                }

                if verified || contact.trust == .verified {
                    Label("Verified", systemImage: "checkmark.seal.fill")
                        .font(.body.weight(.semibold)).foregroundStyle(CPTheme.accent)
                } else {
                    Button {
                        app.contactStore.markVerified(contact.fingerprint)
                        verified = true
                        if let onFinished {
                            onFinished()
                        } else {
                            dismiss()
                        }
                    } label: {
                        Text("Mark as Verified")
                            .font(.body.weight(.semibold)).foregroundStyle(.white)
                            .frame(maxWidth: .infinity).padding(.vertical, 13)
                            .background(Capsule().fill(CPTheme.send))
                    }
                    Text("Only mark verified after you've compared the number and it matches.")
                        .font(.caption).foregroundStyle(.tertiary).multilineTextAlignment(.center)
                }
            }
            .padding(24)
        }
        .navigationTitle("Verify")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Scan camera surface (shared)

private struct ScanTab: View {
    let onScan: (String) -> Void
    @State private var authorized = AVCaptureDevice.authorizationStatus(for: .video) == .authorized
    @State private var denied = AVCaptureDevice.authorizationStatus(for: .video) == .denied

    var body: some View {
        Group {
            if authorized {
                ZStack {
                    QRScannerView(onScan: onScan)
                    RoundedRectangle(cornerRadius: 24, style: .continuous)
                        .stroke(.white.opacity(0.9), lineWidth: 3)
                        .frame(width: 220, height: 220)
                }
            } else if denied {
                permissionDenied
            } else {
                Color.black.task { await requestAccess() }
            }
        }
    }

    private var permissionDenied: some View {
        VStack(spacing: 12) {
            Image(systemName: "camera.fill").font(.largeTitle).foregroundStyle(.secondary)
            Text("Camera access is off").font(.headline)
            Text("Enable camera access in Settings to scan a code.")
                .font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)
            Button("Open Settings") {
                if let url = URL(string: UIApplication.openSettingsURLString) {
                    UIApplication.shared.open(url)
                }
            }
            .tint(CPTheme.accent)
        }
        .padding(40)
    }

    private func requestAccess() async {
        let granted = await AVCaptureDevice.requestAccess(for: .video)
        authorized = granted
        denied = !granted
    }
}

// MARK: - QR generation

enum QRImage {
    static func make(from string: String) -> UIImage? {
        let context = CIContext()
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}

// MARK: - Fingerprint helpers (file-scoped)

private func shortFingerprint(_ fp: Fingerprint) -> String {
    let hex = fp.hex
    guard hex.count >= 8 else { return hex }
    return String(hex.suffix(8))
}

private func groupedFingerprint(_ fp: Fingerprint) -> String {
    let hex = fp.hex
    return stride(from: 0, to: hex.count, by: 4).map {
        let start = hex.index(hex.startIndex, offsetBy: $0)
        let end = hex.index(hex.startIndex, offsetBy: min($0 + 4, hex.count))
        return String(hex[start..<end])
    }.joined(separator: " ")
}
