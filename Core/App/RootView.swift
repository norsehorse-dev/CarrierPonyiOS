import SwiftUI

// The app's root. Owns the AppModel, chooses between onboarding (no identity yet)
// and the inbox (identity present), and drives the polling lifecycle from scene
// phase: poll while active, stop in the background.

struct RootView: View {

    @State private var app = AppModel()
    @Environment(\.scenePhase) private var scenePhase
    #if DEBUG
    // A screenshot launch (DemoSeed) can start on the Files tab or Pairing.
    @State private var tab = DemoSeed.startTab
    @State private var showingPairing = DemoSeed.startPairing
    #else
    @State private var tab = 0
    @State private var showingPairing = false
    #endif
    @State private var showingBackup = false
    @State private var showingProfile = false
    @State private var showingImport = false
    @State private var showingSettings = false
    @State private var showingAddAccount = false
    /// A key file another app opened with CarrierPony. It waits here through
    /// the lock screen and onboarding, then opens Add by Public Key.
    @State private var waitingKey: IncomingKey?
    @State private var pairingKey: IncomingKey?

    var body: some View {
        ZStack {
            Group {
                if let store = app.store, let identity = app.identity, app.onboardingComplete {
                    TabView(selection: $tab) {
                        ConversationListView(
                            store: store,
                            contacts: app.contactStore.contacts,
                            onPair: { showingPairing = true },
                            onBackup: { showingBackup = true },
                            onSignOut: { app.signOut() },
                            onUnpair: { app.contactStore.remove($0) },
                            onEditProfile: { showingProfile = true },
                            onSetNickname: { app.contactStore.setNickname($0, nickname: $1) },
                            onImport: { showingImport = true },
                            onSettings: { showingSettings = true },
                            accounts: app.accounts(),
                            activeFingerprintHex: app.activeFingerprintHex,
                            onSwitchAccount: { app.switchAccount($0) },
                            onAddAccount: { showingAddAccount = true },
                            accountUnread: app.accountUnread,
                            contactRequests: app.contactRequests.requests.filter { request in
                                !app.contactStore.contacts.contains { $0.fingerprint == request.fingerprint }
                            }.count
                        )
                        .tabItem { Label("Messages", systemImage: "bubble.left.and.bubble.right.fill") }
                        .tag(0)

                        FilesView(store: store, contacts: app.contactStore.contacts)
                            .tabItem { Label("Files", systemImage: "folder.fill") }
                            .tag(1)
                    }
                    .sheet(isPresented: $showingPairing) {
                        PairingView(app: app, onFinished: { showingPairing = false }, incomingKey: pairingKey)
                    }
                    .onChange(of: showingPairing) { _, showing in
                        if !showing { pairingKey = nil }
                    }
                    .sheet(isPresented: $showingBackup) {
                        BackupView(identity: identity)
                    }
                    .sheet(isPresented: $showingProfile) {
                        EditProfileView(app: app)
                    }
                    .sheet(isPresented: $showingImport) {
                        ImportKeyView(app: app)
                    }
                    .sheet(isPresented: $showingSettings) {
                        SettingsView(app: app)
                    }
                    .sheet(isPresented: $showingAddAccount) {
                        AddAccountView(app: app)
                    }
                } else {
                    OnboardingView(app: app)
                }
            }

            if app.identity != nil && app.appLock.isLocked {
                LockView(app: app).transition(.opacity)
            }
        }
        .environment(\.locale, Locale(identifier: app.appLanguage))
        // start() registers the device, refreshes, then registers for push, in that
        // order. Calling enablePush() alongside it (as this used to) raced device
        // registration and usually lost, submitting the push token for a device the
        // relay had never seen. That failure was swallowed and never retried.
        .task {
            app.lockForBackground()
            if !app.appLock.isLocked { await app.start() }
        }
        .onChange(of: app.appLock.isLocked) { _, locked in
            if !locked {
                Task { await app.start() }
                showWaitingKey()
            }
        }
        .onChange(of: app.onboardingComplete) { _, _ in showWaitingKey() }
        .onOpenURL { url in
            guard url.isFileURL else { return }
            waitingKey = IncomingKey(data: ContactKey.read(fileAt: url))
            ContactKey.removeInboxCopy(url)
            showWaitingKey()
        }
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .active:
                if !app.appLock.isLocked {
                    PushService.shared.clearDelivered()
                    Task { await app.start() }
                }
            case .background:
                app.stop()
                app.lockForBackground()
            default:
                break
            }
        }
        .onChange(of: app.appLock.isLocked) { _, locked in
            if !locked, scenePhase == .active { PushService.shared.clearDelivered() }
        }
    }

    /// Opens Add by Public Key with the waiting key, once the app is unlocked
    /// and set up. Another sheet that is open is closed first, since only one
    /// can show at a time.
    private func showWaitingKey() {
        guard let key = waitingKey, !app.appLock.isLocked,
              app.identity != nil, app.onboardingComplete else { return }
        waitingKey = nil
        let otherSheetOpen = showingBackup || showingProfile || showingImport || showingSettings || showingAddAccount
        showingBackup = false
        showingProfile = false
        showingImport = false
        showingSettings = false
        showingAddAccount = false
        pairingKey = key
        if otherSheetOpen {
            Task {
                try? await Task.sleep(for: .milliseconds(600))
                showingPairing = true
            }
        } else {
            showingPairing = true
        }
    }
}

#if DEBUG
// A self-contained tour of the real screens (inbox -> thread -> composer) with
// seeded conversations and contacts, backed by the preview store. No identity,
// no relay, no persistence — DEBUG only, purely to see the UI on-device.
struct DemoContainerView: View {

    @Binding var isPresented: Bool

    private let store: ChatStore
    private let contacts: [Contact]

    init(isPresented: Binding<Bool>) {
        _isPresented = isPresented

        let me = Fingerprint("A18FB667413300FDB671D9A8B401BB207C264787")!
        let mayaFP = Fingerprint("4891888765D64C5161D27B04E1E90899E8D16282")!
        let leoFP = Fingerprint("AACECD2CFCEB3213723E94A81D4D2FBCBB6271D4")!

        let maya = Contact(fingerprint: mayaFP, publicKey: PublicKey(fingerprint: mayaFP, armored: ""), name: "Maya")
        let leo = Contact(fingerprint: leoFP, publicKey: PublicKey(fingerprint: leoFP, armored: ""), name: "Leo")
        contacts = [maya, leo]

        let now = Int(Date().timeIntervalSince1970)
        func msg(_ id: String, _ peer: Fingerprint, _ dir: MessageDirection, _ text: String, _ ago: Int, read: Bool = true) -> ChatMessage {
            ChatMessage(id: id, threadID: Threading.pairwise(me.hex, peer.hex), peer: peer, direction: dir,
                        text: text, attachments: [], sentAt: now - ago, expiresAt: now + 30 * 86400, isRead: read)
        }
        let convos = [
            Conversation(threadID: Threading.pairwise(me.hex, mayaFP.hex), peer: mayaFP, peerName: "Maya", messages: [
                msg("1", mayaFP, .incoming, "did the v6 detached sig test pass?", 7200),
                msg("2", mayaFP, .outgoing, "yep, green. Sequoia verified it too", 7100),
                msg("3", mayaFP, .incoming, "the icon looks great btw", 300, read: false),
            ]),
            Conversation(threadID: Threading.pairwise(me.hex, leoFP.hex), peer: leoFP, peerName: "Leo", messages: [
                msg("4", leoFP, .outgoing, "pushed the Nexopera preview branch", 90_000),
            ]),
        ]
        store = ChatStore.preview(identity: me, seeded: convos)
    }

    var body: some View {
        ZStack(alignment: .topTrailing) {
            ConversationListView(store: store, contacts: contacts)
            Button {
                isPresented = false
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.title2)
                    .foregroundStyle(.secondary)
                    .padding(12)
            }
        }
    }
}
#endif

// MARK: - Edit profile

struct EditProfileView: View {
    let app: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var name: String = ""

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 16) {
                Text("Your display name is shown to people you pair with, so they see a name instead of your fingerprint. Leave it blank to stay anonymous — then only your fingerprint is shared.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                TextField("Display name (optional)", text: $name)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.words)
                    .autocorrectionDisabled()

                Spacer()
            }
            .padding(24)
            .navigationTitle("Profile")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Save") {
                        app.setProfileName(name)
                        dismiss()
                    }
                    .fontWeight(.semibold)
                }
            }
            .onAppear { name = app.profileName ?? "" }
        }
    }
}

// MARK: - Add account

// Add a second (or third) account without running the whole first-run
// onboarding. It always creates or imports a FRESH identity, even though one is
// already active; setIdentity() switches the running stack to the new one. When
// the active account changes (create, import, or restore succeeded) the view
// dismisses itself. Reached from Settings > Account and the inbox switcher.
struct AddAccountView: View {
    let app: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var creating = false
    @State private var createError: String?
    @State private var showingImport = false
    @State private var showingRestore = false

    private let startFingerprint: String?

    init(app: AppModel) {
        self.app = app
        self.startFingerprint = app.activeFingerprintHex
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Display name (optional)", text: $name)
                        .textInputAutocapitalization(.words)
                        .autocorrectionDisabled()
                        .disabled(creating)
                    Button {
                        Task { await create() }
                    } label: {
                        HStack {
                            Label("Create Identity", systemImage: "plus.circle")
                            Spacer()
                            if creating { ProgressView() }
                        }
                    }
                    .disabled(creating)
                } footer: {
                    Text("Separate accounts keep their messages and contacts apart on this device. They don't hide from the relay that both come from the same device and network, so anyone watching the relay could still tell they're linked.")
                }

                Section {
                    Button { showingImport = true } label: {
                        Label("Import a Key", systemImage: "square.and.arrow.down")
                    }
                    Button { showingRestore = true } label: {
                        Label("Restore from Backup", systemImage: "arrow.uturn.backward")
                    }
                }
                .disabled(creating)

                if let createError {
                    Section {
                        Text(createError).foregroundStyle(.red).font(.callout)
                    }
                }
            }
            .navigationTitle("Add Account")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { Button("Cancel") { dismiss() } }
            }
            .sheet(isPresented: $showingImport) { ImportKeyView(app: app) }
            .sheet(isPresented: $showingRestore) { ImportBackupView(app: app) }
            .onChange(of: app.activeFingerprintHex) { _, newValue in
                if newValue != startFingerprint { dismiss() }
            }
        }
    }

    private func create() async {
        createError = nil
        creating = true
        defer { creating = false }
        let displayName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            try await app.createIdentity(
                name: displayName.isEmpty ? "CarrierPony User" : displayName,
                email: "user@carrierpony.app"
            )
        } catch {
            createError = "Couldn't create an identity. Please try again."
        }
    }
}
