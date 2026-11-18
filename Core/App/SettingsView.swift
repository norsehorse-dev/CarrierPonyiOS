import SwiftUI

// The settings screen, opened from the gear in the inbox. It gathers the account
// actions that used to live in the top-left menu (edit profile, pair, back up,
// import, sign out), the app lock, links to the other Pony apps and the crypto core,
// and the reset controls.

struct SettingsView: View {
    let app: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var showingProfile = false
    @State private var showingPairing = false
    @State private var showingBackup = false
    @State private var showingImport = false
    @State private var confirmSignOut = false
    @State private var confirmResetOnboarding = false
    @State private var confirmResetApp = false
    @State private var accountsList: [AppModel.AccountSummary] = []
    @State private var pendingRemove: AppModel.AccountSummary?
    @State private var showingAddAccount = false
    @State private var lanDirectOn = AppConfig.lanDirectEnabled
    @State private var lanSkipRelayOn = AppConfig.lanDirectSkipRelay
    @State private var wanDirectOn = AppConfig.wanDirectEnabled
    @State private var nostrOn = AppConfig.nostrEnabled
    @State private var confirmResync = false
    @State private var resyncing = false
    @State private var resyncDoneShown = false

    private let apps: [(name: String, subtitle: String, url: String)] = [
        ("PGPony", "OpenPGP for iPhone", "https://apps.apple.com/us/app/pgpony/id6759994432"),
        ("AgePony", "age & SSH encryption", "https://apps.apple.com/us/app/agepony/id6774821172"),
        ("QuorumPony", "Split-key backup", "https://apps.apple.com/us/app/quorumpony-key-backup/id6783608628"),
        ("BurnPony", "Self-destructing encrypted messages", "https://apps.apple.com/us/app/burnpony/id6788513233"),
        ("RelayPony", "Encrypted file transfer", "https://apps.apple.com/us/app/relaypony-file-transfer/id6785085525"),
        ("ScrubPony", "Strip metadata from your files", "https://scrubpony.app"),
        ("VaultPony", "Encrypted vault for your files", "https://vaultpony.app"),
        ("PassPony", "Password manager", "https://passpony.app"),
        ("TapPony", "NFC tags to webhooks", "https://tappony.app"),
        ("HashPony", "File checksums", "https://hashpony.app"),
        ("StegPony", "Hide messages in photos", "https://stegpony.app"),
        ("See the full pony family", "Every NorseHorse app in one place", "https://pony.norsehor.se")
    ]

    var body: some View {
        NavigationStack {
            Form {
                Section("Account") {
                    ForEach(accountsList) { acct in
                        Button {
                            if acct.fingerprint.hex != app.activeFingerprintHex {
                                dismiss(); app.switchAccount(acct.fingerprint.hex)
                            }
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(acct.name ?? shortHex(acct.fingerprint.hex)).foregroundStyle(.primary)
                                    Text(shortHex(acct.fingerprint.hex)).font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                if acct.fingerprint.hex == app.activeFingerprintHex {
                                    Image(systemName: "checkmark").foregroundStyle(Color.accentColor)
                                } else if (app.accountUnread[acct.fingerprint.hex] ?? 0) > 0 {
                                    Circle().fill(Color.accentColor).frame(width: 8, height: 8)
                                }
                            }
                        }
                        .swipeActions(edge: .trailing) {
                            if accountsList.count > 1 {
                                Button(role: .destructive) { pendingRemove = acct } label: {
                                    Label("Remove", systemImage: "trash")
                                }
                            }
                        }
                    }
                    Button { showingAddAccount = true } label: {
                        Label("Add Account", systemImage: "person.badge.plus")
                    }

                    row("Edit Profile", "person.text.rectangle") { showingProfile = true }
                    row("Pair with Someone", "qrcode") { showingPairing = true }
                    row("Back Up Identity", "arrow.up.doc") { showingBackup = true }
                    row("Import a Key", "square.and.arrow.down") { showingImport = true }
                }

                if app.appLock.biometricsAvailable {
                    Section("Security") {
                        Toggle(isOn: Binding(
                            get: { app.appLock.appLockEnabled },
                            set: { app.setAppLockEnabled($0) }
                        )) {
                            Label("App Lock", systemImage: "faceid")
                        }
                    }
                }

                Section("Language") {
                    Picker("Language", selection: Binding(
                        get: { app.appLanguage },
                        set: { app.setLanguage($0) }
                    )) {
                        ForEach(Self.languages, id: \.code) { lang in
                            Text(lang.name).tag(lang.code)
                        }
                    }
                    .pickerStyle(.navigationLink)
                }

                Section("Relay") {
                    NavigationLink {
                        RelaySettingsView(app: app)
                    } label: {
                        HStack {
                            Label("Relay Server", systemImage: "server.rack")
                                .foregroundStyle(.primary)
                            Spacer()
                            Text(AppConfig.usingCustomRelay ? "Custom" : "Default")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                localNetworkSection
                internetDirectSection
                nostrSection
                sealedResyncSection

                Section("More Pony apps") {
                    ForEach(apps, id: \.name) { item in
                        if let url = URL(string: item.url) {
                            Link(destination: url) {
                                HStack {
                                    VStack(alignment: .leading, spacing: 1) {
                                        Text(item.name).foregroundStyle(.primary)
                                        Text(LocalizedStringKey(item.subtitle)).font(.caption).foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    Image(systemName: "arrow.up.right").font(.caption).foregroundStyle(.tertiary)
                                }
                            }
                        }
                    }
                }

                Section("Open source") {
                    if let url = URL(string: "https://github.com/norsehorse-dev/CarrierPonyiOS") {
                        Link(destination: url) {
                            HStack {
                                Label("CarrierPony on GitHub", systemImage: "chevron.left.forwardslash.chevron.right")
                                    .foregroundStyle(.primary)
                                Spacer()
                                Image(systemName: "arrow.up.right").font(.caption).foregroundStyle(.tertiary)
                            }
                        }
                    }
                    if let url = URL(string: "https://github.com/norsehorse-dev/NorseHorsePGPCore") {
                        Link(destination: url) {
                            HStack {
                                Label("Crypto core on GitHub", systemImage: "chevron.left.forwardslash.chevron.right")
                                    .foregroundStyle(.primary)
                                Spacer()
                                Image(systemName: "arrow.up.right").font(.caption).foregroundStyle(.tertiary)
                            }
                        }
                    }
                }

                Section("Reset") {
                    Button {
                        confirmResetOnboarding = true
                    } label: {
                        Label("Reset Onboarding", systemImage: "arrow.counterclockwise")
                    }
                    Button(role: .destructive) {
                        confirmResetApp = true
                    } label: {
                        Label("Reset App", systemImage: "trash")
                    }
                }

                Section {
                    Button(role: .destructive) {
                        confirmSignOut = true
                    } label: {
                        Label("Sign Out", systemImage: "rectangle.portrait.and.arrow.right")
                    }
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) { Button("Done") { dismiss() } }
            }
        }
        .sheet(isPresented: $showingProfile) { EditProfileView(app: app) }
        .sheet(isPresented: $showingPairing) { PairingView(app: app, onFinished: { showingPairing = false }) }
        .sheet(isPresented: $showingImport) { ImportKeyView(app: app) }
        .sheet(isPresented: $showingBackup) {
            if let identity = app.identity { BackupView(identity: identity) }
        }
        .confirmationDialog("Sign out?", isPresented: $confirmSignOut, titleVisibility: .visible) {
            Button("Sign Out", role: .destructive) { dismiss(); app.signOut() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This removes your identity and its keys from this device. You can't undo this without a backup.")
        }
        .confirmationDialog("Reset onboarding?", isPresented: $confirmResetOnboarding, titleVisibility: .visible) {
            Button("Reset Onboarding") { dismiss(); app.resetOnboarding() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Shows the first-run setup again. Your identity and messages are kept.")
        }
        .confirmationDialog("Reset the entire app?", isPresented: $confirmResetApp, titleVisibility: .visible) {
            Button("Erase Everything", role: .destructive) { dismiss(); app.resetApp() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Erases your identity, contacts, conversations, files, and all settings. This cannot be undone. Back up first if you want to keep your identity.")
        }
        .confirmationDialog(
            "Remove this account?",
            isPresented: Binding(get: { pendingRemove != nil }, set: { if !$0 { pendingRemove = nil } }),
            titleVisibility: .visible
        ) {
            Button("Remove Account", role: .destructive) {
                if let acct = pendingRemove {
                    let wasActive = acct.fingerprint.hex == app.activeFingerprintHex
                    pendingRemove = nil
                    app.removeAccount(acct.fingerprint.hex)
                    if wasActive { dismiss() } else { accountsList = app.accounts() }
                }
            }
            Button("Cancel", role: .cancel) { pendingRemove = nil }
        } message: {
            Text("This erases this account's messages, contacts, and keys from this device. It can't be undone.")
        }
        .sheet(isPresented: $showingAddAccount) { AddAccountView(app: app) }
        .confirmationDialog("Resync sealed delivery?", isPresented: $confirmResync, titleVisibility: .visible) {
            Button("Resync") {
                resyncing = true
                Task {
                    await app.resyncSealedAwait()
                    resyncing = false
                    resyncDoneShown = true
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This regenerates your sealed keys and re-syncs with every contact. Your messages and identity are not affected. If a single pair is stuck, run it on both devices.")
        }
        .alert("Resync complete", isPresented: $resyncDoneShown) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Your sealed keys were regenerated and shared with your contacts. Give it about a minute, then try sending again.")
        }
        .onChange(of: app.activeFingerprintHex) { _, _ in dismiss() }
        .onAppear { accountsList = app.accounts() }
    }

    static let languages: [(code: String, name: String)] = [
        ("en", "English"),
        ("es", "Español"),
        ("de", "Deutsch"),
        ("fr", "Français"),
        ("pt", "Português"),
        ("it", "Italiano"),
        ("zh", "中文"),
        ("ja", "日本語"),
        ("ru", "Русский")
    ]

    @ViewBuilder
    private var internetDirectSection: some View {
        Section {
            Toggle(isOn: $wanDirectOn) {
                Label("Direct over the internet", systemImage: "globe")
            }
            .onChange(of: wanDirectOn) { _, on in
                app.setWanDirectEnabled(on)
            }
            if wanDirectOn, app.wanConnectedCount > 0 {
                Label("Connected directly (\(app.wanConnectedCount))", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .font(.subheadline)
            }
        } header: {
            Text("Internet direct")
        } footer: {
            Text("Connect to contacts directly over the internet, with the relay only introducing you. This shares your IP with a contact you message directly. Off keeps everything on the relay.")
        }
    }

    @ViewBuilder
    private var sealedResyncSection: some View {
        Section {
            Button {
                confirmResync = true
            } label: {
                HStack {
                    Text("Resync sealed delivery")
                    if resyncing {
                        Spacer()
                        ProgressView()
                    }
                }
            }
            .disabled(resyncing)
        } footer: {
            Text("If messages stop arriving after you or a contact reinstalled, this regenerates your sealed keys and re-syncs with your contacts. If a single pair is stuck, run it on both devices.")
        }
    }

    @ViewBuilder
    private var nostrSection: some View {
        Section {
            Toggle(isOn: $nostrOn) {
                Label("Also send over Nostr", systemImage: "antenna.radiowaves.left.and.right")
            }
            .onChange(of: nostrOn) { _, on in
                app.setNostrEnabled(on)
            }
            NavigationLink {
                NostrRelaysView(app: app)
            } label: {
                HStack {
                    Label("Nostr relays", systemImage: "server.rack")
                    Spacer()
                    Text("\(AppConfig.nostrRelays.count)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("Nostr")
        } footer: {
            Text("Also post each message to the peer's sealed mailbox on public Nostr relays, so delivery does not depend only on your relay. Those third-party relays see opaque content under a rotating tag, and they see this device's IP. Off by default.")
        }
    }

    @ViewBuilder
    private var localNetworkSection: some View {
        Section {
            HStack {
                Label("CarrierPony devices nearby", systemImage: "dot.radiowaves.left.and.right")
                    .foregroundStyle(.primary)
                Spacer()
                Text("\(app.lanDiscovery.nearby.count)")
                    .font(.body.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            Toggle(isOn: $lanDirectOn) {
                Label("Direct on this network", systemImage: "point.3.connected.trianglepath.dotted")
            }
            .onChange(of: lanDirectOn) { _, on in
                app.setLanDirectEnabled(on)
            }
            if lanDirectOn {
                HStack {
                    Text("Contacts reachable directly")
                        .foregroundStyle(.primary)
                    Spacer()
                    Text("\(app.lanDiscovery.reachable.count)")
                        .font(.body.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                Toggle(isOn: $lanSkipRelayOn) {
                    Text("Skip the relay when direct")
                }
                .onChange(of: lanSkipRelayOn) { _, on in
                    AppConfig.lanDirectSkipRelay = on
                }
            }
        } header: {
            Text("Local network")
        } footer: {
            VStack(alignment: .leading, spacing: 6) {
                Text("Find contacts on the same Wi-Fi and reach them without the relay. This shares your device's local IP with a contact you message directly. Off keeps everything on the relay.")
                if lanDirectOn {
                    Text("Skip the relay: a message delivered directly won't also go through the relay. The person's other devices and offline delivery won't receive it.")
                }
            }
        }
    }

    private func shortHex(_ hex: String) -> String {
        guard hex.count >= 8 else { return hex }
        let tail = String(hex.suffix(8))
        return stride(from: 0, to: tail.count, by: 4)
            .map { String(tail[tail.index(tail.startIndex, offsetBy: $0)..<tail.index(tail.startIndex, offsetBy: min($0 + 4, tail.count))]) }
            .joined(separator: " ")
    }

    private func row(_ title: LocalizedStringKey, _ icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Label(title, systemImage: icon).foregroundStyle(.primary)
                Spacer()
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
            }
        }
    }
}


// The relay screen, reached from Settings > Relay. Lets a self-hoster point the
// app at their own CarrierPony relay instead of the default api.carrierpony.com.
// The relay base URL is read once at launch (AppModel builds the network stack
// from AppConfig.relayBaseURL), so a change here applies on the next launch.
//
// Honest limits surfaced to the user: messaging is siloed to a single relay, so
// you can only reach contacts registered on the same one; and push notifications
// need the app publisher's APNs/FCM credentials, which a self-hosted relay does
// not have, so a custom relay delivers when the app is open (polling) rather than
// waking it in the background.
struct RelaySettingsView: View {
    let app: AppModel
    var onboarding: Bool = false
    @Environment(\.dismiss) private var dismiss

    @State private var urlText: String = AppConfig.usingCustomRelay ? AppConfig.relayBaseURL : ""
    @State private var testing = false
    @State private var testResult: TestResult?
    @State private var confirmSave = false
    @State private var savedNoticeShown = false

    private enum TestResult: Equatable {
        case ok
        case badURL
        case failed(String)
    }

    private var trimmedIsValid: Bool { AppConfig.isValidRelayURL(urlText) }

    var body: some View {
        Form {
            Section("Current relay") {
                HStack {
                    Text(AppConfig.relayBaseURL)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Text(AppConfig.usingCustomRelay ? "Custom" : "Default")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }

            if AppConfig.usingCustomRelay {
                Section {
                    Toggle(isOn: Binding(
                        get: { AppConfig.gatewayPushEnabled },
                        set: { app.setGatewayPush($0) }
                    )) {
                        Label("Use CarrierPony's push service", systemImage: "bell.badge")
                    }
                } header: {
                    Text("Push notifications")
                } footer: {
                    Text("A relay you run yourself can't send push notifications. Turn this on to be woken through CarrierPony's push service instead. It only ever receives a signal that a message is waiting, never the sender or the message. Left off, you get messages when the app is open.")
                }
            }

            Section {
                TextField("https://relay.example.com", text: $urlText)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .onChange(of: urlText) { _, _ in testResult = nil }

                Button {
                    Task { await testConnection() }
                } label: {
                    HStack {
                        Label("Test Connection", systemImage: "antenna.radiowaves.left.and.right")
                        Spacer()
                        if testing { ProgressView() }
                    }
                }
                .disabled(testing || !trimmedIsValid)

                if let testResult {
                    switch testResult {
                    case .ok:
                        Label("Relay reachable and speaking the protocol", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                            .font(.callout)
                    case .badURL:
                        Label("Enter a valid https:// address", systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                            .font(.callout)
                    case .failed(let why):
                        Label("Couldn't reach it: \(why)", systemImage: "xmark.circle.fill")
                            .foregroundStyle(.red)
                            .font(.callout)
                    }
                }
            } header: {
                Text("Custom relay")
            } footer: {
                Text(onboarding
                    ? "Must be an https address. Your identity will register on this relay, and you'll only be able to reach people on the same one. A self-hosted relay can't send push notifications."
                    : "Must be an https address. You can only exchange messages with people whose app points at the same relay, so switch before you pair, or re-pair afterward. A self-hosted relay can't send push notifications, so you'll receive messages when CarrierPony is open.")
            }

            Section {
                Button {
                    confirmSave = true
                } label: {
                    Label("Use This Relay", systemImage: "checkmark.seal")
                }
                .disabled(!trimmedIsValid)

                if AppConfig.usingCustomRelay {
                    Button(role: .destructive) {
                        AppConfig.setRelayBaseURL(nil)
                        urlText = ""
                        testResult = nil
                        if !onboarding { savedNoticeShown = true }
                    } label: {
                        Label("Reset to CarrierPony Relay", systemImage: "arrow.counterclockwise")
                    }
                }
            }

            Section {
                Link(destination: URL(string: "https://carrierpony.com/self-host")!) {
                    HStack {
                        Label("Set up your own relay", systemImage: "server.rack").foregroundStyle(.primary)
                        Spacer()
                        Image(systemName: "arrow.up.right").font(.caption).foregroundStyle(.tertiary)
                    }
                }
                Link(destination: URL(string: "https://github.com/norsehorse-dev/CarrierPony-Relay")!) {
                    HStack {
                        Label("Relay source on GitHub", systemImage: "chevron.left.forwardslash.chevron.right").foregroundStyle(.primary)
                        Spacer()
                        Image(systemName: "arrow.up.right").font(.caption).foregroundStyle(.tertiary)
                    }
                }
            } header: {
                Text("Self-hosting")
            } footer: {
                Text("The relay is open source. Run your own and point the app at it.")
            }
        }
        .navigationTitle("Relay")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if onboarding {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
        .confirmationDialog("Use this relay?", isPresented: $confirmSave, titleVisibility: .visible) {
            Button("Use This Relay") {
                if AppConfig.setRelayBaseURL(urlText) {
                    if onboarding { dismiss() } else { savedNoticeShown = true }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(onboarding
                ? "Your identity will register on this relay when you create it. You can change it later in Settings."
                : "Quit and reopen CarrierPony to connect to the new relay. Your identity stays on this device, but you'll need to pair again with contacts on the new relay.")
        }
        .alert("Relay saved", isPresented: $savedNoticeShown) {
            Button("OK") { dismiss() }
        } message: {
            Text("Quit and reopen CarrierPony for the change to take effect.")
        }
    }

    // A non-destructive reachability + protocol probe: POST /v1/challenge with our
    // own fingerprint. A 200 carrying a nonce means the relay is up and speaks the
    // CarrierPony protocol. The nonce is one-time and unused, so this is harmless.
    private func testConnection() async {
        testResult = nil
        let base = AppConfig.normalizedRelayURL(urlText)
        guard AppConfig.isValidRelayURL(base), let url = URL(string: base + "/v1/challenge") else {
            testResult = .badURL
            return
        }
        testing = true
        defer { testing = false }

        let fpr = app.identity?.fingerprint.hex ?? String(repeating: "0", count: 40)
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["fpr": fpr])
        req.timeoutInterval = 12

        do {
            let (data, resp) = try await URLSession.shared.data(for: req)
            guard let http = resp as? HTTPURLResponse else {
                testResult = .failed("no response")
                return
            }
            if http.statusCode == 200,
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               obj["nonce"] is String {
                testResult = .ok
            } else {
                testResult = .failed("HTTP \(http.statusCode)")
            }
        } catch {
            testResult = .failed(error.localizedDescription)
        }
    }
}

// The Nostr relay set editor: the public relays this device posts to and reads
// from for the Nostr delivery path. Add, remove or reset; changes restart the
// Nostr manager when Nostr is on.
struct NostrRelaysView: View {
    let app: AppModel
    @State private var relays: [String] = AppConfig.nostrRelays
    @State private var newURL: String = ""

    private var trimmed: String { newURL.trimmingCharacters(in: .whitespaces) }
    private var validNew: Bool { isValidNostrRelay(trimmed) && !relays.contains(trimmed) }

    private func apply(_ updated: [String]) {
        relays = updated
        app.setNostrRelays(updated)
    }

    var body: some View {
        Form {
            Section {
                if relays.isEmpty {
                    Text("No relays set. Nostr delivery stays off until you add at least one.")
                        .font(.callout)
                        .foregroundStyle(.red)
                }
                ForEach(relays, id: \.self) { relay in
                    Text(relay)
                        .font(.callout)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                .onDelete { offsets in
                    var updated = relays
                    updated.remove(atOffsets: offsets)
                    apply(updated)
                }
            } header: {
                Text("Current relays")
            }

            Section {
                TextField("wss://relay.example.com", text: $newURL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                Button {
                    apply(relays + [trimmed])
                    newURL = ""
                } label: {
                    Label("Add relay", systemImage: "plus.circle")
                }
                .disabled(!validNew)
            } header: {
                Text("Add a relay")
            } footer: {
                Text("These are the public Nostr relays this app posts to and reads from for the extra delivery path. Each one sees opaque content under a rotating tag, plus this device's IP. Add relays you trust, or point them at your own.")
            }

            Section {
                Button(role: .destructive) {
                    apply(AppConfig.defaultNostrRelays)
                    newURL = ""
                } label: {
                    Label("Reset to defaults", systemImage: "arrow.counterclockwise")
                }
            }
        }
        .navigationTitle("Nostr relays")
    }
}

private func isValidNostrRelay(_ url: String) -> Bool {
    let t = url.trimmingCharacters(in: .whitespaces)
    guard let u = URL(string: t), let scheme = u.scheme?.lowercased(),
          scheme == "wss" || scheme == "ws", let host = u.host, !host.isEmpty else { return false }
    return true
}
