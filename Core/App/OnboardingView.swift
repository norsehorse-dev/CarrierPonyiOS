import SwiftUI

// Immersive first run, in the house style shared with the other Pony apps: a
// paged flow with capsule dots that ends with the user fully set up — a real
// identity created or imported, optionally backed up, and optionally paired —
// before entering the app. A language step lays the rails for localization
// (English is live; others are shown as coming).

struct OnboardingView: View {
    let app: AppModel

    @State private var step = 0
    @State private var name = ""
    @State private var creating = false
    @State private var createError: String?
    @State private var showingImport = false
    @State private var showingRestore = false
    @State private var showingBackup = false
    @State private var showingPairing = false
    @State private var didBackup = false
    @State private var showingRelay = false

    private let lastStep = 6

    private var canContinue: Bool {
        step != 3 || app.identity != nil
    }

    private var isSkippable: Bool {
        step == 4 || step == 5
    }

    var body: some View {
        ZStack {
            CPTheme.screen.ignoresSafeArea()
            VStack(spacing: 0) {
                content
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .padding(.horizontal, 32)
                    .transition(.opacity.combined(with: .move(edge: .trailing)))
                    .id(step)
                controls
            }
        }
        .animation(.easeInOut(duration: 0.25), value: step)
        .sheet(isPresented: $showingImport) { ImportKeyView(app: app) }
        .sheet(isPresented: $showingRestore) { ImportBackupView(app: app) }
        .sheet(isPresented: $showingBackup) {
            if let identity = app.identity {
                BackupView(identity: identity)
            }
        }
        .sheet(isPresented: $showingPairing) {
            PairingView(app: app, onFinished: { showingPairing = false })
        }
        .sheet(isPresented: $showingRelay) {
            NavigationStack { RelaySettingsView(app: app, onboarding: true) }
        }
    }

    // MARK: - Steps

    @ViewBuilder private var content: some View {
        switch step {
        case 0: welcome
        case 1: language
        case 2: howItWorks
        case 3: identityStep
        case 4: backupStep
        case 5: connectStep
        default: doneStep
        }
    }

    private var welcome: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "envelope.badge.shield.half.filled")
                .font(.system(size: 76, weight: .medium))
                .foregroundStyle(CPTheme.brand)
            Text("CarrierPony")
                .font(.largeTitle.bold())
            Text("Private messaging and file transfer.\nEnd to end encrypted, signed, and yours.")
                .font(.title3)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
        }
    }

    private var language: some View {
        VStack(alignment: .leading, spacing: 16) {
            stepHeader("Choose your language", "You can change this later. More languages are on the way.")
            ScrollView {
                VStack(spacing: 0) {
                    ForEach(Self.languages, id: \.code) { lang in
                        Button {
                            app.setLanguage(lang.code)
                        } label: {
                            HStack {
                                Text(lang.name).foregroundStyle(Color.primary)
                                Spacer()
                                if app.appLanguage == lang.code {
                                    Image(systemName: "checkmark").foregroundStyle(CPTheme.accent)
                                }
                            }
                            .padding(.vertical, 14)
                            .contentShape(Rectangle())
                        }
                        Divider()
                    }
                }
            }
        }
        .padding(.top, 40)
    }

    private var howItWorks: some View {
        VStack(alignment: .leading, spacing: 22) {
            stepHeader("How it works", "Three things worth knowing before you start.")
            infoRow("lock.fill", "End to end encrypted", "Only you and the people you pair with can read your messages and open your files.")
            infoRow("person.2.fill", "Pair to connect", "Swap an invite in person or over any channel you trust. A safety number confirms it's really them.")
            infoRow("externaldrive.badge.xmark", "The relay knows nothing", "Our server only forwards sealed envelopes. No names, no message contents, no plaintext.")
            Spacer()
        }
        .padding(.top, 40)
    }

    private var identityStep: some View {
        VStack(spacing: 18) {
            Spacer()
            if let identity = app.identity {
                Image(systemName: "checkmark.seal.fill")
                    .font(.system(size: 60)).foregroundStyle(CPTheme.accent)
                Text("Your identity is ready")
                    .font(.title2.bold())
                Text(shortFingerprint(identity.fingerprint))
                    .font(.system(.subheadline, design: .monospaced))
                    .foregroundStyle(.secondary)
                Text("This is your fingerprint — how others confirm it's you.")
                    .font(.caption).foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
            } else if creating {
                ProgressView("Generating your keys…")
            } else {
                Image(systemName: "key.horizontal.fill")
                    .font(.system(size: 52)).foregroundStyle(CPTheme.brand)
                Text("Set up your identity")
                    .font(.title2.bold())
                Text("Create a new key on this device, or bring your own.")
                    .font(.subheadline).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                TextField("Your name (optional)", text: $name)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.words)
                    .frame(maxWidth: 300)
                    .padding(.top, 6)

                Button { Task { await create() } } label: {
                    Text("Create Identity")
                        .font(.body.weight(.semibold)).foregroundStyle(.white)
                        .frame(maxWidth: 300).padding(.vertical, 13)
                        .background(Capsule().fill(CPTheme.send))
                }

                HStack(spacing: 18) {
                    Button("Import a key") { showingImport = true }
                    Button("Restore a backup") { showingRestore = true }
                }
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(CPTheme.accent)

                Button("Use a custom relay") { showingRelay = true }
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .padding(.top, 2)

                if let createError {
                    Text(createError).font(.footnote).foregroundStyle(.red)
                }
            }
            Spacer()
        }
    }

    private var backupStep: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: didBackup ? "checkmark.circle.fill" : "arrow.up.doc.fill")
                .font(.system(size: 56)).foregroundStyle(didBackup ? AnyShapeStyle(CPTheme.accent) : AnyShapeStyle(CPTheme.brand))
            Text(didBackup ? "Backed up" : "Back up your identity")
                .font(.title2.bold())
            Text("If you lose this device, a backup file is the only way to restore your identity. It's protected by a passphrase only you know.")
                .font(.subheadline).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button {
                showingBackup = true
                didBackup = true
            } label: {
                Text(didBackup ? "Back Up Again" : "Back Up Now")
                    .font(.body.weight(.semibold)).foregroundStyle(.white)
                    .frame(maxWidth: 300).padding(.vertical, 13)
                    .background(Capsule().fill(CPTheme.send))
            }
            .padding(.top, 4)
            Spacer()
        }
    }

    private var connectStep: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "person.2.badge.gearshape.fill")
                .font(.system(size: 56)).foregroundStyle(CPTheme.brand)
            Text("Connect with someone")
                .font(.title2.bold())
            Text("Pair with a friend now by swapping an invite, or do it any time from the app.")
                .font(.subheadline).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button {
                showingPairing = true
            } label: {
                Text("Pair Now")
                    .font(.body.weight(.semibold)).foregroundStyle(.white)
                    .frame(maxWidth: 300).padding(.vertical, 13)
                    .background(Capsule().fill(CPTheme.send))
            }
            .padding(.top, 4)
            Spacer()
        }
    }

    private var doneStep: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "sparkles")
                .font(.system(size: 60)).foregroundStyle(CPTheme.brand)
            Text("You're all set")
                .font(.largeTitle.bold())
            Text("Your identity is on this device and ready. Welcome to CarrierPony.")
                .font(.title3).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
        }
    }

    // MARK: - Controls

    private var controls: some View {
        VStack(spacing: 14) {
            HStack(spacing: 7) {
                ForEach(0...lastStep, id: \.self) { i in
                    Capsule()
                        .fill(i == step ? AnyShapeStyle(CPTheme.accent) : AnyShapeStyle(Color(.systemGray4)))
                        .frame(width: i == step ? 22 : 7, height: 7)
                }
            }

            HStack {
                if step > 0 {
                    Button("Back") { withAnimation { step -= 1 } }
                        .foregroundStyle(.secondary)
                } else {
                    Spacer().frame(width: 44)
                }
                Spacer()
                if isSkippable {
                    Button("Skip") { advance() }
                        .foregroundStyle(.secondary)
                        .padding(.trailing, 8)
                }
                Button {
                    if step == lastStep { app.completeOnboarding() } else { advance() }
                } label: {
                    Text(step == lastStep ? "Enter CarrierPony" : "Continue")
                        .font(.body.weight(.semibold)).foregroundStyle(.white)
                        .padding(.horizontal, 24).padding(.vertical, 12)
                        .background(Capsule().fill(canContinue ? AnyShapeStyle(CPTheme.send) : AnyShapeStyle(Color(.systemGray4))))
                }
                .disabled(!canContinue)
            }
            .font(.body.weight(.semibold))
        }
        .padding(.horizontal, 28)
        .padding(.bottom, 20)
        .padding(.top, 8)
    }

    private func advance() {
        withAnimation { step = min(step + 1, lastStep) }
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

    // MARK: - Bits

    private func stepHeader(_ title: LocalizedStringKey, _ subtitle: LocalizedStringKey) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.title.bold())
            Text(subtitle).font(.subheadline).foregroundStyle(.secondary)
        }
    }

    private func infoRow(_ icon: String, _ title: LocalizedStringKey, _ body: LocalizedStringKey) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: icon)
                .font(.title2).foregroundStyle(CPTheme.accent)
                .frame(width: 34)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.headline)
                Text(body).font(.subheadline).foregroundStyle(.secondary)
            }
        }
    }

    private func shortFingerprint(_ fp: Fingerprint) -> String {
        let hex = fp.hex
        guard hex.count >= 8 else { return hex }
        let tail = String(hex.suffix(8))
        return stride(from: 0, to: tail.count, by: 4)
            .map { String(tail[tail.index(tail.startIndex, offsetBy: $0)..<tail.index(tail.startIndex, offsetBy: min($0 + 4, tail.count))]) }
            .joined(separator: " ")
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
}
