import SwiftUI
import UIKit
import NorseHorsePGPCore

// MARK: - Backup packaging
//
// A CarrierPony identity backup is a passphrase-sealed blob. Inside is a small
// JSON payload carrying everything needed to reconstruct the Identity: the
// fingerprint, the armored public key, and the raw secret-key bytes (base64).
// The whole payload is encrypted under the user's passphrase via PassphraseBox
// (OpenPGP symmetric, S2K-derived key), so the secret is never written in the
// clear. Restore is the exact inverse.
//
// There is no passphrase recovery. A lost passphrase means the backup — and the
// identity it holds — cannot be recovered.

enum BackupError: LocalizedError {
    case noIdentity
    case malformed

    var errorDescription: String? {
        switch self {
        case .noIdentity: return "There is no identity to back up."
        case .malformed:  return "This backup is not valid, or the passphrase is wrong."
        }
    }
}

enum IdentityBackup {

    private struct Payload: Codable {
        let v: Int
        let fpr: String
        let pub: String   // armored public key
        let sec: String   // base64 of the raw secret-key bytes
    }

    /// Seal an identity into an armored, passphrase-protected backup blob.
    static func export(_ identity: Identity, passphrase: String) throws -> String {
        let payload = Payload(
            v: 1,
            fpr: identity.fingerprint.hex,
            pub: identity.armoredPublicKey,
            sec: identity.secretKey.base64EncodedString()
        )
        let json = try JSONEncoder().encode(payload)
        return try PassphraseBox.seal(json, passphrase: passphrase)
    }

    /// Open a backup blob with its passphrase and reconstruct the Identity.
    static func restore(_ blob: String, passphrase: String) throws -> Identity {
        let json: Data
        do {
            json = try PassphraseBox.open(blob, passphrase: passphrase)
        } catch {
            throw BackupError.malformed
        }
        guard let payload = try? JSONDecoder().decode(Payload.self, from: json),
              let fingerprint = Fingerprint(payload.fpr),
              let secretKey = Data(base64Encoded: payload.sec) else {
            throw BackupError.malformed
        }
        return Identity(
            fingerprint: fingerprint,
            secretKey: secretKey,
            armoredPublicKey: payload.pub
        )
    }
}

// MARK: - Backup screen

struct BackupView: View {

    let identity: Identity
    @Environment(\.dismiss) private var dismiss

    @State private var passphrase = ""
    @State private var confirm = ""
    @State private var blob: String?
    @State private var error: String?
    @State private var working = false
    @State private var copied = false

    private var canCreate: Bool {
        passphrase.count >= 8 && passphrase == confirm && !working
    }

    var body: some View {
        NavigationStack {
            Group {
                if let blob {
                    resultView(blob)
                } else {
                    formView
                }
            }
            .padding(24)
            .navigationTitle("Back Up Identity")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private var formView: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Choose a passphrase to protect this backup. You'll need it to restore your identity on another device.")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            SecureField("Passphrase", text: $passphrase)
                .textFieldStyle(.roundedBorder)
            SecureField("Confirm passphrase", text: $confirm)
                .textFieldStyle(.roundedBorder)

            if !passphrase.isEmpty && passphrase.count < 8 {
                Text("Use at least 8 characters.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if !confirm.isEmpty && passphrase != confirm {
                Text("Passphrases don't match.")
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            Label(
                "There is no way to recover this backup if you forget the passphrase. Store it somewhere safe.",
                systemImage: "exclamationmark.triangle.fill"
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .padding(.top, 4)

            Button {
                create()
            } label: {
                Group {
                    if working {
                        ProgressView().tint(.white)
                    } else {
                        Text("Create Backup").font(.body.weight(.semibold))
                    }
                }
                .foregroundStyle(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 13)
                .background(Capsule().fill(CPTheme.send))
                .opacity(canCreate ? 1 : 0.5)
            }
            .disabled(!canCreate)
            .padding(.top, 8)

            if let error {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }

            Spacer()
        }
    }

    private func resultView(_ blob: String) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Your encrypted backup is ready. Save it somewhere safe — a password manager, or a file you keep offline.")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            ScrollView {
                Text(blob)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
            }
            .frame(maxHeight: 260)
            .background(RoundedRectangle(cornerRadius: 10).fill(Color(.secondarySystemBackground)))

            HStack(spacing: 12) {
                Button {
                    UIPasteboard.general.string = blob
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                } label: {
                    Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                        .font(.body.weight(.semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                        .background(Capsule().fill(Color(.secondarySystemBackground)))
                        .foregroundStyle(CPTheme.accent)
                }

                ShareLink(item: blob) {
                    Label("Share", systemImage: "square.and.arrow.up")
                        .font(.body.weight(.semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                        .background(Capsule().fill(Color(.secondarySystemBackground)))
                        .foregroundStyle(CPTheme.accent)
                }
            }

            Spacer()
        }
    }

    private func create() {
        error = nil
        working = true
        let pass = passphrase
        let id = identity
        Task {
            do {
                let out = try await Task.detached {
                    try IdentityBackup.export(id, passphrase: pass)
                }.value
                blob = out
                working = false
            } catch {
                self.error = "Couldn't create the backup. Please try again."
                working = false
            }
        }
    }
}

// MARK: - Import screen

struct ImportBackupView: View {

    let app: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var blob = ""
    @State private var passphrase = ""
    @State private var error: String?
    @State private var working = false

    private var canRestore: Bool {
        !blob.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !passphrase.isEmpty
            && !working
    }

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 16) {
                Text("Paste an encrypted CarrierPony backup and enter its passphrase to restore your identity on this device.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                ScrollView {
                    TextEditor(text: $blob)
                        .font(.system(.footnote, design: .monospaced))
                        .frame(minHeight: 180)
                        .scrollContentBackground(.hidden)
                        .padding(8)
                }
                .frame(maxHeight: 220)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color(.secondarySystemBackground)))
                .overlay(alignment: .topLeading) {
                    if blob.isEmpty {
                        Text("-----BEGIN PGP MESSAGE-----")
                            .font(.system(.footnote, design: .monospaced))
                            .foregroundStyle(.tertiary)
                            .padding(16)
                            .allowsHitTesting(false)
                    }
                }

                SecureField("Passphrase", text: $passphrase)
                    .textFieldStyle(.roundedBorder)

                Button {
                    restore()
                } label: {
                    Group {
                        if working {
                            ProgressView().tint(.white)
                        } else {
                            Text("Restore").font(.body.weight(.semibold))
                        }
                    }
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 13)
                    .background(Capsule().fill(CPTheme.send))
                    .opacity(canRestore ? 1 : 0.5)
                }
                .disabled(!canRestore)

                if let error {
                    Text(error)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }

                Spacer()
            }
            .padding(24)
            .navigationTitle("Import Backup")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private func restore() {
        error = nil
        working = true
        let trimmed = blob.trimmingCharacters(in: .whitespacesAndNewlines)
        let pass = passphrase
        Task {
            do {
                try await app.importBackup(trimmed, passphrase: pass)
                working = false
                dismiss()
            } catch {
                self.error = "Couldn't restore. Check the backup text and passphrase."
                working = false
            }
        }
    }
}
