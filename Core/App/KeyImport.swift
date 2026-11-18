import SwiftUI
import UIKit
import UniformTypeIdentifiers
import NorseHorsePGPCore

// Import an existing OpenPGP private key (from gpg, PGPony, etc.) as this device's
// identity. CarrierPony's engine is v4 Ed25519 (sign) + Cv25519 (encrypt), so
// other algorithms are rejected with a clear message. A passphrase-protected key
// is kept protected: its bytes are stored as-is and its passphrase is held behind
// the biometric app lock.

enum KeyImportError: LocalizedError {
    case malformed
    case notSupported
    case noEncryptionSubkey
    case wrongPassphrase

    var errorDescription: String? {
        switch self {
        case .malformed:          return "That doesn't look like a valid private key."
        case .notSupported:       return "CarrierPony only supports Ed25519 keys with a Curve25519 or ML-KEM-768 encryption subkey. RSA and other key types can't be imported."
        case .noEncryptionSubkey: return "This key has no encryption subkey CarrierPony can use, so it can't receive messages. Import a key that includes a Curve25519 or ML-KEM-768 encryption subkey."
        case .wrongPassphrase:    return "Wrong passphrase for this key."
        }
    }
}

enum KeyImport {

    struct Inspection {
        let secretKey: Data
        let armoredPublic: String
        let needsPassphrase: Bool
    }

    /// Validate the armored key without a passphrase: confirm it's an Ed25519 key,
    /// derive its public key, and report whether it's passphrase-protected.
    static func inspect(_ armored: String) throws -> Inspection {
        guard let secret = PGPArmor.dearmor(armored), !secret.isEmpty else {
            throw KeyImportError.malformed
        }
        // Deriving the public key parses the primary key packet and rejects any
        // non-Ed25519/Cv25519 algorithm — a passphrase-free algorithm gate.
        let armoredPublic: String
        do {
            armoredPublic = try OpenPGPPacketParser.transferablePublicKey(fromSecretKey: secret)
        } catch {
            throw KeyImportError.notSupported
        }
        // A v6 key has to have an Ed25519 primary. Its keys can be protected one
        // by one, so the signing key and the ML-KEM subkey are both looked at.
        if OpenPGPPacketParser.openPGPKeyVersion(from: secret) == 6 {
            guard let publicData = PGPArmor.dearmor(armoredPublic),
                  (try? OpenPGPPacketParser.ed25519PrimaryPublicKey(fromV6PublicKey: publicData)) != nil else {
                throw KeyImportError.notSupported
            }
            return Inspection(
                secretKey: secret, armoredPublic: armoredPublic,
                needsPassphrase: OpenPGPPacketParser.v6SecretKeyNeedsPassphrase(secret))
        }
        // Unprotected keys extract with a nil passphrase; protected ones throw.
        let unprotectedWorks = (try? OpenPGPPacketParser.ed25519SigningInfo(fromSecretKey: secret, passphrase: nil)) != nil
        return Inspection(secretKey: secret, armoredPublic: armoredPublic, needsPassphrase: !unprotectedWorks)
    }

    /// Produce an Identity, validating the passphrase (if any) and the presence of
    /// an encryption subkey.
    static func makeIdentity(_ inspection: Inspection, passphrase: String?) throws -> Identity {
        let secret = inspection.secretKey

        if OpenPGPPacketParser.openPGPKeyVersion(from: secret) == 6 {
            // The key that signs (a signing subkey when there is one, else the
            // primary) and the ML-KEM-768 + X25519 subkey must both open.
            guard (try? OpenPGPPacketParser.ed25519SigningInfo(fromV6SecretKey: secret, passphrase: passphrase)) != nil else {
                throw inspection.needsPassphrase ? KeyImportError.wrongPassphrase : KeyImportError.notSupported
            }
            let composite: CompositeKEMDecryptionKey?
            do {
                composite = try OpenPGPPacketParser.compositeDecryptionKey(fromV6SecretKey: secret, passphrase: passphrase)
            } catch {
                throw inspection.needsPassphrase ? KeyImportError.wrongPassphrase : KeyImportError.noEncryptionSubkey
            }
            guard composite != nil else { throw KeyImportError.noEncryptionSubkey }
        } else {
            // Signing key must extract with this passphrase (proves the passphrase).
            guard (try? OpenPGPPacketParser.ed25519SigningInfo(fromSecretKey: secret, passphrase: passphrase)) != nil else {
                throw KeyImportError.wrongPassphrase
            }
            // Encryption subkey must be present and usable (passphrase already proven).
            guard (try? OpenPGPPacketParser.cv25519DecryptionKey(fromSecretKey: secret, passphrase: passphrase)) != nil else {
                throw KeyImportError.noEncryptionSubkey
            }
        }

        guard let fprHex = OpenPGPKeyID.primaryFingerprint(armoredPublicKey: inspection.armoredPublic),
              let fingerprint = Fingerprint(fprHex) else {
            throw KeyImportError.malformed
        }

        return Identity(
            fingerprint: fingerprint,
            secretKey: secret,
            armoredPublicKey: inspection.armoredPublic,
            protected: (passphrase != nil && !passphrase!.isEmpty)
        )
    }

    /// Pull the display name out of the key's User ID ("Name <email>" -> "Name").
    /// Returns nil if the UID is only an email or has no name.
    static func userIDName(fromSecretKey data: Data) -> String? {
        let bytes = [UInt8](data)
        var i = 0
        while i < bytes.count {
            let c = bytes[i]; i += 1
            guard c & 0x80 != 0 else { return nil }
            let newFormat = (c & 0x40) != 0
            let tag: Int
            var length = 0
            if newFormat {
                tag = Int(c & 0x3F)
                guard i < bytes.count else { return nil }
                let l = Int(bytes[i]); i += 1
                if l < 192 {
                    length = l
                } else if l < 224 {
                    guard i < bytes.count else { return nil }
                    length = ((l - 192) << 8) + Int(bytes[i]) + 192; i += 1
                } else if l == 255 {
                    guard i + 4 <= bytes.count else { return nil }
                    length = Int(bytes[i]) << 24 | Int(bytes[i+1]) << 16 | Int(bytes[i+2]) << 8 | Int(bytes[i+3]); i += 4
                } else {
                    return nil  // partial lengths not expected in a key
                }
            } else {
                tag = Int((c >> 2) & 0x0F)
                switch Int(c & 0x03) {
                case 0: guard i < bytes.count else { return nil }; length = Int(bytes[i]); i += 1
                case 1: guard i + 2 <= bytes.count else { return nil }; length = Int(bytes[i]) << 8 | Int(bytes[i+1]); i += 2
                case 2: guard i + 4 <= bytes.count else { return nil }; length = Int(bytes[i]) << 24 | Int(bytes[i+1]) << 16 | Int(bytes[i+2]) << 8 | Int(bytes[i+3]); i += 4
                default: return nil
                }
            }
            guard i + length <= bytes.count else { return nil }
            if tag == 13 {  // User ID
                let uid = String(bytes: bytes[i..<(i + length)], encoding: .utf8)
                return uid.flatMap(displayName(fromUID:))
            }
            i += length
        }
        return nil
    }

    private static func displayName(fromUID uid: String) -> String? {
        let trimmed = uid.trimmingCharacters(in: .whitespacesAndNewlines)
        if let bracket = trimmed.firstIndex(of: "<") {
            let name = String(trimmed[..<bracket]).trimmingCharacters(in: .whitespacesAndNewlines)
            return name.isEmpty ? nil : name
        }
        return trimmed.isEmpty ? nil : trimmed
    }
}

// MARK: - Import screen

struct ImportKeyView: View {
    let app: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var armored = ""
    @State private var passphrase = ""
    @State private var inspection: KeyImport.Inspection?
    @State private var error: String?
    @State private var showingFile = false
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Paste an OpenPGP private key, or import it from a file. Your key stays on this device. If it's passphrase-protected, it stays protected and unlocks with Face ID.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                if inspection == nil {
                    Section("Private key") {
                        TextEditor(text: $armored)
                            .frame(minHeight: 140)
                            .font(.system(.footnote, design: .monospaced))
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                        HStack {
                            Button {
                                if let clip = UIPasteboard.general.string { armored = clip }
                            } label: {
                                Label("Paste", systemImage: "doc.on.clipboard")
                            }
                            Spacer()
                            Button(role: .destructive) {
                                armored = ""
                                error = nil
                            } label: {
                                Label("Clear", systemImage: "xmark.circle")
                            }
                            .disabled(armored.isEmpty)
                        }
                        Button {
                            showingFile = true
                        } label: {
                            Label("Import from File", systemImage: "doc")
                        }
                    }
                } else if inspection?.needsPassphrase == true {
                    Section("Passphrase") {
                        SecureField("Key passphrase", text: $passphrase)
                        Text("This key is protected. Enter its passphrase once; after that, Face ID unlocks it.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                if let error {
                    Section {
                        Text(error).foregroundStyle(.red).font(.subheadline)
                    }
                }

                Section {
                    Button {
                        Task { await proceed() }
                    } label: {
                        HStack {
                            Text(inspection == nil ? "Continue" : "Import Key")
                            if busy { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(busy || (inspection == nil && armored.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty))
                } footer: {
                    Text("Importing replaces your current identity on this device. Back it up first if you still need it.")
                }
            }
            .navigationTitle("Import a Key")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancel") { dismiss() }
                }
            }
            .fileImporter(isPresented: $showingFile, allowedContentTypes: [.item], allowsMultipleSelection: false) { result in
                loadFile(result)
            }
        }
    }

    private func proceed() async {
        error = nil
        busy = true
        defer { busy = false }

        do {
            if inspection == nil {
                let result = try KeyImport.inspect(armored)
                inspection = result
                if !result.needsPassphrase {
                    try await adopt(result, passphrase: nil)
                }
            } else if let inspection {
                try await adopt(inspection, passphrase: passphrase.isEmpty ? nil : passphrase)
            }
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ?? "Import failed."
        }
    }

    private func adopt(_ inspection: KeyImport.Inspection, passphrase: String?) async throws {
        let identity = try KeyImport.makeIdentity(inspection, passphrase: passphrase)
        try await app.adoptImportedIdentity(identity, passphrase: passphrase)
        dismiss()
    }

    private func loadFile(_ result: Result<[URL], Error>) {
        guard case .success(let urls) = result, let url = urls.first else { return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        if let data = try? Data(contentsOf: url), let text = String(data: data, encoding: .utf8) {
            armored = text
        } else {
            error = "Couldn't read that file as a text key."
        }
    }
}
