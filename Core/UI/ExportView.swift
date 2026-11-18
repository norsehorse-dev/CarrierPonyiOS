import SwiftUI

// Export one conversation to a file. Encrypted (passphrase-sealed) by default so
// the export leaves no plaintext at rest; plaintext is a deliberate, warned
// opt-in. The finished file is handed to the system share sheet, so the user
// chooses where it goes. Nothing here touches the relay.

struct ExportView: View {
    let conversation: Conversation
    let peerName: String

    @Environment(\.dismiss) private var dismiss

    @State private var format: ExportFormat = .txt
    @State private var encrypt = true
    @State private var passphrase = ""
    @State private var confirmPass = ""
    @State private var error: String?
    @State private var shareItem: IdentifiedURL?

    var body: some View {
        NavigationStack {
            Form {
                Section("Format") {
                    Picker("Format", selection: $format) {
                        ForEach(ExportFormat.allCases) { Text($0.label).tag($0) }
                    }
                    .pickerStyle(.inline)
                    .labelsHidden()
                }

                Section {
                    Toggle("Encrypt with a passphrase", isOn: $encrypt)
                    if encrypt {
                        SecureField("Passphrase", text: $passphrase)
                        SecureField("Confirm passphrase", text: $confirmPass)
                    }
                } footer: {
                    Text(encrypt
                        ? "The file is sealed with your passphrase, the same encryption as an identity backup, and opens in CarrierPony or any OpenPGP tool. Without the passphrase it cannot be read, so keep it safe."
                        : "The file is written as plain, unencrypted text. Anyone who gets it can read the whole conversation.")
                }

                Section {
                    Text("Export saves a copy of this conversation to a file you choose where to send. Messages auto-expire in CarrierPony, but an exported copy does not, so it outlives the disappear time. Attachments are listed by name; their contents are not included.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                if let error {
                    Section {
                        Text(error).foregroundStyle(.red).font(.subheadline)
                    }
                }

                Section {
                    Button {
                        runExport()
                    } label: {
                        Label("Export", systemImage: "square.and.arrow.up")
                    }
                }
            }
            .navigationTitle("Export Chat")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancel") { dismiss() }
                }
            }
            .sheet(item: $shareItem) { item in
                ShareSheet(items: [item.url])
            }
        }
    }

    private func runExport() {
        error = nil
        if encrypt {
            guard !passphrase.isEmpty else {
                error = "Enter a passphrase, or turn off encryption."
                return
            }
            guard passphrase == confirmPass else {
                error = "The passphrases don't match."
                return
            }
        }
        do {
            let url = try ChatExport.writeTempFile(
                conversation: conversation,
                peerName: peerName,
                format: format,
                passphrase: encrypt ? passphrase : nil
            )
            shareItem = IdentifiedURL(url: url)
        } catch {
            self.error = "Export failed: \(error.localizedDescription)"
        }
    }
}
