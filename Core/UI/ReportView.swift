import SwiftUI

// Report a contact for abuse or illegal content. Because messages are end-to-end
// encrypted, a report is assembled on the reporter's device and only carries what
// they choose to share: the reason, an optional description, and — with explicit
// consent — the text of recent messages they received. File and image bytes are
// never uploaded. Blocking (unpair) is offered in the same step, covering both
// halves of the report-and-block requirement.

struct ReportView: View {
    let store: ChatStore
    let contact: Contact
    var onBlock: (() -> Void)? = nil

    @Environment(\.dismiss) private var dismiss

    @State private var category = "harassment"
    @State private var details = ""
    @State private var includeContent = false
    @State private var alsoBlock = true
    @State private var submitting = false
    @State private var error: String?

    private let categories: [(id: String, label: String)] = [
        ("spam", "Spam"),
        ("harassment", "Harassment or abuse"),
        ("illegal", "Illegal content"),
        ("csam", "Child sexual abuse material"),
        ("other", "Something else")
    ]

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Your report goes to CarrierPony's developer for review. Because messages are end to end encrypted, only what you include below is shared.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section("Reason") {
                    Picker("Reason", selection: $category) {
                        ForEach(categories, id: \.id) { Text(LocalizedStringKey($0.label)).tag($0.id) }
                    }
                    .pickerStyle(.inline)
                    .labelsHidden()
                }

                Section("Details") {
                    TextField("Describe what happened (optional)", text: $details, axis: .vertical)
                        .lineLimit(3...6)
                }

                Section {
                    Toggle("Include recent messages", isOn: $includeContent)
                } footer: {
                    Text("Includes the text of recent messages you received from this contact so they can be reviewed. Files and images are never uploaded — describe them above instead.")
                }

                Section {
                    Toggle("Block this contact", isOn: $alsoBlock)
                } footer: {
                    Text("Blocking removes them from this device. You won't receive new messages from them unless you pair again.")
                }

                if let error {
                    Section {
                        Text(error).foregroundStyle(.red).font(.subheadline)
                    }
                }

                Section {
                    Button(role: .destructive) {
                        Task { await submit() }
                    } label: {
                        HStack {
                            Text("Submit Report")
                            if submitting { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(submitting)
                }
            }
            .navigationTitle("Report")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { Button("Cancel") { dismiss() } }
            }
        }
    }

    private func submit() async {
        submitting = true
        error = nil
        defer { submitting = false }
        let trimmed = details.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            try await store.submitReport(
                contact: contact,
                category: category,
                description: trimmed.isEmpty ? nil : trimmed,
                includeContent: includeContent
            )
            if alsoBlock { onBlock?() }
            dismiss()
        } catch {
            self.error = "Report failed: \(error.localizedDescription)"
        }
    }
}
