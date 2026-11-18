import SwiftUI
import PhotosUI
import UniformTypeIdentifiers

// The Files tab: a dedicated transfer space over the same message store. It shows
// every attachment ever sent or received as a flat, reverse-chronological list of
// transfers (a file-manager feel, not chat bubbles), and offers a "send a file"
// flow that picks a contact and a file directly. All the crypto, relay, pairing
// and on-disk storage are reused from messaging — this is purely a new surface.

private struct FileTransfer: Identifiable {
    let attachment: ChatMessage.Attachment
    let peer: Fingerprint
    let direction: MessageDirection
    let sentAt: Int

    var id: String { attachment.id }

    init(attachment: ChatMessage.Attachment, message: ChatMessage) {
        self.attachment = attachment
        self.peer = message.peer
        self.direction = message.direction
        self.sentAt = message.sentAt
    }
}

struct FilesView: View {
    let store: ChatStore
    let contacts: [Contact]

    @State private var showingSend = false

    private var transfers: [FileTransfer] {
        store.conversations.values
            .flatMap { conversation in
                conversation.messages.flatMap { message in
                    message.attachments.map { FileTransfer(attachment: $0, message: message) }
                }
            }
            .sorted { $0.sentAt > $1.sentAt }
    }

    var body: some View {
        NavigationStack {
            Group {
                if transfers.isEmpty {
                    EmptyFilesView()
                } else {
                    List(transfers) { transfer in
                        TransferRow(transfer: transfer, contactName: name(for: transfer.peer))
                            .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 8, trailing: 16))
                    }
                    .listStyle(.plain)
                }
            }
            // Sending is the only action on this screen, so it gets one obvious
            // button at the bottom (tester feedback: the toolbar icon was hard to
            // find). The inset keeps it above the tab bar and pushes the list up,
            // and it serves the empty state too.
            .safeAreaInset(edge: .bottom) {
                SendFileButton { showingSend = true }
                    .padding(.bottom, 8)
            }
            .navigationTitle("Files")
        }
        .sheet(isPresented: $showingSend) {
            SendFileSheet(store: store, contacts: contacts)
        }
    }

    private func name(for peer: Fingerprint) -> String {
        contacts.first { $0.fingerprint == peer }?.displayName ?? shortFingerprint(peer)
    }
}

// MARK: - Transfer row

private struct TransferRow: View {
    let transfer: FileTransfer
    let contactName: String

    @State private var thumbnail: UIImage?
    @State private var showingFull = false
    @State private var shareItem: IdentifiedURL?
    @State private var exportItem: IdentifiedURL?
    @State private var showingActions = false

    private var attachment: ChatMessage.Attachment { transfer.attachment }
    private var isIncoming: Bool { transfer.direction == .incoming }

    var body: some View {
        Button {
            if attachment.isImage {
                showingFull = true
            } else {
                showingActions = true
            }
        } label: {
            HStack(spacing: 12) {
                thumb
                VStack(alignment: .leading, spacing: 3) {
                    Text(attachment.filename)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    HStack(spacing: 6) {
                        Image(systemName: isIncoming ? "arrow.down" : "arrow.up")
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(isIncoming ? Color.green : CPTheme.accent)
                        Text(isIncoming ? "From \(contactName)" : "To \(contactName)")
                            .lineLimit(1)
                        Text("·")
                        Text(sizeLabel)
                        Text("·")
                        Text(dateLabel)
                    }
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                }
                Spacer(minLength: 4)
                Menu {
                    Button {
                        exportItem = AttachmentStore.temporaryCopy(of: attachment.localPath, filename: attachment.filename).map(IdentifiedURL.init)
                    } label: {
                        Label("Save to Files", systemImage: "folder")
                    }
                    Button {
                        shareItem = AttachmentStore.temporaryCopy(of: attachment.localPath, filename: attachment.filename).map(IdentifiedURL.init)
                    } label: {
                        Label("Share", systemImage: "square.and.arrow.up")
                    }
                } label: {
                    Image(systemName: "ellipsis")
                        .foregroundStyle(.secondary)
                        .frame(width: 30, height: 30)
                        .contentShape(Rectangle())
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .task { await loadThumb() }
        .fullScreenCover(isPresented: $showingFull) {
            FullScreenImageView(attachment: attachment)
        }
        .confirmationDialog(attachment.filename, isPresented: $showingActions, titleVisibility: .visible) {
            Button("Save to Files") {
                exportItem = AttachmentStore.temporaryCopy(of: attachment.localPath, filename: attachment.filename).map(IdentifiedURL.init)
            }
            Button("Share") {
                shareItem = AttachmentStore.temporaryCopy(of: attachment.localPath, filename: attachment.filename).map(IdentifiedURL.init)
            }
            Button("Cancel", role: .cancel) {}
        }
        .sheet(item: $shareItem) { ShareSheet(items: [$0.url]) }
        .sheet(item: $exportItem) { DocumentExporter(url: $0.url) }
    }

    private var thumb: some View {
        Group {
            if let thumbnail {
                Image(uiImage: thumbnail)
                    .resizable()
                    .scaledToFill()
            } else {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color(.secondarySystemBackground))
                    .overlay(
                        Image(systemName: icon)
                            .font(.title3)
                            .foregroundStyle(.secondary)
                    )
            }
        }
        .frame(width: 46, height: 46)
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    private func loadThumb() async {
        guard attachment.isImage, thumbnail == nil else { return }
        let path = attachment.localPath
        thumbnail = await Task.detached { AttachmentThumbnail.make(path: path, maxPixel: 140) }.value
    }

    private var icon: String {
        if attachment.mime.hasPrefix("video/") { return "film" }
        if attachment.mime.hasPrefix("audio/") { return "waveform" }
        if attachment.mime.contains("pdf") { return "doc.richtext" }
        if attachment.mime.contains("zip") || attachment.mime.contains("compressed") { return "doc.zipper" }
        return "doc"
    }

    private var sizeLabel: String {
        ByteCountFormatter.string(fromByteCount: Int64(attachment.size), countStyle: .file)
    }

    private var dateLabel: String {
        let date = Date(timeIntervalSince1970: TimeInterval(transfer.sentAt))
        if Calendar.current.isDateInToday(date) {
            return date.formatted(date: .omitted, time: .shortened)
        }
        return date.formatted(date: .abbreviated, time: .omitted)
    }
}

// MARK: - Send a file

private struct SendFileSheet: View {
    let store: ChatStore
    let contacts: [Contact]

    @Environment(\.dismiss) private var dismiss

    @State private var selected: Contact?
    @State private var showingSource = false
    @State private var showingFiles = false
    @State private var showingCamera = false
    @State private var showingPhotos = false
    @State private var photoItems: [PhotosPickerItem] = []
    @State private var sending = false

    var body: some View {
        NavigationStack {
            Group {
                if contacts.isEmpty {
                    ContentUnavailableView(
                        "No contacts yet",
                        systemImage: "person.crop.circle.badge.plus",
                        description: Text("Pair with someone to send them a file.")
                    )
                } else {
                    List(contacts, id: \.fingerprint) { contact in
                        Button {
                            selected = contact
                            showingSource = true
                        } label: {
                            HStack(spacing: 12) {
                                ContactInitial(name: contact.displayName ?? shortFingerprint(contact.fingerprint))
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(contact.displayName ?? shortFingerprint(contact.fingerprint))
                                        .font(.body.weight(.semibold))
                                        .foregroundStyle(.primary)
                                    Text(shortFingerprint(contact.fingerprint))
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
                            }
                            .contentShape(Rectangle())
                        }
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle("Send a File")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { Button("Cancel") { dismiss() } }
            }
            .overlay {
                if sending {
                    ProgressView("Sending…").padding(20).background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
                }
            }
        }
        .confirmationDialog("Send from", isPresented: $showingSource, titleVisibility: .visible) {
            Button("Files") { showingFiles = true }
            Button("Photo Library") { showingPhotos = true }
            Button("Camera") { showingCamera = true }
            Button("Cancel", role: .cancel) {}
        }
        .fileImporter(isPresented: $showingFiles, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
            handleFiles(result)
        }
        .photosPicker(isPresented: $showingPhotos, selection: $photoItems, maxSelectionCount: 10, matching: .any(of: [.images, .videos]))
        .onChange(of: photoItems) { _, items in
            guard !items.isEmpty else { return }
            Task { await handlePhotos(items) }
        }
        .sheet(isPresented: $showingCamera) {
            CameraPicker { image in
                if let data = image.jpegData(compressionQuality: 0.9) {
                    send([.init(filename: "photo-\(Int(Date().timeIntervalSince1970)).jpg", mime: "image/jpeg", data: data)])
                }
            }
            .ignoresSafeArea()
        }
    }

    private func handleFiles(_ result: Result<[URL], Error>) {
        guard case .success(let urls) = result else { return }
        var atts: [OutgoingMessage.Attachment] = []
        for url in urls {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            guard let data = try? Data(contentsOf: url) else { continue }
            let mime = (UTType(filenameExtension: url.pathExtension)?.preferredMIMEType) ?? "application/octet-stream"
            atts.append(.init(filename: url.lastPathComponent, mime: mime, data: data))
        }
        send(atts)
    }

    private func handlePhotos(_ items: [PhotosPickerItem]) async {
        var atts: [OutgoingMessage.Attachment] = []
        for item in items {
            guard let data = try? await item.loadTransferable(type: Data.self) else { continue }
            let ext = item.supportedContentTypes.first?.preferredFilenameExtension ?? "jpg"
            let mime = item.supportedContentTypes.first?.preferredMIMEType ?? "image/jpeg"
            atts.append(.init(filename: "photo-\(UUID().uuidString.prefix(6)).\(ext)", mime: mime, data: data))
        }
        await MainActor.run { photoItems = []; send(atts) }
    }

    private func send(_ attachments: [OutgoingMessage.Attachment]) {
        guard let contact = selected, !attachments.isEmpty else { return }
        sending = true
        Task {
            await store.send(text: nil, attachments: attachments, to: contact)
            await MainActor.run { sending = false; dismiss() }
        }
    }
}

// MARK: - Empty state

private struct EmptyFilesView: View {
    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "tray.and.arrow.down")
                .font(.system(size: 46))
                .foregroundStyle(CPTheme.accent)
            Text("No files yet")
                .font(.title3.bold())
            Text("Files you send and receive appear here, encrypted end to end.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)
        }
    }
}

// MARK: - Send button

/// The Files tab's one primary action, bottom center, empty or not.
private struct SendFileButton: View {
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label("Send a File", systemImage: "arrow.up.doc.fill")
                .font(.body.weight(.semibold))
                .foregroundStyle(.white)
                .padding(.horizontal, 24)
                .padding(.vertical, 12)
                .background(Capsule().fill(CPTheme.send))
        }
        .shadow(color: .black.opacity(0.15), radius: 6, y: 2)
    }
}

// MARK: - Shared helper

private struct ContactInitial: View {
    let name: String
    var body: some View {
        Circle()
            .fill(CPTheme.send)
            .frame(width: 40, height: 40)
            .overlay(
                Text(String(name.prefix(1)).uppercased())
                    .font(.headline)
                    .foregroundStyle(.white)
            )
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
