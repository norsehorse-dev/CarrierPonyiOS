import SwiftUI
import UIKit
import ImageIO
import PhotosUI
import UniformTypeIdentifiers
import SafariServices

// The conversation screen: one thread with one peer. Reads its messages from the
// ChatStore (observed) and sends through it. Everything is keyed off the peer
// Contact, so the view never needs to compute a thread ID itself.
//
// Depends only on ChatStore, ChatMessage, Conversation, Contact, and CPTheme, so
// it previews with a seeded preview store, no relay or crypto required.

struct ConversationView: View {

    let store: ChatStore
    let contact: Contact
    var onSetNickname: ((Fingerprint, String?) -> Void)? = nil
    var onUnpair: ((Fingerprint) -> Void)? = nil

    @Environment(\.dismiss) private var dismiss
    @State private var showingReport = false
    @State private var linkToOpen: IdentifiedURL?
    @State private var showingClearHistory = false
    @State private var showingExport = false

    @State private var draft: String = ""
    @FocusState private var composerFocused: Bool
    @State private var showingNicknamePrompt = false
    @State private var nicknameDraft = ""

    @State private var pending: [OutgoingMessage.Attachment] = []
    @State private var showingFiles = false
    @State private var showingCamera = false
    @State private var photoItems: [PhotosPickerItem] = []
    @State private var showingPhotos = false
    /// Whether the end of the thread is on screen. A new message only pulls the
    /// list down when it is, so reading older messages is not interrupted.
    @State private var atBottom = true

    private var conversation: Conversation? {
        store.conversations.values.first { $0.peer == contact.fingerprint }
    }

    private var messages: [ChatMessage] {
        conversation?.sortedMessages ?? []
    }

    private var title: String {
        contact.displayName ?? conversation?.peerName ?? shortFingerprint(contact.fingerprint)
    }

    var body: some View {
        VStack(spacing: 0) {
            if store.awaitingPeers.contains(contact.fingerprint.hex) {
                InfoBanner(text: "\(title) hasn't finished pairing yet. Your messages will open on their side once their app checks in.")
            }
            messageList
            Divider().overlay(CPTheme.hairline)
            composer
        }
        .background(CPTheme.screen)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                HStack(spacing: 10) {
                    Avatar(name: contact.displayName, size: 30)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(title)
                            .font(.headline)
                            .lineLimit(1)
                        HStack(spacing: 4) {
                            Image(systemName: isSealed ? "lock.fill" : "lock.open")
                                .font(.caption2)
                                .foregroundStyle(isSealed ? Color.green : Color.secondary)
                            Text(shortFingerprint(contact.fingerprint))
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel(isSealed
                            ? "Sealed, \(shortFingerprint(contact.fingerprint))"
                            : "Standard, \(shortFingerprint(contact.fingerprint))")
                    }
                }
            }
            if onSetNickname != nil {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button {
                            nicknameDraft = contact.nickname ?? ""
                            showingNicknamePrompt = true
                        } label: {
                            Label(contact.nickname == nil ? "Set Nickname" : "Edit Nickname", systemImage: "pencil")
                        }
                        if contact.nickname != nil {
                            Button(role: .destructive) {
                                onSetNickname?(contact.fingerprint, nil)
                            } label: {
                                Label("Remove Nickname", systemImage: "xmark")
                            }
                        }
                        Divider()
                        Button(role: .destructive) {
                            showingReport = true
                        } label: {
                            Label("Report", systemImage: "flag")
                        }
                        Button {
                            showingExport = true
                        } label: {
                            Label("Export Chat", systemImage: "square.and.arrow.up")
                        }
                        Button(role: .destructive) {
                            showingClearHistory = true
                        } label: {
                            Label("Clear Chat History", systemImage: "trash")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle").tint(CPTheme.accent)
                    }
                }
            }
        }
        .alert("Nickname", isPresented: $showingNicknamePrompt) {
            TextField("Nickname", text: $nicknameDraft)
            Button("Save") { onSetNickname?(contact.fingerprint, nicknameDraft) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("A private name for this contact, visible only to you. It overrides the name they share.")
        }
        .confirmationDialog("Clear this chat's history?", isPresented: $showingClearHistory, titleVisibility: .visible) {
            Button("Clear History", role: .destructive) {
                if let threadID = conversation?.threadID {
                    store.clearHistory(threadID: threadID)
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Deletes every message in this chat on this device. The contact stays paired.")
        }
        .sheet(isPresented: $showingExport) {
            if let conversation {
                ExportView(conversation: conversation, peerName: title)
            }
        }
        .sheet(isPresented: $showingReport) {
            ReportView(store: store, contact: contact, onBlock: {
                onUnpair?(contact.fingerprint)
                dismiss()
            })
        }
        .task { await markReadIfNeeded() }
        .onChange(of: messages.count) { _, _ in
            Task { await markReadIfNeeded() }
        }
    }

    // MARK: - Message list

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                if messages.isEmpty {
                    EmptyThread()
                        .frame(maxWidth: .infinity)
                        .padding(.top, 80)
                } else {
                    LazyVStack(spacing: 3) {
                        ForEach(groupedByDay, id: \.day) { group in
                            DaySeparator(date: group.day)
                                .padding(.vertical, 8)
                            ForEach(group.messages) { message in
                                MessageRow(
                                    message: message,
                                    onDeleteForMe: { store.deleteLocally(messageID: message.id) },
                                    onDeleteForEveryone: {
                                        Task { await store.deleteForEveryone(messageID: message.id, to: contact) }
                                    }
                                )
                                .id(message.id)
                            }
                        }
                        Color.clear.frame(height: 8).id(bottomAnchor)
                            .onAppear { atBottom = true }
                            .onDisappear { atBottom = false }
                    }
                    .padding(.horizontal, 12)
                    .padding(.top, 8)
                }
            }
            .scrollDismissesKeyboard(.interactively)
            .onChange(of: messages.count) { _, _ in
                // Jumping to the end from far up makes the lazy stack build every
                // row on the way, which froze the list for seconds in a long
                // thread. Follow only when already at the end, or for my own send.
                guard atBottom || messages.last?.direction == .outgoing else { return }
                withAnimation(.easeOut(duration: 0.25)) {
                    proxy.scrollTo(bottomAnchor, anchor: .bottom)
                }
            }
            .onAppear {
                proxy.scrollTo(bottomAnchor, anchor: .bottom)
            }
        }
        .environment(\.openURL, OpenURLAction { url in
            if url.scheme == "http" || url.scheme == "https" {
                linkToOpen = IdentifiedURL(url: url)
                return .handled
            }
            return .systemAction
        })
        .sheet(item: $linkToOpen) { item in
            SafariView(url: item.url)
        }
    }

    private let bottomAnchor = "cp-bottom-anchor"

    private var groupedByDay: [(day: Date, messages: [ChatMessage])] {
        let cal = Calendar.current
        let groups = Dictionary(grouping: messages) { msg in
            cal.startOfDay(for: Date(timeIntervalSince1970: TimeInterval(msg.sentAt)))
        }
        // messages is already in time order and grouping keeps that order.
        return groups.keys.sorted().map { ($0, groups[$0]!) }
    }

    // MARK: - Composer

    private var composer: some View {
        VStack(spacing: 8) {
            if !pending.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(Array(pending.enumerated()), id: \.offset) { index, item in
                            PendingChip(attachment: item) {
                                pending.remove(at: index)
                            }
                        }
                    }
                    .padding(.horizontal, 4)
                }
            }
            HStack(alignment: .bottom, spacing: 10) {
                Menu {
                    Button {
                        showingFiles = true
                    } label: {
                        Label("Files", systemImage: "folder")
                    }
                    Button {
                        showingCamera = true
                    } label: {
                        Label("Camera", systemImage: "camera")
                    }
                    Button {
                        showingPhotos = true
                    } label: {
                        Label("Photo Library", systemImage: "photo.on.rectangle")
                    }
                } label: {
                    Image(systemName: "plus")
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(CPTheme.accent)
                        .frame(width: 38, height: 38)
                }

                TextField("Message", text: $draft, axis: .vertical)
                    .lineLimit(1...5)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 9)
                    .background(CPTheme.composerField, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
                    .focused($composerFocused)

                Button(action: sendDraft) {
                    Image(systemName: "arrow.up")
                        .font(.system(size: 18, weight: .bold))
                        .foregroundStyle(.white)
                        .frame(width: 38, height: 38)
                        .background {
                            Circle().fill(canSend ? AnyShapeStyle(CPTheme.send) : AnyShapeStyle(Color(.systemGray4)))
                        }
                }
                .disabled(!canSend)
                .animation(.easeInOut(duration: 0.15), value: canSend)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(CPTheme.screen)
        .fileImporter(isPresented: $showingFiles, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
            handleFileImport(result)
        }
        .photosPicker(isPresented: $showingPhotos, selection: $photoItems, maxSelectionCount: 10, matching: .any(of: [.images, .videos]))
        .sheet(isPresented: $showingCamera) {
            CameraPicker { image in
                if let data = image.jpegData(compressionQuality: 0.9) {
                    pending.append(.init(filename: "photo-\(Int(Date().timeIntervalSince1970)).jpg", mime: "image/jpeg", data: data))
                }
            }
            .ignoresSafeArea()
        }
        .onChange(of: photoItems) { _, items in
            guard !items.isEmpty else { return }
            Task { await loadPickedPhotos(items) }
        }
    }

    private var canSend: Bool {
        !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !pending.isEmpty
    }

    private func sendDraft() {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        let attachments = pending
        guard !text.isEmpty || !attachments.isEmpty else { return }
        draft = ""
        pending = []
        Task { await store.send(text: text.isEmpty ? nil : text, attachments: attachments, to: contact) }
    }

    private func handleFileImport(_ result: Result<[URL], Error>) {
        guard case .success(let urls) = result else { return }
        for url in urls {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            guard let data = try? Data(contentsOf: url) else { continue }
            let mime = (UTType(filenameExtension: url.pathExtension)?.preferredMIMEType) ?? "application/octet-stream"
            pending.append(.init(filename: url.lastPathComponent, mime: mime, data: data))
        }
    }

    private func loadPickedPhotos(_ items: [PhotosPickerItem]) async {
        var loaded: [OutgoingMessage.Attachment] = []
        for item in items {
            guard let data = try? await item.loadTransferable(type: Data.self) else { continue }
            let ext = item.supportedContentTypes.first?.preferredFilenameExtension ?? "jpg"
            let mime = item.supportedContentTypes.first?.preferredMIMEType ?? "image/jpeg"
            loaded.append(.init(filename: "photo-\(UUID().uuidString.prefix(6)).\(ext)", mime: mime, data: data))
        }
        await MainActor.run {
            pending.append(contentsOf: loaded)
            photoItems = []
        }
    }

    private func markReadIfNeeded() async {
        guard let threadID = conversation?.threadID else { return }
        await store.markRead(threadID: threadID)
    }

    private var isSealed: Bool {
        store.isSealed(with: contact.fingerprint)
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

// MARK: - Message row + bubble

/// Copy a message's text from a bubble's context menu, 1:1 and groups. People
/// paste ciphertext from a keyboard encryption tool into a message and the
/// other side copies it back out to decrypt, so sent and received bubbles both
/// need it. Local only: the text does not travel to the user's other Apple
/// devices over Universal Clipboard.
enum MessageClipboard {
    static func copy(_ text: String) {
        UIPasteboard.general.setItems([[UTType.utf8PlainText.identifier: text]], options: [.localOnly: true])
    }
}

private struct MessageRow: View {
    let message: ChatMessage
    var onDeleteForMe: (() -> Void)? = nil
    var onDeleteForEveryone: (() -> Void)? = nil

    private var isOutgoing: Bool { message.direction == .outgoing }

    var body: some View {
        HStack {
            if isOutgoing { Spacer(minLength: 48) }
            VStack(alignment: isOutgoing ? .trailing : .leading, spacing: 3) {
                bubble
                    .contextMenu {
                        if let text = message.text, !text.isEmpty {
                            Button {
                                MessageClipboard.copy(text)
                            } label: {
                                Label("Copy", systemImage: "doc.on.doc")
                            }
                        }
                        if isOutgoing, let onDeleteForEveryone {
                            Button(role: .destructive, action: onDeleteForEveryone) {
                                Label("Delete for Everyone", systemImage: "trash")
                            }
                        }
                        if let onDeleteForMe {
                            Button(role: .destructive, action: onDeleteForMe) {
                                Label("Delete for Me", systemImage: "trash")
                            }
                        }
                    }
                metadata
            }
            if !isOutgoing { Spacer(minLength: 48) }
        }
    }

    private var bubble: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(message.attachments) { attachment in
                if attachment.isImage {
                    AttachmentImageView(attachment: attachment)
                } else {
                    AttachmentChip(attachment: attachment, onLight: isOutgoing)
                }
            }
            if let text = message.text, !text.isEmpty {
                Text(MessageRow.linkified(text))
                    .foregroundStyle(isOutgoing ? .white : Color.primary)
                    .tint(isOutgoing ? .white : CPTheme.accent)
            }
        }
        .padding(.horizontal, isImageOnly ? 4 : 14)
        .padding(.vertical, isImageOnly ? 4 : 9)
        .background {
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .fill(isOutgoing ? AnyShapeStyle(CPTheme.accent) : AnyShapeStyle(CPTheme.incomingBubble))
        }
    }

    // Detect URLs in message text and mark them as tappable, underlined links.
    // The tap is handled by the openURL action installed on the message list,
    // which opens http/https links in an in-app SFSafariViewController.
    // One detector for the app, and results cached per text: building an
    // NSDataDetector and scanning on every render of every bubble was a large
    // share of the cost of scrolling a long conversation.
    private static let linkDetector = try? NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue)
    private static let linkCache: NSCache<NSString, LinkifiedBox> = {
        let cache = NSCache<NSString, LinkifiedBox>()
        cache.countLimit = 2000
        return cache
    }()

    final class LinkifiedBox {
        let value: AttributedString
        init(_ value: AttributedString) { self.value = value }
    }

    static func linkified(_ text: String) -> AttributedString {
        if let hit = linkCache.object(forKey: text as NSString) { return hit.value }
        let result = makeLinkified(text)
        linkCache.setObject(LinkifiedBox(result), forKey: text as NSString)
        return result
    }

    private static func makeLinkified(_ text: String) -> AttributedString {
        guard let detector = linkDetector else {
            return AttributedString(text)
        }
        let ns = NSMutableAttributedString(string: text)
        let full = NSRange(location: 0, length: (text as NSString).length)
        for match in detector.matches(in: text, options: [], range: full) {
            guard let url = match.url else { continue }
            ns.addAttribute(.link, value: url, range: match.range)
            ns.addAttribute(.underlineStyle, value: NSUnderlineStyle.single.rawValue, range: match.range)
        }
        return AttributedString(ns)
    }

    private var isImageOnly: Bool {
        message.text == nil
            && !message.attachments.isEmpty
            && message.attachments.allSatisfy { $0.isImage }
    }

    private var metadata: some View {
        HStack(spacing: 4) {
            if let remaining = disappearingLabel {
                Image(systemName: "timer")
                Text(remaining)
            }
            Text(timeLabel)
            if message.viaLan {
                // viaLan now marks any direct-path delivery (LAN or WAN hole-punch),
                // so the glyph and label are generic "delivered directly".
                Image(systemName: "point.3.connected.trianglepath.dotted")
                    .accessibilityLabel(Text("Delivered directly"))
            }
            if isOutgoing {
                Image(systemName: message.isRead ? "checkmark.circle.fill" : "checkmark")
                    .foregroundStyle(message.isRead ? CPTheme.accent : Color.secondary)
            }
        }
        .font(.caption2)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 4)
    }

    private var timeLabel: String {
        Date(timeIntervalSince1970: TimeInterval(message.sentAt))
            .formatted(date: .omitted, time: .shortened)
    }

    // Only surface the disappearing indicator when it is actually imminent
    // (under a day), so a standard 30-day TTL does not clutter every message.
    private var disappearingLabel: String? {
        let remaining = message.expiresAt - Int(Date().timeIntervalSince1970)
        guard remaining > 0, remaining < 86_400 else { return nil }
        let hours = remaining / 3600
        if hours >= 1 { return "\(hours)h" }
        let minutes = max(1, remaining / 60)
        return "\(minutes)m"
    }
}

struct AttachmentImageView: View {
    let attachment: ChatMessage.Attachment
    @State private var image: UIImage?
    @State private var showingFull = false

    var body: some View {
        // A row scrolled away and back loses its state. The cache gives it the
        // picture again at once, so the bubble does not flash a placeholder and
        // change size under the finger.
        let shown = image ?? AttachmentThumbnail.cached(path: attachment.localPath, maxPixel: 640)
        return Group {
            if let image = shown {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFill()
                    .frame(maxWidth: 240, maxHeight: 280)
                    .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                    .onTapGesture { showingFull = true }
            } else {
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(Color(.tertiarySystemBackground))
                    .frame(width: 180, height: 180)
                    .overlay(ProgressView())
            }
        }
        .task { await load() }
        .fullScreenCover(isPresented: $showingFull) {
            FullScreenImageView(attachment: attachment)
        }
    }

    private func load() async {
        if image != nil { return }
        let path = attachment.localPath
        image = await Task.detached { AttachmentThumbnail.make(path: path, maxPixel: 640) }.value
    }
}

struct AttachmentChip: View {
    let attachment: ChatMessage.Attachment
    let onLight: Bool
    @State private var shareItem: IdentifiedURL?
    @State private var exportItem: IdentifiedURL?
    @State private var showingActions = false

    var body: some View {
        Button {
            showingActions = true
        } label: {
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .font(.title3)
                VStack(alignment: .leading, spacing: 1) {
                    Text(attachment.filename)
                        .lineLimit(1)
                        .font(.subheadline.weight(.medium))
                    Text(sizeLabel)
                        .font(.caption2)
                        .opacity(0.7)
                }
                Image(systemName: "arrow.down.circle").font(.body)
            }
            .foregroundStyle(onLight ? .white : Color.primary)
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .background {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(onLight ? Color.white.opacity(0.18) : Color(.tertiarySystemBackground))
            }
        }
        .buttonStyle(.plain)
        .confirmationDialog(attachment.filename, isPresented: $showingActions, titleVisibility: .visible) {
            Button("Save to Files") {
                exportItem = AttachmentStore.temporaryCopy(of: attachment.localPath, filename: attachment.filename).map(IdentifiedURL.init)
            }
            Button("Share") {
                shareItem = AttachmentStore.temporaryCopy(of: attachment.localPath, filename: attachment.filename).map(IdentifiedURL.init)
            }
            Button("Cancel", role: .cancel) {}
        }
        .sheet(item: $shareItem) { item in
            ShareSheet(items: [item.url])
        }
        .sheet(item: $exportItem) { item in
            DocumentExporter(url: item.url)
        }
    }

    private var sizeLabel: String {
        ByteCountFormatter.string(fromByteCount: Int64(attachment.size), countStyle: .file)
    }

    private var icon: String {
        if attachment.mime.hasPrefix("video/") { return "film" }
        if attachment.mime.hasPrefix("audio/") { return "waveform" }
        if attachment.mime.contains("pdf") { return "doc.richtext" }
        return "doc"
    }
}

struct PendingChip: View {
    let attachment: OutgoingMessage.Attachment
    let onRemove: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: attachment.mime.hasPrefix("image/") ? "photo" : "doc")
                .font(.caption)
            Text(attachment.filename)
                .font(.caption)
                .lineLimit(1)
                .frame(maxWidth: 120, alignment: .leading)
            Button(action: onRemove) {
                Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(Capsule().fill(Color(.secondarySystemBackground)))
    }
}

// Downsampled thumbnail via ImageIO, so large images never fully decode for the bubble.
// Nothing here touches the UI, so it is taken off the main actor: decoding a
// photo on the main actor while the list scrolls is what made scrolling stick.
enum AttachmentThumbnail {
    nonisolated(unsafe) private static let cache: NSCache<NSString, UIImage> = {
        let cache = NSCache<NSString, UIImage>()
        cache.countLimit = 150
        return cache
    }()

    nonisolated private static func key(_ path: String, _ maxPixel: Int) -> NSString {
        "\(maxPixel)|\(path)" as NSString
    }

    nonisolated static func cached(path: String, maxPixel: Int) -> UIImage? {
        cache.object(forKey: key(path, maxPixel))
    }

    nonisolated static func make(path: String, maxPixel: Int) -> UIImage? {
        if let hit = cache.object(forKey: key(path, maxPixel)) { return hit }
        let url = AttachmentStore.url(for: path)
        guard let src = CGImageSourceCreateWithURL(url as CFURL, nil) else { return nil }
        let options: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceThumbnailMaxPixelSize: maxPixel
        ]
        guard let cg = CGImageSourceCreateThumbnailAtIndex(src, 0, options as CFDictionary) else { return nil }
        let image = UIImage(cgImage: cg)
        // Bubble and file-list sizes only. Full screen images are too big to keep.
        if maxPixel <= 640 { cache.setObject(image, forKey: key(path, maxPixel)) }
        return image
    }
}

struct FullScreenImageView: View {
    let attachment: ChatMessage.Attachment
    @Environment(\.dismiss) private var dismiss
    @State private var image: UIImage?
    @State private var shareItem: IdentifiedURL?
    @State private var savedNotice = false

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            if let image {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFit()
            } else {
                ProgressView().tint(.white)
            }
            VStack {
                HStack {
                    Button { dismiss() } label: {
                        Image(systemName: "xmark").font(.title3.weight(.semibold))
                            .foregroundStyle(.white).padding(12)
                            .background(Circle().fill(.black.opacity(0.4)))
                    }
                    Spacer()
                    Button {
                        if let image { UIImageWriteToSavedPhotosAlbum(image, nil, nil, nil); savedNotice = true }
                    } label: {
                        Image(systemName: savedNotice ? "checkmark" : "square.and.arrow.down").font(.title3.weight(.semibold))
                            .foregroundStyle(.white).padding(12)
                            .background(Circle().fill(.black.opacity(0.4)))
                    }
                    Button {
                        shareItem = AttachmentStore.temporaryCopy(of: attachment.localPath, filename: attachment.filename).map(IdentifiedURL.init)
                    } label: {
                        Image(systemName: "square.and.arrow.up").font(.title3.weight(.semibold))
                            .foregroundStyle(.white).padding(12)
                            .background(Circle().fill(.black.opacity(0.4)))
                    }
                }
                .padding()
                Spacer()
            }
        }
        .task {
            let path = attachment.localPath
            image = await Task.detached { AttachmentThumbnail.make(path: path, maxPixel: 2048) }.value
        }
        .sheet(item: $shareItem) { item in ShareSheet(items: [item.url]) }
    }
}

struct CameraPicker: UIViewControllerRepresentable {
    let onCapture: (UIImage) -> Void
    @Environment(\.dismiss) private var dismiss

    func makeUIViewController(context: Context) -> UIImagePickerController {
        let picker = UIImagePickerController()
        picker.sourceType = .camera
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ picker: UIImagePickerController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    final class Coordinator: NSObject, UIImagePickerControllerDelegate, UINavigationControllerDelegate {
        let parent: CameraPicker
        init(_ parent: CameraPicker) { self.parent = parent }

        func imagePickerController(_ picker: UIImagePickerController, didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey: Any]) {
            if let image = info[.originalImage] as? UIImage {
                parent.onCapture(image)
            }
            parent.dismiss()
        }

        func imagePickerControllerDidCancel(_ picker: UIImagePickerController) {
            parent.dismiss()
        }
    }
}

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}

struct DocumentExporter: UIViewControllerRepresentable {
    let url: URL
    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(forExporting: [url], asCopy: true)
        return picker
    }
    func updateUIViewController(_ controller: UIDocumentPickerViewController, context: Context) {}
}

struct IdentifiedURL: Identifiable {
    let url: URL
    var id: String { url.absoluteString }
}

// Opens a link inside the app rather than kicking out to Safari, so a tapped
// URL never leaves CarrierPony's session or lands in the system browser's
// history. Used for http/https links only.
struct SafariView: UIViewControllerRepresentable {
    let url: URL
    func makeUIViewController(context: Context) -> SFSafariViewController {
        SFSafariViewController(url: url)
    }
    func updateUIViewController(_ controller: SFSafariViewController, context: Context) {}
}

// MARK: - Supporting views

private struct DaySeparator: View {
    @Environment(\.locale) private var locale
    let date: Date
    var body: some View {
        Text(label)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 4)
            .background(Capsule().fill(Color(.secondarySystemBackground)))
    }
    private var label: String {
        if Calendar.current.isDateInToday(date) { return InAppStrings.string("Today", locale: locale) }
        if Calendar.current.isDateInYesterday(date) { return InAppStrings.string("Yesterday", locale: locale) }
        return date.formatted(date: .abbreviated, time: .omitted)
    }
}

private struct Avatar: View {
    let name: String?
    let size: CGFloat
    var body: some View {
        Circle()
            .fill(CPTheme.brand)
            .frame(width: size, height: size)
            .overlay {
                Text(initial)
                    .font(.system(size: size * 0.45, weight: .semibold))
                    .foregroundStyle(.white)
            }
    }
    private var initial: String {
        guard let c = name?.trimmingCharacters(in: .whitespaces).first else { return "?" }
        return String(c).uppercased()
    }
}

private struct EmptyThread: View {
    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "envelope.fill")
                .font(.system(size: 44, weight: .medium))
                .foregroundStyle(CPTheme.brand)
            Text("No messages yet")
                .font(.headline)
            Text("Messages are end-to-end encrypted and signed. Say hello.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)
        }
    }
}

// MARK: - Preview

#if DEBUG
#Preview("Conversation") {
    let me = Fingerprint("A18FB667413300FDB671D9A8B401BB207C264787")!
    let peerFP = Fingerprint("4891888765D64C5161D27B04E1E90899E8D16282")!
    let peer = Contact(fingerprint: peerFP, publicKey: PublicKey(fingerprint: peerFP, armored: ""), name: "Maya")

    let now = Int(Date().timeIntervalSince1970)
    let thread = Threading.pairwise(me.hex, peerFP.hex)
    func msg(_ id: String, _ dir: MessageDirection, _ text: String, _ ago: Int, read: Bool = true) -> ChatMessage {
        ChatMessage(id: id, threadID: thread, peer: peerFP, direction: dir, text: text,
                    attachments: [], sentAt: now - ago, expiresAt: now + 30 * 86400, isRead: read)
    }
    let convo = Conversation(threadID: thread, peer: peerFP, peerName: "Maya", messages: [
        msg("1", .incoming, "hey, did the v6 detached sig test pass?", 7200),
        msg("2", .outgoing, "yep, green. Sequoia verified it too", 7100),
        msg("3", .incoming, "nice. is the relay going to choke on v6 though?", 3600),
        msg("4", .outgoing, "gpg 2.4.4 can't verify it yet, so that's the next piece server-side", 3500),
        msg("5", .incoming, "makes sense. ship the v4 path first", 120, read: false),
    ])

    let store = ChatStore.preview(identity: me, seeded: [convo])
    return NavigationStack {
        ConversationView(store: store, contact: peer)
    }
}
#endif
