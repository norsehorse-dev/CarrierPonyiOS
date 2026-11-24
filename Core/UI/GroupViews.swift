import SwiftUI
import PhotosUI
import UniformTypeIdentifiers
import UIKit

// Group list row, roster detail, and the create-group sheet. Group messaging
// itself lands in a later build; for now a group can be created (which generates
// and distributes the group key) and its roster viewed.

struct GroupRow: View {
    @Environment(\.locale) private var locale
    let group: ChatGroup
    var messages: [ChatMessage] = []

    private var lastMessage: ChatMessage? { messages.max { $0.sentAt < $1.sentAt } }
    private var unreadCount: Int { messages.filter { $0.direction == .incoming && !$0.isRead }.count }

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                Circle().fill(CPTheme.brand).frame(width: 44, height: 44)
                Image(systemName: "person.3.fill")
                    .foregroundStyle(.white)
                    .font(.system(size: 17, weight: .semibold))
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(group.name).font(.headline).lineLimit(1)
                Text(subtitle).font(.subheadline).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 6) {
                Text(timeLabel).font(.caption2).foregroundStyle(.secondary)
                if unreadCount > 0 {
                    Text("\(unreadCount)")
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 7).padding(.vertical, 2)
                        .background(Capsule().fill(CPTheme.accent))
                } else {
                    Spacer().frame(height: 18)
                }
            }
        }
    }

    private var subtitle: String {
        if let last = lastMessage {
            if let text = last.text, !text.isEmpty { return text }
            if let attachment = last.attachments.first { return "\u{1F4CE} " + attachment.filename }
        }
        return group.members.count == 1
            ? InAppStrings.string("1 member", locale: locale)
            : InAppStrings.format("%lld members", group.members.count, locale: locale)
    }

    private var timeLabel: String {
        guard let last = lastMessage else { return "" }
        let date = Date(timeIntervalSince1970: TimeInterval(last.sentAt))
        let cal = Calendar.current
        if cal.isDateInToday(date) { return date.formatted(date: .omitted, time: .shortened) }
        if cal.isDateInYesterday(date) { return InAppStrings.string("Yesterday", locale: locale) }
        if let days = cal.dateComponents([.day], from: date, to: Date()).day, days < 7 {
            return date.formatted(.dateTime.weekday(.abbreviated))
        }
        return date.formatted(.dateTime.month(.abbreviated).day())
    }
}

struct GroupDetailView: View {
    let store: ChatStore
    let groupID: String
    var contacts: [Contact] = []

    @Environment(\.dismiss) private var dismiss
    @State private var showingRename = false
    @State private var renameDraft = ""
    @State private var showingAddMembers = false
    @State private var needsUpdate: [String] = []
    @State private var pendingNeedsUpdate: [String] = []
    @State private var showingLeaveConfirm = false
    @State private var showingInvite = false
    @State private var inviteText = ""

    private var group: ChatGroup? { store.groups[groupID] }
    private var isAdmin: Bool { store.amGroupAdmin(groupID) }
    private var isChannelSub: Bool { (group?.isChannel == true) && !isAdmin }

    var body: some View {
        Group {
            if let group {
                List {
                    if isAdmin {
                        Section {
                            Button { renameDraft = group.name; showingRename = true } label: {
                                Label("Rename Group", systemImage: "pencil")
                            }
                            Button { showingAddMembers = true } label: {
                                Label(group.isChannel ? "Add Subscribers" : "Add Members", systemImage: "person.badge.plus")
                            }
                            if group.isChannel {
                                Button { if let s = store.channelInvite(groupID) { inviteText = s; showingInvite = true } } label: {
                                    Label("Share Invite Link", systemImage: "link")
                                }
                            }
                        }
                    }
                    Section("Members (\(group.members.count))") {
                        ForEach(group.members) { member in
                            memberRow(member)
                        }
                    }
                    Section {
                        Button(role: .destructive) { showingLeaveConfirm = true } label: {
                            Label(isChannelSub ? "Unsubscribe" : "Leave Group", systemImage: "rectangle.portrait.and.arrow.right")
                        }
                    }
                }
                .listStyle(.insetGrouped)
            } else {
                Text("Group not found").foregroundStyle(.secondary)
            }
        }
        .navigationTitle(group?.name ?? "Group")
        .navigationBarTitleDisplayMode(.inline)
        .alert("Rename Group", isPresented: $showingRename) {
            TextField("Group name", text: $renameDraft)
            Button("Save") { Task { await store.renameGroup(groupID, to: renameDraft) } }
            Button("Cancel", role: .cancel) {}
        }
        .sheet(isPresented: $showingAddMembers, onDismiss: {
            // Shown once the sheet is gone; an alert raised while it is still
            // closing can be dropped.
            needsUpdate = pendingNeedsUpdate
            pendingNeedsUpdate = []
        }) {
            MemberPickerSheet(contacts: addableContacts) { picked in
                showingAddMembers = false
                if store.groups[groupID]?.isChannel != true {
                    let blocked = store.membersNeedingUpdate(adding: picked, toGroup: groupID)
                    guard blocked.isEmpty else {
                        pendingNeedsUpdate = blocked
                        return
                    }
                }
                Task {
                    if store.groups[groupID]?.isChannel == true {
                        await store.addSubscribers(picked, toChannel: groupID)
                    } else {
                        await store.addMembers(picked, toGroup: groupID)
                    }
                }
            }
        }
        .membersNeedUpdateAlert($needsUpdate)
        .confirmationDialog(isChannelSub ? "Unsubscribe from this channel?" : "Leave this group?", isPresented: $showingLeaveConfirm, titleVisibility: .visible) {
            Button(isChannelSub ? "Unsubscribe" : "Leave", role: .destructive) {
                Task {
                    if isChannelSub { await store.unsubscribeFromChannel(groupID) }
                    else { await store.leaveGroup(groupID) }
                    dismiss()
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(isChannelSub ? "You will stop receiving its posts on this device."
                              : "You will stop receiving messages from this group on this device.")
        }
        .sheet(isPresented: $showingInvite) {
            NavigationStack {
                VStack(spacing: 16) {
                    Text("Anyone with this link can subscribe to this channel.")
                        .font(.subheadline).foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                    Text(inviteText)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: 12).fill(Color.gray.opacity(0.12)))
                    ShareLink(item: inviteText) { Label("Share", systemImage: "square.and.arrow.up") }
                        .buttonStyle(.borderedProminent)
                    Spacer()
                }
                .padding()
                .navigationTitle("Channel Invite")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Done") { showingInvite = false } } }
            }
            .presentationDetents([.medium])
        }
    }

    @ViewBuilder
    private func memberRow(_ member: GroupMember) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(contacts.first { $0.fingerprint == member.fingerprint }?.displayName ?? member.name ?? shortFingerprint(member.fingerprint)).font(.body)
                Text(shortFingerprint(member.fingerprint)).font(.caption2).foregroundStyle(.secondary)
            }
            Spacer()
            if member.isAdmin {
                Text("Admin")
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(Capsule().fill(CPTheme.accent.opacity(0.15)))
                    .foregroundStyle(CPTheme.accent)
            }
        }
        .swipeActions(edge: .trailing) {
            if isAdmin && member.fingerprint != store.identityFingerprint {
                Button(role: .destructive) {
                    Task { await store.removeMember(member.fingerprint, fromGroup: groupID) }
                } label: {
                    Label("Remove", systemImage: "person.badge.minus")
                }
            }
        }
    }

    private var addableContacts: [Contact] {
        let present = Set((group?.members.map { $0.fingerprint.hex }) ?? [])
        return contacts.filter { !present.contains($0.fingerprint.hex) }
    }

    private func shortFingerprint(_ fp: Fingerprint) -> String {
        let hex = fp.hex
        guard hex.count >= 8 else { return hex }
        return String(hex.suffix(8))
    }
}

// Shown when a group cannot be made or grown yet: it would include a v6
// identity, and the people named are on an app from before 4.0.
extension View {
    func membersNeedUpdateAlert(_ names: Binding<[String]>) -> some View {
        alert(
            "Update needed first",
            isPresented: Binding(
                get: { !names.wrappedValue.isEmpty },
                set: { if !$0 { names.wrappedValue = [] } }
            )
        ) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("This group would include someone with a new 4.0 identity, which older versions of CarrierPony can't see. Ask these people to update to version 4.0 or later: \(names.wrappedValue.joined(separator: ", ")). If they already have, try again once they've been online.")
        }
    }
}

struct NewGroupSheet: View {
    let contacts: [Contact]
    var channel: Bool = false
    let onCreate: (String, [Contact]) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var selected: Set<String> = []

    var body: some View {
        NavigationStack {
            Form {
                Section("Name") {
                    TextField(channel ? "Channel name" : "Group name", text: $name)
                }
                Section(channel ? "Subscribers" : "Members") {
                    if contacts.isEmpty {
                        Text("Pair with someone first to add them to a group.")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(sortedContacts) { contact in
                            Button {
                                toggle(contact)
                            } label: {
                                HStack {
                                    Text(contact.displayName ?? shortFingerprint(contact.fingerprint))
                                        .foregroundStyle(.primary)
                                    Spacer()
                                    if selected.contains(contact.fingerprint.hex) {
                                        Image(systemName: "checkmark")
                                            .foregroundStyle(CPTheme.accent)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle(channel ? "New Channel" : "New Group")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Create") {
                        let members = contacts.filter { selected.contains($0.fingerprint.hex) }
                        onCreate(name.trimmingCharacters(in: .whitespaces), members)
                    }
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty || (!channel && selected.isEmpty))
                }
            }
        }
    }

    private var sortedContacts: [Contact] {
        contacts.sorted {
            ($0.displayName ?? $0.fingerprint.hex).lowercased() < ($1.displayName ?? $1.fingerprint.hex).lowercased()
        }
    }

    private func toggle(_ contact: Contact) {
        let key = contact.fingerprint.hex
        if selected.contains(key) { selected.remove(key) } else { selected.insert(key) }
    }

    private func shortFingerprint(_ fp: Fingerprint) -> String {
        let hex = fp.hex
        guard hex.count >= 8 else { return hex }
        return String(hex.suffix(8))
    }
}

// The group thread: messages plus a composer with text and attachments. Incoming
// messages show the sender's name (resolved from the roster). A roster/info button
// opens GroupDetailView.
struct GroupConversationView: View {
    let store: ChatStore
    let groupID: String
    var contacts: [Contact] = []

    @Environment(\.dismiss) private var dismiss
    @State private var draft = ""
    @State private var pending: [OutgoingMessage.Attachment] = []
    @State private var showingRoster = false
    @State private var showingFiles = false
    @State private var showingCamera = false
    @State private var showingPhotos = false
    @State private var photoItems: [PhotosPickerItem] = []
    @FocusState private var composerFocused: Bool

    private var group: ChatGroup? { store.groups[groupID] }
    private var messages: [ChatMessage] {
        (store.groupMessages[groupID] ?? []).sorted { $0.sentAt < $1.sentAt }
    }
    private var canSend: Bool {
        !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !pending.isEmpty
    }
    private var readOnly: Bool {
        (group?.isChannel == true) && !store.amGroupAdmin(groupID)
    }

    var body: some View {
        VStack(spacing: 0) {
            messageList
            Divider().overlay(CPTheme.hairline)
            if readOnly {
                Text("This is a broadcast channel. Only its admins can post.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
                    .padding()
            } else {
                composer
            }
        }
        .background(CPTheme.screen)
        .navigationTitle(group?.name ?? "Group")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button { showingRoster = true } label: {
                    Image(systemName: "person.3")
                }
                .tint(CPTheme.accent)
            }
        }
        .sheet(isPresented: $showingRoster) {
            NavigationStack { GroupDetailView(store: store, groupID: groupID, contacts: contacts) }
        }
        .onChange(of: store.groups[groupID] == nil) { _, gone in
            if gone { dismiss() }
        }
        .onAppear { store.markGroupRead(groupID: groupID) }
        .onChange(of: messages.count) { _, _ in store.markGroupRead(groupID: groupID) }
    }

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                if messages.isEmpty {
                    Text("No messages yet. Say hello to the group.")
                        .font(.subheadline).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity).padding(.top, 60)
                } else {
                    LazyVStack(alignment: .leading, spacing: 4) {
                        ForEach(messages) { message in
                            GroupMessageRow(message: message, senderName: senderName(message))
                                .id(message.id)
                        }
                        Color.clear.frame(height: 8).id("group-bottom")
                    }
                    .padding(.horizontal, 12).padding(.top, 8)
                }
            }
            .scrollDismissesKeyboard(.interactively)
            .onChange(of: messages.count) { _, _ in
                withAnimation(.easeOut(duration: 0.25)) { proxy.scrollTo("group-bottom", anchor: .bottom) }
            }
            .onAppear { proxy.scrollTo("group-bottom", anchor: .bottom) }
        }
    }

    private var composer: some View {
        VStack(spacing: 8) {
            if !pending.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(Array(pending.enumerated()), id: \.offset) { index, item in
                            PendingChip(attachment: item) { pending.remove(at: index) }
                        }
                    }
                    .padding(.horizontal, 4)
                }
            }
            HStack(alignment: .bottom, spacing: 10) {
                Menu {
                    Button { showingFiles = true } label: { Label("Files", systemImage: "folder") }
                    Button { showingCamera = true } label: { Label("Camera", systemImage: "camera") }
                    Button { showingPhotos = true } label: { Label("Photo Library", systemImage: "photo.on.rectangle") }
                } label: {
                    Image(systemName: "plus")
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(CPTheme.accent)
                        .frame(width: 38, height: 38)
                }
                TextField("Message", text: $draft, axis: .vertical)
                    // The unsent text lives in the store so it survives leaving
                    // the thread and the app being ended in the background.
                    .onAppear { draft = store.draft(for: ChatStore.groupDraftKey(groupID)) }
                    .onChange(of: draft) { _, text in store.setDraft(text, for: ChatStore.groupDraftKey(groupID)) }
                    .onDisappear { store.saveDraftsNow() }
                    .lineLimit(1...5)
                    .padding(.horizontal, 14).padding(.vertical, 9)
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
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
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

    private func sendDraft() {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        let attachments = pending
        guard !text.isEmpty || !attachments.isEmpty else { return }
        draft = ""
        pending = []
        Task { await store.sendGroupMessage(groupID: groupID, text: text, attachments: attachments) }
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

    private func senderName(_ message: ChatMessage) -> String? {
        guard message.direction == .incoming else { return nil }
        return contacts.first { $0.fingerprint == message.peer }?.displayName
            ?? group?.member(message.peer)?.name
            ?? String(message.peer.hex.suffix(8))
    }
}

private struct GroupMessageRow: View {
    let message: ChatMessage
    let senderName: String?

    private var isOutgoing: Bool { message.direction == .outgoing }
    private var isImageOnly: Bool {
        message.text == nil && !message.attachments.isEmpty && message.attachments.allSatisfy { $0.isImage }
    }

    var body: some View {
        HStack {
            if isOutgoing { Spacer(minLength: 48) }
            VStack(alignment: isOutgoing ? .trailing : .leading, spacing: 2) {
                if let senderName {
                    Text(senderName).font(.caption2).foregroundStyle(.secondary).padding(.horizontal, 8)
                }
                bubble
                    .contextMenu {
                        // Copy, same as the 1:1 bubble (see MessageClipboard).
                        if let text = message.text, !text.isEmpty {
                            Button {
                                MessageClipboard.copy(text)
                            } label: {
                                Label("Copy", systemImage: "doc.on.doc")
                            }
                        }
                    }
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
                Text(text).foregroundStyle(isOutgoing ? .white : Color.primary)
            }
        }
        .padding(.horizontal, isImageOnly ? 4 : 14)
        .padding(.vertical, isImageOnly ? 4 : 9)
        .background {
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .fill(isOutgoing ? AnyShapeStyle(CPTheme.accent) : AnyShapeStyle(CPTheme.incomingBubble))
        }
    }
}

// Pick paired contacts to add to a group. No name field (unlike NewGroupSheet).
struct MemberPickerSheet: View {
    let contacts: [Contact]
    let onAdd: ([Contact]) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var selected: Set<String> = []

    var body: some View {
        NavigationStack {
            Form {
                if contacts.isEmpty {
                    Text("No more contacts to add.").foregroundStyle(.secondary)
                } else {
                    ForEach(sortedContacts) { contact in
                        Button {
                            toggle(contact)
                        } label: {
                            HStack {
                                Text(contact.displayName ?? shortFingerprint(contact.fingerprint))
                                    .foregroundStyle(.primary)
                                Spacer()
                                if selected.contains(contact.fingerprint.hex) {
                                    Image(systemName: "checkmark").foregroundStyle(CPTheme.accent)
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle("Add Members")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Add") {
                        onAdd(contacts.filter { selected.contains($0.fingerprint.hex) })
                    }
                    .disabled(selected.isEmpty)
                }
            }
        }
    }

    private var sortedContacts: [Contact] {
        contacts.sorted {
            ($0.displayName ?? $0.fingerprint.hex).lowercased() < ($1.displayName ?? $1.fingerprint.hex).lowercased()
        }
    }
    private func toggle(_ contact: Contact) {
        let key = contact.fingerprint.hex
        if selected.contains(key) { selected.remove(key) } else { selected.insert(key) }
    }
    private func shortFingerprint(_ fp: Fingerprint) -> String {
        let hex = fp.hex
        guard hex.count >= 8 else { return hex }
        return String(hex.suffix(8))
    }
}
