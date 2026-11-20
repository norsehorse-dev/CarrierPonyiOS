import SwiftUI
import UIKit

// The home screen: every conversation, most-recent first, tapping into the
// thread. Contacts are supplied by the app layer (same source the ChatStore
// uses), so a thread's peer fingerprint can be resolved to a full Contact for
// sending. Routing is by Fingerprint, which unifies row taps and the compose
// sheet through one navigationDestination.
//
// Depends only on ChatStore, Conversation, Contact, Fingerprint, ConversationView,
// and CPTheme, so it previews with a seeded mock store.

struct ConversationListView: View {

    let store: ChatStore
    let contacts: [Contact]
    var onPair: (() -> Void)? = nil
    var onBackup: (() -> Void)? = nil
    var onSignOut: (() -> Void)? = nil
    var onUnpair: ((Fingerprint) -> Void)? = nil
    var onEditProfile: (() -> Void)? = nil
    var onSetNickname: ((Fingerprint, String?) -> Void)? = nil
    var onImport: (() -> Void)? = nil
    var onSettings: (() -> Void)? = nil
    var accounts: [AppModel.AccountSummary] = []
    var activeFingerprintHex: String? = nil
    var onSwitchAccount: ((String) -> Void)? = nil
    var onAddAccount: (() -> Void)? = nil
    var accountUnread: [String: Int] = [:]
    // How many contact requests are waiting for an answer on the pairing screen.
    var contactRequests: Int = 0

    @State private var showingSignOutConfirm = false
    @State private var pendingUnpair: Fingerprint?
    @State private var reportingContact: Contact?

    #if DEBUG
    // A screenshot launch (DemoSeed) can open straight into a chat or group.
    @State private var path: [ChatRoute] = DemoSeed.startPath
    #else
    @State private var path: [ChatRoute] = []
    #endif
    @State private var showingNewMessage = false
    @State private var showingNewGroup = false
    @State private var showingNewChannel = false
    @State private var showingSubscribe = false
    @State private var needsUpdate: [String] = []
    @State private var pendingNeedsUpdate: [String] = []

    private var activeAccountLabel: String {
        if let a = accounts.first(where: { $0.fingerprint.hex == activeFingerprintHex }) {
            return a.name ?? shortHex(a.fingerprint.hex)
        }
        return "CarrierPony"
    }

    private func shortHex(_ hex: String) -> String {
        guard hex.count >= 8 else { return hex }
        let tail = String(hex.suffix(8))
        return stride(from: 0, to: tail.count, by: 4)
            .map { String(tail[tail.index(tail.startIndex, offsetBy: $0)..<tail.index(tail.startIndex, offsetBy: min($0 + 4, tail.count))]) }
            .joined(separator: " ")
    }

    // One inbox, sorted by most-recent activity: groups and 1:1 threads share a
    // single list instead of groups pinning to the top. A group rises only when
    // it holds the newest message, exactly like a conversation.
    private var orderedItems: [InboxItem] {
        let convItems = store.conversations.values.map {
            InboxItem.conversation($0, activity: $0.lastMessage?.sentAt ?? 0)
        }
        let groupItems = store.groups.values.map { group in
            // Sort by the newest message, or by when we created/joined when it has no
            // messages yet, so a freshly made channel appears at the top instead of the bottom.
            let latest = store.groupMessages[group.groupID]?.map(\.sentAt).max() ?? 0
            return InboxItem.group(group, activity: max(latest, group.createdAt))
        }
        return (convItems + groupItems).sorted {
            if $0.activity != $1.activity { return $0.activity > $1.activity }
            return $0.sortName.localizedCaseInsensitiveCompare($1.sortName) == .orderedAscending
        }
    }

    /// Error, contact request and waiting banners, in that order.
    @ViewBuilder private var banners: some View {
        if let error = store.lastError {
            ErrorBanner(message: error) { store.clearError() }
        }
        if contactRequests > 0, let onPair {
            Button(action: onPair) {
                HStack(spacing: 10) {
                    Image(systemName: "person.badge.plus")
                        .font(.footnote)
                    Text("Someone wants to connect. Tap to review.")
                        .font(.footnote.weight(.semibold))
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                    Image(systemName: "chevron.right")
                        .font(.caption)
                }
                .foregroundStyle(CPTheme.accent)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.secondarySystemBackground))
                .overlay(alignment: .bottom) {
                    Rectangle().fill(CPTheme.hairline).frame(height: 0.5)
                }
            }
            .buttonStyle(.plain)
        }
        if store.heldCount > 0 {
            InfoBanner(
                text: "\(store.heldCount) messages can't be opened yet. They are from someone who isn't in your contacts on this device. They open by themselves if you pair with them.",
                onDismiss: { store.dismissHeld() }
            )
        }
    }

    var body: some View {
        NavigationStack(path: $path) {
            VStack(spacing: 0) {
                // With no conversations there is no list, so the banners sit above
                // the empty state. Otherwise they are the first rows of the list:
                // views stacked above a List confuse the large title, which then
                // drew over the banner or left a gap after coming back to the app.
                if orderedItems.isEmpty { banners }
                Group {
                    if orderedItems.isEmpty {
                        EmptyInbox { showingNewMessage = true }
                    } else {
                        List {
                            Group { banners }
                                .buttonStyle(.borderless)
                                .listRowInsets(EdgeInsets())
                                .listRowSeparator(.hidden)
                            ForEach(orderedItems) { item in
                                switch item {
                                case .group(let group, _):
                                    Button {
                                        path.append(.group(group.groupID))
                                    } label: {
                                        GroupRow(group: group, messages: store.groupMessages[group.groupID] ?? [])
                                    }
                                    .listRowInsets(EdgeInsets(top: 6, leading: 16, bottom: 6, trailing: 16))
                                case .conversation(let conversation, _):
                                    Button {
                                        path.append(.chat(conversation.peer))
                                    } label: {
                                        ConversationRow(
                                            conversation: conversation,
                                            displayName: name(for: conversation),
                                            verified: isVerified(conversation.peer)
                                        )
                                    }
                                    .listRowInsets(EdgeInsets(top: 6, leading: 16, bottom: 6, trailing: 16))
                                    .swipeActions(edge: .trailing) {
                                        if onUnpair != nil {
                                            Button(role: .destructive) {
                                                pendingUnpair = conversation.peer
                                            } label: {
                                                Label("Unpair", systemImage: "person.crop.circle.badge.minus")
                                            }
                                        }
                                        Button(role: .destructive) {
                                            store.deleteConversation(threadID: conversation.threadID)
                                        } label: {
                                            Label("Delete", systemImage: "trash")
                                        }
                                        Button {
                                            reportingContact = contacts.first { $0.fingerprint == conversation.peer }
                                        } label: {
                                            Label("Report", systemImage: "flag")
                                        }
                                        .tint(.orange)
                                    }
                                }
                            }
                        }
                        .listStyle(.plain)
                    }
                }
            }
            .navigationTitle("CarrierPony")
            .toolbar {
                if accounts.count > 1 {
                    ToolbarItem(placement: .principal) {
                        Menu {
                            ForEach(accounts) { acct in
                                Button {
                                    if acct.fingerprint.hex != activeFingerprintHex { onSwitchAccount?(acct.fingerprint.hex) }
                                } label: {
                                    if acct.fingerprint.hex == activeFingerprintHex {
                                        Label(acct.name ?? shortHex(acct.fingerprint.hex), systemImage: "checkmark")
                                    } else if (accountUnread[acct.fingerprint.hex] ?? 0) > 0 {
                                        Label(acct.name ?? shortHex(acct.fingerprint.hex), systemImage: "circle.fill")
                                    } else {
                                        Text(acct.name ?? shortHex(acct.fingerprint.hex))
                                    }
                                }
                            }
                            Divider()
                            Button { onAddAccount?() } label: { Label("Add Account", systemImage: "person.badge.plus") }
                        } label: {
                            HStack(spacing: 4) {
                                Text(activeAccountLabel).font(.headline).foregroundStyle(.primary)
                                Image(systemName: "chevron.down").font(.caption2).foregroundStyle(.secondary)
                                if accounts.contains(where: { $0.fingerprint.hex != activeFingerprintHex && (accountUnread[$0.fingerprint.hex] ?? 0) > 0 }) {
                                    Circle().fill(CPTheme.accent).frame(width: 7, height: 7)
                                }
                            }
                        }
                    }
                }
                if onSettings != nil {
                    ToolbarItem(placement: .topBarLeading) {
                        Button {
                            onSettings?()
                        } label: {
                            Image(systemName: "gearshape")
                        }
                        .tint(CPTheme.accent)
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button {
                            showingNewMessage = true
                        } label: {
                            Label("New Message", systemImage: "square.and.pencil")
                        }
                        Button {
                            showingNewGroup = true
                        } label: {
                            Label("New Group", systemImage: "person.3")
                        }
                        Button {
                            showingNewChannel = true
                        } label: {
                            Label("New Channel", systemImage: "megaphone")
                        }
                        Button {
                            showingSubscribe = true
                        } label: {
                            Label("Subscribe to Channel", systemImage: "link")
                        }
                    } label: {
                        Image(systemName: "square.and.pencil")
                    }
                    .tint(CPTheme.accent)
                }
            }
            .confirmationDialog(
                "Sign out?",
                isPresented: $showingSignOutConfirm,
                titleVisibility: .visible
            ) {
                Button("Sign Out", role: .destructive) { onSignOut?() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This removes your identity and its keys from this device. You can't undo this without a backup.")
            }
            .confirmationDialog(
                "Unpair this contact?",
                isPresented: Binding(
                    get: { pendingUnpair != nil },
                    set: { if !$0 { pendingUnpair = nil } }
                ),
                titleVisibility: .visible
            ) {
                Button("Unpair", role: .destructive) {
                    if let fp = pendingUnpair { onUnpair?(fp) }
                    pendingUnpair = nil
                }
                Button("Cancel", role: .cancel) { pendingUnpair = nil }
            } message: {
                Text("This removes their key from this device. You won't be able to read new messages from them until you pair again.")
            }
            .navigationDestination(for: ChatRoute.self) { route in
                switch route {
                case .chat(let fingerprint):
                    ConversationView(store: store, contact: resolveContact(fingerprint), onSetNickname: onSetNickname, onUnpair: onUnpair)
                case .group(let groupID):
                    GroupConversationView(store: store, groupID: groupID, contacts: contacts)
                }
            }
            .sheet(isPresented: $showingNewMessage) {
                NewMessageSheet(contacts: contacts) { contact in
                    showingNewMessage = false
                    path.append(.chat(contact.fingerprint))
                }
            }
            .sheet(isPresented: $showingNewGroup, onDismiss: {
                // Shown once the sheet is gone; an alert raised while it is
                // still closing can be dropped.
                needsUpdate = pendingNeedsUpdate
                pendingNeedsUpdate = []
            }) {
                NewGroupSheet(contacts: contacts) { name, members in
                    showingNewGroup = false
                    let blocked = store.membersNeedingUpdate(forNewGroupWith: members)
                    guard blocked.isEmpty else {
                        pendingNeedsUpdate = blocked
                        return
                    }
                    Task { await store.createGroup(name: name, members: members) }
                }
            }
            .membersNeedUpdateAlert($needsUpdate)
            .sheet(isPresented: $showingNewChannel) {
                NewGroupSheet(contacts: contacts, channel: true) { name, members in
                    showingNewChannel = false
                    Task { await store.createChannel(name: name, subscribers: members) }
                }
            }
            .sheet(isPresented: $showingSubscribe) {
                ChannelSubscribeSheet(store: store) { showingSubscribe = false }
            }
            .sheet(item: $reportingContact) { contact in
                ReportView(store: store, contact: contact, onBlock: { onUnpair?(contact.fingerprint) })
            }
        }
    }

    private func name(for conversation: Conversation) -> String {
        let contact = contacts.first { $0.fingerprint == conversation.peer }
        return contact?.displayName
            ?? conversation.peerName
            ?? shortFingerprint(conversation.peer)
    }

    private func isVerified(_ peer: Fingerprint) -> Bool {
        contacts.first { $0.fingerprint == peer }?.trust == .verified
    }

    // Resolve a routed fingerprint to a Contact. Peers you can message are
    // contacts (pairing is a prerequisite); if a thread's peer is not yet a
    // contact, fall back to a minimal Contact so the thread still opens.
    private func resolveContact(_ fingerprint: Fingerprint) -> Contact {
        if let known = contacts.first(where: { $0.fingerprint == fingerprint }) {
            return known
        }
        let peerName = store.conversations.values.first { $0.peer == fingerprint }?.peerName
        return Contact(
            fingerprint: fingerprint,
            publicKey: PublicKey(fingerprint: fingerprint, armored: ""),
            name: peerName
        )
    }
}

// MARK: - Error banner

// ChatStore records every relay and envelope failure in lastError, and until now
// nothing rendered it. A message that couldn't be opened, a push registration that
// was rejected, an inbox fetch that failed: all of it happened silently, which made
// receive bugs look like "the message just never arrived".
private struct ErrorBanner: View {
    let message: String
    let onDismiss: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.footnote)
                .foregroundStyle(.orange)
            Text(message)
                .font(.footnote)
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 4)
            Button(action: onDismiss) {
                Image(systemName: "xmark")
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.secondarySystemBackground))
        .overlay(alignment: .bottom) {
            Rectangle().fill(CPTheme.hairline).frame(height: 0.5)
        }
        .accessibilityElement(children: .combine)
    }
}

// A quiet, non-dismissable notice (state, not an error).
struct InfoBanner: View {
    let text: LocalizedStringKey
    var onDismiss: (() -> Void)? = nil

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "hourglass")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Text(text)
                .font(.footnote)
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            if let onDismiss {
                Button(action: onDismiss) {
                    Image(systemName: "xmark")
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(.secondary)
                        .frame(minWidth: 44, minHeight: 28, alignment: .topTrailing)
                        .contentShape(Rectangle())
                }
                .accessibilityLabel("Dismiss")
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.secondarySystemBackground))
        .overlay(alignment: .bottom) {
            Rectangle().fill(CPTheme.hairline).frame(height: 0.5)
        }
        .accessibilityElement(children: onDismiss == nil ? .combine : .contain)
    }
}

// MARK: - Row

private struct ConversationRow: View {
    @Environment(\.locale) private var locale
    let conversation: Conversation
    let displayName: String
    var verified: Bool = false

    var body: some View {
        HStack(spacing: 12) {
            Avatar(name: displayName, size: 46)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 4) {
                    Text(displayName)
                        .font(.body.weight(.semibold))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    if verified {
                        Image(systemName: "checkmark.seal.fill")
                            .font(.caption2)
                            .foregroundStyle(CPTheme.accent)
                    }
                }
                Text(preview)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 8)

            VStack(alignment: .trailing, spacing: 6) {
                Text(timeLabel)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                if conversation.unreadCount > 0 {
                    Text("\(conversation.unreadCount)")
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(CPTheme.accent))
                } else {
                    Spacer().frame(height: 18)
                }
            }
        }
        .contentShape(Rectangle())
    }

    private var preview: String {
        guard let last = conversation.lastMessage else { return InAppStrings.string("No messages yet", locale: locale) }
        let prefix = last.direction == .outgoing ? InAppStrings.string("You: ", locale: locale) : ""
        if let text = last.text, !text.isEmpty {
            return prefix + text
        }
        if let attachment = last.attachments.first {
            return prefix + "📎 " + attachment.filename
        }
        return prefix + InAppStrings.string("Message", locale: locale)
    }

    private var timeLabel: String {
        guard let last = conversation.lastMessage else { return "" }
        let date = Date(timeIntervalSince1970: TimeInterval(last.sentAt))
        let cal = Calendar.current
        if cal.isDateInToday(date) {
            return date.formatted(date: .omitted, time: .shortened)
        }
        if cal.isDateInYesterday(date) {
            return InAppStrings.string("Yesterday", locale: locale)
        }
        if let days = cal.dateComponents([.day], from: date, to: Date()).day, days < 7 {
            return date.formatted(.dateTime.weekday(.abbreviated))
        }
        return date.formatted(.dateTime.month(.abbreviated).day())
    }
}

// MARK: - New message sheet

// A single inbox row: a 1:1 conversation or a group, tagged with the last
// activity time so the list interleaves both and sorts by recency. Groups no
// longer pin to the top; a group rises only when it has the newest message.
private enum InboxItem: Identifiable {
    case conversation(Conversation, activity: Int)
    case group(ChatGroup, activity: Int)

    var activity: Int {
        switch self {
        case .conversation(_, let a): return a
        case .group(_, let a): return a
        }
    }

    var id: String {
        switch self {
        case .conversation(let c, _): return "c-" + c.threadID
        case .group(let g, _): return "g-" + g.groupID
        }
    }

    // Tiebreak only, for rows that share an activity time (e.g. both empty).
    var sortName: String {
        switch self {
        case .conversation(let c, _): return c.peerName ?? c.threadID
        case .group(let g, _): return g.name
        }
    }
}

enum ChatRoute: Hashable {
    case chat(Fingerprint)
    case group(String)
}

private struct NewMessageSheet: View {
    let contacts: [Contact]
    let onSelect: (Contact) -> Void

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Group {
                if contacts.isEmpty {
                    ContentUnavailableView(
                        "No contacts yet",
                        systemImage: "person.crop.circle.badge.plus",
                        description: Text("Pair with someone to start a conversation.")
                    )
                } else {
                    List(sortedContacts, id: \.fingerprint) { contact in
                        Button {
                            onSelect(contact)
                        } label: {
                            HStack(spacing: 12) {
                                Avatar(name: contact.name, size: 40)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(contact.name ?? shortFingerprint(contact.fingerprint))
                                        .font(.body.weight(.semibold))
                                        .foregroundStyle(.primary)
                                    Text(shortFingerprint(contact.fingerprint))
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                            }
                            .contentShape(Rectangle())
                        }
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle("New Message")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancel") { dismiss() }
                        .tint(CPTheme.accent)
                }
            }
        }
    }

    private var sortedContacts: [Contact] {
        contacts.sorted {
            ($0.name ?? $0.fingerprint.hex).localizedCaseInsensitiveCompare($1.name ?? $1.fingerprint.hex) == .orderedAscending
        }
    }
}

// MARK: - Empty state

private struct EmptyInbox: View {
    let onCompose: () -> Void

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "envelope.fill")
                .font(.system(size: 52, weight: .medium))
                .foregroundStyle(CPTheme.brand)
            Text("No conversations")
                .font(.title3.weight(.semibold))
            Text("Your encrypted threads will appear here.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Button(action: onCompose) {
                Text("New Message")
                    .font(.body.weight(.semibold))
                    .foregroundStyle(.white)
                    .padding(.horizontal, 22)
                    .padding(.vertical, 11)
                    .background(Capsule().fill(CPTheme.send))
            }
            .padding(.top, 4)
        }
        .padding(40)
    }
}

// MARK: - Avatar + fingerprint helper

// File-scoped copies mirroring the conversation screen so the list and the
// thread read as one product, with no cross-file symbol clash. If you later add
// a shared Components file, these can be lifted there and the per-file copies
// removed.

private struct Avatar: View {
    let name: String?
    let size: CGFloat
    var body: some View {
        Circle()
            .fill(CPTheme.brand)
            .frame(width: size, height: size)
            .overlay {
                Text(initial)
                    .font(.system(size: size * 0.42, weight: .semibold))
                    .foregroundStyle(.white)
            }
    }
    private var initial: String {
        guard let c = name?.trimmingCharacters(in: .whitespaces).first else { return "?" }
        return String(c).uppercased()
    }
}

private func shortFingerprint(_ fp: Fingerprint) -> String {
    let hex = fp.hex
    guard hex.count >= 8 else { return hex }
    let tail = String(hex.suffix(8))
    return stride(from: 0, to: tail.count, by: 4).map {
        let start = tail.index(tail.startIndex, offsetBy: $0)
        let end = tail.index(tail.startIndex, offsetBy: min($0 + 4, tail.count))
        return String(tail[start..<end])
    }.joined(separator: " ")
}

// MARK: - Preview

#if DEBUG
#Preview("Inbox") {
    let me = Fingerprint("A18FB667413300FDB671D9A8B401BB207C264787")!
    let mayaFP = Fingerprint("4891888765D64C5161D27B04E1E90899E8D16282")!
    let leoFP = Fingerprint("AACECD2CFCEB3213723E94A81D4D2FBCBB6271D4")!

    let maya = Contact(fingerprint: mayaFP, publicKey: PublicKey(fingerprint: mayaFP, armored: ""), name: "Maya")
    let leo = Contact(fingerprint: leoFP, publicKey: PublicKey(fingerprint: leoFP, armored: ""), name: "Leo")

    let now = Int(Date().timeIntervalSince1970)
    func convo(_ peer: Fingerprint, _ pname: String, _ msgs: [ChatMessage]) -> Conversation {
        Conversation(threadID: Threading.pairwise(me.hex, peer.hex), peer: peer, peerName: pname, messages: msgs)
    }
    func m(_ id: String, _ peer: Fingerprint, _ dir: MessageDirection, _ t: String, _ ago: Int, read: Bool = true) -> ChatMessage {
        ChatMessage(id: id, threadID: Threading.pairwise(me.hex, peer.hex), peer: peer, direction: dir,
                    text: t, attachments: [], sentAt: now - ago, expiresAt: now + 30 * 86400, isRead: read)
    }

    let convos = [
        convo(mayaFP, "Maya", [
            m("1", mayaFP, .incoming, "makes sense. ship the v4 path first", 300, read: false),
            m("2", mayaFP, .incoming, "and the icon looks great btw", 240, read: false),
        ]),
        convo(leoFP, "Leo", [
            m("3", leoFP, .outgoing, "pushed the Nexopera preview branch", 90_000),
        ]),
    ]

    let store = ChatStore.preview(identity: me, seeded: convos)
    return ConversationListView(store: store, contacts: [maya, leo])
}
#endif

private struct ChannelSubscribeSheet: View {
    let store: ChatStore
    var onClose: () -> Void
    @State private var pasted = ""
    @State private var bad = false
    @State private var adminNeedsUpdate = false

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 16) {
                Text("You will receive its posts. The channel will learn your identity.")
                    .font(.subheadline).foregroundStyle(.secondary)
                TextField("Paste a channel invite link (CPCHAN1:…)", text: $pasted, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .lineLimit(2...5)
                    .onChange(of: pasted) { bad = false; adminNeedsUpdate = false }
                Button {
                    if let s = UIPasteboard.general.string { pasted = s; bad = false; adminNeedsUpdate = false }
                } label: {
                    Label("Paste", systemImage: "doc.on.clipboard")
                }
                if bad {
                    Text("That is not a valid channel invite.").font(.caption).foregroundStyle(.red)
                }
                if adminNeedsUpdate {
                    Text("This channel's admin is on an older CarrierPony. Ask them to update to version 4.0 or later, then subscribe again.")
                        .font(.caption).foregroundStyle(.red)
                }
                Spacer()
            }
            .padding()
            .navigationTitle("Subscribe to Channel")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { Button("Cancel") { onClose() } }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Subscribe") {
                        if let invite = ChannelInvite.decode(pasted.trimmingCharacters(in: .whitespacesAndNewlines)) {
                            if store.channelAdminNeedsUpdate(invite) {
                                adminNeedsUpdate = true
                            } else {
                                Task { await store.subscribeToChannel(invite) }
                                onClose()
                            }
                        } else {
                            bad = true
                        }
                    }
                }
            }
        }
        .presentationDetents([.medium])
    }
}
