import Foundation

enum MessageDirection {
    case incoming
    case outgoing
}

struct ChatMessage: Identifiable, Hashable {
    let id: String
    let threadID: String
    let peer: Fingerprint
    let direction: MessageDirection
    var text: String?
    var attachments: [Attachment]
    let sentAt: Int
    let expiresAt: Int
    var isRead: Bool
    // True when this message was delivered/received over the local network
    // (LAN-direct) rather than fetched from the relay. Drives a subtle indicator.
    var viaLan: Bool = false

    // Attachment bytes live on disk (see AttachmentStore); the message only
    // carries metadata + a local path, so large files don't bloat the
    // conversation store or sit in memory.
    struct Attachment: Hashable, Identifiable {
        let id: String
        let filename: String
        let mime: String
        let size: Int
        let localPath: String

        var isImage: Bool { mime.hasPrefix("image/") }
    }
}

struct Conversation: Identifiable {
    let threadID: String
    let peer: Fingerprint
    var peerName: String?
    var messages: [ChatMessage]

    var id: String { threadID }

    var sortedMessages: [ChatMessage] {
        messages.sorted { $0.sentAt < $1.sentAt }
    }

    var lastMessage: ChatMessage? {
        messages.max { $0.sentAt < $1.sentAt }
    }

    var unreadCount: Int {
        messages.filter { $0.direction == .incoming && !$0.isRead }.count
    }
}

// How sure we are that a contact's key really belongs to them.
//   .unverified — paired and usable, but the key was accepted over the relay
//     (or any channel we can't vouch for). Messaging works; identity is TOFU.
//   .verified — a human compared the safety number out-of-band, or the pair was
//     made in person by QR. The key is confirmed.
enum TrustLevel: String, Codable {
    case unverified
    case verified
}

struct Contact: Identifiable {
    let fingerprint: Fingerprint
    let publicKey: PublicKey
    var name: String?          // display name the peer told us (travels via pairing)
    var trust: TrustLevel = .unverified
    var nickname: String? = nil      // local override you set; wins over `name`
    var caps: [String]? = nil        // what their app says it supports (PairingCaps); nil until they say

    var id: String { fingerprint.hex }

    /// What to show for this contact: your nickname, else their sent name.
    var displayName: String? { nickname ?? name }
}
