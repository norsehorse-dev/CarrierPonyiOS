import Foundation
import Security

// A group's identity and membership. The epoch key itself is never stored here; it
// lives in the Keychain (see GroupKeyStore), keyed by (groupID, epoch). This value
// is safe to persist in the conversation store alongside pairwise contacts: it holds
// no secret key material, only public keys and roster metadata.

struct GroupMember: Codable, Hashable, Identifiable {
    let fingerprint: Fingerprint
    var armoredPublicKey: String
    var name: String?
    var isAdmin: Bool

    var id: String { fingerprint.hex }

    var publicKey: PublicKey {
        PublicKey(fingerprint: fingerprint, armored: armoredPublicKey)
    }
}

struct ChatGroup: Codable, Identifiable {
    let groupID: String          // 16 random bytes, hex; also the conversation's threadID
    var name: String
    var members: [GroupMember]
    var epoch: Int               // current key epoch; bumped on every membership change
    var isChannel: Bool          // broadcast channel: admins post, others subscribe
    var createdAt: Int           // local epoch-seconds this device created/joined; sorts empty groups by recency

    var id: String { groupID }

    init(groupID: String, name: String, members: [GroupMember], epoch: Int, isChannel: Bool = false, createdAt: Int = 0) {
        self.groupID = groupID
        self.name = name
        self.members = members
        self.epoch = epoch
        self.isChannel = isChannel
        self.createdAt = createdAt
    }

    // Custom decode so snapshots written before channels (no isChannel key) still load.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        groupID = try c.decode(String.self, forKey: .groupID)
        name = try c.decode(String.self, forKey: .name)
        members = try c.decode([GroupMember].self, forKey: .members)
        epoch = try c.decode(Int.self, forKey: .epoch)
        isChannel = try c.decodeIfPresent(Bool.self, forKey: .isChannel) ?? false
        createdAt = try c.decodeIfPresent(Int.self, forKey: .createdAt) ?? 0
    }

    func member(_ fpr: Fingerprint) -> GroupMember? {
        members.first { $0.fingerprint == fpr }
    }

    func isAdmin(_ fpr: Fingerprint) -> Bool {
        member(fpr)?.isAdmin == true
    }

    var admins: [GroupMember] { members.filter { $0.isAdmin } }

    /// A fresh random group identifier (16 bytes, hex).
    static func newID() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
}
