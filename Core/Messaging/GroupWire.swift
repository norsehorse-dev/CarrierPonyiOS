import Foundation

// Wire payloads for group control envelopes. A group-key payload carries the
// current epoch key (base64) plus the full roster, PGP-encrypted to one member on
// join or rekey. Sent silent so it syncs without a banner.

struct GroupKeyPayload: Codable {
    let groupID: String
    let epoch: Int
    let keyB64: String
    let name: String
    let members: [GroupMember]
    let isChannel: Bool

    enum CodingKeys: String, CodingKey {
        case groupID = "group_id"
        case epoch
        case keyB64 = "key_b64"
        case name
        case members
        case isChannel = "is_channel"
    }

    init(groupID: String, epoch: Int, keyB64: String, name: String, members: [GroupMember], isChannel: Bool = false) {
        self.groupID = groupID
        self.epoch = epoch
        self.keyB64 = keyB64
        self.name = name
        self.members = members
        self.isChannel = isChannel
    }

    // Tolerant decode: a payload from before channels has no is_channel key.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        groupID = try c.decode(String.self, forKey: .groupID)
        epoch = try c.decode(Int.self, forKey: .epoch)
        keyB64 = try c.decode(String.self, forKey: .keyB64)
        name = try c.decode(String.self, forKey: .name)
        members = try c.decode([GroupMember].self, forKey: .members)
        isChannel = try c.decodeIfPresent(Bool.self, forKey: .isChannel) ?? false
    }
}
