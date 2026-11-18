import Foundation
import CryptoKit

struct Manifest: Codable {
    var v: Int
    var type: String
    var messageID: String
    var threadID: String
    var to: String?
    var groupID: String?
    var epoch: Int?
    var sentAt: Int
    var expiresAt: Int
    var parts: [Part]

    struct Part: Codable {
        var kind: String
        var mime: String?
        var filename: String?
        var size: Int?
    }

    enum CodingKeys: String, CodingKey {
        case v
        case type
        case messageID = "message_id"
        case threadID = "thread_id"
        case to
        case groupID = "group_id"
        case epoch
        case sentAt = "sent_at"
        case expiresAt = "expires_at"
        case parts
    }

    func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return try encoder.encode(self)
    }

    static func decode(_ data: Data) throws -> Manifest {
        return try JSONDecoder().decode(Manifest.self, from: data)
    }
}

enum Threading {
    static func pairwise(_ a: String, _ b: String) -> String {
        let upperA = a.uppercased()
        let upperB = b.uppercased()
        let (lo, hi) = upperA <= upperB ? (upperA, upperB) : (upperB, upperA)
        let input = Data((lo + hi).utf8)
        let digest = SHA256.hash(data: input)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
