import Foundation

struct RelayError: Error {
    let status: Int
    let code: String?
}

struct ChallengeResponse: Decodable {
    let nonce: String
}

struct OkResponse: Decodable {
    let ok: Bool
}

struct SendResponse: Decodable {
    let messageId: String
    let expiresAt: Int
}

struct InboxResponse: Decodable {
    let messages: [InboxMessage]
}

struct InboxMessage: Decodable {
    let messageId: String
    let envelope: String
    let receivedAt: String
    let expiresAt: String
}

struct AckResponse: Decodable {
    let acked: Int
}

struct PairOfferResponse: Decodable {
    let token: String
    let expiresIn: Int
}

struct PairAcceptResponse: Decodable {
    let offererFpr: String
    let offererPubkey: String
}

struct PairStatusResponse: Decodable {
    let state: String
    let responderFpr: String?
    let responderPubkey: String?
}

struct ErrorBody: Decodable {
    let error: String
}

// MARK: - Sealed sender

// Responses for the /v1/sealed/* endpoints. Field names arrive snake_case and
// are mapped by the decoder's convertFromSnakeCase strategy.

struct SealedOkResponse: Decodable {
    let ok: Bool
    let registered: Int?
}

struct SealedSendResponse: Decodable {
    let ok: Bool
    let throttled: Bool?
}

struct SealedInboxResponse: Decodable {
    let messages: [SealedInboxMessage]
}

struct SealedInboxMessage: Decodable {
    let messageId: String
    let mailbox: String
    let envelope: String
    let receivedAt: String
    let expiresAt: String
}

struct SealedAckResponse: Decodable {
    let ok: Bool
    let deleted: Int
}
