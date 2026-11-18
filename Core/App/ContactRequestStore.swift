import Foundation
import Observation

// Requests from people who added this identity by its public key and are
// waiting to be added back. A request is only ever stored after its envelope
// was checked against the key it carries (ChatStore), so what is here is a
// real key and a name its owner chose. Nothing here is a contact: no message
// from these people opens until the request is accepted.
//
// Anyone who has the public key can send a request, so the list is bounded:
// one request per person, a cap on how many are kept, names cut to length.
// Declining remembers the fingerprint, and a later request from the same
// person is dropped without a word. Adding their key yourself still works.
//
// Per account, like contacts: activate(fpr) points the store at that
// identity's file.

struct ContactRequest: Identifiable, Equatable {
    let fingerprint: Fingerprint
    let armoredPublicKey: String
    var name: String?          // the name they gave, already cleaned
    let caps: [String]?        // what their app says it supports
    let receivedAt: Int        // epoch seconds

    var id: String { fingerprint.hex }
}

@MainActor
@Observable
final class ContactRequestStore {

    nonisolated static let maxRequests = 50
    nonisolated static let maxDeclined = 500
    nonisolated static let maxNameLength = 64

    private(set) var requests: [ContactRequest] = []

    @ObservationIgnored private var declined: [String] = []
    @ObservationIgnored private var fileURL: URL?
    @ObservationIgnored private let dir: URL

    private struct Record: Codable {
        let fingerprint: String
        let armored: String
        let name: String?
        let caps: PairingCaps.Stated?
        let receivedAt: Int
    }

    private struct File: Codable {
        var requests: [Record]
        var declined: [String]
    }

    init() {
        dir = (try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        )) ?? FileManager.default.temporaryDirectory
    }

    private func url(_ identityHex: String) -> URL {
        dir.appendingPathComponent("carrierpony-contact-requests-\(identityHex).json")
    }

    func activate(_ identityHex: String) {
        fileURL = url(identityHex)
        load()
    }

    /// Delete this account's file (used when an account is removed).
    func deleteFile(_ identityHex: String) {
        try? FileManager.default.removeItem(at: url(identityHex))
    }

    /// Keep a request. False when it was not kept: declined before, or the
    /// list is full. A second request from the same person replaces the first.
    @discardableResult
    func add(_ request: ContactRequest) -> Bool {
        guard !declined.contains(request.fingerprint.hex) else { return false }
        var others = requests.filter { $0.fingerprint != request.fingerprint }
        guard others.count < Self.maxRequests else { return false }
        var cleaned = request
        cleaned.name = Self.cleanName(request.name)
        others.append(cleaned)
        requests = others
        persist()
        return true
    }

    /// Drop a request without remembering anything (it was accepted, or the
    /// person became a contact some other way).
    func remove(_ fingerprint: Fingerprint) {
        guard requests.contains(where: { $0.fingerprint == fingerprint }) else { return }
        requests.removeAll { $0.fingerprint == fingerprint }
        persist()
    }

    /// Drop a request and ignore that person's requests from now on.
    func decline(_ fingerprint: Fingerprint) {
        requests.removeAll { $0.fingerprint == fingerprint }
        declined.removeAll { $0 == fingerprint.hex }
        declined.append(fingerprint.hex)
        if declined.count > Self.maxDeclined { declined.removeFirst(declined.count - Self.maxDeclined) }
        persist()
    }

    func isDeclined(_ fingerprint: Fingerprint) -> Bool {
        declined.contains(fingerprint.hex)
    }

    /// Forget that someone was declined (you added their key yourself).
    func clearDeclined(_ fingerprint: Fingerprint) {
        guard declined.contains(fingerprint.hex) else { return }
        declined.removeAll { $0 == fingerprint.hex }
        persist()
    }

    /// A name as it will be shown: one line, no control characters, cut to
    /// length. Nil when nothing is left.
    nonisolated static func cleanName(_ name: String?) -> String? {
        guard let name else { return nil }
        let kept = String(String.UnicodeScalarView(name.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }))
        let cut = String(kept.trimmingCharacters(in: .whitespacesAndNewlines).prefix(maxNameLength))
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return cut.isEmpty ? nil : cut
    }

    // MARK: - Persistence

    private func load() {
        declined = []
        guard let fileURL, let data = try? Data(contentsOf: fileURL),
              let file = try? JSONDecoder().decode(File.self, from: data) else {
            requests = []
            return
        }
        requests = file.requests.prefix(Self.maxRequests).compactMap { record in
            guard let fingerprint = Fingerprint(record.fingerprint), !record.armored.isEmpty else { return nil }
            return ContactRequest(fingerprint: fingerprint, armoredPublicKey: record.armored, name: record.name,
                                  caps: record.caps?.caps, receivedAt: record.receivedAt)
        }
        declined = file.declined
    }

    private func persist() {
        guard let fileURL else { return }
        let file = File(
            requests: requests.map {
                Record(fingerprint: $0.fingerprint.hex, armored: $0.armoredPublicKey, name: $0.name,
                       caps: PairingCaps.Stated($0.caps), receivedAt: $0.receivedAt)
            },
            declined: declined
        )
        guard let data = try? JSONEncoder().encode(file) else { return }
        // Same protection as the contacts file: readable after first unlock, so a
        // background refresh can store a request while the device is locked.
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}
