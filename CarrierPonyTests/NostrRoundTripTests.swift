import XCTest
import CryptoKit
@testable import CarrierPony

/// End-to-end M2 proof against a live relay. Skipped unless NOSTR_LIVE is set in the
/// scheme/environment, since it needs network and a working public relay. Override the
/// relay with NOSTR_RELAY.
final class NostrRoundTripTests: XCTestCase {

    func testPublishAndReadBack() throws {
        let env = ProcessInfo.processInfo.environment
        try XCTSkipUnless(env["NOSTR_LIVE"] != nil, "set NOSTR_LIVE=1 to run")
        let relay = URL(string: env["NOSTR_RELAY"] ?? "wss://relay.damus.io")!

        let addr = "cpmbx" + UUID().uuidString.replacingOccurrences(of: "-", with: "")
        let seckey = NostrEventBuilder.randomSecretKey()
        let event = try NostrEventBuilder.build(
            secretKey: seckey, createdAt: Int64(Date().timeIntervalSince1970),
            kind: NostrKind.mailbox, tags: [["t", addr]], content: "aGVsbG8=")

        let client = NostrRelayClient(url: relay)
        let got = expectation(description: "event returns from relay")
        client.onMessage = { msg in
            if case .event(_, let ev) = msg, ev["id"] as? String == event.id { got.fulfill() }
        }
        client.connect()

        let sub = Task {
            try await client.subscribe(subId: "m2", filterJson: NostrRelayClient.idFilter(event.id))
            try await Task.sleep(nanoseconds: 300_000_000)
            try await client.publish(eventJson: event.json())
        }
        wait(for: [got], timeout: 20)
        sub.cancel()
        client.close()
    }
}
