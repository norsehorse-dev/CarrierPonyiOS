import XCTest
@testable import CarrierPony

final class NostrRelayTests: XCTestCase {

    func testParseEvent() {
        let msg = "[\"EVENT\",\"sub1\",{\"id\":\"abc\",\"kind\":1314}]"
        guard case .event(let sub, let ev)? = NostrRelayClient.parse(msg) else { return XCTFail("not event") }
        XCTAssertEqual(sub, "sub1")
        XCTAssertEqual(ev["id"] as? String, "abc")
        XCTAssertEqual(ev["kind"] as? Int, 1314)
    }

    func testParseOk() {
        guard case .ok(let id, let accepted, let m)? = NostrRelayClient.parse("[\"OK\",\"evid\",true,\"\"]") else { return XCTFail("not ok") }
        XCTAssertEqual(id, "evid"); XCTAssertTrue(accepted); XCTAssertEqual(m, "")
        guard case .ok(_, let rejected, let reason)? = NostrRelayClient.parse("[\"OK\",\"evid\",false,\"blocked: pow\"]") else { return XCTFail("not ok") }
        XCTAssertFalse(rejected); XCTAssertEqual(reason, "blocked: pow")
    }

    func testParseEoseNoticeClosed() {
        guard case .eose(let s)? = NostrRelayClient.parse("[\"EOSE\",\"sub1\"]") else { return XCTFail("not eose") }
        XCTAssertEqual(s, "sub1")
        guard case .notice(let n)? = NostrRelayClient.parse("[\"NOTICE\",\"hi\"]") else { return XCTFail("not notice") }
        XCTAssertEqual(n, "hi")
        guard case .closed(let cs, let cm)? = NostrRelayClient.parse("[\"CLOSED\",\"sub1\",\"error: x\"]") else { return XCTFail("not closed") }
        XCTAssertEqual(cs, "sub1"); XCTAssertEqual(cm, "error: x")
    }

    func testParseRejectsGarbage() {
        XCTAssertNil(NostrRelayClient.parse("not json"))
        XCTAssertNil(NostrRelayClient.parse("[\"WAT\"]"))
        XCTAssertNil(NostrRelayClient.parse("[\"EVENT\"]"))
    }

    func testFilters() {
        XCTAssertEqual(NostrRelayClient.idFilter("abc123"), "{\"ids\":[\"abc123\"]}")
        XCTAssertEqual(NostrRelayClient.mailboxFilter(addresses: ["aa", "bb"]),
                       "{\"kinds\":[1314],\"#t\":[\"aa\",\"bb\"]}")
    }
}
