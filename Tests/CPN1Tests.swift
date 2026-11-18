import XCTest
@testable import CarrierPony

final class CPN1Tests: XCTestCase {

    func testContainerRoundTrip() throws {
        let text = Data("hello CPN1".utf8)
        let blob = Data((0..<257).map { _ in UInt8.random(in: 0...255) })
        let manifest = Data("{\"v\":1}".utf8)

        let container = CPN1.encode(manifest: manifest, parts: [text, blob])
        let (decodedManifest, parts) = try CPN1.decode(container)

        XCTAssertEqual(decodedManifest, manifest)
        XCTAssertEqual(parts.count, 2)
        XCTAssertEqual(parts[0], text)
        XCTAssertEqual(parts[1], blob)
    }

    func testEmptyAndLargePartsRoundTrip() throws {
        let empty = Data()
        let large = Data(repeating: 0xAB, count: 200_000)
        let manifest = Data("{}".utf8)

        let container = CPN1.encode(manifest: manifest, parts: [empty, large])
        let (_, parts) = try CPN1.decode(container)

        XCTAssertEqual(parts[0].count, 0)
        XCTAssertEqual(parts[1], large)
    }

    func testManifestRoundTrip() throws {
        let manifest = Manifest(
            v: 1,
            type: "message",
            messageID: UUID().uuidString,
            threadID: Threading.pairwise("AA", "BB"),
            sentAt: 1,
            expiresAt: 2,
            parts: [
                Manifest.Part(kind: "text", mime: "text/plain; charset=utf-8", filename: nil, size: nil),
                Manifest.Part(kind: "file", mime: "application/octet-stream", filename: "blob.bin", size: 257),
            ]
        )

        let container = CPN1.encode(manifest: try manifest.encoded(), parts: [Data("x".utf8)])
        let (manifestData, _) = try CPN1.decode(container)
        let decoded = try Manifest.decode(manifestData)

        XCTAssertEqual(decoded.messageID, manifest.messageID)
        XCTAssertEqual(decoded.threadID, manifest.threadID)
        XCTAssertEqual(decoded.parts.count, 2)
        XCTAssertEqual(decoded.parts[0].filename, nil)
        XCTAssertEqual(decoded.parts[1].filename, "blob.bin")
        XCTAssertEqual(decoded.parts[1].size, 257)
    }

    func testThreadIDDeterministic() {
        let a = "08108C383A81C409F3E28757397AC5A52B6C5A8D"
        let b = "05299C734EA466728C71BD7ACDD6B5F7C410B233"
        XCTAssertEqual(Threading.pairwise(a, b), Threading.pairwise(b, a))
        XCTAssertEqual(Threading.pairwise(a, b).count, 64)
    }

    func testThreadIDMatchesHarness() {
        let a = "08108C383A81C409F3E28757397AC5A52B6C5A8D"
        let b = "05299C734EA466728C71BD7ACDD6B5F7C410B233"
        let expected = "7bc838882b284a83f951e98d25aac64fda850784be9ca03e1062867c9c9460e4"
        XCTAssertEqual(Threading.pairwise(a, b), expected)
    }

    func testBadMagicThrows() {
        var bad = Data("XXXX".utf8)
        bad.append(Data(count: 4))
        XCTAssertThrowsError(try CPN1.decode(bad))
    }

    func testTruncatedThrows() {
        let short = Data("CPN".utf8)
        XCTAssertThrowsError(try CPN1.decode(short))
    }
}
