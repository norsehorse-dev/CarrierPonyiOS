import XCTest
import CryptoKit
@testable import CarrierPony

final class NostrCryptoTests: XCTestCase {
    private func hex(_ s: String) -> Data {
        var d = Data(); var i = s.startIndex
        while i < s.endIndex { let n = s.index(i, offsetBy: 2); d.append(UInt8(s[i..<n], radix: 16)!); i = n }
        return d
    }

    // BIP340 vector 0 (seckey 3, msg zeros, aux zeros) - proves P256K does strict
    // BIP340 for a 32-byte message and that our pubkey/sig wiring is correct.
    func testBip340Vector0() throws {
        let e = try NostrCrypto.signRaw(
            secretKey: hex("0000000000000000000000000000000000000000000000000000000000000003"),
            message: hex("0000000000000000000000000000000000000000000000000000000000000000"),
            aux: hex("0000000000000000000000000000000000000000000000000000000000000000"))
        XCTAssertEqual(e.pubkey, "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
        XCTAssertEqual(e.sig, "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0")
    }

    func testNip01EventId() {
        let preimage = NostrSerialize.idPreimage(
            pubkey: "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            createdAt: 1700000000, kind: 24242, tags: [["t", String(repeating: "a", count: 64)]], content: "aGVsbG8=")
        let id = Data(SHA256.hash(data: Data(preimage.utf8))).hexLower
        XCTAssertEqual(id, "d6343636d714b18191a06894f7ecc3ca64b712b38509d566fa7ba33f30684793")
    }

    func testBuildMatchesReferenceId() throws {
        let e = try NostrEventBuilder.build(
            secretKey: hex("0000000000000000000000000000000000000000000000000000000000000003"),
            createdAt: 1700000000, kind: 24242, tags: [["t", String(repeating: "a", count: 64)]], content: "aGVsbG8=")
        XCTAssertEqual(e.pubkey, "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
        XCTAssertEqual(e.id, "d6343636d714b18191a06894f7ecc3ca64b712b38509d566fa7ba33f30684793")
        XCTAssertEqual(e.sig.count, 128)
    }
}
