//
//  V6IdentityTests.swift
//  CarrierPonyTests
//
//  The v6 identity the core generates: an Ed25519 primary that certifies and
//  signs, and one ML-KEM-768 + X25519 (algorithm 35) encryption subkey. These
//  tests check the shape and that the primary signs. Whether another OpenPGP
//  stack accepts the key is settled outside this process: emitV6IdentityForAndroid
//  writes one identity and a signed relay challenge to /tmp/carrierpony-fixtures,
//  the Android core's CPIosV6IdentityTest reads the key, and the relay's
//  cp-verify checks the signature.
//

import Foundation
import Testing
import NorseHorsePGPCore
@testable import CarrierPony

struct V6IdentityTests {

    private func generate() throws -> GeneratedIdentity {
        try OpenPGPKeyGenerator.generateV6Identity(name: "Test Pony", email: "test@carrierpony.com")
    }

    private func binary(_ armored: String) throws -> Data {
        let body = armored
            .split(whereSeparator: { $0.isNewline })
            .filter { !$0.hasPrefix("-----") && !$0.hasPrefix("=") && !$0.contains(":") }
            .joined()
        return try #require(Data(base64Encoded: body))
    }

    // Top-level packets as (tag, body). Every packet these keys contain uses
    // the new format with a one, two or five octet length.
    private func packets(_ data: Data) throws -> [(tag: UInt8, body: [UInt8])] {
        let bytes = [UInt8](data)
        var out: [(tag: UInt8, body: [UInt8])] = []
        var i = 0
        while i < bytes.count {
            try #require(bytes[i] & 0xC0 == 0xC0)
            let tag = bytes[i] & 0x3F
            i += 1
            var length = 0
            if bytes[i] < 192 {
                length = Int(bytes[i]); i += 1
            } else if bytes[i] < 224 {
                length = (Int(bytes[i]) - 192) << 8 + Int(bytes[i + 1]) + 192; i += 2
            } else {
                try #require(bytes[i] == 255)
                length = Int(bytes[i + 1]) << 24 | Int(bytes[i + 2]) << 16 | Int(bytes[i + 3]) << 8 | Int(bytes[i + 4]); i += 5
            }
            try #require(i + length <= bytes.count)
            out.append((tag, Array(bytes[i..<i + length])))
            i += length
        }
        return out
    }

    @Test func fingerprintIs64HexAndTheKeyIsV6() throws {
        let identity = try generate()
        #expect(identity.fingerprint.count == 64)
        let fingerprint = try #require(Fingerprint(identity.fingerprint))
        #expect(fingerprint.isV6)
        #expect(OpenPGPPacketParser.openPGPKeyVersion(from: identity.secretKey) == 6)
        #expect(OpenPGPPacketParser.openPGPKeyVersion(from: try binary(identity.armoredPublicKey)) == 6)
    }

    @Test func twoIdentitiesDiffer() throws {
        #expect(try generate().fingerprint != generate().fingerprint)
    }

    // primary | direct-key signature | user ID | certification | subkey | binding,
    // and nothing else: no signing subkey, no separate X25519 subkey.
    @Test func keyIsASigningPrimaryAndOneCompositeSubkey() throws {
        let identity = try generate()
        let pub = try packets(try binary(identity.armoredPublicKey))
        #expect(pub.map { $0.tag } == [6, 2, 13, 2, 14, 2])
        let primary = pub[0].body
        let subkey = pub[4].body
        #expect(primary[0] == 6 && primary[5] == 27)
        #expect(primary.count == 10 + 32)
        #expect(subkey[0] == 6 && subkey[5] == 35)
        #expect(subkey.count == 10 + 1216)

        let sec = try packets(identity.secretKey)
        #expect(sec.map { $0.tag } == [5, 2, 13, 2, 7, 2])
        // Unprotected: the public body, a zero usage octet, then the secret.
        #expect(sec[0].body.count == primary.count + 1 + 32)
        #expect(sec[4].body.count == subkey.count + 1 + 96)
        #expect(Array(sec[4].body.prefix(subkey.count)) == subkey)
        #expect(sec[4].body[subkey.count] == 0)
    }

    // The secret subkey material is a working KEM key for the public half.
    @Test func storedSubkeyMaterialDrivesTheKEM() throws {
        let identity = try generate()
        let subkey = try packets(try binary(identity.armoredPublicKey))[4].body
        let secretSubkey = try packets(identity.secretKey)[4].body
        let publicMaterial = Data(subkey.suffix(1216))
        let secretMaterial = Data(secretSubkey.suffix(96))
        #expect(try CompositeKEM.publicKey(fromSecret: secretMaterial) == publicMaterial)
        let sent = try CompositeKEM.encapsulate(compositePublic: publicMaterial)
        let received = try CompositeKEM.decapsulate(ephemeralPublic: sent.ephemeralPublic,
                                                    mlkemCiphertext: sent.mlkemCiphertext,
                                                    compositeSecret: secretMaterial)
        #expect(received == sent.kek)
    }

    @Test func primaryKeySignsAndItsSignatureVerifies() throws {
        let identity = try generate()
        let challenge = Data("relay-challenge-0123456789".utf8)
        let signing = try OpenPGPPacketParser.ed25519SigningInfo(fromV6SecretKey: identity.secretKey)
        let signature = try OpenPGPPacketBuilder.detachedSignatureEd25519V6(over: challenge, signingInfo: signing)
        let primary = try OpenPGPPacketParser.ed25519PrimaryPublicKey(fromV6PublicKey: try binary(identity.armoredPublicKey))

        #expect(try OpenPGPPacketParser.verifyDetachedSignatureEd25519V6(
            armored: signature, over: challenge, signerV6PublicKey: primary))
        #expect(try !OpenPGPPacketParser.verifyDetachedSignatureEd25519V6(
            armored: signature, over: challenge + Data([0x21]), signerV6PublicKey: primary))

        let other = try generate()
        let otherPrimary = try OpenPGPPacketParser.ed25519PrimaryPublicKey(fromV6PublicKey: try binary(other.armoredPublicKey))
        #expect(try !OpenPGPPacketParser.verifyDetachedSignatureEd25519V6(
            armored: signature, over: challenge, signerV6PublicKey: otherPrimary))
    }

    // One identity and a signed challenge for the Android core and cp-verify.
    // The key belongs to nobody.
    @Test func emitV6IdentityForAndroid() throws {
        let identity = try OpenPGPKeyGenerator.generateV6Identity(name: "iOS Fixture", email: "fixture@carrierpony.com")
        let nonce = "ios-v6-login-challenge-0123456789abcdef"
        let signing = try OpenPGPPacketParser.ed25519SigningInfo(fromV6SecretKey: identity.secretKey)
        let signature = try OpenPGPPacketBuilder.detachedSignatureEd25519V6(over: Data(nonce.utf8), signingInfo: signing)
        let request = try JSONSerialization.data(withJSONObject: [
            "pubkey": identity.armoredPublicKey,
            "fpr": identity.fingerprint,
            "data": nonce,
            "sig": signature,
        ])

        let directory = URL(fileURLWithPath: "/tmp/carrierpony-fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        func write(_ text: String, _ name: String) throws {
            try text.write(to: directory.appendingPathComponent(name), atomically: true, encoding: .utf8)
        }
        try write(identity.armoredPublicKey, "ios-v6-public.asc")
        try write(identity.armoredSecretKey, "ios-v6-secret.asc")
        try write(identity.fingerprint, "ios-v6-fingerprint.txt")
        try write(nonce, "ios-v6-login-nonce.txt")
        try write(signature, "ios-v6-login-signature.asc")
        try request.write(to: directory.appendingPathComponent("ios-v6-login-request.json"))
    }
}
