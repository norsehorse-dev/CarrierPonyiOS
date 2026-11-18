//
//  CompositeKEMTests.swift
//  CarrierPonyTests
//
//  The ML-KEM-768 + X25519 KEM (algorithm 35) in NorseHorsePGPCore: both sides
//  derive the same key, the wrong key does not, tampering is caught, and the
//  byte layout matches two things computed outside this code: a combiner
//  known-answer, and a full vector from a third implementation (Python:
//  kyber-py, cryptography, hashlib) that the Android core replays as well in
//  CPCompositeKemTest.
//

import Foundation
import Testing
import NorseHorsePGPCore

struct CompositeKEMTests {

    private func bytes(_ hex: String) -> [UInt8] {
        let digits = Array(hex.filter { !$0.isWhitespace })
        return stride(from: 0, to: digits.count, by: 2).map { UInt8(String(digits[$0...$0 + 1]), radix: 16)! }
    }
    private func data(_ hex: String) -> Data { Data(bytes(hex)) }
    private func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    private func range(_ from: UInt8) -> [UInt8] { (0..<32).map { from + UInt8($0) } }

    @Test func keyPairHasTheWireLengths() throws {
        let pair = try CompositeKEM.generateKeyPair()
        #expect(pair.publicKey.count == 1216)
        #expect(pair.secretKey.count == 96)
        #expect(try CompositeKEM.publicKey(fromSecret: pair.secretKey) == pair.publicKey)
    }

    @Test func bothSidesDeriveTheSameKey() throws {
        let pair = try CompositeKEM.generateKeyPair()
        let sent = try CompositeKEM.encapsulate(compositePublic: pair.publicKey)
        #expect(sent.ephemeralPublic.count == 32)
        #expect(sent.mlkemCiphertext.count == 1088)
        #expect(sent.kek.count == 32)
        let received = try CompositeKEM.decapsulate(ephemeralPublic: sent.ephemeralPublic,
                                                    mlkemCiphertext: sent.mlkemCiphertext,
                                                    compositeSecret: pair.secretKey)
        #expect(received == sent.kek)
    }

    @Test func eachEncapsulationIsFresh() throws {
        let pair = try CompositeKEM.generateKeyPair()
        let first = try CompositeKEM.encapsulate(compositePublic: pair.publicKey)
        let second = try CompositeKEM.encapsulate(compositePublic: pair.publicKey)
        #expect(first.kek != second.kek)
        #expect(first.ephemeralPublic != second.ephemeralPublic)
        #expect(first.mlkemCiphertext != second.mlkemCiphertext)
    }

    @Test func wrongKeyDerivesADifferentKey() throws {
        let pair = try CompositeKEM.generateKeyPair()
        let other = try CompositeKEM.generateKeyPair()
        let sent = try CompositeKEM.encapsulate(compositePublic: pair.publicKey)
        let received = try CompositeKEM.decapsulate(ephemeralPublic: sent.ephemeralPublic,
                                                    mlkemCiphertext: sent.mlkemCiphertext,
                                                    compositeSecret: other.secretKey)
        #expect(received != sent.kek)
    }

    // Each half has to matter on its own: swapping only the X25519 secret, or
    // only the ML-KEM seed, must change the result.
    @Test func eitherHalfAloneChangesTheKey() throws {
        let pair = try CompositeKEM.generateKeyPair()
        let other = try CompositeKEM.generateKeyPair()
        let sent = try CompositeKEM.encapsulate(compositePublic: pair.publicKey)
        let wrongCurve = other.secretKey.prefix(32) + pair.secretKey.suffix(64)
        let wrongLattice = pair.secretKey.prefix(32) + other.secretKey.suffix(64)
        for secret in [Data(wrongCurve), Data(wrongLattice)] {
            let received = try CompositeKEM.decapsulate(ephemeralPublic: sent.ephemeralPublic,
                                                        mlkemCiphertext: sent.mlkemCiphertext,
                                                        compositeSecret: secret)
            #expect(received != sent.kek)
        }
    }

    @Test func tamperedCiphertextDerivesADifferentKey() throws {
        let pair = try CompositeKEM.generateKeyPair()
        let sent = try CompositeKEM.encapsulate(compositePublic: pair.publicKey)
        var altered = [UInt8](sent.mlkemCiphertext)
        altered[100] ^= 0x01
        let received = try CompositeKEM.decapsulate(ephemeralPublic: sent.ephemeralPublic,
                                                    mlkemCiphertext: Data(altered),
                                                    compositeSecret: pair.secretKey)
        #expect(received != sent.kek)
    }

    @Test func lowOrderEphemeralIsRefused() throws {
        let pair = try CompositeKEM.generateKeyPair()
        let sent = try CompositeKEM.encapsulate(compositePublic: pair.publicKey)
        #expect(throws: CompositeKEMError.keyAgreementFailed) {
            _ = try CompositeKEM.decapsulate(ephemeralPublic: Data(count: 32),
                                             mlkemCiphertext: sent.mlkemCiphertext,
                                             compositeSecret: pair.secretKey)
        }
    }

    @Test func wrongLengthsAreRefused() throws {
        let pair = try CompositeKEM.generateKeyPair()
        let sent = try CompositeKEM.encapsulate(compositePublic: pair.publicKey)
        #expect(throws: CompositeKEMError.badLength) {
            _ = try CompositeKEM.encapsulate(compositePublic: pair.publicKey.dropLast())
        }
        #expect(throws: CompositeKEMError.badLength) {
            _ = try CompositeKEM.decapsulate(ephemeralPublic: sent.ephemeralPublic.dropLast(),
                                             mlkemCiphertext: sent.mlkemCiphertext,
                                             compositeSecret: pair.secretKey)
        }
        #expect(throws: CompositeKEMError.badLength) {
            _ = try CompositeKEM.decapsulate(ephemeralPublic: sent.ephemeralPublic,
                                             mlkemCiphertext: sent.mlkemCiphertext + Data([0]),
                                             compositeSecret: pair.secretKey)
        }
        #expect(throws: CompositeKEMError.badLength) {
            _ = try CompositeKEM.decapsulate(ephemeralPublic: sent.ephemeralPublic,
                                             mlkemCiphertext: sent.mlkemCiphertext,
                                             compositeSecret: pair.secretKey.dropLast())
        }
    }

    @Test func sessionKeyWrapRoundTrips() throws {
        let pair = try CompositeKEM.generateKeyPair()
        let sent = try CompositeKEM.encapsulate(compositePublic: pair.publicKey)
        let sessionKey = Data(range(0xA0))
        let wrapped = try CompositeKEM.wrapSessionKey(kek: sent.kek, sessionKey: sessionKey)
        #expect(wrapped.count == 40)
        #expect(try CompositeKEM.unwrapSessionKey(kek: sent.kek, wrapped: wrapped) == sessionKey)
    }

    @Test func unwrapWithTheWrongKeyFails() throws {
        let pair = try CompositeKEM.generateKeyPair()
        let sent = try CompositeKEM.encapsulate(compositePublic: pair.publicKey)
        let other = try CompositeKEM.encapsulate(compositePublic: pair.publicKey)
        let wrapped = try CompositeKEM.wrapSessionKey(kek: sent.kek, sessionKey: Data(range(0xA0)))
        #expect(throws: CompositeKEMError.unwrapFailed) {
            _ = try CompositeKEM.unwrapSessionKey(kek: other.kek, wrapped: wrapped)
        }
    }

    // Same inputs and the same answer as combinerMatchesTheKnownAnswer on Android.
    @Test func combinerMatchesTheKnownAnswer() {
        let kek = CompositeKEM.combine(mlkemShare: range(0x00), ecdhShare: range(0x20),
                                       ephemeralPublic: range(0x40), recipientX25519Public: range(0x60))
        #expect(hex(Data(kek)) == "8b341efe0f87f2e97e1ab8772b8e7cebc6b52240a631ad4d5e220acd0f419b75")
    }

    // A message key encapsulated by a third implementation opens here. This
    // covers what the round-trip tests cannot: seed expansion, the ML-KEM
    // decapsulation, the X25519 share and the wrap all agree with code that
    // shares nothing with this package.
    @Test func opensTheSharedVector() throws {
        let secret = data(Vector.compositeSecret)
        #expect(try CompositeKEM.publicKey(fromSecret: secret) == data(Vector.compositePublic))
        let kek = try CompositeKEM.decapsulate(ephemeralPublic: data(Vector.ephemeralPublic),
                                               mlkemCiphertext: data(Vector.mlkemCiphertext),
                                               compositeSecret: secret)
        #expect(hex(kek) == Vector.kek)
        let sessionKey = try CompositeKEM.unwrapSessionKey(kek: kek, wrapped: data(Vector.wrappedSessionKey))
        #expect(hex(sessionKey) == Vector.sessionKey)
        #expect(hex(try CompositeKEM.wrapSessionKey(kek: kek, sessionKey: sessionKey)) == Vector.wrappedSessionKey)
    }

    // And the other direction: a key encapsulated here to the vector's public
    // key opens with the vector's secret key.
    @Test func encapsulatesToTheSharedVectorKey() throws {
        let sent = try CompositeKEM.encapsulate(compositePublic: data(Vector.compositePublic))
        let received = try CompositeKEM.decapsulate(ephemeralPublic: sent.ephemeralPublic,
                                                    mlkemCiphertext: sent.mlkemCiphertext,
                                                    compositeSecret: data(Vector.compositeSecret))
        #expect(received == sent.kek)
    }
}

// kem-vector-1. Every input is SHAKE-256 of a fixed label, so the vector can be
// regenerated. The same values sit in the Android core's test resources.
private enum Vector {
    static let compositeSecret = """
        d145c678528947b4111ce4f5c5dab490353d54fd40b7ee132a5a7af4f8f66af005698549a4e4a4d9144d52e3c856fb29
        b22b8569fa276ada9df6d37e3e09fa232234724c490f17d1727c55c9445377c23528753c72389ae47893898ff4c93a71
        """
    static let compositePublic = """
        b5b716a84352141be4bb337a72e2d321480f7cf73bf12873bea13e64210adc67e88b79bda099572ab78f6304d72656a4
        3993724c765e52291cc5528b808112700156c29e0ad2264345bd042cb195f921bc60a4e848579f5c3a9d6c750da69029
        27a56437b3bf45a722bba2d159c55bb94df75a3d2b224b21e878bd82a379fc1c2f3b865431439e11ab4217bddc918254
        b60e8a874d48206cb2b0037c6980d8cc4eda154b19f9c26804771977231cfc6638f38a23943868d27a1d3c63ac219c73
        36297b78c5d2c0cfbbe00b4928939a1a1666068996591262748f8df5344f1979d6fb04e8ec5ee2822e9c3a94ea8c26d3
        40c818d504d91b06023304f492b424e59437406b8ef80983d86b2f163fbc50400a2529f6b6b2d963639b17b55af65f62
        eaa04f28784ea2505b178e35a55a3fda0bc7826ef4b717a3a0300c3842f945a6247cc5c7c4a6d7e8ceda69859b907c4d
        9a120008aa7fccaa3b340b55ea5693b632a42c582a6bcb84363ede7a599b9363bd725b1dd3abd6783318436c48f076f6
        851bdde6762e71b3e18b42cd149c55183b7b75bee17b5f384499c847b67ff3b6b85b29d3db233d94b33d1270e965b957
        024c27ab31273b204b6567f69abd1d8242ca441ba015811242ade11cb4f0210807d59ff79a86dbca3cc701c43d44808e
        162d7ba25ad2213d3d95240398c351b424de07ac7e948dfc145702a92fcc309d249065969b645d67398bcb7039c42355
        9c2237f2225bbb1d2ca19d1f2c833e2345fc855197873d33282be4aa71561c099b95bff252400360a8d8a28124c69b72
        b2a6c02cc18d971543337fcdac6441c1bd834750d46266d298b0ec544bb7fb9fbfd64568205fbcf2c718e11806d3953f
        b2381e6b233eb2cae9b477a6f10ac5261510a657c5aa60485a7032908fd602727e14770f459dc4b75bf4e11bddb99720
        c96839477f9234a581671938f69a3e803d59f38ae4b5870eb2b6e09b6ec718c21d5371b354204ef18075e78c74954c91
        c1b16a4136e3f35ce4d37de7869cf168b89a546374d6c972b0abae437f09db445a2ca66f3645a3d92dcf10cab725a30e
        1a7ab1966c1bf07267e39c22fc401b8b77992cc6e0b32cdf92c5cb351f06ea6a1ff5789eba7f23999e7de15b5b51aaa1
        ab2e4009b79242682f310024446328230a668a722a99c9e1996d1d68736cb9aebf6927299095eaaa28757682330c1956
        413f8d654084352a85481aac355a73e169d8b699510846725ac26ca2048609a719f357f38077ef6c774fb99762e4b48e
        42609b86512d627caf9b42e59629efd738f0565fb0613270c00b388670c28c104322296ea96edd1b26160ca4eb757598
        c5c72356cb94420cfbc66e76279206c23453582cf254917611851abb3ed7d1b4a0856c01cacae8064849359abb97401f
        299607e4be1ef6485ab443cdb7cefc515f8e2514ac9484bb48483acab2dd270cfbe459749848dc05007cc9c47623180c
        b821dfb25da5638f24766731626558539de1028800b045de71212f56440328865ad72b6df64697a55abdb854bdbc0c55
        1ab8b7e28ad97a2b94867d9cf377ad49cf4ea34f808cbd9c42637b194b4b76220a7a58121a31eb2c0d1d5b8ac2a3bcde
        00b65c222cbc2a1ce6a97dfbb2ae8f18909701a422da6bf4dc6366b7bd8286844cf94c26576cb8dc63a1c28f2b50770a
        9908c9890dd49a488ceb253b69666a30
        """
    static let ephemeralPublic = "7021458a62927476f695c2f220c54f0674082c8fd8a662e1c3a4006fdb5a3b0d"
    static let mlkemCiphertext = """
        75a98a33c260afb66a438604456b04f4e2a48a0209af4a9b93652beb0797a7ec8a562023415f6e303373b6247a8dff41
        2b67982611bffe922be0058b1319dc93c1a53622c2501486afcd5e66a48f7b2892ab3cf8256af126ec01175edacd855a
        34b5b79839ea09874cc70d0c7181bdab3819658689552f3bbdb40b15e3fd9c6f22fef456036f1e21ff6afad01f4538a7
        0ead3026e5de1a716f3ef02e593c9a6231723d8c5d9d3641c449154727ce21baaa1ae31d85c9cf6048d917a81f46b4da
        3008ed2d42ea76f7799f3b7f02e8b85a3af7f93c2ca3682f3aef7dab579182e9a2104d8a4e0750339b8b1cfd23efda15
        e5d49634148da1f6b11b18f8f83f7e545565315b432fdd65665809a40789f20c6b5ac8aee04cfaa846696afe4696fd90
        1e00ac57948b3e4fefe3a19179f33b1e9d6ab497f86f3e9bfb384c39298f37d9ce60a76759a9ac167ba919f9f7c6bbca
        4478b01fb3e91c3b8ca784e7ddc57e08c71609f1501e6b1102ffdb2587917a160d732fed4a8d1ca0b77ddf63a95c90d5
        c1e7e759d6e2d6a5e2a120cb38b2a2b7320794207cf7a1f6f5d55fded1505da9a1bc42599c4808d2de28469260709294
        6551166103a89e02955f4be4be4a3d5dcefca099038acdde6e7ba6c5c9a3825aa7ba8950cab691c88d7c4eb524922386
        8d656fe49c36aaa8c5aa21c346760f0ce8ea6c5010beb8e4b2d9988e676e8bd7ad13d361ab045d4c4216e217c249090a
        bc7e3102af5aab0a1c074de27c7d1919a6a6bd9c3e43ffd04f04e45bc340b85c87d6dc35f6977fe6e59e1f2c7b5e44fb
        4a20b89f655a2fe6fd2d7f3d4170c42d1ca7776043e1a978cbee9cd3fa3e9285065716bc88ba4d2885ec317702cefa87
        a7da9011db53d447508a5811ebecd241d79950b83e1598ffeb0eab4159de4c5545dcf7c0d32021c92739954d24796537
        be48cddb4a3ceab6d1f544b05bd55bf5e963619a2e9d153f1d86964a8ee75bf77544ada6220d140190a1f124a42910c6
        283936deabe7123d5c7ab18e5a2920ecf9ec06e779c453aa556c143d0055a81b4c406928c70ab9d42c32f64342a65385
        b472c3dc61bee76be6a5e0d9abaef0b3bc6abfd8b67d9974c2a687de87ac99feb9cb5b0c13b233b5356d06e4f84513f5
        680551b4ff7298931008abd561ec7e415d8691ff5a504a1a2c3faf57290cdff5617ec0722faccbc5d81b52358caf5420
        4c41f20d8fc31a0e68aca8a8a9f6b91478260587fae67321763bd0fd74ea6101b35f78059bb095c59468cd6db50c4326
        6ad820d9dd4ae139c7c03b5f47627a3cd9500ad3194f4b5bb90c6a4c3fe3989e4ed31a089114dfa41378905e96583de5
        95ed3e381cd4a4a3046a16b9e42e0699d85e8740d4dadcbe33ee98174eee91e0b531d3af2699820a103780d2c3dbad9f
        3f9ad18845451ff97632ecbf99139bf328c673b87e2d1f83704725a40a99cb02699a615572ca64781576d98d834b74f0
        90ce1f1520840095c14b3b2528088ed7cc5c28b5b002c4e8dd8d00a569a11cb8
        """
    static let kek = "8bbf235e45cdf1d1c132bdbc39a46ab27c9d087af125032df961ffd431aaf960"
    static let sessionKey = "7f96a5758b37629e52dc4e11c6ceb1b38c00ce08adf6743bd7252642198917f3"
    static let wrappedSessionKey = "cb22ac838db26118249ed7dd527869f5f37b2d11707eefd93cf30f923b6e2911d9eeaec07e4d8fc7"
}
