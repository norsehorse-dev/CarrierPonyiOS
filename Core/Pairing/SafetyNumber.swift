import Foundation
import CryptoKit

// A safety number is a short, human-comparable digest of two identities' key
// fingerprints. Both sides compute the same value (the inputs are sorted first,
// so order doesn't matter), so if the two people read it to each other over any
// out-of-band channel and it matches, they've confirmed there's no man in the
// middle — and the contact can be marked verified.
//
// Format: 60 decimal digits, shown as twelve groups of five. Numeric so it's
// language-neutral and easy to read aloud.

enum SafetyNumber {

    /// The 60-digit safety number for a pair of fingerprints (order-independent).
    static func compute(_ a: Fingerprint, _ b: Fingerprint) -> String {
        let pair = [a.hex, b.hex].sorted()
        let seed = Data((pair[0] + pair[1]).utf8)

        // 32 + 32 = 64 bytes of deterministic material; we use the first 60.
        let h1 = Array(SHA256.hash(data: seed))
        let h2 = Array(SHA256.hash(data: Data(h1)))
        let bytes = (h1 + h2)

        var digits = ""
        for group in 0..<12 {
            let start = group * 5
            var value: UInt64 = 0
            for j in 0..<5 {
                value = (value << 8) | UInt64(bytes[start + j])
            }
            let chunk = value % 100000
            digits += String(format: "%05u", chunk)
        }
        return digits
    }

    /// The safety number split into twelve space-separated groups of five.
    static func grouped(_ a: Fingerprint, _ b: Fingerprint) -> String {
        let s = compute(a, b)
        return stride(from: 0, to: s.count, by: 5).map {
            let start = s.index(s.startIndex, offsetBy: $0)
            let end = s.index(s.startIndex, offsetBy: min($0 + 5, s.count))
            return String(s[start..<end])
        }.joined(separator: " ")
    }
}
