import Foundation

// App Review demonstration mode.
//
// CarrierPony is peer-to-peer, so a single reviewer on one device cannot exchange
// messages without a second party. Apple's Guideline 2.1(a) explicitly allows a
// demonstration mode that exhibits the app's full features. Entering the code
// below in "Enter an invite" pairs the reviewer with a simulated local contact
// that auto-replies (and echoes a file back), so the entire messaging and
// file-transfer flow can be verified on one device.
//
// This activates only when someone types the exact code. Real users never see it,
// and it uses no network — the simulated contact and its replies are generated
// entirely on-device. The code is documented in the App Review notes.

enum DemoMode {
    static let inviteCode = "CPDEMO-REVIEW"
    static let fingerprintHex = "DE300DE300DE300DE300DE300DE300DE300DE300"
    static let peerName = "CarrierPony Demo"

    static var fingerprint: Fingerprint { Fingerprint(fingerprintHex)! }

    static func matches(_ input: String) -> Bool {
        let core = input.uppercased().unicodeScalars
            .filter { CharacterSet.alphanumerics.contains($0) }
            .map(String.init)
            .joined()
        return core == "CPDEMOREVIEW"
    }

    /// Diagnostic: shows exactly what the running binary sees.
    static func debugDescribe(_ input: String) -> String {
        let core = input.uppercased().unicodeScalars
            .filter { CharacterSet.alphanumerics.contains($0) }
            .map(String.init)
            .joined()
        return "len=\(input.count) core=[\(core)] match=\(core == "CPDEMOREVIEW")"
    }
}
