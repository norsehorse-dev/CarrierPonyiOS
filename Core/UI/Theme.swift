import SwiftUI

// CarrierPony visual theme.
//
// Every color here is sampled directly from the app icon (the gold-to-red
// envelope), so the UI reads as the same product. The warm gradient is reserved
// for brand moments (avatar, send button, empty state); flat coral carries the
// user's own message bubbles so a long thread stays calm.

enum CPTheme {

    // MARK: - Icon palette (exact hex from CarrierPony-AppIcon-1024)

    static let gold       = Color(cpHex: 0xEBC289)   // gradient top-left
    static let coral      = Color(cpHex: 0xF28B80)   // gradient midpoint
    static let red        = Color(cpHex: 0xF1667B)   // gradient bottom-right

    static let accent     = Color(cpHex: 0xEC6755)   // horse mid — sent bubbles, primary
    static let accentLite = Color(cpHex: 0xEF8055)   // horse upper (coral)
    static let accentDeep = Color(cpHex: 0xF15056)   // horse lower (red)

    // MARK: - Gradients

    /// The icon background gradient (gold -> coral -> red), same diagonal axis.
    static let brand = LinearGradient(
        colors: [gold, coral, red],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )

    /// A tighter coral-to-red used on the send button, matching the horse fill.
    static let send = LinearGradient(
        colors: [accentLite, accentDeep],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )

    // MARK: - Surfaces (system-driven so light/dark both work)

    static let screen        = Color(.systemBackground)
    static let incomingBubble = Color(.secondarySystemBackground)
    static let composerField  = Color(.secondarySystemBackground)
    static let hairline       = Color(.separator)
}

extension Color {
    /// Build a Color from a 0xRRGGBB literal in sRGB.
    init(cpHex hex: UInt, alpha: Double = 1) {
        self.init(
            .sRGB,
            red:   Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue:  Double(hex & 0xFF) / 255,
            opacity: alpha
        )
    }
}
