import Foundation
import NorseHorsePGPCore

// Local, user-initiated export of one conversation to a file. Nothing here touches
// the relay or the network. The rendered transcript can optionally be sealed with
// a passphrase via PassphraseBox (the same OpenPGP symmetric box used for identity
// backups), so the default path leaves no plaintext at rest. Attachment bytes are
// never embedded; attachments are listed by name and size only.

enum ExportFormat: String, CaseIterable, Identifiable {
    case txt
    case json
    case html

    var id: String { rawValue }

    var label: String {
        switch self {
        case .txt: return "Plain text (.txt)"
        case .json: return "JSON (.json)"
        case .html: return "Web page (.html)"
        }
    }
}

enum ChatExport {

    /// Render a conversation into a temp file and return its URL for sharing.
    /// When `passphrase` is non-empty the rendered bytes are sealed and the file
    /// carries a `.<fmt>.asc` extension; otherwise the plaintext file is written.
    static func writeTempFile(
        conversation: Conversation,
        peerName: String,
        format: ExportFormat,
        passphrase: String?
    ) throws -> URL {
        let content = render(
            messages: conversation.sortedMessages,
            peerName: peerName,
            fingerprint: conversation.peer,
            format: format
        )

        let base = "CarrierPony-\(safeName(peerName))-\(stamp())"
        let data: Data
        let ext: String
        if let pass = passphrase, !pass.isEmpty {
            let sealed = try PassphraseBox.seal(content, passphrase: pass)
            data = Data(sealed.utf8)
            ext = "\(format.rawValue).asc"
        } else {
            data = content
            ext = format.rawValue
        }

        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(base).\(ext)")
        try data.write(to: url, options: .atomic)
        return url
    }

    // MARK: - Rendering

    private static func render(
        messages: [ChatMessage],
        peerName: String,
        fingerprint: Fingerprint,
        format: ExportFormat
    ) -> Data {
        switch format {
        case .txt: return Data(renderText(messages, peerName: peerName, fingerprint: fingerprint).utf8)
        case .json: return renderJSON(messages, peerName: peerName, fingerprint: fingerprint)
        case .html: return Data(renderHTML(messages, peerName: peerName, fingerprint: fingerprint).utf8)
        }
    }

    private static func who(_ m: ChatMessage, peerName: String) -> String {
        m.direction == .outgoing ? "Me" : peerName
    }

    private static func renderText(_ messages: [ChatMessage], peerName: String, fingerprint: Fingerprint) -> String {
        var out = "CarrierPony chat export\n"
        out += "With: \(peerName) (\(fingerprint.hex))\n"
        out += "Exported: \(medium(Date()))\n"
        out += "Messages auto-expire in CarrierPony; this exported copy does not.\n\n"
        for m in messages {
            let when = medium(Date(timeIntervalSince1970: TimeInterval(m.sentAt)))
            let line = m.text?.isEmpty == false ? m.text! : ""
            out += "[\(when)] \(who(m, peerName: peerName)): \(line)\n"
            for a in m.attachments {
                out += "    [attachment: \(a.filename) (\(byteLabel(a.size)))]\n"
            }
        }
        return out
    }

    private static func renderJSON(_ messages: [ChatMessage], peerName: String, fingerprint: Fingerprint) -> Data {
        struct Doc: Encodable {
            let app: String
            let exportedAt: String
            let peer: String
            let fingerprint: String
            let note: String
            let messages: [Msg]
        }
        struct Msg: Encodable {
            let from: String
            let sentAt: String
            let text: String?
            let attachments: [Att]
        }
        struct Att: Encodable {
            let filename: String
            let size: Int
        }
        let iso = ISO8601DateFormatter()
        let doc = Doc(
            app: "CarrierPony",
            exportedAt: iso.string(from: Date()),
            peer: peerName,
            fingerprint: fingerprint.hex,
            note: "Messages auto-expire in CarrierPony; this exported copy does not. Attachment bytes are not included.",
            messages: messages.map { m in
                Msg(
                    from: m.direction == .outgoing ? "me" : "peer",
                    sentAt: iso.string(from: Date(timeIntervalSince1970: TimeInterval(m.sentAt))),
                    text: m.text,
                    attachments: m.attachments.map { Att(filename: $0.filename, size: $0.size) }
                )
            }
        )
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return (try? enc.encode(doc)) ?? Data("{}".utf8)
    }

    private static func renderHTML(_ messages: [ChatMessage], peerName: String, fingerprint: Fingerprint) -> String {
        var rows = ""
        for m in messages {
            let side = m.direction == .outgoing ? "out" : "in"
            let when = esc(medium(Date(timeIntervalSince1970: TimeInterval(m.sentAt))))
            var inner = ""
            if let t = m.text, !t.isEmpty {
                inner += "<div class=\"text\">\(esc(t))</div>"
            }
            for a in m.attachments {
                inner += "<div class=\"att\">\(esc(a.filename)) (\(esc(byteLabel(a.size))))</div>"
            }
            rows += "<div class=\"row \(side)\"><div class=\"bubble\">\(inner)<div class=\"meta\">\(esc(who(m, peerName: peerName))) &middot; \(when)</div></div></div>\n"
        }
        return """
        <!doctype html>
        <html lang="en"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>CarrierPony chat with \(esc(peerName))</title>
        <style>
        :root { color-scheme: light dark; }
        body { margin: 0; background: #f2f2f7; color: #111; font: 15px/1.4 -apple-system, system-ui, sans-serif; }
        header { padding: 16px; background: #fff; border-bottom: 1px solid #ddd; }
        header h1 { margin: 0 0 4px; font-size: 17px; }
        header .sub { color: #666; font-size: 12px; word-break: break-all; }
        header .warn { color: #8a6d00; font-size: 12px; margin-top: 6px; }
        main { max-width: 720px; margin: 0 auto; padding: 12px; }
        .row { display: flex; margin: 3px 0; }
        .row.out { justify-content: flex-end; }
        .bubble { max-width: 78%; padding: 8px 12px; border-radius: 18px; background: #fff; }
        .row.out .bubble { background: #2f6bff; color: #fff; }
        .att { font-size: 13px; opacity: 0.85; margin-top: 4px; }
        .meta { font-size: 11px; opacity: 0.6; margin-top: 4px; }
        @media (prefers-color-scheme: dark) {
          body { background: #000; color: #eee; }
          header { background: #1c1c1e; border-color: #333; }
          .bubble { background: #26262a; }
        }
        </style></head>
        <body>
        <header>
          <h1>Chat with \(esc(peerName))</h1>
          <div class="sub">\(esc(fingerprint.hex))</div>
          <div class="sub">Exported \(esc(medium(Date())))</div>
          <div class="warn">Messages auto-expire in CarrierPony. This exported copy does not, so it outlives the disappear time.</div>
        </header>
        <main>
        \(rows)
        </main>
        </body></html>
        """
    }

    // MARK: - Helpers

    private static func esc(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
         .replacingOccurrences(of: "<", with: "&lt;")
         .replacingOccurrences(of: ">", with: "&gt;")
         .replacingOccurrences(of: "\"", with: "&quot;")
    }

    private static func medium(_ d: Date) -> String {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f.string(from: d)
    }

    private static func byteLabel(_ n: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file)
    }

    private static func safeName(_ s: String) -> String {
        let allowed = CharacterSet.alphanumerics
        let mapped = s.unicodeScalars.map { allowed.contains($0) ? Character($0) : "-" }
        let joined = String(mapped)
        let trimmed = joined.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return trimmed.isEmpty ? "chat" : String(trimmed.prefix(40))
    }

    private static func stamp() -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd-HHmm"
        return f.string(from: Date())
    }
}
