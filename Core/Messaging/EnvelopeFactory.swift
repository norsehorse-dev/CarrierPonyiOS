import Foundation

struct OutgoingMessage {
    var threadID: String
    var text: String?
    var attachments: [Attachment]
    var expiresAt: Int

    struct Attachment {
        var filename: String
        var mime: String
        var data: Data
    }
}

struct IncomingMessage {
    var sender: Fingerprint
    var manifest: Manifest
    var text: String?
    var files: [(part: Manifest.Part, data: Data)]
}

struct EnvelopeFactory {
    let crypto: CryptoEngine

    func build(_ message: OutgoingMessage, to recipient: PublicKey, messageID: String = UUID().uuidString) throws -> Data {
        var parts: [Data] = []
        var meta: [Manifest.Part] = []

        if let text = message.text {
            parts.append(Data(text.utf8))
            meta.append(Manifest.Part(kind: "text", mime: "text/plain; charset=utf-8", filename: nil, size: nil))
        }
        for attachment in message.attachments {
            parts.append(attachment.data)
            meta.append(Manifest.Part(kind: "file", mime: attachment.mime, filename: attachment.filename, size: attachment.data.count))
        }

        let manifest = Manifest(
            v: 1,
            type: "message",
            messageID: messageID,
            threadID: message.threadID,
            sentAt: Int(Date().timeIntervalSince1970),
            expiresAt: message.expiresAt,
            parts: meta
        )

        let container = CPN1.encode(manifest: try manifest.encoded(), parts: parts)
        return try crypto.signAndEncrypt(container, to: recipient)
    }

    func open(_ envelope: Data) throws -> IncomingMessage {
        let verified = try crypto.decryptAndVerify(envelope)
        let (manifestData, parts) = try CPN1.decode(verified.plaintext)
        let manifest = try Manifest.decode(manifestData)

        var text: String?
        var files: [(part: Manifest.Part, data: Data)] = []
        for (index, part) in manifest.parts.enumerated() where index < parts.count {
            switch part.kind {
            case "text":
                text = String(data: parts[index], encoding: .utf8)
            case "file":
                files.append((part, parts[index]))
            case "control":
                files.append((part, parts[index]))
            default:
                break
            }
        }

        return IncomingMessage(sender: verified.sender, manifest: manifest, text: text, files: files)
    }
}
