import Foundation

// Attachment bytes are stored as individual files on disk rather than inline in
// the conversation JSON. That keeps the conversation store small and cheap to
// rewrite, and keeps large blobs out of memory until they're actually viewed.
// Files are content-addressed by a random id prefix so names never collide.

enum AttachmentStore {

    static let directory: URL = {
        let base = (try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        )) ?? FileManager.default.temporaryDirectory
        let dir = base.appendingPathComponent("carrierpony-attachments", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }()

    /// Persist bytes and return the on-disk relative name to store on the message.
    static func save(_ data: Data, suggestedName: String) -> String {
        let safe = sanitize(suggestedName)
        let name = UUID().uuidString + "_" + safe
        let url = directory.appendingPathComponent(name)
        try? data.write(to: url, options: .atomic)
        return name
    }

    static func url(for localPath: String) -> URL {
        directory.appendingPathComponent(localPath)
    }

    static func data(for localPath: String) -> Data? {
        try? Data(contentsOf: url(for: localPath))
    }

    static func delete(_ localPath: String) {
        try? FileManager.default.removeItem(at: url(for: localPath))
    }

    /// Write a temporary copy under the original filename, for share/save/QuickLook.
    static func temporaryCopy(of localPath: String, filename: String) -> URL? {
        guard let data = data(for: localPath) else { return nil }
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent(sanitize(filename))
        do {
            try data.write(to: tmp, options: .atomic)
            return tmp
        } catch {
            return nil
        }
    }

    private static func sanitize(_ name: String) -> String {
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._- ")
        let cleaned = String(name.unicodeScalars.filter { allowed.contains($0) })
        let trimmed = cleaned.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? "file" : String(trimmed.prefix(120))
    }
}
