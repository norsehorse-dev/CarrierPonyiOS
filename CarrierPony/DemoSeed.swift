// DemoSeed.swift
// CarrierPony iOS (DEBUG only)
//
// Store screenshots. The snapshot UI test (CarrierPonyUITests/SnapshotTests)
// launches the app with
//   -demoSeed                wipe local data and seed demo data
//   -demoScreen <screen>     open inbox, chat, group, files or pair
// fastlane snapshot adds -AppleLanguages; the demo writes its data and the
// in-app language (cp.lang) to match. Seeding writes the app's own files
// (Keychain identity, contacts, conversations, groups, attachments) for
// fictional contacts, so the screens show real UI over made-up data, and the
// app then stays off the network (AppModel.start returns early).
//
// Not compiled into release builds. Demo data uses fictional first names and
// example.com addresses.

#if DEBUG
import Foundation
import UIKit
import NorseHorsePGPCore

@MainActor
enum DemoSeed {

    private static let args = ProcessInfo.processInfo.arguments
    private static let chatKey = "cp.demo.chatPeer"
    static let groupID = "0D3E0D3E0D3E0D3E0D3E0D3E0D3E0D3E"

    /// True for a screenshot launch. The app then makes no network calls.
    static var isActive: Bool { args.contains("-demoSeed") }

    static var screen: String? {
        guard let i = args.firstIndex(of: "-demoScreen"), i + 1 < args.count else { return nil }
        return args[i + 1]
    }

    static var startTab: Int { isActive && screen == "files" ? 1 : 0 }
    static var startPairing: Bool { isActive && screen == "pair" }
    static var startPath: [ChatRoute] {
        guard isActive else { return [] }
        switch screen {
        case "chat":
            if let hex = UserDefaults.standard.string(forKey: chatKey), let fpr = Fingerprint(hex) { return [.chat(fpr)] }
        case "group":
            return [.group(groupID)]
        default:
            break
        }
        return []
    }

    /// Called from CarrierPonyApp.init, before RootView builds AppModel.
    static func seedIfRequested() {
        guard isActive else { return }
        do { try seed() } catch { NSLog("DemoSeed failed: \(error)") }
    }

    // MARK: - Seeding

    private static let languages = ["en", "de", "es", "fr", "it", "ja", "pt", "ru", "zh"]

    private static var language: String {
        let preferred = Locale.preferredLanguages.first ?? "en"
        let code = String(preferred.prefix { $0 != "-" && $0 != "_" }).lowercased()
        return languages.contains(code) ? code : "en"
    }

    private struct Person {
        let name: String
        let fingerprint: Fingerprint
        let secretKey: Data
        let armored: String
        var hex: String { fingerprint.hex }
    }

    private struct ContactRecord: Codable {
        let fingerprint: String
        let armored: String
        let name: String?
        let trust: String?
        let nickname: String?
    }
    private struct StoredAttachment: Codable {
        let id: String; let filename: String; let mime: String; let size: Int; let localPath: String
    }
    private struct StoredMessage: Codable {
        let id: String; let threadID: String; let peer: String; let direction: String; let text: String?
        let attachments: [StoredAttachment]; let sentAt: Int; let expiresAt: Int; let isRead: Bool; let viaLan: Bool?
    }
    private struct StoredConversation: Codable {
        let threadID: String; let peer: String; let peerName: String?; let messages: [StoredMessage]
    }
    private struct StoredGroupThread: Codable {
        let groupID: String; let messages: [StoredMessage]
    }
    private struct Snapshot: Codable {
        let conversations: [StoredConversation]; let seen: [String]
        let groups: [ChatGroup]?; let groupThreads: [StoredGroupThread]?
    }

    private static func seed() throws {
        let lang = language
        let t = DemoTexts.forLang(lang)
        func s(_ key: String) -> String { t[key] ?? key }

        // Start clean: no leftover accounts, conversations or attachments.
        IdentityStore().deleteAll()
        let fm = FileManager.default
        let dir = try fm.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        for name in (try? fm.contentsOfDirectory(atPath: dir.path)) ?? [] where name.hasPrefix("carrierpony-") {
            try? fm.removeItem(at: dir.appendingPathComponent(name))
        }

        func person(_ name: String, _ email: String) throws -> Person {
            let g = try OpenPGPKeyGenerator.generateV4Identity(name: name, email: email)
            guard let fpr = Fingerprint(g.fingerprint) else { throw CocoaError(.coderInvalidValue) }
            return Person(name: name, fingerprint: fpr, secretKey: g.secretKey, armored: g.armoredPublicKey)
        }
        let me = try person(s("me"), "me@example.com")
        let maya = try person(s("maya"), "maya@example.com")
        let leo = try person(s("leo"), "leo@example.org")
        let priya = try person(s("priya"), "priya@example.net")
        let jonas = try person(s("jonas"), "jonas@example.com")

        try IdentityStore().save(Identity(fingerprint: me.fingerprint, secretKey: me.secretKey, armoredPublicKey: me.armored))

        let contacts = [(maya, true), (leo, true), (priya, false), (jonas, false)].map { pair -> ContactRecord in
            let (p, verified) = pair
            return ContactRecord(fingerprint: p.hex, armored: p.armored, name: p.name,
                          trust: verified ? TrustLevel.verified.rawValue : TrustLevel.unverified.rawValue, nickname: nil)
        }
        try JSONEncoder().encode(contacts).write(to: dir.appendingPathComponent("carrierpony-contacts-\(me.hex).json"))

        // Times line up with the 9:41 status bar fastlane sets.
        var cal = Calendar.current
        cal.timeZone = .current
        let base = Int(cal.date(bySettingHour: 9, minute: 41, second: 0, of: Date())?.timeIntervalSince1970 ?? Date().timeIntervalSince1970)
        let month = Int(Date().timeIntervalSince1970) + 30 * 86_400
        func ago(_ minutes: Int) -> Int { base - minutes * 60 }

        func msg(_ peer: Person, _ thread: String, incoming: Bool, _ text: String?, _ sentAt: Int,
                 read: Bool = true, attachments: [StoredAttachment] = []) -> StoredMessage {
            StoredMessage(id: UUID().uuidString, threadID: thread, peer: peer.hex, direction: incoming ? "in" : "out",
                          text: text, attachments: attachments, sentAt: sentAt, expiresAt: month,
                          isRead: read || !incoming, viaLan: false)
        }
        func attachment(_ filename: String, _ mime: String, _ data: Data) -> [StoredAttachment] {
            [StoredAttachment(id: UUID().uuidString, filename: filename, mime: mime, size: data.count,
                              localPath: AttachmentStore.save(data, suggestedName: filename))]
        }
        func thread(_ peer: Person, _ messages: [StoredMessage]) -> StoredConversation {
            StoredConversation(threadID: Threading.pairwise(me.hex, peer.hex), peer: peer.hex, peerName: peer.name, messages: messages)
        }

        let mayaThread = Threading.pairwise(me.hex, maya.hex)
        let leoThread = Threading.pairwise(me.hex, leo.hex)
        let priyaThread = Threading.pairwise(me.hex, priya.hex)
        let jonasThread = Threading.pairwise(me.hex, jonas.hex)
        let conversations = [
            thread(maya, [
                msg(maya, mayaThread, incoming: true, s("maya1"), ago(46)),
                msg(maya, mayaThread, incoming: false, s("maya2"), ago(44)),
                msg(maya, mayaThread, incoming: true, s("maya3"), ago(41),
                    attachments: attachment("trailhead.png", "image/png", scene(warm: false))),
                msg(maya, mayaThread, incoming: false, s("maya4"), ago(39)),
                msg(maya, mayaThread, incoming: true, s("maya5"), ago(37), read: false),
            ]),
            thread(leo, [
                msg(leo, leoThread, incoming: true, s("leo1"), ago(190),
                    attachments: attachment("contract-draft.pdf", "application/pdf", pdf())),
                msg(leo, leoThread, incoming: false, s("leo2"), ago(180)),
            ]),
            thread(priya, [
                msg(priya, priyaThread, incoming: false, nil, ago(26 * 60),
                    attachments: attachment("sunset.png", "image/png", scene(warm: true))),
                msg(priya, priyaThread, incoming: true, s("priya1"), ago(26 * 60 - 4)),
            ]),
            thread(jonas, [
                msg(jonas, jonasThread, incoming: true, s("jonas1"), ago(2 * 24 * 60)),
                msg(jonas, jonasThread, incoming: false, s("jonas2"), ago(2 * 24 * 60 - 3),
                    attachments: attachment("notes.txt", "text/plain", Data(s("jonas2").utf8))),
            ]),
        ]

        let members = [
            GroupMember(fingerprint: me.fingerprint, armoredPublicKey: me.armored, name: me.name, isAdmin: true),
            GroupMember(fingerprint: maya.fingerprint, armoredPublicKey: maya.armored, name: maya.name, isAdmin: false),
            GroupMember(fingerprint: leo.fingerprint, armoredPublicKey: leo.armored, name: leo.name, isAdmin: false),
            GroupMember(fingerprint: priya.fingerprint, armoredPublicKey: priya.armored, name: priya.name, isAdmin: false),
        ]
        let group = ChatGroup(groupID: groupID, name: s("group"), members: members, epoch: 1, createdAt: ago(3 * 24 * 60))
        let groupMessages = [
            msg(leo, groupID, incoming: true, s("group1"), ago(24)),
            msg(priya, groupID, incoming: true, s("group2"), ago(21)),
            msg(me, groupID, incoming: false, s("group3"), ago(18)),
            msg(maya, groupID, incoming: true, s("group4"), ago(12), read: false),
        ]
        let snapshot = Snapshot(conversations: conversations, seen: [], groups: [group],
                                groupThreads: [StoredGroupThread(groupID: groupID, messages: groupMessages)])
        try JSONEncoder().encode(snapshot).write(to: dir.appendingPathComponent("carrierpony-conversations-\(me.hex).json"))

        let defaults = UserDefaults.standard
        defaults.set(lang, forKey: "cp.lang")
        defaults.set(true, forKey: "cp.onboarded")
        defaults.set(false, forKey: "cp.appLock.enabled")
        defaults.set(me.name, forKey: "cp.profile.\(me.hex)")
        defaults.set(maya.hex, forKey: chatKey)
        IdentityStore().setSelected(me.hex)
    }

    /// A simple generated landscape (no stock photos): sky, sun, hills.
    private static func scene(warm: Bool) -> Data {
        let size = CGSize(width: 1200, height: 900)
        // Scale 1: the default (screen scale, 3x) makes a 3600x2700 PNG.
        let format = UIGraphicsImageRendererFormat()
        format.scale = 1
        let image = UIGraphicsImageRenderer(size: size, format: format).image { ctx in
            let c = ctx.cgContext
            let colors = warm
                ? [UIColor(red: 0.96, green: 0.70, blue: 0.42, alpha: 1).cgColor, UIColor(red: 0.88, green: 0.42, blue: 0.46, alpha: 1).cgColor]
                : [UIColor(red: 0.56, green: 0.77, blue: 0.99, alpha: 1).cgColor, UIColor(red: 0.88, green: 0.95, blue: 1.0, alpha: 1).cgColor]
            if let gradient = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: colors as CFArray, locations: [0, 1]) {
                c.drawLinearGradient(gradient, start: .zero, end: CGPoint(x: 0, y: size.height), options: [])
            }
            (warm ? UIColor(red: 1, green: 0.88, blue: 0.54, alpha: 1) : UIColor(red: 1, green: 0.97, blue: 0.84, alpha: 1)).setFill()
            let sun = warm ? CGPoint(x: 820, y: 520) : CGPoint(x: 300, y: 220)
            c.fillEllipse(in: CGRect(x: sun.x - 90, y: sun.y - 90, width: 180, height: 180))
            func hill(_ color: UIColor, _ peaks: [CGPoint]) {
                let p = UIBezierPath()
                p.move(to: CGPoint(x: 0, y: size.height))
                peaks.forEach { p.addLine(to: $0) }
                p.addLine(to: CGPoint(x: size.width, y: size.height))
                p.close()
                color.setFill()
                p.fill()
            }
            if warm {
                hill(UIColor(red: 0.61, green: 0.31, blue: 0.42, alpha: 1), [CGPoint(x: 0, y: 640), CGPoint(x: 260, y: 520), CGPoint(x: 520, y: 610), CGPoint(x: 800, y: 500), CGPoint(x: 1200, y: 620)])
                hill(UIColor(red: 0.37, green: 0.21, blue: 0.33, alpha: 1), [CGPoint(x: 0, y: 760), CGPoint(x: 340, y: 680), CGPoint(x: 700, y: 760), CGPoint(x: 1000, y: 690), CGPoint(x: 1200, y: 740)])
            } else {
                hill(UIColor(red: 0.50, green: 0.65, blue: 0.79, alpha: 1), [CGPoint(x: 0, y: 560), CGPoint(x: 300, y: 330), CGPoint(x: 520, y: 480), CGPoint(x: 760, y: 280), CGPoint(x: 1200, y: 520)])
                hill(UIColor(red: 0.25, green: 0.43, blue: 0.35, alpha: 1), [CGPoint(x: 0, y: 760), CGPoint(x: 280, y: 600), CGPoint(x: 600, y: 720), CGPoint(x: 900, y: 590), CGPoint(x: 1200, y: 700)])
            }
        }
        return image.pngData() ?? Data()
    }

    /// A one-page PDF padded with PDF comment lines to a believable size.
    private static func pdf() -> Data {
        var body = "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
            "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" +
            "3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
        let filler = "% " + String(repeating: "0", count: 77) + "\n"
        while body.utf8.count < 238_000 { body += filler }
        body += "trailer<</Root 1 0 R>>\n%%EOF\n"
        return Data(body.utf8)
    }
}
#endif
