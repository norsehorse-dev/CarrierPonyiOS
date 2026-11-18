import Foundation

enum CPN1Error: Error {
    case badMagic
    case truncated
}

enum CPN1 {
    static let magic = Array("CPN1".utf8)

    static func encode(manifest: Data, parts: [Data]) -> Data {
        var out = Data()
        out.append(contentsOf: magic)
        out.append(beUInt32(UInt32(manifest.count)))
        out.append(manifest)
        for part in parts {
            out.append(beUInt64(UInt64(part.count)))
            out.append(part)
        }
        return out
    }

    static func decode(_ blob: Data) throws -> (manifest: Data, parts: [Data]) {
        let bytes = [UInt8](blob)
        guard bytes.count >= 8 else { throw CPN1Error.truncated }
        guard Array(bytes[0..<4]) == magic else { throw CPN1Error.badMagic }

        let manifestLen = Int(readUInt32(bytes, 4))
        var offset = 8
        guard offset + manifestLen <= bytes.count else { throw CPN1Error.truncated }
        let manifest = Data(bytes[offset ..< offset + manifestLen])
        offset += manifestLen

        var parts: [Data] = []
        while offset < bytes.count {
            guard offset + 8 <= bytes.count else { throw CPN1Error.truncated }
            let partLen = Int(readUInt64(bytes, offset))
            offset += 8
            guard offset + partLen <= bytes.count else { throw CPN1Error.truncated }
            parts.append(Data(bytes[offset ..< offset + partLen]))
            offset += partLen
        }
        return (manifest, parts)
    }

    private static func beUInt32(_ value: UInt32) -> Data {
        var data = Data(count: 4)
        data[0] = UInt8((value >> 24) & 0xFF)
        data[1] = UInt8((value >> 16) & 0xFF)
        data[2] = UInt8((value >> 8) & 0xFF)
        data[3] = UInt8(value & 0xFF)
        return data
    }

    private static func beUInt64(_ value: UInt64) -> Data {
        var data = Data(count: 8)
        for i in 0..<8 {
            data[i] = UInt8((value >> (56 - 8 * i)) & 0xFF)
        }
        return data
    }

    private static func readUInt32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        return (UInt32(bytes[offset]) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
    }

    private static func readUInt64(_ bytes: [UInt8], _ offset: Int) -> UInt64 {
        var value: UInt64 = 0
        for i in 0..<8 {
            value = (value << 8) | UInt64(bytes[offset + i])
        }
        return value
    }
}
