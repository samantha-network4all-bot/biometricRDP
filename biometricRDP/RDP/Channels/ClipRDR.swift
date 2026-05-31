import Foundation

/// Clipboard virtual channel protocol (MS-RDPECLIP).
/// Message types: CB_MONITOR_READY(1), CB_FORMAT_LIST(2), CB_FORMAT_LIST_RESPONSE(3),
/// CB_FORMAT_DATA_REQUEST(4), CB_FORMAT_DATA_RESPONSE(5), CB_TEMP_DIRECTORY(6), CB_CLIP_CAPS(7)
enum ClipRDR {
    // Message types
    static let CB_MSG_TYPE_MONITOR_READY: UInt16 = 0x0001
    static let CB_MSG_TYPE_FORMAT_LIST: UInt16 = 0x0002
    static let CB_MSG_TYPE_FORMAT_LIST_RESPONSE: UInt16 = 0x0003
    static let CB_MSG_TYPE_FORMAT_DATA_REQUEST: UInt16 = 0x0004
    static let CB_MSG_TYPE_FORMAT_DATA_RESPONSE: UInt16 = 0x0005

    // Clipboard format IDs
    static let CF_UNICODETEXT: UInt32 = 13
    static let CF_TEXT: UInt32 = 1

    /// Build CB_MONITOR_READY message.
    static func buildMonitorReady() -> Data {
        return buildClipMessage(msgType: CB_MSG_TYPE_MONITOR_READY, msgLen: 0, payload: Data())
    }

    /// Build CB_FORMAT_LIST message announcing CF_UNICODETEXT support.
    static func buildFormatList() -> Data {
        var payload = Data()
        // Format ID (4 bytes, little-endian) + format name (null-terminated UTF-16LE, min 2 null bytes)
        payload.append(contentsOf: withUnsafeBytes(of: CF_UNICODETEXT.littleEndian) { Array($0) })
        payload.append(contentsOf: [0x00, 0x00]) // empty format name = two null UTF-16LE code units
        return buildClipMessage(msgType: CB_MSG_TYPE_FORMAT_LIST, msgLen: UInt32(payload.count), payload: payload)
    }

    /// Build CB_FORMAT_LIST_RESPONSE (msgFlags = 0 = success).
    static func buildFormatListResponse() -> Data {
        return buildClipMessage(msgType: CB_MSG_TYPE_FORMAT_LIST_RESPONSE, msgLen: 4,
                                payload: Data([0x01, 0x00, 0x00, 0x00])) // responseOk = 1
    }

    /// Build CB_FORMAT_DATA_REQUEST for CF_UNICODETEXT.
    static func buildFormatDataRequest() -> Data {
        var payload = Data()
        payload.append(contentsOf: withUnsafeBytes(of: CF_UNICODETEXT.littleEndian) { Array($0) })
        return buildClipMessage(msgType: CB_MSG_TYPE_FORMAT_DATA_REQUEST, msgLen: 4, payload: payload)
    }

    /// Build CB_FORMAT_DATA_RESPONSE with UTF-16LE text payload.
    static func buildFormatDataResponse(text: String) -> Data {
        var payload = Data()
        let utf16units = Array(text.utf16)
        for unit in utf16units {
            payload.append(contentsOf: withUnsafeBytes(of: unit.littleEndian) { Array($0) })
        }
        payload.append(0x00); payload.append(0x00) // null terminator
        return buildClipMessage(msgType: CB_MSG_TYPE_FORMAT_DATA_RESPONSE, msgLen: UInt32(payload.count), payload: payload)
    }

    /// Parse a cliprdr message. Returns (msgType, msgLen, msgFlags, payload).
    static func parseClipMessage(_ data: Data) -> (msgType: UInt16, msgLen: UInt32, msgFlags: UInt16, payload: Data)? {
        guard data.count >= 8 else { return nil }
        let msgType = UInt16(data[0]) | (UInt16(data[1]) << 8)
        let msgFlags = UInt16(data[2]) | (UInt16(data[3]) << 8)
        let msgLen = UInt32(data[4]) | (UInt32(data[5]) << 8) | (UInt32(data[6]) << 16) | (UInt32(data[7]) << 24)
        guard Int(msgLen) + 8 <= data.count else { return nil }
        let payload = data.subdata(in: 8..<(8 + Int(msgLen)))
        return (msgType, msgLen, msgFlags, payload)
    }

    /// Parse CB_FORMAT_LIST payload → [(formatID, formatName)].
    static func parseFormatList(_ payload: Data) -> [(formatID: UInt32, formatName: String)] {
        var result: [(UInt32, String)] = []
        var off = 0
        while off + 4 <= payload.count {
            let fmtID = UInt32(payload[off]) | (UInt32(payload[off+1]) << 8) |
                        (UInt32(payload[off+2]) << 16) | (UInt32(payload[off+3]) << 24)
            off += 4
            // Read null-terminated UTF-16LE string
            var nameEnd = off
            while nameEnd + 1 < payload.count {
                if payload[nameEnd] == 0 && payload[nameEnd + 1] == 0 { break }
                nameEnd += 2
            }
            let nameData = payload.subdata(in: off..<nameEnd)
            let name = String(data: nameData, encoding: .utf16LittleEndian) ?? ""
            result.append((fmtID, name))
            off = nameEnd + 2 // skip null terminator
        }
        return result
    }

    /// Parse CB_FORMAT_DATA_RESPONSE payload → String.
    static func parseFormatDataResponse(_ payload: Data) -> String? {
        // Find null terminator in UTF-16LE
        var end = payload.count
        for stride in stride(from: 0, to: payload.count - 1, by: 2) {
            if payload[stride] == 0 && payload[stride + 1] == 0 {
                end = stride
                break
            }
        }
        let textData = payload.subdata(in: 0..<end)
        return String(data: textData, encoding: .utf16LittleEndian)
    }

    /// Parse CB_FORMAT_DATA_REQUEST payload → formatID.
    static func parseFormatDataRequest(_ payload: Data) -> UInt32? {
        guard payload.count >= 4 else { return nil }
        return UInt32(payload[0]) | (UInt32(payload[1]) << 8) |
               (UInt32(payload[2]) << 16) | (UInt32(payload[3]) << 24)
    }

    /// Build a cliprdr message header + payload.
    private static func buildClipMessage(msgType: UInt16, msgLen: UInt32, payload: Data) -> Data {
        var msg = Data()
        msg.append(contentsOf: withUnsafeBytes(of: msgType.littleEndian) { Array($0) })
        msg.append(contentsOf: withUnsafeBytes(of: UInt16(0).littleEndian) { Array($0) }) // msgFlags = 0
        msg.append(contentsOf: withUnsafeBytes(of: msgLen.littleEndian) { Array($0) })
        msg.append(payload)
        return msg
    }
}
