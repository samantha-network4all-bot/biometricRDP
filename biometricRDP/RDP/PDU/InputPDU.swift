import Foundation

enum InputPDU {
    static let PTRFLAGS_DOWN: UInt16    = 0x8000
    static let PTRFLAGS_BUTTON1: UInt16 = 0x1000
    static let PTRFLAGS_BUTTON2: UInt16 = 0x2000
    static let PTRFLAGS_BUTTON3: UInt16 = 0x4000
    static let PTRFLAGS_MOVE: UInt16    = 0x0800
    static let PTRFLAGS_WHEEL: UInt16   = 0x0200

    /// Keyboard flag constants
    static let KBDFLAGS_EXTENDED: UInt16 = 0x0100
    static let KBDFLAGS_DOWN: UInt16     = 0x4000  //实际上 RDP "key up" = 0x8000, "key down" has no flag
    /// Build a slow-path keyboard input event TS_INPUT_PDU containing a single key event.
    static func buildKeyboardEvent(keyCode: UInt16, down: Bool) -> Data {
        let messageType: UInt16 = 0x0001 // INPUT_EVENT_KEYBOARD
        var event = Data()
        event.append(contentsOf: withUnsafeBytes(of: UInt32(0).littleEndian) { Array($0) }) // eventTime
        event.append(contentsOf: withUnsafeBytes(of: messageType.littleEndian) { Array($0) })
        // TS_KEYBOARD_EVENT: keyboardFlags(2) + pad(2) + keyCode(2) + flags(2)
        // RDP convention: key-up = 0x8000, key-down = 0x0000
        let flags: UInt16 = down ? 0x0000 : 0x8000
        event.append(contentsOf: withUnsafeBytes(of: flags.littleEndian) { Array($0) })
        event.append(contentsOf: [0x00, 0x00]) // padding
        event.append(contentsOf: withUnsafeBytes(of: keyCode.littleEndian) { Array($0) })
        event.append(contentsOf: [0x00, 0x00]) // flags2

        // Wrap in TS_INPUT_PDU_DATA
        var pduData = Data()
        pduData.append(contentsOf: withUnsafeBytes(of: UInt16(1).littleEndian) { Array($0) })
        pduData.append(contentsOf: [0x00, 0x00])
        pduData.append(event)

        // Wrap in Share Data Header
        let pduType2: UInt16 = 0x001C
        let pduSource: UInt16 = 0x03E9
        let totalLen = 6 + pduData.count
        var shareData = Data()
        shareData.append(contentsOf: withUnsafeBytes(of: UInt16(totalLen).littleEndian) { Array($0) })
        shareData.append(contentsOf: withUnsafeBytes(of: pduType2.littleEndian) { Array($0) })
        shareData.append(contentsOf: withUnsafeBytes(of: pduSource.littleEndian) { Array($0) })
        shareData.append(pduData)

        return wrapTPKT(payload: shareData)
    }

    /// Build a unicode type event: sends a key-down + key-up pair for a unicode code point.
    /// Uses INPUT_EVENT_UNICODE (messageType 0x0002) which carries the raw unicode code point.
    static func buildUnicodeEvent(unicodeCode: UInt16) -> Data {
        // We send a key-down (flags=0x0000) then key-up (flags=0x8000) unicode event
        var eventsData = Data()
        for flagsVal in [UInt16(0x0000), UInt16(0x8000)] {
            let messageType: UInt16 = 0x0002 // INPUT_EVENT_UNICODE
            var event = Data()
            event.append(contentsOf: withUnsafeBytes(of: UInt32(0).littleEndian) { Array($0) })
            event.append(contentsOf: withUnsafeBytes(of: messageType.littleEndian) { Array($0) })
            // TS_UNICODE_KEYBOARD_EVENT: unicodeCode(2) + keyboardFlags(2)
            event.append(contentsOf: withUnsafeBytes(of: unicodeCode.littleEndian) { Array($0) })
            event.append(contentsOf: withUnsafeBytes(of: flagsVal.littleEndian) { Array($0) })
            eventsData.append(event)
        }

        var pduData = Data()
        pduData.append(contentsOf: withUnsafeBytes(of: UInt16(2).littleEndian) { Array($0) }) // 2 events
        pduData.append(contentsOf: [0x00, 0x00])
        pduData.append(eventsData)

        let pduType2: UInt16 = 0x001C
        let pduSource: UInt16 = 0x03E9
        let totalLen = 6 + pduData.count
        var shareData = Data()
        shareData.append(contentsOf: withUnsafeBytes(of: UInt16(totalLen).littleEndian) { Array($0) })
        shareData.append(contentsOf: withUnsafeBytes(of: pduType2.littleEndian) { Array($0) })
        shareData.append(contentsOf: withUnsafeBytes(of: pduSource.littleEndian) { Array($0) })
        shareData.append(pduData)

        return wrapTPKT(payload: shareData)
    }

    /// Build a slow-path input event TS_INPUT_PDU containing a single mouse event.
    static func buildMouseEvent(destX: Int, destY: Int, flags: UInt16) -> Data {
        // TS_INPUT_EVENT: eventTime(4) + messageType(2) + slowPathInputData
        let messageType: UInt16 = 0x8001 // INPUT_EVENT_MOUSE
        var event = Data()
        event.append(contentsOf: withUnsafeBytes(of: UInt32(0).littleEndian) { Array($0) }) // eventTime
        event.append(contentsOf: withUnsafeBytes(of: messageType.littleEndian) { Array($0) })
        // TS_POINTER_EVENT: pointerFlags(2) + xPos(2) + yPos(2)
        event.append(contentsOf: withUnsafeBytes(of: flags.littleEndian) { Array($0) })
        event.append(contentsOf: withUnsafeBytes(of: UInt16(destX).littleEndian) { Array($0) })
        event.append(contentsOf: withUnsafeBytes(of: UInt16(destY).littleEndian) { Array($0) })

        // Wrap in TS_INPUT_PDU_DATA: numberEvents(1) + pad(1) + slowPathInputData
        var pduData = Data()
        pduData.append(contentsOf: withUnsafeBytes(of: UInt16(1).littleEndian) { Array($0) }) // numberEvents = 1
        pduData.append(contentsOf: [0x00, 0x00]) // padding
        pduData.append(event)

        // Wrap in Share Data Header
        let pduType2: UInt16 = 0x001C // PDUTYPE2_INPUT (14)
        let pduSource: UInt16 = 0x03E9
        let totalLen = 6 + pduData.count
        var shareData = Data()
        shareData.append(contentsOf: withUnsafeBytes(of: UInt16(totalLen).littleEndian) { Array($0) })
        shareData.append(contentsOf: withUnsafeBytes(of: pduType2.littleEndian) { Array($0) })
        shareData.append(contentsOf: withUnsafeBytes(of: pduSource.littleEndian) { Array($0) })
        shareData.append(pduData)

        return wrapTPKT(payload: shareData)
    }

    private static func wrapTPKT(payload: Data) -> Data {
        let x224PayloadLen = 2 + payload.count
        var x224Hdr = Data()
        if x224PayloadLen < 128 {
            x224Hdr.append(UInt8(x224PayloadLen))
        } else {
            x224Hdr.append(0x82)
            x224Hdr.append(UInt8(x224PayloadLen & 0xFF))
            x224Hdr.append(UInt8((x224PayloadLen >> 8) & 0xFF))
        }
        x224Hdr.append(0xF0)
        x224Hdr.append(0x80)
        let tpktLen = 4 + x224Hdr.count + payload.count
        var pkt = Data([0x03, 0x00, UInt8((tpktLen >> 8) & 0xFF), UInt8(tpktLen & 0xFF)])
        pkt.append(x224Hdr)
        pkt.append(payload)
        return pkt
    }
}
