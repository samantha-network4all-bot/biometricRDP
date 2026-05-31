import Foundation

enum FastPath {
    /// Build a fast-path mouse input event (TS_FP_INPUT_PDU).
    /// Format: action(1) + length(1 or 2) + eventsData
    /// Each event: eventCode(1) + ...
    static func buildMouseEvent(destX: Int, destY: Int, flags: UInt16) -> Data {
        // TS_FP_POINTER_EVENT: eventCode(1) + pointerFlags(2) + xPos(2) + yPos(2) = 7 bytes
        let eventCode: UInt8 = 0x01 // TS_FP_POINTER_EVENT
        var eventData = Data()
        eventData.append(eventCode)
        eventData.append(contentsOf: withUnsafeBytes(of: flags.littleEndian) { Array($0) })
        eventData.append(contentsOf: withUnsafeBytes(of: UInt16(destX).littleEndian) { Array($0) })
        eventData.append(contentsOf: withUnsafeBytes(of: UInt16(destY).littleEndian) { Array($0) })
        return wrapFastPathInput(events: [eventData])
    }

    /// Build a fast-path keyboard input event (TS_FP_INPUT_PDU with TS_FP_KBD_EVENT).
    static func buildKeyboardEvent(scancode: UInt16, down: Bool) -> Data {
        // TS_FP_KBD_EVENT: eventCode(1) + keyboardFlags(1) + keyCode(2) + pad(1) = 5 bytes
        let eventCode: UInt8 = 0x02 // TS_FP_KBD_EVENT
        let kbdFlags: UInt8 = down ? 0x00 : 0x01 // 0x01 = release
        var eventData = Data()
        eventData.append(eventCode)
        eventData.append(kbdFlags)
        eventData.append(contentsOf: withUnsafeBytes(of: scancode.littleEndian) { Array($0) })
        eventData.append(0x00) // padding
        return wrapFastPathInput(events: [eventData])
    }

    /// Build a fast-path unicode keyboard event.
    static func buildUnicodeEvent(unicodeCode: UInt16, down: Bool) -> Data {
        // TS_FP_UNICODE_KBD_EVENT: eventCode(1) + keyboardFlags(1) + unicodeCode(2) + pad(1) = 5 bytes
        let eventCode: UInt8 = 0x03 // TS_FP_UNICODE_KBD_EVENT
        let kbdFlags: UInt8 = down ? 0x00 : 0x01
        var eventData = Data()
        eventData.append(eventCode)
        eventData.append(kbdFlags)
        eventData.append(contentsOf: withUnsafeBytes(of: unicodeCode.littleEndian) { Array($0) })
        eventData.append(0x00)
        return wrapFastPathInput(events: [eventData])
    }

    /// Wrap one or more fast-path input events in TS_FP_INPUT_PDU → TPKT.
    /// TS_FP_INPUT_PDU: action(1) + numberEvents(1) + length(1 or 2) + eventsData
    static func wrapFastPathInput(events: [Data]) -> Data {
        let action: UInt8 = 0x01 // FASTPATH_INPUT_ACTION_FASTPATH
        let numEvents = UInt8(events.count)
        var eventsData = Data()
        for e in events { eventsData.append(e) }
        let totalLen = 1 + 1 + eventsData.count // action + numEvents(1) + events
        var fpInput = Data()
        fpInput.append(action)
        fpInput.append(numEvents)
        if totalLen + 2 < 128 {
            // Single-byte length: length fits in 7 bits, no lengthEncoding flag
            fpInput.append(UInt8(totalLen + 1)) // +1 for the length byte itself
        } else {
            // Two-byte length: set bit 7 of first length byte
            let lenBytes = 1 + 2 + eventsData.count // action + numEvents + 2-byte len + events
            fpInput.append(UInt8(0x80 | ((lenBytes >> 8) & 0x7F)))
            fpInput.append(UInt8(lenBytes & 0xFF))
        }
        fpInput.append(eventsData)
        // Wrap in TPKT (no X.224 — fast-path skips X.224, TPKT payload IS the fast-path data)
        let tpktLen = 4 + fpInput.count
        var tpkt = Data([0x03, 0x00, UInt8((tpktLen >> 8) & 0xFF), UInt8(tpktLen & 0xFF)])
        tpkt.append(fpInput)
        return tpkt
    }
}
