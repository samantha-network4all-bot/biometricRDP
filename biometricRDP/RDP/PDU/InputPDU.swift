import Foundation

enum InputPDU {
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
