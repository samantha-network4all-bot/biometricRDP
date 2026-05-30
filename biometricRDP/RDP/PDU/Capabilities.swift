import Foundation

/// RDP Capability exchange: Confirm Active + Synchronise + Control + Font List.
/// Then read back server Demand Active.
enum Capabilities {

    private static let pduTypeConfirmActive: UInt8 = 0x03
    private static let pduTypeSync: UInt8 = 0x1F
    private static let pduTypeControl: UInt8 = 0x14
    private static let pduTypeFontList: UInt8 = 0x27

    /// Build Confirm Active PDU.
    static func buildConfirmActivePDU(width: Int, height: Int, bpp: Int, channelID: UInt16 = 0x03E9) -> Data {
        let shareID: UInt32 = 0
        let capsData = buildCapabilitySets(width: width, height: height, bpp: bpp)

        var body = Data()
        body.append(contentsOf: withUnsafeBytes(of: shareID.littleEndian) { Array($0) })
        body.append(contentsOf: [0x03, 0xEA]) // originatorID = 1002
        body.append(contentsOf: [0x00, 0x04]) // lengthSourceDescriptor
        body.append(contentsOf: [0x00, 0x00]) // combinedCapLen (placeholder)
        body.append(contentsOf: [0x0A, 0x00]) // totalCapCount = 10
        body.append(contentsOf: Array("RDP ".utf8)) // source descriptor
        body.append(contentsOf: capsData)
        body.append(0x00) // pad

        // combinedCapLen = body - 8 bytes (after shareID/originatorID)
        let ccLen = body.count - 8
        body[10] = UInt8(ccLen & 0xFF)
        body[11] = UInt8((ccLen >> 8) & 0xFF)

        let shareCtrl = buildShareControl(pduType: UInt16(pduTypeConfirmActive), pduSource: channelID,
                                          bodyLen: body.count)
        return wrapInTPKT(content: shareCtrl + body)
    }

    /// Build Synchronise PDU.
    static func buildSynchronisePDU(channelID: UInt16 = 0x03E9) -> Data {
        let body = buildBody([0x00, 0x01, // targetUser
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) // flags
        let sc = buildShareControl(pduType: UInt16(pduTypeSync), pduSource: channelID, bodyLen: body.count)
        return wrapInTPKT(content: sc + body)
    }

    /// Build Control Cooperate PDU.
    static func buildControlCooperatePDU(channelID: UInt16 = 0x03E9) -> Data {
        let body = buildBody([0x00, 0x00, 0x00, 0x00])
        let sc = buildShareControl(pduType: UInt16(pduTypeControl), pduSource: channelID, bodyLen: body.count)
        return wrapInTPKT(content: sc + body)
    }

    /// Build Control Request PDU.
    static func buildControlRequestPDU(channelID: UInt16 = 0x03E9) -> Data {
        let body = buildBody([0x00, 0x01, 0x00, 0x00])
        let sc = buildShareControl(pduType: UInt16(pduTypeControl), pduSource: channelID, bodyLen: body.count)
        return wrapInTPKT(content: sc + body)
    }

    /// Build Font List PDU.
    static func buildFontListPDU(channelID: UInt16 = 0x03E9) -> Data {
        let body = buildBody([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        let sc = buildShareControl(pduType: UInt16(pduTypeFontList), pduSource: channelID, bodyLen: body.count)
        return wrapInTPKT(content: sc + body)
    }

    // MARK: - Private

    static func buildCapabilitySets(width: Int, height: Int, bpp: Int) -> Data {
        var result = Data()
        result.append(contentsOf: buildCapSet(capsTypeGeneralID, data: buildGeneralCaps()))
        result.append(contentsOf: buildCapSet(capsTypeBitmapID, data: buildBitmapCaps(width: width, height: height, bpp: bpp)))
        result.append(contentsOf: buildCapSet(capsTypeOrderID, data: buildOrderCaps()))
        result.append(contentsOf: buildCapSet(capsTypeBitmapCacheID, data: Data([UInt8](repeating: 0, count: 40))))
        result.append(contentsOf: buildCapSet(capsTypeControlID, data: buildControlCaps()))
        result.append(contentsOf: buildCapSet(capsTypeProtocolVersionID, data: Data([0x00, 0x02] + [UInt8](repeating: 0, count: 8))))
        result.append(contentsOf: buildCapSet(capsTypeMultifragUpdateID, data: Data([0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00])))
        result.append(contentsOf: buildCapSet(capsTypeLargePointerID, data: Data([0x01, 0x00] + [UInt8](repeating: 0, count: 8))))
        // Pad to make 10
        result.append(contentsOf: buildCapSet(capsTypeGeneralID, data: buildGeneralCaps()))
        result.append(contentsOf: buildCapSet(capsTypeBitmapID, data: buildBitmapCaps(width: width, height: height, bpp: bpp)))
        return result
    }

    private static let capsTypeGeneralID: UInt16 = 0x0001
    private static let capsTypeBitmapID: UInt16 = 0x0002
    private static let capsTypeOrderID: UInt16 = 0x0003
    private static let capsTypeBitmapCacheID: UInt16 = 0x0004
    private static let capsTypeControlID: UInt16 = 0x0005
    private static let capsTypeCapsProtocolVersionID: UInt16 = 0x0007
    private static let capsTypeMultifragUpdateID: UInt16 = 0x001B
    private static let capsTypeLargePointerID: UInt16 = 0x001C
    private static let capsTypeProtocolVersionID: UInt16 = 0x001A

    private static func buildCapSet(_ type: UInt16, data: Data) -> Data {
        var result = Data()
        result.append(contentsOf: withUnsafeBytes(of: type.littleEndian) { Array($0) })
        result.append(UInt8(data.count & 0xFF))
        result.append(UInt8((data.count >> 8) & 0xFF))
        result.append(contentsOf: data)
        return result
    }

    private static func buildGeneralCaps() -> Data {
        return Data([
            0x01, 0x00, 0x03, 0x00, // osMajor/Minor
            0x20, 0x00, 0x00, 0x00, // protocolVersion
            0x00, 0x00, 0x00, 0x00, // pad + compression
            0x00, 0x10, // extraFlags
            0x00, 0x00, 0x00, 0x00, // updateCapFlag / remoteUnshareFlag
            0x00, 0x00, // level
            0x00, 0x00  // refresh/suppress
        ])
    }

    private static func buildBitmapCaps(width: Int, height: Int, bpp: Int) -> Data {
        var d = Data()
        d.append(contentsOf: withUnsafeBytes(of: UInt16(bpp).littleEndian) { Array($0) })
        d.append(contentsOf: [0x01, 0x00, 0x01, 0x00, 0x01, 0x00]) // bit depth support
        d.append(contentsOf: withUnsafeBytes(of: UInt16(width).littleEndian) { Array($0) })
        d.append(contentsOf: withUnsafeBytes(of: UInt16(height).littleEndian) { Array($0) })
        d.append(contentsOf: [0x00, 0x00]) // pad
        d.append(contentsOf: [0x01, 0x00]) // drawingFlags
        d.append(contentsOf: [0x01, 0x00]) // multipleRect
        d.append(contentsOf: [0x00, 0x00]) // pad
        return d
    }

    private static func buildOrderCaps() -> Data {
        var d = [UInt8](repeating: 0, count: 32)
        d[0] = 0xFF; d[1] = 0xFF; d[2] = 0xFF; d[3] = 0xFF; d[4] = 0xFF
        return Data(d + [
            0x00, 0x40, 0x00, 0x00, // desktopSaveGranularity
            0x01, 0x00, // maxOrderLevel
            0x0A, 0x00, // numberFonts
            0x22, 0x00, // orderFlags
            0x00, 0x40, 0x00, 0x00, // desktopSaveSize
            0x00, 0x01, // pad
            0x00, 0x00  // textAnsiCodePage
        ])
    }

    private static func buildControlCaps() -> Data {
        return Data([0x00, 0x00, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00])
    }

    private static func buildShareControl(pduType: UInt16, pduSource: UInt16, bodyLen: Int) -> Data {
        let totalLen: Int = 6 + 4 + bodyLen
        var d = Data()
        d.append(UInt8(totalLen & 0xFF))
        d.append(UInt8((totalLen >> 8) & 0xFF))
        let encodedType: UInt8 = UInt8(min(pduType, 0x0F) | 0x10)
        d.append(encodedType)
        d.append(UInt8(pduSource & 0xFF))
        d.append(UInt8((pduSource >> 8) & 0xFF))
        d.append(0x01) // streamID
        let ulen = bodyLen + 12
        d.append(UInt8(ulen & 0xFF))
        d.append(UInt8((ulen >> 8) & 0xFF))
        d.append(UInt8(pduType & 0xFF))
        d.append(0x00)
        return d
    }

    private static func buildBody(_ bytes: [UInt8]) -> Data {
        return Data(bytes)
    }

    private static func wrapInTPKT(content: Data) -> Data {
        let x224Hdr: [UInt8] = [UInt8(2 + content.count), 0xF0, 0x80]
        let tpktLen = 4 + x224Hdr.count + content.count
        let tpkt: [UInt8] = [
            0x03, 0x00,
            UInt8((tpktLen >> 8) & 0xFF),
            UInt8(tpktLen & 0xFF)
        ]
        var packet = Data(tpkt)
        packet.append(contentsOf: x224Hdr)
        packet.append(content)
        return packet
    }

    private static let capsTypeBitmapCacheV2ID: UInt16 = 0x0013
}
