import Foundation

/// Device Redirection Virtual Channel (rdpdr) message types and serialization.
/// Protocol reference: MS-RDPDR
enum RDPDR {
    // Component types
    static let RDPDR_CTYP_CORE: UInt16 = 0x4472
    static let RDPDR_CTYP_PRN:  UInt16 = 0x5052

    // Core packet IDs
    static let PAKID_CORE_CLIENTID_CONFIRM: UInt16 = 0x4343
    static let PAKID_CORE_SERVER_ANNOUNCE:  UInt16 = 0x496E
    static let PAKID_CORE_CLIENT_NAME:      UInt16 = 0x434E
    static let PAKID_CORE_DEVICELIST_ANNOUNCE: UInt16 = 0x4441
    static let PAKID_CORE_DEVICELIST_REPLY:    UInt16 = 0x4452
    static let PAKID_CORE_DEVICE_IOCOMPLETION: UInt16 = 0x4943
    static let PAKID_CORE_SERVER_CAPABILITY:   UInt16 = 0x5350
    static let PAKID_CORE_CLIENT_CAPABILITY:   UInt16 = 0x4350

    // Device types
    static let RDPDR_DTYP_FILESYSTEM: UInt32 = 0x00000004
    static let RDPDR_DTYP_PRINT: UInt32 = 0x00000002

    // Build a Server Announce PDU.
    static func buildServerAnnounce(versionMajor: UInt16 = 1, versionMinor: UInt16 = 13, clientID: UInt32 = 1) -> Data {
        var body = Data()
        body.append(contentsOf: withUnsafeBytes(of: RDPDR_CTYP_CORE.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: PAKID_CORE_SERVER_ANNOUNCE.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: versionMajor.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: versionMinor.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: clientID.littleEndian) { Array($0) })
        return body
    }

    /// Build a Client ID Confirm PDU.
    static func buildClientIDConfirm(clientID: UInt32 = 1) -> Data {
        var body = Data()
        body.append(contentsOf: withUnsafeBytes(of: RDPDR_CTYP_CORE.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: PAKID_CORE_CLIENTID_CONFIRM.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: UInt16(1).littleEndian) { Array($0) }) // versionMajor
        body.append(contentsOf: withUnsafeBytes(of: UInt16(13).littleEndian) { Array($0) }) // versionMinor
        body.append(contentsOf: withUnsafeBytes(of: clientID.littleEndian) { Array($0) }) // clientID
        return body
    }

    /// Build a Server Capability PDU.
    static func buildServerCapability() -> Data {
        var body = Data()
        body.append(contentsOf: withUnsafeBytes(of: RDPDR_CTYP_CORE.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: PAKID_CORE_SERVER_CAPABILITY.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: UInt16(5).littleEndian) { Array($0) }) // numCapabilities
        body.append(contentsOf: [0x00, 0x00]) // pad
        // General capability (type=1, len=44, version=1)
        body.append(contentsOf: withUnsafeBytes(of: UInt16(1).littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: UInt16(44).littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: UInt32(1).littleEndian) { Array($0) })
        body.append(contentsOf: [UInt8](repeating: 0, count: 36))
        // 4 more empty capabilities (type=2,3,4,5)
        for _ in 2...5 {
            body.append(contentsOf: withUnsafeBytes(of: UInt16(0).littleEndian) { Array($0) })
            body.append(contentsOf: withUnsafeBytes(of: UInt16(4).littleEndian) { Array($0) })
            body.append(contentsOf: withUnsafeBytes(of: UInt32(0).littleEndian) { Array($0) })
        }
        return body
    }

    /// Build a Client Name PDU.
    static func buildClientName(clientName: String = "biometricRDP") -> Data {
        var body = Data()
        body.append(contentsOf: withUnsafeBytes(of: RDPDR_CTYP_CORE.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: PAKID_CORE_CLIENT_NAME.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: UInt32(1).littleEndian) { Array($0) }) // unicodeFlag
        body.append(contentsOf: withUnsafeBytes(of: UInt32(0).littleEndian) { Array($0) }) // codePage
        let nameData = clientName.data(using: .utf16LittleEndian) ?? Data()
        body.append(contentsOf: withUnsafeBytes(of: UInt32(nameData.count + 2).littleEndian) { Array($0) }) // nameLen including null
        body.append(nameData)
        body.append(0x00); body.append(0x00) // null terminator
        return body
    }

    /// Build a Client Capability PDU.
    static func buildClientCapability() -> Data {
        var body = Data()
        body.append(contentsOf: withUnsafeBytes(of: RDPDR_CTYP_CORE.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: PAKID_CORE_CLIENT_CAPABILITY.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: UInt16(5).littleEndian) { Array($0) }) // numCapabilities
        body.append(contentsOf: [0x00, 0x00]) // pad
        // General capability (type=1, len=44, version=1)
        body.append(contentsOf: withUnsafeBytes(of: UInt16(1).littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: UInt16(44).littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: UInt32(1).littleEndian) { Array($0) })
        body.append(contentsOf: [UInt8](repeating: 0, count: 36))
        // 4 more empty capabilities (type=2,3,4,5)
        for _ in 2...5 {
            body.append(contentsOf: withUnsafeBytes(of: UInt16(0).littleEndian) { Array($0) })
            body.append(contentsOf: withUnsafeBytes(of: UInt16(4).littleEndian) { Array($0) })
            body.append(contentsOf: withUnsafeBytes(of: UInt32(0).littleEndian) { Array($0) })
        }
        return body
    }

    /// Build a Device List Announce PDU for a drive.
    static func buildDeviceListAnnounce(deviceID: UInt32, deviceName: String, localPath: String) -> Data {
        var body = Data()
        body.append(contentsOf: withUnsafeBytes(of: RDPDR_CTYP_CORE.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: PAKID_CORE_DEVICELIST_ANNOUNCE.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: UInt32(1).littleEndian) { Array($0) }) // deviceCount
        // Device announcement: deviceType(4) + deviceID(4) + preferredDosName(8) + deviceDataLen(4) + deviceData
        body.append(contentsOf: withUnsafeBytes(of: RDPDR_DTYP_FILESYSTEM.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: deviceID.littleEndian) { Array($0) })
        // preferredDosName: 8 bytes, ASCII padded
        var dosName = Data(repeating: 0, count: 8)
        let nameBytes = Array(deviceName.utf8.prefix(8))
        for (i, b) in nameBytes.enumerated() { dosName[i] = b }
        body.append(dosName)
        // deviceData: the local path as UTF-8
        let pathData = localPath.data(using: .utf8) ?? Data()
        body.append(contentsOf: withUnsafeBytes(of: UInt32(pathData.count).littleEndian) { Array($0) })
        body.append(pathData)
        return body
    }

    /// Build a Device List Announce PDU for a printer.
    static func buildPrinterDeviceListAnnounce(deviceID: UInt32, deviceName: String) -> Data {
        var body = Data()
        body.append(contentsOf: withUnsafeBytes(of: RDPDR_CTYP_CORE.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: PAKID_CORE_DEVICELIST_ANNOUNCE.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: UInt32(1).littleEndian) { Array($0) }) // deviceCount
        body.append(contentsOf: withUnsafeBytes(of: RDPDR_DTYP_PRINT.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: deviceID.littleEndian) { Array($0) })
        // preferredDosName: 8 bytes, ASCII padded
        var dosName = Data(repeating: 0, count: 8)
        let nameBytes = Array(deviceName.utf8.prefix(8))
        for (i, b) in nameBytes.enumerated() { dosName[i] = b }
        body.append(dosName)
        // deviceData: the printer name as UTF-8
        let nameData = deviceName.data(using: .utf8) ?? Data()
        body.append(contentsOf: withUnsafeBytes(of: UInt32(nameData.count).littleEndian) { Array($0) })
        body.append(nameData)
        return body
    }

    /// Build a Device List Reply PDU (acknowledges the client's device list).
    static func buildDeviceListReply(deviceID: UInt32, status: UInt32 = 0) -> Data {
        var body = Data()
        body.append(contentsOf: withUnsafeBytes(of: RDPDR_CTYP_CORE.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: PAKID_CORE_DEVICELIST_REPLY.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: deviceID.littleEndian) { Array($0) })
        body.append(contentsOf: withUnsafeBytes(of: status.littleEndian) { Array($0) })
        return body
    }

    /// Parse an RDPDR message header. Returns (component, packetID, payload) or nil.
    static func parseHeader(_ data: Data) -> (component: UInt16, packetID: UInt16, payload: Data)? {
        guard data.count >= 4 else { return nil }
        let component = UInt16(data[0]) | (UInt16(data[1]) << 8)
        let packetID  = UInt16(data[2]) | (UInt16(data[3]) << 8)
        let payload = data.subdata(in: 4..<data.count)
        return (component, packetID, payload)
    }
}
