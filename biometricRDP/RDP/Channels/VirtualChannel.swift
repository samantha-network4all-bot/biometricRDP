import Foundation

/// Virtual channel PDU header (MS-RDPBCGR §2.2.6.1).
enum VirtualChannel {
    /// Parse a virtual channel PDU from raw TP_ data.
    /// Returns (channelID, data) or nil if incomplete/invalid.
    static func parseChannelPDU(_ data: Data) -> (channelID: UInt32, data: Data)? {
        guard data.count >= 4 else { return nil }
        var off = 0
        let length = readBE32(data, &off)
        let flags = readBE32(data, &off)
        guard off + Int(length) <= data.count else { return nil }
        let channelData = data.subdata(in: off..<(off + Int(length)))
        return (channelID: UInt32(flags), data: channelData)
    }

    /// Wrap data in a virtual channel PDU.
    static func buildChannelPDU(data: Data, flags: UInt32 = 0) -> Data {
        var pdu = Data()
        pdu.append(contentsOf: withUnsafeBytes(of: UInt32(data.count).bigEndian) { Array($0) })
        pdu.append(contentsOf: withUnsafeBytes(of: flags.bigEndian) { Array($0) })
        pdu.append(data)
        return pdu
    }

    private static func readBE32(_ data: Data, _ off: inout Int) -> UInt32 {
        guard off + 4 <= data.count else { return 0 }
        var bytes = [UInt8](repeating: 0, count: 4)
        for i in 0..<4 { bytes[i] = data[off + i] }
        off += 4
        return UInt32(bigEndian: bytes.withUnsafeBytes { $0.load(as: UInt32.self) })
    }
}
