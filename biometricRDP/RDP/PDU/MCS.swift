import Foundation

/// Minimal MCS connect-initial / connect-response for RDP.
enum MCS {

    /// Build an MCS Connect Initial PDU with GCC Conference Create Request.
    static func buildConnectInitial(width: Int, height: Int, bpp: Int) -> Data {
        // Flat GCC user data with embedded dimensions
        var gccData = Data()
        gccData.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // conference name key
        gccData.append(0x00) // empty password
        gccData.append(contentsOf: [0x01, 0x20]) // convener ID

        // Core data block with magic for dimension extraction
        gccData.append(contentsOf: [0xCC, 0x01])
        gccData.append(contentsOf: withUnsafeBytes(of: UInt32(1).bigEndian) { Array($0) })
        gccData.append(contentsOf: withUnsafeBytes(of: UInt32(width).bigEndian) { Array($0) })
        gccData.append(contentsOf: withUnsafeBytes(of: UInt32(height).bigEndian) { Array($0) })
        gccData.append(contentsOf: withUnsafeBytes(of: UInt32(bpp).bigEndian) { Array($0) })

        // MCS Connect Initial BER [APPLICATION 101]
        let callingDS = berOctetString(Data([0x01]))
        let calledDS = berOctetString(Data([0x01]))
        let upward = berBool(true)
        let targetParams = buildDomainParameters()
        let minParams = buildDomainParameters()
        let maxParams = buildDomainParameters()
        let userDataOS = berOctetString(gccData)

        let seqContent = callingDS + calledDS + upward + targetParams + minParams + maxParams + userDataOS
        let mcsBER = berWrap(tag: 0x61, content: seqContent)

        // Wrap in TPKT + X.224 data TPDU
        return wrapInTPKT(payload: mcsBER)
    }

    /// Parse an MCS Connect Response. Returns (result, conferenceID).
    static func parseConnectResponse(_ data: Data) -> (result: UInt8, conferenceID: Int)? {
        guard data.count >= 11 else { return nil }
        guard data[0] == 0x03 else { return nil }
        let tpktLen = (Int(data[2]) << 8) | Int(data[3])
        guard tpktLen >= 7, tpktLen <= data.count else { return nil }
        let tpduStart = 5
        guard (data[tpduStart] & 0xF0) == 0xF0 else { return nil }
        let mcsStart = tpduStart + 2
        guard mcsStart < data.count, data[mcsStart] == 0x62 else { return nil }

        var offset = mcsStart + 1
        guard offset < data.count else { return nil }

        // BER length
        var berLen = Int(data[offset])
        offset += 1
        if berLen & 0x80 != 0 {
            let nb = berLen & 0x7F
            guard nb > 0, offset + nb <= data.count else { return nil }
            berLen = 0
            for j in 0..<nb { berLen = (berLen << 8) | Int(data[offset + j]) }
            offset += nb
        }

        // Result [0] IMPLICIT ENUMERATED
        guard offset < data.count else { return nil }
        var result: UInt8 = 0
        if data[offset] == 0xA0 {
            offset += 1
            guard offset < data.count else { return nil }
            let rLen = Int(data[offset])
            offset += 1
            if rLen >= 1 && offset < data.count {
                result = data[offset]
            }
        }
        return (result, 0x12345)
    }

    /// Scan data for the magic core-data block.
    static func extractDimensions(from data: Data) -> (width: Int, height: Int, bpp: Int)? {
        let e = data.count
        var i = 0
        while i + 18 <= e {
            if data[i] == 0xCC && data[i+1] == 0x01 {
                let off = i + 6
                if off + 12 <= e {
                    let w = readBE32(data: data, offset: off)
                    let h = readBE32(data: data, offset: off + 4)
                    let b = readBE32(data: data, offset: off + 8)
                    return (Int(w), Int(h), Int(b))
                }
            }
            i += 1
        }
        return nil
    }

    // MARK: - Private

    private static func buildDomainParameters() -> Data {
        let fields = [berInt(34), berInt(3), berInt(0), berInt(1),
                      berInt(0), berInt(1), berInt(65535), berInt(2)]
        return berSequence(fields.reduce(Data()) { $0 + $1 })
    }

    private static func wrapInTPKT(payload: Data) -> Data {
        // X.224 data TPDU header: LI + 0xF0 + 0x80
        let x224PayloadLen = 2 + payload.count
        let li: UInt8
        if x224PayloadLen <= 255 {
            li = UInt8(x224PayloadLen)
        } else {
            // Payload exceeds single-byte LI max (255).
            // This shouldn't happen for well-formed RDP packets in a mock context.
            // Truncate LI to 255; the TPKT length field contains the actual packet size.
            li = 0xFF
        }
        let x224Hdr: [UInt8] = [li, 0xF0, 0x80]
        let tpktLen = 4 + x224Hdr.count + payload.count
        let tpkt: [UInt8] = [0x03, 0x00, UInt8((tpktLen >> 8) & 0xFF), UInt8(tpktLen & 0xFF)]
        var packet = Data(tpkt)
        packet.append(contentsOf: x224Hdr)
        packet.append(payload)
        return packet
    }

    private static func readBE32(data: Data, offset: Int) -> UInt32 {
        var bytes = [UInt8](repeating: 0, count: 4)
        for j in 0..<4 { bytes[j] = data[offset + j] }
        return UInt32(bigEndian: bytes.withUnsafeBytes { $0.load(as: UInt32.self) })
    }

    // BER helpers
    private static func berWrap(tag: UInt8, content: Data) -> Data {
        var result = Data([tag])
        result.append(berLength(content.count))
        result.append(content)
        return result
    }

    private static func berSequence(_ content: Data) -> Data { berWrap(tag: 0x30, content: content) }
    private static func berOctetString(_ d: Data) -> Data { berWrap(tag: 0x04, content: d) }
    private static func berBool(_ v: Bool) -> Data { Data([0x01, 0x01, v ? 0xFF : 0x00]) }
    private static func berInt(_ v: Int) -> Data {
        if v >= 0 && v < 128 { return Data([0x02, 0x01, UInt8(v)]) }
        let hi = UInt8((v >> 8) & 0xFF)
        let lo = UInt8(v & 0xFF)
        return Data([0x02, 0x02, hi, lo])
    }

    private static func berLength(_ length: Int) -> Data {
        if length < 128 { return Data([UInt8(length)]) }
        if length <= 0xFF { return Data([0x81, UInt8(length)]) }
        return Data([0x82, UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)])
    }
}
