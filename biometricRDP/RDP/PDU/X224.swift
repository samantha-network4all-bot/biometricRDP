import Foundation

enum X224 {

    /// Build a TPKT + X.224 CR-TPDU packet (connection request).
    static func buildConnectionRequest() -> Data {
        // X.224 Connection Request TPDU (fixed part)
        // CR-TPDU: CR-CDT=0, DST-REF=0, SRC-REF=0, CLASS=0
        let x224Fixed: [UInt8] = [
            0xE0, // CR code
            0x00, 0x00, // DST-REF
            0x00, 0x00, // SRC-REF
            0x00  // CLASS 0
        ]

        // Variable part: RDP Negotiation Request
        // Include PROTOCOL_HYBRID (0x01 = CredSSP) for NLA support
        let rdpNegReq: [UInt8] = [
            0x01, // TYPE_RDP_NEG_REQ
            0x00, // flags
            0x08, 0x00, // length (8)
            0x01, 0x00, 0x00, 0x00  // requested protocols: PROTOCOL_HYBRID (CredSSP/NLA)
        ]

        // Assemble TPDU: fixed header + variable items
        var tpdu = Data(x224Fixed)
        tpdu.append(contentsOf: rdpNegReq)

        // LI = length of TPDU bytes after the LI byte itself
        // Fixed part (CODE+DST-REF+SRC-REF+CLASS) = 6 bytes + variable = 8 bytes
        let li = tpdu.count

        // Build TPKT-wrapped packet
        let totalLen = 4 /* TPKT header */ + 1 /* LI */ + tpdu.count
        var packet = buildTPktHeader(payloadLength: totalLen)
        packet.append(UInt8(li)) // LI
        packet.append(contentsOf: tpdu)
        return Data(packet)
    }

    /// Parse an X.224 CC-TPDU (connection confirm) from received data.
    /// Returns the negotiated protocols (0 for direct mode) or nil if not valid.
    static func parseConnectionConfirm(_ data: Data) -> UInt32? {
        // Need at least TPKT header (4) + LI (1) + CC-TPDU (min 7)
        guard data.count >= 12 else { return nil }

        // TPKT: version=3, reserved, length
        guard data[0] == 0x03 else { return nil }
        let tpktLen = (Int(data[2]) << 8) | Int(data[3])
        guard tpktLen >= 7, tpktLen <= data.count else { return nil }

        let li = data[4]
        guard li >= 5 else { return nil }

        let tpduStart = 5
        guard tpduStart < data.count else { return nil }
        guard data[tpduStart] == 0xD0 else { return nil } // CC code

        // Look for RDP_NEG_RSP or fallback to no negotiation
        var offset = tpduStart + 1
        // Skip DST-REF(2) + SRC-REF(2) + CLASS(1)
        guard data.count > offset + 4 else { return nil }
        offset += 5

        // Parse variable parts: iterate looking for TYPE_RDP_NEG_RSP (0x02) or TYPE_RDP_NEG_FAILURE (0x03)
        // RDP X.224 negotiation variable item format:
        //   type(1) + flags(1) + length(2, little-endian) + data(length-4)
        // length field = total item size including 4-byte header
        while offset + 7 <= data.count {
            let type = data[offset]
            _ = data[offset + 1] // flags
            let length = Int(data[offset + 2]) | (Int(data[offset + 3]) << 8)
            guard length >= 8 else { break }
            guard offset + length <= data.count else { break }
            if type == 0x02 { // TYPE_RDP_NEG_RSP
                let protoBytes = data[(offset + 4)..<(offset + 8)]
                let proto = protoBytes.enumerated().reduce(UInt32(0)) { acc, el in
                    acc | (UInt32(el.element) << (24 - el.offset * 8))
                }
                return proto
            }
            if type == 0x03 { // TYPE_RDP_NEG_FAILURE
                return nil
            }
            offset += length
        }
        // No negotiation result found — return 0 for direct mode
        return 0
    }

    // MARK: - Helpers

    private static func buildTPktHeader(payloadLength: Int) -> [UInt8] {
        let len = payloadLength
        return [
            0x03,       // version
            0x00,       // reserved
            UInt8((len >> 8) & 0xFF),
            UInt8(len & 0xFF)
        ]
    }
}
