import Foundation

enum X224 {

    /// Build a TPKT + X.224 CR-TPDU packet (connection request).
    static func buildConnectionRequest() -> Data {
        // X.224 Connection Request TPDU (fixed part)
        // CR-TPDU: CR-CDT=0, DST-REF=0, SRC-REF=0, CLASS=0
        let x224: [UInt8] = [
            0xE0, // CR code
            0x00, 0x00, // DST-REF
            0x00, 0x00, // SRC-REF
            0x00  // CLASS 0
        ]

        // Variable part: RDP Negotiation Request
        let rdpNegReq: [UInt8] = [
            0x01, // TYPE_RDP_NEG_REQ
            0x00, // flags
            0x08, 0x00, // length (8)
            0x00, 0x00, 0x00, 0x00  // requested protocols (direct-only)
        ]

        var tpdu = x224
        tpdu.append(contentsOf: rdpNegReq)

        // Prepend TPKT header
        let tpkt = buildTPktHeader(payloadLength: tpdu.count + 7)
        var packet = tpkt
        packet.append(7 + UInt8(tpdu.count)) // LI
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
        while offset + 7 <= data.count {
            let type = data[offset]
            let flags = data[offset + 1]
            let length = (Int(data[offset + 2]) << 8) | Int(data[offset + 3])
            // length includes the 4 type/flags/length bytes themselves? No, in RDP the length field is just payload length after the header
            // Actually in T.123 the variable items have: type(1) + flags(1) + length(2) + value(length-4)
            // So total item length = 4 + (length - 4) = length
            // But the RDP spec says: type(1) flags(1) length(2) data(length)
            // Let me just be safe: total variable item = 4 + length_value where length_value is the raw field
            let totalItemLen = 4 + length
            guard totalItemLen > 4 else { break }
            guard offset + totalItemLen <= data.count else { break }
            if type == 0x02 { // TYPE_RDP_NEG_RSP
                let protoLen = length - 4
                guard protoLen >= 4 else { return nil }
                let protoBytes = data[(offset + 4)..<(offset + 8)]
                let proto = protoBytes.enumerated().reduce(UInt32(0)) { acc, el in
                    acc | (UInt32(el.element) << (24 - el.offset * 8))
                }
                return proto
            }
            if type == 0x03 { // TYPE_RDP_NEG_FAILURE
                let failureCode = (Int(data[offset + 4]) << 24) | (Int(data[offset + 5]) << 16) |
                                  (Int(data[offset + 6]) << 8)  | Int(data[offset + 7])
                NSLog("RDP negotiated failure: \(failureCode)")
                return nil
            }
            offset += totalItemLen
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
