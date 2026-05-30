import Foundation

/// Parse RDP Bitmap Update PDUs from incoming wire data.
/// Handles both slow-path (Share Data Header + TS_BITMAP_DATA)
/// and fast-path (TS_FP_UPDATE + TS_BITMAP_DATA) encapsulation.
/// All parsing is bounds-checked; returns nil on malformed data.
enum BitmapUpdate {

    /// A single decoded bitmap rectangle.
    struct BitmapRectangle {
        let destX: Int
        let destY: Int
        let width: Int
        let height: Int
        let bpp: Int
        let isCompressed: Bool
        let bitmapData: Data
    }

    /// Parse any complete bitmap update PDUs from the buffer.
    /// Returns the parsed rectangles and the number of bytes consumed from the buffer.
    static func parseBitmapUpdate(_ data: Data) -> [(destX: Int, destY: Int, width: Int, height: Int, bpp: Int, isCompressed: Bool, bitmapData: Data)]? {
        var results: [(destX: Int, destY: Int, width: Int, height: Int, bpp: Int, isCompressed: Bool, bitmapData: Data)] = []
        var offset = 0

        while offset < data.count {
            // Try to parse one TPKT + X.224 data PDU
            guard offset + 4 <= data.count else { break }

            // TPKT header: version(1) + reserved(1) + length(2)
            guard data[offset] == 0x03 else { break }
            let tpktLen = (Int(data[offset + 2]) << 8) | Int(data[offset + 3])
            guard tpktLen >= 7 else { break }
            guard offset + tpktLen <= data.count else { break } // incomplete

            let packetEnd = offset + tpktLen
            var pktOffset = offset + 4 // skip TPKT header

            // X.224 data TPDU: LI + type(0xF0) + credit(0x80)
            // LI may be short form (< 0x80) or extended (>= 0x80)
            guard pktOffset + 3 <= packetEnd else { break }
            let liByte = Int(data[pktOffset])
            let x224HdrLen: Int
            if liByte < 0x80 {
                // Short form: LI(1) + code(1) + credit(1) = 3 bytes
                x224HdrLen = 3
            } else {
                // Extended form: LI(1) + lenBytes(N) + code(1) + credit(1)
                let lenBytes = liByte & 0x7F
                guard lenBytes >= 2 else { break }
                x224HdrLen = 1 + lenBytes + 2
            }
            guard pktOffset + x224HdrLen <= packetEnd else { break }
            guard data[pktOffset + x224HdrLen - 2] == 0xF0 else { break } // data TPDU code
            pktOffset += x224HdrLen

            // Remaining bytes = Share Data Header + payload
            let shareDataStart = pktOffset
            let shareDataLen = packetEnd - shareDataStart
            guard shareDataLen > 0 else { break }

            // Determine if this is a fast-path or slow-path PDU
            let remaining = data.subdata(in: shareDataStart..<packetEnd)

            if let rects = parseSlowPath(remaining) {
                results.append(contentsOf: rects)
            } else if let rects = parseFastPath(remaining) {
                results.append(contentsOf: rects)
            }

            offset = packetEnd
        }

        guard !results.isEmpty else { return nil }
        return results
    }

    // MARK: - Slow-path parsing

    private static func parseSlowPath(_ data: Data) -> [(destX: Int, destY: Int, width: Int, height: Int, bpp: Int, isCompressed: Bool, bitmapData: Data)]? {
        guard data.count >= 12 else { return nil }

        var offset = 0

        // Share Control Header:
        //   totalLength(2, little-endian) + pduType(2) + PDUSource(2)
        let totalLength = Int(readLE16(data, &offset))
        let pduType = readLE16(data, &offset)
        _ = readLE16(data, &offset) // PDUSource

        // PDU type 0x02 = PDUTYPE2_UPDATE
        guard (pduType & 0x0F) == 0x02 else { return nil }

        guard offset < data.count else { return nil }

        // shareControlLen should match data.count
        guard totalLength <= data.count else { return nil }

        // TS_UPDATE_DATA: updateType(2)
        guard offset + 2 <= data.count else { return nil }
        let updateType = readLE16(data, &offset)

        // updateType 0x0001 = UPDATETYPE_BITMAP
        guard updateType == 0x0001 else { return nil }

        var results: [(destX: Int, destY: Int, width: Int, height: Int, bpp: Int, isCompressed: Bool, bitmapData: Data)] = []

        // numberOfRectangles(2)
        guard offset + 2 <= data.count else { return nil }
        let numRects = Int(readLE16(data, &offset))

        for _ in 0..<numRects {
            guard let rect = parseBitmapData(data, &offset) else { return nil }
            results.append(rect)
        }

        return results
    }

    // MARK: - Fast-path parsing

    private static func parseFastPath(_ data: Data) -> [(destX: Int, destY: Int, width: Int, height: Int, bpp: Int, isCompressed: Bool, bitmapData: Data)]? {
        guard data.count >= 2 else { return nil }
        var offset = 0

        let fpHeader = readU8(data, &offset)

        // Fast-path: action in bits 0-1, should be 0 (FASTPATH_OUTPUT_ACTION) for server output
        let action = fpHeader & 0x03
        guard action == 0 else { return nil }

        // Number of TS_FP_UPDATE units follows (variable-length encoded)
        // Length encoding: if bit 7 of the first length byte is clear, single byte
        //                  if bit 7 is set, two-byte length (byte1&0x7F << 8 | byte2)
        let hasTwoByteLen = (fpHeader & 0x80) != 0
        var fpLen: Int
        if hasTwoByteLen {
            guard offset + 1 < data.count else { return nil }
            let hi = Int(readU8(data, &offset)) & 0x7F
            let lo = Int(readU8(data, &offset))
            fpLen = (hi << 8) | lo
        } else {
            fpLen = Int(readU8(data, &offset))
        }
        _ = fpLen // total fast-path payload length, used for bounds

        // Check for enhanced codec header (may be present with compression)
        let _ = fpHeader & 0xC0 // flags

        guard offset < data.count else { return nil }

        // TS_FP_UPDATE
        guard offset + 2 <= data.count else { return nil }
        let updateHeader = readU8(data, &offset)
        let updateCode = updateHeader & 0x0F // 2 = UPDATETYPE_BITMAP
        guard updateCode == 2 else { return nil }

        let fragmentation = (updateHeader >> 4) & 0x03
        _ = fragmentation // not handling fragmented updates in this slice

        let compressionFlags = (updateHeader >> 6) & 0x03
        if compressionFlags != 0 {
            // Skip compression headers (not handling in this slice)
            return nil
        }

        // TS_UDPATE_BITMAP_DATA
        var results: [(destX: Int, destY: Int, width: Int, height: Int, bpp: Int, isCompressed: Bool, bitmapData: Data)] = []
        // In a single fast-path PDU, typically one bitmap update
        // But the structure is similar; parse it as a simple structure
        // Fast-path bitmap update: rect bounds + bpp + flags + dataLength + data
        guard offset + 2 <= data.count else { return nil }
        let _ = readLE16(data, &offset) // numberRects in fast-path

        guard let rect = parseFastPathBitmapData(data, &offset) else { return nil }
        results.append(rect)

        return results
    }

    // MARK: - TS_BITMAP_DATA (slow-path)

    private static func parseBitmapData(_ data: Data, _ offset: inout Int) -> (destX: Int, destY: Int, width: Int, height: Int, bpp: Int, isCompressed: Bool, bitmapData: Data)? {
        // TS_BITMAP_DATA fields (all little-endian):
        //   destLeft(2) + destTop(2) + destRight(2) + destBottom(2) +
        //   width(2) + height(2) + bitsPerPixel(2) +
        //   flags(2) + bitmapDataLength(2) + bitmapData(...)

        guard offset + 18 <= data.count else { return nil }

        let destLeft = Int(readLE16(data, &offset))
        let destTop = Int(readLE16(data, &offset))
        let destRight = Int(readLE16(data, &offset))
        let destBottom = Int(readLE16(data, &offset))
        let width = Int(readLE16(data, &offset))
        let height = Int(readLE16(data, &offset))
        let bpp = Int(readLE16(data, &offset))
        let flags = readLE16(data, &offset)
        let bitmapDataLength = Int(readLE16(data, &offset))

        let isCompressed = (flags & 0x0001) != 0

        guard bitmapDataLength >= 0 else { return nil }
        guard offset + bitmapDataLength <= data.count else { return nil }

        let bitmapData = data.subdata(in: offset..<(offset + bitmapDataLength))
        offset += bitmapDataLength

        return (destX: destLeft, destY: destTop, width: width, height: height,
                bpp: bpp, isCompressed: isCompressed, bitmapData: bitmapData)
    }

    // MARK: - TS_UPDATE_BITMAP_DATA (fast-path)

    private static func parseFastPathBitmapData(_ data: Data, _ offset: inout Int) -> (destX: Int, destY: Int, width: Int, height: Int, bpp: Int, isCompressed: Bool, bitmapData: Data)? {
        // Fast-path TS_UPDATE_BITMAP_DATA:
        //   left(2) + top(2) + width(2) + height(2) + bitsPerPixel(2) +
        //   flags(2) + bitmapDataLength(2)
        guard offset + 14 <= data.count else { return nil }

        let left = Int(readLE16(data, &offset))
        let top = Int(readLE16(data, &offset))
        let width = Int(readLE16(data, &offset))
        let height = Int(readLE16(data, &offset))
        let bpp = Int(readLE16(data, &offset))
        let flags = readLE16(data, &offset)
        let bitmapDataLength = Int(readLE16(data, &offset))

        let isCompressed = (flags & 0x0001) != 0

        guard bitmapDataLength >= 0 else { return nil }
        guard offset + bitmapDataLength <= data.count else { return nil }

        let bitmapData = data.subdata(in: offset..<(offset + bitmapDataLength))
        offset += bitmapDataLength

        return (destX: left, destY: top, width: width, height: height,
                bpp: bpp, isCompressed: isCompressed, bitmapData: bitmapData)
    }

    // MARK: - Read helpers

    private static func readU8(_ data: Data, _ offset: inout Int) -> UInt8 {
        let v = data[offset]; offset += 1; return v
    }

    private static func readLE16(_ data: Data, _ offset: inout Int) -> UInt16 {
        let lo = data[offset]
        let hi = data[offset + 1]
        offset += 2
        return UInt16(lo) | (UInt16(hi) << 8)
    }
}
