import Foundation

/// Decode raw (uncompressed) bitmap data into an RGBA Framebuffer.
/// RLE decode comes in the next slice — for this slice: raw only.
enum BitmapCodec {

    /// Decode raw (uncompressed) bitmap data into the framebuffer.
    /// `bitmapData` is raw pixel bytes in BGR (or BGRA) format, top-down.
    /// Uncompressed RDP bitmaps are sent top-down (row 0 = first scan line).
    /// `bpp` determines bytes per pixel.
    public static func decodeRaw(bitmapData: Data, destX: Int, destY: Int,
                                  width: Int, height: Int, bpp: Int,
                                  into fb: Framebuffer) {
        let bytesPerPixel = bpp / 8
        guard bytesPerPixel > 0 else { return }
        guard width > 0, height > 0 else { return }

        let srcRowStride = width * bytesPerPixel
        var dataOffset = 0

        // RDP uncompressed bitmap data is top-down: row 0 = top scan line = destY.
        for row in 0..<height {
            let fbY = destY + row

            for col in 0..<width {
                let fbX = destX + col

                guard dataOffset + bytesPerPixel <= bitmapData.count else { return }

                let r: UInt8
                let g: UInt8
                let b: UInt8

                switch bytesPerPixel {
                case 4: // BGRA
                    b = bitmapData[dataOffset]
                    g = bitmapData[dataOffset + 1]
                    r = bitmapData[dataOffset + 2]
                    // alpha = bitmapData[dataOffset + 3]
                case 3: // BGR
                    b = bitmapData[dataOffset]
                    g = bitmapData[dataOffset + 1]
                    r = bitmapData[dataOffset + 2]
                case 2: // 16-bit RGB565
                    let lo = bitmapData[dataOffset]
                    let hi = bitmapData[dataOffset + 1]
                    let pixel = UInt16(lo) | (UInt16(hi) << 8)
                    r = UInt8((pixel >> 8) & 0xF8)
                    g = UInt8((pixel >> 3) & 0xFC)
                    b = UInt8((pixel << 3) & 0xF8)
                default:
                    r = 0; g = 0; b = 0
                }

                fb.setPixel(x: fbX, y: fbY, r: r, g: g, b: b)
                dataOffset += bytesPerPixel
            }

            // Pad to 4-byte boundary if needed (RDP pads rows)
            let rowPad = (4 - (srcRowStride % 4)) % 4
            dataOffset += rowPad
        }
    }

    /// Decode interleaved RLE bitmap data into the framebuffer.
    /// Follows MS-RDPBCGR §2.2.9.1.1.3.1.2.3.
    /// Supports 8bpp (palette-indexed) and 24bpp/32bpp (direct color).
    public static func decodeInterleavedRLE(bitmapData: Data, destX: Int, destY: Int,
                                              width: Int, height: Int, bpp: Int,
                                              into fb: Framebuffer) {
        guard width > 0, height > 0 else { return }

        let bytesPerPixel: Int
        switch bpp {
        case 8:
            bytesPerPixel = 1
        case 15:
            bytesPerPixel = 2
        case 16:
            bytesPerPixel = 2
        case 24:
            bytesPerPixel = 3
        case 32:
            bytesPerPixel = 4
        default:
            return // unsupported bpp
        }

        // For 8bpp, we need to read the palette first (256 BGR entries = 768 bytes)
        var palette: [(r: UInt8, g: UInt8, b: UInt8)]?
        var src = bitmapData
        if bpp == 8 {
            var palArray: [(r: UInt8, g: UInt8, b: UInt8)] = []
            var dataOff = 0
            for _ in 0..<256 {
                guard dataOff + 3 <= src.count else { return }
                let b = src[dataOff]
                let g = src[dataOff + 1]
                let r = src[dataOff + 2]
                palArray.append((r: r, g: g, b: b))
                dataOff += 3
            }
            palette = palArray
            src = src.subdata(in: dataOff..<src.count)
        }

        // Decode the interleaved-RLE stream.
        // Two-level coding:
        //   Level 1: control byte
        //     - If high bit set (0x80): run-length encoding
        //       control byte & 0x7F = runLength - 1 (so runLength = (control & 0x7F) + 1)
        //       next `bytesPerPixel` bytes = fill color
        //     - If high bit clear: literal pixels
        //       control byte & 0x3F = pixelCount - 1 (with continuation bit)
        //       Actually per interleaved RLE:
        //       * first byte is the control/opcode
        //       * 0x00 = escape: next byte determines escape type
        //         - 0x00 0x00 = line done (advance to next scanline)
        //         - 0x00 0x01 = bitmap done
        //         - 0x00 0x02..0x7F = delta (advance fill position by that many pixels)
        //       * if first byte != 0x00:
        //         bit 7 set → run-length: runCount = byte & 0x3F (+ continuation from bit 6)
        //         bit 7 clear → literal count
        //
        // Per MS-RDPBCGR §2.2.9.1.1.3.1.2.3 (interleaved-RLE):
        // The encoding uses two levels:
        //   LEVEL 1 (first byte):
        //     If bit 7 is 1: run-length encoding
        //       bits 0-3 (n4) and optionally bit 5 (n6) give run length
        //       - if bit 5 is 0: runLen = (firstByte & 0x3F) + 1
        //       - if bit 5 is 1: runLen = ((firstByte & 0x3F) << 8) | secondByte + 1
        //       The next `bytesPerPixel` bytes are the color
        //     If bit 7 is 0: literal pixel data
        //       - if bit 5 is 0: pixelCount = (firstByte & 0x3F) + 1
        //       - if bit 5 is 1: pixelCount = ((firstByte & 0x3F) << 8) | secondByte + 1
        //       The next pixelCount * bytesPerPixel bytes are literal pixel data
        //     If firstByte == 0x00: escape
        //       Second byte:
        //         0x00 = line done (move to next row)
        //         0x01 = bitmap done
        //         0x02..0x7F = delta (advance position in current row)
        //         0x80..0x81 = fill color from palette[byte - 0x80] (8bpp only)
        //         0x82..0x83 = fill color from 2-byte RGB (8bpp only)

        var pos = 0 // byte position in src
        var fillX = destX
        var fillY = destY

        func readByte() -> UInt8? {
            guard pos < src.count else { return nil }
            let b = src[pos]; pos += 1; return b
        }

        func peekByte() -> UInt8? {
            guard pos < src.count else { return nil }
            return src[pos]
        }

        func readColor() -> (r: UInt8, g: UInt8, b: UInt8)? {
            if bytesPerPixel == 1 {
                // 8bpp: palette index
                guard let idx = readByte() else { return nil }
                guard let pal = palette, Int(idx) < pal.count else { return nil }
                return pal[Int(idx)]
            }
            switch bytesPerPixel {
            case 4:
                guard pos + 3 < src.count else { return nil }
                let b = src[pos]
                let g = src[pos + 1]
                let r = src[pos + 2]
                // src[pos + 3] = alpha or padding
                pos += 4
                return (r: r, g: g, b: b)
            case 3:
                guard pos + 2 < src.count else { return nil }
                let b = src[pos]
                let g = src[pos + 1]
                let r = src[pos + 2]
                pos += 3
                return (r: r, g: g, b: b)
            case 2:
                guard pos + 1 < src.count else { return nil }
                let lo = src[pos]
                let hi = src[pos + 1]
                pos += 2
                let pixel = UInt16(lo) | (UInt16(hi) << 8)
                let r = UInt8((pixel >> 8) & 0xF8)
                let g = UInt8((pixel >> 3) & 0xFC)
                let b = UInt8((pixel << 3) & 0xF8)
                return (r: r, g: g, b: b)
            default:
                return nil
            }
        }

        func writePixel(_ color: (r: UInt8, g: UInt8, b: UInt8)) {
            guard fillY >= destY && fillY < destY + height else { return }
            guard fillX >= destX && fillX < destX + width else { return }
            fb.setPixel(x: fillX, y: fillY, r: color.r, g: color.g, b: color.b)
        }

        // The interleaved-RLE stream is sequential: pixels are written left-to-right,
        // top-to-bottom. The line-done escape handles the row transition from the
        // encoder side. Row tracking is driven ONLY by escapes, not by pixel writes.
        // We use sentinel-y to detect writes past the framebuffer to avoid crashing.
        let sentinelY = destY + height

        while fillY < sentinelY {
            guard let firstByte = readByte() else { return }

            if firstByte == 0x00 {
                // Escape sequence
                guard let escByte = readByte() else { return }
                if escByte == 0x00 {
                    // Line done: advance to next row
                    fillY += 1
                    fillX = destX
                } else if escByte == 0x01 {
                    // Bitmap done
                    return
                } else if escByte >= 0x02 && escByte <= 0x7F {
                    // Delta: advance fill position
                    fillX += Int(escByte)
                } else if escByte >= 0x80 && escByte <= 0x81 && bytesPerPixel == 1 {
                    // 8bpp: fill with palette[escByte - 0x80]
                    let palIdx = Int(escByte - 0x80)
                    guard let pal = palette, palIdx < pal.count else { return }
                    writePixel(pal[palIdx])
                    fillX += 1
                } else if escByte >= 0x82 && escByte <= 0x83 && bytesPerPixel == 1 {
                    // 8bpp: fill with 2-byte RGB color
                    guard let b1 = readByte(), let b2 = readByte() else { return }
                    let r8 = (b1 & 0xE0) << 0
                    let g8 = (b1 & 0x1C) << 3
                    let b8 = (b2 & 0xF8)
                    writePixel((r: r8, g: g8, b: b8))
                    fillX += 1
                } else {
                    // Unknown escape, skip
                }
            } else if (firstByte & 0x80) != 0 {
                // Run-length encoding
                let ext = (firstByte & 0x40) != 0
                var runLen = Int(firstByte & 0x3F)
                if ext {
                    guard let extByte = readByte() else { return }
                    runLen = (runLen << 8) | Int(extByte)
                }
                runLen += 1
                guard let color = readColor() else { return }
                for _ in 0..<runLen {
                    writePixel(color)
                    fillX += 1
                }
            } else {
                // Literal pixel data
                let ext = (firstByte & 0x40) != 0
                var pixCount = Int(firstByte & 0x3F)
                if ext {
                    guard let extByte = readByte() else { return }
                    pixCount = (pixCount << 8) | Int(extByte)
                }
                pixCount += 1
                for _ in 0..<pixCount {
                    guard let color = readColor() else { return }
                    writePixel(color)
                    fillX += 1
                }
            }
        }
    }
}
