import Foundation

/// Decode raw (uncompressed) bitmap data into an RGBA Framebuffer.
/// RLE decode comes in the next slice — for this slice: raw only.
enum BitmapCodec {

    /// Decode raw (uncompressed) bitmap data into the framebuffer.
    /// `bitmapData` is raw pixel bytes in BGR (or BGRA) format, bottom-up by default.
    /// `bpp` determines bytes per pixel.
    public static func decodeRaw(bitmapData: Data, destX: Int, destY: Int,
                                  width: Int, height: Int, bpp: Int,
                                  into fb: Framebuffer) {
        let bytesPerPixel = bpp / 8
        guard bytesPerPixel > 0 else { return }
        guard width > 0, height > 0 else { return }

        let srcRowStride = width * bytesPerPixel
        var dataOffset = 0

        // RDP sends bitmap data bottom-up by default (unless compressed with a flag).
        // For uncompressed, row 0 in the data = bottom of the rectangle.
        // We decode row by row.
        for row in 0..<height {
            // Source row 0 = bottom row, so flip Y
            let fbY = destY + (height - 1 - row)

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

    /// Decode interleaved RLE (not yet implemented — RLE comes in next slice).
    public static func decodeInterleavedRLE(bitmapData: Data, destX: Int, destY: Int,
                                              width: Int, height: Int, bpp: Int,
                                              into fb: Framebuffer) {
        // Not implemented in this slice.
    }
}
