import Foundation

/// RFC 1320 MD4 hash — pure Swift, no AppKit.
/// Used by NTLMv2 to compute the NTLM hash: MD4(UTF-16LE(password)).
enum MD4 {

    static func md4(_ data: Data) -> Data {
        // Initial state (little-endian)
        var a: UInt32 = 0x67452301
        var b: UInt32 = 0xEFCDAB89
        var c: UInt32 = 0x98BADCFE
        var d: UInt32 = 0x10325476

        // Pre-processing: padding
        let originalLen = data.count
        var msg = data
        // Append bit '1' (0x80)
        msg.append(0x80)
        // Append zeros until length ≡ 56 (mod 64)
        while msg.count % 64 != 56 {
            msg.append(0x00)
        }
        // Append original length in bits as 64-bit little-endian
        let bitLen = UInt64(originalLen) * 8
        for i in 0..<8 {
            msg.append(UInt8((bitLen >> (i * 8)) & 0xFF))
        }

        // Process each 64-byte block
        let blocks = msg.count / 64
        for blockIdx in 0..<blocks {
            let blockStart = blockIdx * 64
            // Read block as 16 little-endian UInt32 words
            var X = [UInt32](repeating: 0, count: 16)
            for i in 0..<16 {
                let off = blockStart + i * 4
                X[i] = UInt32(msg[off])
                    | (UInt32(msg[off + 1]) << 8)
                    | (UInt32(msg[off + 2]) << 16)
                    | (UInt32(msg[off + 3]) << 24)
            }

            let (aa, bb, cc, dd) = (a, b, c, d)

            // Round 1
            a = rol((a &+ F(b, c, d) &+ X[0]), 3)
            d = rol((d &+ F(a, b, c) &+ X[1]), 7)
            c = rol((c &+ F(d, a, b) &+ X[2]), 11)
            b = rol((b &+ F(c, d, a) &+ X[3]), 19)
            a = rol((a &+ F(b, c, d) &+ X[4]), 3)
            d = rol((d &+ F(a, b, c) &+ X[5]), 7)
            c = rol((c &+ F(d, a, b) &+ X[6]), 11)
            b = rol((b &+ F(c, d, a) &+ X[7]), 19)
            a = rol((a &+ F(b, c, d) &+ X[8]), 3)
            d = rol((d &+ F(a, b, c) &+ X[9]), 7)
            c = rol((c &+ F(d, a, b) &+ X[10]), 11)
            b = rol((b &+ F(c, d, a) &+ X[11]), 19)
            a = rol((a &+ F(b, c, d) &+ X[12]), 3)
            d = rol((d &+ F(a, b, c) &+ X[13]), 7)
            c = rol((c &+ F(d, a, b) &+ X[14]), 11)
            b = rol((b &+ F(c, d, a) &+ X[15]), 19)

            // Round 2
            let c1: UInt32 = 0x5A827999
            a = rol((a &+ G(b, c, d) &+ X[0] &+ c1), 3)
            d = rol((d &+ G(a, b, c) &+ X[4] &+ c1), 5)
            c = rol((c &+ G(d, a, b) &+ X[8] &+ c1), 9)
            b = rol((b &+ G(c, d, a) &+ X[12] &+ c1), 13)
            a = rol((a &+ G(b, c, d) &+ X[1] &+ c1), 3)
            d = rol((d &+ G(a, b, c) &+ X[5] &+ c1), 5)
            c = rol((c &+ G(d, a, b) &+ X[9] &+ c1), 9)
            b = rol((b &+ G(c, d, a) &+ X[13] &+ c1), 13)
            a = rol((a &+ G(b, c, d) &+ X[2] &+ c1), 3)
            d = rol((d &+ G(a, b, c) &+ X[6] &+ c1), 5)
            c = rol((c &+ G(d, a, b) &+ X[10] &+ c1), 9)
            b = rol((b &+ G(c, d, a) &+ X[14] &+ c1), 13)
            a = rol((a &+ G(b, c, d) &+ X[3] &+ c1), 3)
            d = rol((d &+ G(a, b, c) &+ X[7] &+ c1), 5)
            c = rol((c &+ G(d, a, b) &+ X[11] &+ c1), 9)
            b = rol((b &+ G(c, d, a) &+ X[15] &+ c1), 13)

            // Round 3
            let c2: UInt32 = 0x6ED9EBA1
            a = rol((a &+ H(b, c, d) &+ X[0] &+ c2), 3)
            d = rol((d &+ H(a, b, c) &+ X[8] &+ c2), 9)
            c = rol((c &+ H(d, a, b) &+ X[4] &+ c2), 11)
            b = rol((b &+ H(c, d, a) &+ X[12] &+ c2), 15)
            a = rol((a &+ H(b, c, d) &+ X[2] &+ c2), 3)
            d = rol((d &+ H(a, b, c) &+ X[10] &+ c2), 9)
            c = rol((c &+ H(d, a, b) &+ X[6] &+ c2), 11)
            b = rol((b &+ H(c, d, a) &+ X[14] &+ c2), 15)
            a = rol((a &+ H(b, c, d) &+ X[1] &+ c2), 3)
            d = rol((d &+ H(a, b, c) &+ X[9] &+ c2), 9)
            c = rol((c &+ H(d, a, b) &+ X[5] &+ c2), 11)
            b = rol((b &+ H(c, d, a) &+ X[13] &+ c2), 15)
            a = rol((a &+ H(b, c, d) &+ X[3] &+ c2), 3)
            d = rol((d &+ H(a, b, c) &+ X[11] &+ c2), 9)
            c = rol((c &+ H(d, a, b) &+ X[7] &+ c2), 11)
            b = rol((b &+ H(c, d, a) &+ X[15] &+ c2), 15)

            a = a &+ aa
            b = b &+ bb
            c = c &+ cc
            d = d &+ dd
        }

        // Output as 16 bytes little-endian
        var result = Data(count: 16)
        result[0] = UInt8(a & 0xFF)
        result[1] = UInt8((a >> 8) & 0xFF)
        result[2] = UInt8((a >> 16) & 0xFF)
        result[3] = UInt8((a >> 24) & 0xFF)
        result[4] = UInt8(b & 0xFF)
        result[5] = UInt8((b >> 8) & 0xFF)
        result[6] = UInt8((b >> 16) & 0xFF)
        result[7] = UInt8((b >> 24) & 0xFF)
        result[8] = UInt8(c & 0xFF)
        result[9] = UInt8((c >> 8) & 0xFF)
        result[10] = UInt8((c >> 16) & 0xFF)
        result[11] = UInt8((c >> 24) & 0xFF)
        result[12] = UInt8(d & 0xFF)
        result[13] = UInt8((d >> 8) & 0xFF)
        result[14] = UInt8((d >> 16) & 0xFF)
        result[15] = UInt8((d >> 24) & 0xFF)
        return result
    }

    // MARK: - MD4 auxiliary functions

    @inline(__always)
    private static func F(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { (x & y) | (~x & z) }

    @inline(__always)
    private static func G(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { (x & y) | (x & z) | (y & z) }

    @inline(__always)
    private static func H(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { x ^ y ^ z }

    @inline(__always)
    private static func rol(_ x: UInt32, _ n: UInt32) -> UInt32 {
        (x << n) | (x >> (32 - n))
    }
}
