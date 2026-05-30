import Foundation

/// Minimal DER ASN.1 encoding for CredSSP TSRequest.
/// Pure Swift — no AppKit.
enum CredSSP {

    // ASN.1 tags
    private static let tagSequence: UInt8 = 0x30
    private static let tagInteger: UInt8 = 0x02
    private static let tagOctetString: UInt8 = 0x04
    private static let tagContextSpecific: UInt8 = 0xA0 // Context-specific [0]

    // SEQUENCE OF = 0x30
    private static let tagSequenceOf: UInt8 = 0x30

    /// Build a TSRequest with version and negoTokens.
    static func wrapTSRequest(negoTokens: [Data]) -> Data {
        return buildTSRequest(version: 2, negoTokens: negoTokens,
                              authInfo: nil, pubKeyAuth: nil,
                              errorCode: nil, nonce: nil)
    }

    /// Build a full TSRequest.
    static func buildTSRequest(version: UInt32, negoTokens: [Data],
                                authInfo: Data?, pubKeyAuth: Data?,
                                errorCode: UInt32?, nonce: Data?) -> Data {
        var content = Data()

        // version [0] INTEGER
        content.append(derContextSpecific(tag: 0, content: derInteger(Int(version))))

        // negoTokens [1] SEQUENCE OF NegoData
        if !negoTokens.isEmpty {
            var negoData = Data()
            for token in negoTokens {
                // NegoData ::= SEQUENCE { negoToken [0] OCTET_STRING }
                let octetStr = derOctetString(token)
                let taggedToken = derContextSpecific(tag: 0, content: octetStr)
                let negoSeq = derSequence(taggedToken)
                negoData.append(negoSeq)
            }
            let seqOf = derSequence(negoData)
            content.append(derContextSpecific(tag: 1, content: seqOf))
        }

        // authInfo [2] OCTET_STRING
        if let ai = authInfo {
            content.append(derContextSpecific(tag: 2, content: derOctetString(ai)))
        }

        // pubKeyAuth [3] OCTET_STRING
        if let pk = pubKeyAuth {
            content.append(derContextSpecific(tag: 3, content: derOctetString(pk)))
        }

        // errorCode [4] INTEGER
        if let ec = errorCode {
            content.append(derContextSpecific(tag: 4, content: derInteger(Int(ec))))
        }

        // nonce [5] OCTET_STRING
        if let n = nonce {
            content.append(derContextSpecific(tag: 5, content: derOctetString(n)))
        }

        return derSequence(content)
    }

    /// Parse a TSRequest and extract negoTokens as raw Data array.
    static func unwrapNLA(_ data: Data) -> [Data]? {
        guard let fields = parseTSRequest(data) else { return nil }
        return fields.negoTokens
    }

    /// Parse TSRequest returning all fields.
    static func parseTSRequest(_ data: Data) -> TSRequest? {
        var offset = 0

        // TSRequest ::= SEQUENCE
        guard let (seqLen, seqContentOffset) = parseSequence(data, offset: offset, dataLen: data.count) else {
            return nil
        }
        offset = seqContentOffset
        let seqEnd = seqContentOffset + seqLen

        var version: UInt32 = 0
        var negoTokens: [Data] = []
        var authInfo: Data?
        var pubKeyAuth: Data?
        var errorCode: UInt32?
        var nonce: Data?

        while offset < seqEnd {
            guard offset + 2 <= data.count else { break }
            let tag = data[offset]
            guard offset + 1 < data.count else { break }
            guard let (len, contentOffset) = parseLength(data, offset: offset + 1, dataLen: data.count) else { break }
            let contentEnd = contentOffset + len
            guard contentEnd <= data.count else { break }

            if tag & 0xA0 == 0xA0 {
                // Context-specific tagged field
                let tagNum = tag & 0x0F
                let innerData = data.subdata(in: contentOffset..<contentEnd)

                switch tagNum {
                case 0: // version INTEGER
                    if let v = parseInteger(innerData, dataLen: innerData.count) {
                        version = UInt32(v)
                    }
                case 1: // negoTokens
                    if let tokens = parseNegoTokens(innerData, dataLen: innerData.count) {
                        negoTokens = tokens
                    }
                case 2: // authInfo
                    authInfo = innerData
                case 3: // pubKeyAuth
                    pubKeyAuth = innerData
                case 4: // errorCode
                    if let ec = parseInteger(innerData, dataLen: innerData.count) {
                        errorCode = UInt32(ec)
                    }
                case 5: // nonce
                    nonce = innerData
                default:
                    break
                }
            }

            offset = contentEnd
        }

        return TSRequest(version: version, negoTokens: negoTokens,
                         authInfo: authInfo, pubKeyAuth: pubKeyAuth,
                         errorCode: errorCode, nonce: nonce)
    }

    // MARK: - DER primitives

    private static func derSequence(_ content: Data) -> Data {
        var result = Data([tagSequence])
        result.append(derLength(content.count))
        result.append(content)
        return result
    }

    private static func derInteger(_ value: Int) -> Data {
        if value == 0 {
            return Data([tagInteger, 0x01, 0x00])
        }
        // Find minimum bytes needed
        var v = value
        var bytes: [UInt8] = []
        if v < 0 {
            // Not expected for our use case, but handle
            // Use two's complement
            let uv = UInt32(value)
            bytes = withUnsafeBytes(of: uv.littleEndian) { Array($0) }
            // Trim trailing 0xFF (if negative sign extension)
            while bytes.count > 1 && bytes.last == 0xFF && (bytes[bytes.count - 2] & 0x80) != 0 {
                bytes.removeLast()
            }
        } else {
            while v > 0 {
                bytes.append(UInt8(v & 0xFF))
                v >>= 8
            }
            bytes.reverse()
            // If high bit is set, prepend 0x00 to indicate positive
            if let first = bytes.first, first & 0x80 != 0 {
                bytes.insert(0x00, at: 0)
            }
        }
        var result = Data([tagInteger])
        result.append(derLength(bytes.count))
        result.append(contentsOf: bytes)
        return result
    }

    private static func derOctetString(_ content: Data) -> Data {
        var result = Data([tagOctetString])
        result.append(derLength(content.count))
        result.append(content)
        return result
    }

    private static func derContextSpecific(tag: UInt8, content: Data) -> Data {
        var result = Data([0xA0 | tag])
        result.append(derLength(content.count))
        result.append(content)
        return result
    }

    private static func derLength(_ length: Int) -> Data {
        if length < 128 {
            return Data([UInt8(length)])
        }
        if length <= 0xFF {
            return Data([0x81, UInt8(length)])
        }
        if length <= 0xFFFF {
            return Data([0x82, UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)])
        }
        return Data([0x83, UInt8((length >> 16) & 0xFF), UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)])
    }

    // MARK: - Parsing primitives

    private static func parseSequence(_ data: Data, offset: Int, dataLen: Int) -> (Int, Int)? {
        guard offset < dataLen else { return nil }
        guard data[offset] == tagSequence else { return nil }
        return parseLength(data, offset: offset + 1, dataLen: dataLen)
            .map { (len: $0.0, contentOffset: $0.1) }
    }

    private static func parseLength(_ data: Data, offset: Int, dataLen: Int) -> (Int, Int)? {
        guard offset < dataLen else { return nil }
        let first = Int(data[offset])
        if first < 128 {
            return (first, offset + 1)
        }
        let numBytes = first & 0x7F
        guard numBytes > 0, offset + numBytes <= dataLen else { return nil }
        var length = 0
        for i in 1...numBytes {
            length = (length << 8) | Int(data[offset + i])
        }
        return (length, offset + 1 + numBytes)
    }

    private static func parseInteger(_ data: Data, dataLen: Int) -> Int? {
        guard dataLen > 0 else { return 0 }
        guard data[0] == tagInteger else { return nil }
        guard let (len, offset) = parseLength(data, offset: 1, dataLen: dataLen) else { return nil }
        guard offset + len <= dataLen else { return nil }
        var result = 0
        for i in 0..<len {
            result = (result << 8) | Int(data[offset + i])
        }
        // Check if negative
        if len > 0 && data[offset] & 0x80 != 0 {
            // We don't expect negative values for version/errorCode
            return result
        }
        return result
    }

    private static func parseNegoTokens(_ data: Data, dataLen: Int) -> [Data]? {
        // negoTokens content is: SEQUENCE OF NegoData
        // where NegoData ::= SEQUENCE { negoToken [0] OCTET_STRING }
        //
        // Structure:
        //   30 <len>                       <- outer SEQUENCE (OF)
        //     30 <len>                     <- NegoData SEQUENCE
        //       A0 <len>                   <- [0] context-specific
        //         04 <len> <data>          <- OCTET_STRING (the NTLM message)
        //     30 <len>                     <- another NegoData
        //       A0 <len>
        //         04 <len> <data>

        var offset = 0
        var tokens: [Data] = []

        // Parse the outer SEQUENCE (SEQUENCE OF)
        guard offset < dataLen, data[offset] == tagSequence else {
            return nil
        }
        guard let (outerLen, outerContentOff) = parseLength(data, offset: offset + 1, dataLen: dataLen) else {
            return nil
        }
        let outerEnd = outerContentOff + outerLen
        guard outerEnd <= dataLen else { return nil }

        // Iterate over NegoData entries inside the outer SEQUENCE
        offset = outerContentOff
        while offset < outerEnd {
            // Each NegoData is: SEQUENCE { [0] OCTET_STRING }
            guard offset < outerEnd, data[offset] == tagSequence else { break }
            guard let (negoLen, negoContentOff) = parseLength(data, offset: offset + 1, dataLen: outerEnd) else { break }
            let negoEnd = negoContentOff + negoLen
            guard negoEnd <= outerEnd else { break }

            // Inside NegoData, find [0] OCTET_STRING
            var innerOff = negoContentOff
            while innerOff < negoEnd {
                guard innerOff < outerEnd else { break }
                let tag = data[innerOff]
                guard let (tagLen, tagContentOff) = parseLength(data, offset: innerOff + 1, dataLen: negoEnd) else { break }
                let tagEnd = tagContentOff + tagLen
                guard tagEnd <= negoEnd else { break }

                if tag == 0xA0 {
                    // [0] context-specific — its content should be an OCTET_STRING
                    let octOff = tagContentOff
                    guard octOff < negoEnd else { break }
                    guard data[octOff] == tagOctetString else { break }
                    guard let (octLen, octDataOff) = parseLength(data, offset: octOff + 1, dataLen: negoEnd) else { break }
                    let octEnd = octDataOff + octLen
                    guard octEnd <= negoEnd else { break }
                    tokens.append(data.subdata(in: octDataOff..<octEnd))
                    innerOff = tagEnd
                    continue
                }

                innerOff = tagEnd
            }

            offset = negoEnd
        }

        return tokens
    }
}

// MARK: - TSRequest value type

struct TSRequest {
    var version: UInt32 = 0
    var negoTokens: [Data] = []
    var authInfo: Data?
    var pubKeyAuth: Data?
    var errorCode: UInt32?
    var nonce: Data?
}
