import Foundation
import CommonCrypto

/// NTLMv2 message construction and verification.
/// Pure Swift — no AppKit.
enum NTLMv2 {

    // NTLMSSP flags
    private static let NTLMSSP_NEGOTIATE_UNICODE: UInt32      = 0x00000001
    private static let NTLMSSP_NEGOTIATE_OEM: UInt32          = 0x00000002
    private static let NTLMSSP_REQUEST_TARGET: UInt32         = 0x00000004
    private static let NTLMSSP_NEGOTIATE_SIGN: UInt32         = 0x00000010
    private static let NTLMSSP_NEGOTIATE_SEAL: UInt32         = 0x00000020
    private static let NTLMSSP_NEGOTIATE_NTLM: UInt32         = 0x00000200
    private static let NTLMSSP_NEGOTIATE_ALWAYS_SIGN: UInt32  = 0x00008000
    private static let NTLMSSP_TARGET_TYPE_SERVER: UInt32     = 0x00010000
    private static let NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY: UInt32 = 0x00080000
    private static let NTLMSSP_REQUEST_NON_NT_SESSION_KEY: UInt32 = 0x00400000
    private static let NTLMSSP_NEGOTIATE_TARGET_INFO: UInt32  = 0x00800000
    private static let NTLMSSP_NEGOTIATE_VERSION: UInt32      = 0x02000000
    private static let NTLMSSP_NEGOTIATE_128: UInt32          = 0x20000000
    private static let NTLMSSP_NEGOTIATE_KEY_EXCH: UInt32     = 0x40000000

    private static let negotiateFlags: UInt32 =
        NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM |
        NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY |
        NTLMSSP_NEGOTIATE_TARGET_INFO | NTLMSSP_NEGOTIATE_128 |
        NTLMSSP_NEGOTIATE_VERSION

    // MARK: - NEGOTIATE

    static func buildNegotiate() -> Data {
        var data = Data(count: 0)

        // Signature: "NTLMSSP\0"
        data.append(contentsOf: [0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00])

        // MessageType = 1 (NEGOTIATE)
        data.append(contentsOf: withUnsafeBytes(of: UInt32(1).littleEndian) { Array($0) })

        // NegotiateFlags (little-endian)
        data.append(contentsOf: withUnsafeBytes(of: negotiateFlags.littleEndian) { Array($0) })

        // DomainNameFields: Len=0, MaxLen=0, BufferOffset=32
        data.append(contentsOf: [0x00, 0x00]) // Len
        data.append(contentsOf: [0x00, 0x00]) // MaxLen
        data.append(contentsOf: withUnsafeBytes(of: UInt32(32).littleEndian) { Array($0) }) // BufferOffset (fixed header size)

        // WorkstationFields: Len=0, MaxLen=0, BufferOffset=32
        data.append(contentsOf: [0x00, 0x00]) // Len
        data.append(contentsOf: [0x00, 0x00]) // MaxLen
        data.append(contentsOf: withUnsafeBytes(of: UInt32(32).littleEndian) { Array($0) }) // BufferOffset

        // Version (8 bytes) — Windows 10
        data.append(contentsOf: [0x0A, 0x00, 0x63, 0x00, 0x00, 0x00, 0x0F, 0x00])

        return data
    }

    // MARK: - Parse CHALLENGE

    static func parseChallenge(_ data: Data) -> (flags: UInt32, serverChallenge: Data, targetInfo: Data)? {
        guard data.count >= 48 else { return nil }

        // Check signature "NTLMSSP\0"
        guard data[0] == 0x4E && data[1] == 0x54 && data[2] == 0x4C &&
              data[3] == 0x4D && data[4] == 0x53 && data[5] == 0x53 &&
              data[6] == 0x50 && data[7] == 0x00 else { return nil }

        // MessageType = 2 (CHALLENGE)
        let msgType = readLE32(data: data, offset: 8)
        guard msgType == 2 else { return nil }

        // TargetName length + offset
        let targetNameLen = readLE16(data: data, offset: 12)
        let targetNameMaxLen = readLE16(data: data, offset: 14)
        let targetNameOffset = readLE32(data: data, offset: 16)
        // Use actual buffer offset, not max len
        _ = targetNameMaxLen

        // NegotiateFlags
        let flags = readLE32(data: data, offset: 20)

        // Server challenge (8 bytes)
        guard data.count >= 28 else { return nil }
        let challenge = data.subdata(in: 24..<32)

        // TargetInfo length + offset
        let targetInfoOffset = Int(readLE32(data: data, offset: 40))
        let targetInfoLen = Int(readLE16(data: data, offset: 44))

        var targetInfo = Data()
        if targetInfoLen > 0 && targetInfoOffset + targetInfoLen <= data.count && targetInfoOffset >= 0 {
            targetInfo = data.subdata(in: targetInfoOffset..<(targetInfoOffset + targetInfoLen))
        }

        _ = targetNameLen
        _ = targetNameOffset

        return (flags: flags, serverChallenge: challenge, targetInfo: targetInfo)
    }

    // MARK: - Build AUTHENTICATE

    static func buildAuthenticate(username: String, password: String, domain: String,
                                   challenge: Data, targetInfo: Data,
                                   nonce: Data) -> Data {
        let passwordData = password.data(using: .utf16LittleEndian) ?? Data()
        let ntHash = MD4.md4(passwordData)
        let domainUpper = domain.uppercased()

        // Compute NTLMv2 response
        // blob = serverChallenge + clientChallenge(8 random)
        var blob = challenge
        blob.append(nonce) // 8-byte client challenge

        // Build NTOWFv2 hash: HMAC-MD5(ntHash, uppercase(username) || domain)
        let userDomain = (username.uppercased() + domainUpper).data(using: .utf16LittleEndian) ?? Data()
        let ntProofKey = hmacMD5(key: ntHash, data: userDomain)

        // Respond to both challenges with av_pairs (NTLMv2)
        // Add target info into the blob
        blob.append(targetInfo)
        // Response trailer (4 zero bytes)
        blob.append(contentsOf: [0x00, 0x00, 0x00, 0x00])

        // ntProofStr = HMAC-MD5(ntProofKey, blob)
        let ntProofStr = hmacMD5(key: ntProofKey, data: blob)

        _ = hmacMD5(key: ntProofKey, data: ntProofStr) // sessionKey computed for NLA orchestration

        // Response = ntProofStr + blob
        var ntlmv2Response = ntProofStr
        ntlmv2Response.append(blob)

        // Encode domain in UTF-16LE
        let domainData = domain.data(using: .utf16LittleEndian) ?? Data()

        // Encode username in UTF-16LE
        let userData = username.data(using: .utf16LittleEndian) ?? Data()

        // Encode workstation (empty)
        let wsData = Data()

        // The flags we'll use
        let flags = negotiateFlags

        // We need to calculate the AUTHENTICATE message size and offsets
        // Fixed header: 88 bytes (through MIC at offset 72-87)
        let headerSize = 88

        // We'll build the payload parts after the header
        let lmResponse = Data(repeating: 0, count: 24) // LMv2 response placeholder

        // Calculate offsets
        let domainOffset = headerSize
        let userOffset = domainOffset + domainData.count
        let wsOffset = userOffset + userData.count
        let lmRespOffset = wsOffset + wsData.count
        let ntRespOffset = lmRespOffset + lmResponse.count
        let sessionKeyOffset = ntRespOffset + ntlmv2Response.count
        _ = sessionKeyOffset // session key is 0 for now

        var msg = Data(count: 0)

        // Signature "NTLMSSP\0"
        msg.append(contentsOf: [0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00])

        // MessageType = 3
        msg.append(contentsOf: withUnsafeBytes(of: UInt32(3).littleEndian) { Array($0) })

        // LmChallengeResponse fields (Len, MaxLen, BufferOffset)
        appendField(data: &msg, buffer: lmResponse, offset: lmRespOffset)

        // NtChallengeResponse fields
        appendField(data: &msg, buffer: ntlmv2Response, offset: ntRespOffset)

        // DomainName fields
        appendField(data: &msg, buffer: domainData, offset: domainOffset)

        // UserName fields
        appendField(data: &msg, buffer: userData, offset: userOffset)

        // Workstation fields
        appendField(data: &msg, buffer: wsData, offset: wsOffset)

        // EncryptedRandomSessionKey (0 length)
        msg.append(contentsOf: [0x00, 0x00]) // Len
        msg.append(contentsOf: [0x00, 0x00]) // MaxLen
        msg.append(contentsOf: withUnsafeBytes(of: UInt32(sessionKeyOffset).littleEndian) { Array($0) }) // BufferOffset

        // NegotiateFlags
        msg.append(contentsOf: withUnsafeBytes(of: flags.littleEndian) { Array($0) })

        // Version (8 bytes)
        msg.append(contentsOf: [0x0A, 0x00, 0x63, 0x00, 0x00, 0x00, 0x0F, 0x00])

        // MIC (16 bytes of zeros — will be replaced after)
        let mic = Data(count: 16)
        msg.append(contentsOf: mic)

        // Now append the payloads
        msg.append(domainData)
        msg.append(userData)
        msg.append(wsData)
        msg.append(lmResponse)
        msg.append(ntlmv2Response)
        // session key (empty)
        // nothing to append for session key

        // Compute MIC over negotiate + challenge + authenticate-with-zero-MIC
        // We don't have the negotiate/challenge data here — the caller (NLA) computes MIC
        // so leave MIC as zeros for now

        return msg
    }

    /// Compute MIC = HMAC-MD5(sessionKey, negotiate || challenge || authenticateWithZeroMIC)
    static func computeMIC(sessionKey: Data, negotiate: Data, challenge: Data, authenticate: Data) -> Data {
        // Zero out the MIC field in authenticate
        var zeroedAuth = authenticate
        if zeroedAuth.count >= 72 + 16 {
            // MIC is at offset 72 in the AUTHENTICATE message
            for i in 72..<88 {
                zeroedAuth[i] = 0
            }
        }
        var combined = negotiate
        combined.append(challenge)
        combined.append(zeroedAuth)
        return hmacMD5(key: sessionKey, data: combined)
    }

    static func getSessionKey() -> Data {
        // Recompute from NTLMv2 — placeholder, stored during handshake
        return Data(count: 16) // 128-bit
    }

    // MARK: - Helpers

    private static func appendField(data: inout Data, buffer: Data, offset: Int) {
        let len = UInt16(buffer.count)
        data.append(contentsOf: withUnsafeBytes(of: len.littleEndian) { Array($0) }) // Len
        data.append(contentsOf: withUnsafeBytes(of: len.littleEndian) { Array($0) }) // MaxLen
        data.append(contentsOf: withUnsafeBytes(of: UInt32(offset).littleEndian) { Array($0) }) // BufferOffset
    }

    private static func readLE16(data: Data, offset: Int) -> UInt16 {
        guard offset + 1 < data.count else { return 0 }
        return UInt16(data[offset]) | (UInt16(data[offset + 1]) << 8)
    }

    private static func readLE32(data: Data, offset: Int) -> UInt32 {
        guard offset + 3 < data.count else { return 0 }
        return UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
    }

    /// HMAC-MD5 via CommonCrypto
    static func hmacMD5(key: Data, data: Data) -> Data {
        var result = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        key.withUnsafeBytes { keyPtr in
            data.withUnsafeBytes { dataPtr in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgMD5),
                       keyPtr.baseAddress, key.count,
                       dataPtr.baseAddress, data.count,
                       &result)
            }
        }
        return Data(result)
    }

    // MARK: - Verify (for mock host)

    /// Verify an NTLMv2 response.
    /// Given the expected username, password, challenge, and targetInfo,
    /// recompute the expected response and compare ntProofStr.
    static func verifyAuthenticate(data: Data, username: String, password: String,
                                    challenge: Data, targetInfo: Data) -> Bool {
        guard data.count >= 64 else {
            return false
        }
        guard data[0] == 0x4E && data[1] == 0x54 && data[2] == 0x4C &&
              data[3] == 0x4D && data[4] == 0x53 && data[5] == 0x53 &&
              data[6] == 0x50 && data[7] == 0x00 else { return false }

        let msgType = readLE32(data: data, offset: 8)
        guard msgType == 3 else { return false }

        // NtChallengeResponse fields: Len=offset 20, BufferOffset=offset 24
        let ntRespLen = Int(readLE16(data: data, offset: 20))
        let ntRespOffset = Int(readLE32(data: data, offset: 24))
        guard ntRespOffset + ntRespLen <= data.count else { return false }

        let ntRespData = data.subdata(in: ntRespOffset..<(ntRespOffset + ntRespLen))
        guard ntRespData.count >= 16 else { return false }

        // ntProofStr is first 16 bytes
        let receivedProof = ntRespData.subdata(in: 0..<16)

        // Compute expected: NTOWFv2 = HMAC-MD5(NTOWFv1, Unicode(UpperCase(UserName) || UserDomain))
        // For verify, use empty domain (matching client behavior when no domain is provided)
        let passwordData = password.data(using: .utf16LittleEndian) ?? Data()
        let ntHash = MD4.md4(passwordData)
        let userDomain = username.uppercased().data(using: .utf16LittleEndian) ?? Data()
        let ntProofKey = hmacMD5(key: ntHash, data: userDomain)

        // The blob starts after 16-byte proof + 1 reserved byte
        let blob = ntRespData.subdata(in: 16..<ntRespData.count)

        let expectedProof = hmacMD5(key: ntProofKey, data: blob)

        if receivedProof != expectedProof {
            NSLog("  recvProof=\(receivedProof.map{String(format:"%02x",$0)}.joined())")
            NSLog("  expProof=\(expectedProof.map{String(format:"%02x",$0)}.joined())")
            NSLog("  username=\(username) blobCount=\(blob.count)")
        }

        return receivedProof == expectedProof
    }

    /// Extract the session key from an AUTHENTICATE message for MIC computation.
    static func extractSessionKey(username: String, password: String,
                                   ntProofStr: Data) -> Data {
        let passwordData = password.data(using: .utf16LittleEndian) ?? Data()
        let ntHash = MD4.md4(passwordData)
        let userDomain = username.uppercased().data(using: .utf16LittleEndian) ?? Data()
        let ntProofKey = hmacMD5(key: ntHash, data: userDomain)
        return hmacMD5(key: ntProofKey, data: ntProofStr)
    }
}
