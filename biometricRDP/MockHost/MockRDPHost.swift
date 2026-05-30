import Foundation
import Network
import Security

final class MockRDPHost {

    private(set) var port: NWEndpoint.Port = .any
    var width: Int = 1280
    var height: Int = 800
    var bpp: Int = 32
    private var nlaEnabled: Bool = false
    private var mockUsername: String = ""
    private var mockPassword: String = ""
    private var serverChallengeData: Data = Data()
    private var targetInfoData: Data = Data()

    private var listener: NWListener?
    private var connection: NWConnection?
    private let queue = DispatchQueue(label: "mock-rdp-host")
    private var lastKeys: [[String: Any]] = []
    private var lastMouse: [[String: Any]] = []
    private var lastText: String = ""

    // MARK: - Embedded self-signed PKCS#12 identity (base64-encoded, password: "mock")

    private static let mockP12Base64 = "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"

    func start(nla: Bool, username: String, password: String,
               width: Int, height: Int, bpp: Int) throws {
        self.width = width
        self.height = height
        self.bpp = bpp
        self.nlaEnabled = nla
        self.mockUsername = username
        self.mockPassword = password

        // Create TLS parameters with embedded self-signed cert
        let tlsOptions = NWProtocolTLS.Options()
        let params = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())

        // Build SecIdentity from embedded PKCS#12 blob
        guard let identity = Self.loadTLSIdentity() else {
            throw NSError(domain: "MockRDPHost", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "failed to create TLS identity"])
        }
        sec_protocol_options_set_local_identity(tlsOptions.securityProtocolOptions, identity)

        listener = try NWListener(using: params, on: .any)
        listener?.stateUpdateHandler = { state in
            if case .failed(let err) = state {
                NSLog("MockRDPHost listener failed: \(err)")
            }
        }
        listener?.newConnectionHandler = { [weak self] conn in
            self?.handleConnection(conn)
        }
        listener?.start(queue: queue)

        var waited = 0
        while (listener?.port ?? .any) == .any && waited < 100 {
            Thread.sleep(forTimeInterval: 0.01)
            waited += 1
        }
        guard let p = listener?.port, p != .any else {
            throw NSError(domain: "MockRDPHost", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "no port assigned"])
        }
        self.port = p
    }

    var isRunning: Bool { listener != nil }
    var hasClientConnected: Bool { connection != nil }

    func stop() {
        connection?.cancel()
        connection = nil
        listener?.cancel()
        listener = nil
        port = .any
        lastKeys = []
        lastMouse = []
        lastText = ""
        serverChallengeData = Data()
    }

    func lastInputKeys() -> [[String: Any]] { lastKeys }
    func lastInputMouse() -> [[String: Any]] { lastMouse }
    func lastInputText() -> String { lastText }
    func pushSolid(r: UInt8, g: UInt8, b: UInt8) { /* S2 placeholder */ }

    // MARK: - PKCS#12 → sec_identity_t

    private static func loadTLSIdentity() -> sec_identity_t? {
        guard let p12Data = Data(base64Encoded: mockP12Base64) else { return nil }
        let options: [String: String] = [kSecImportExportPassphrase as String: "mock"]
        var items: CFArray?
        let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &items)
        guard status == errSecSuccess, let arr = items as? [[String: Any]] else { return nil }
        guard let first = arr.first, let identity = first[kSecImportItemIdentity as String] else { return nil }
        return sec_identity_create(identity as! SecIdentity)
    }

    // MARK: - Connection handling

    private func handleConnection(_ conn: NWConnection) {
        connection = conn
        conn.start(queue: queue)
        handleHandshakePhase(conn)
    }

    private enum Phase { case waitingCR, waitingNLA, waitingNLAAuth, waitingMCS, waitingCaps, active }

    private func handleHandshakePhase(_ conn: NWConnection) {
        var phase: Phase = .waitingCR
        var buf = Data()

        func tryProcess() -> Bool {
            switch phase {
            case .waitingNLA:
                if let tsReq = self.consumeTSRequest(buf: &buf) {
                    let (serverChallenge, targetInfo, challengeTS) = self.buildNLAChallenge(from: tsReq)
                    self.serverChallengeData = serverChallenge
                    self.targetInfoData = targetInfo
                    conn.send(content: challengeTS, completion: .contentProcessed { _ in })
                    phase = .waitingNLAAuth
                    return true
                }
            case .waitingNLAAuth:
                if let authTSReq = self.consumeTSRequest(buf: &buf) {
                    let valid = self.validateNLAAuth(authTSReq)
                    if valid {
                        let successTS = self.buildNLASuccess()
                        conn.send(content: successTS, completion: .contentProcessed { _ in })
                        phase = .waitingMCS
                    } else {
                        let failTS = self.buildNLAFailure()
                        conn.send(content: failTS, completion: .contentProcessed { _ in
                            conn.cancel()
                            self.connection = nil
                        })
                        return false
                    }
                    return true
                }
            case .waitingCR:
                if self.consumeX224CR(buf: &buf) {
                    let proto: UInt32 = self.nlaEnabled ? 0x01 : 0x00
                    conn.send(content: self.buildCC(negotiatedProtocol: proto), completion: .contentProcessed { _ in })
                    if self.nlaEnabled {
                        phase = .waitingNLA
                    } else {
                        phase = .waitingMCS
                    }
                    return true
                }
            case .waitingMCS:
                if self.consumeMCSConnect(buf: &buf) {
                    conn.send(content: self.buildMCSResponse(), completion: .contentProcessed { _ in })
                    phase = .waitingCaps
                    return true
                }
            case .waitingCaps:
                if self.consumeCapabilities(buf: &buf) {
                    conn.send(content: self.buildDemandActive(), completion: .contentProcessed { _ in })
                    phase = .active
                    return true
                }
            case .active:
                return false
            }
            return false
        }

        func readNext() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, _ in
                guard let self else { return }
                if let d = data, !d.isEmpty { buf.append(d) }

                // Loop to process all buffered messages
                while phase != .active {
                    if !tryProcess() { break }
                }

                if phase == .active {
                    if isComplete { conn.cancel(); self.connection = nil }
                    return
                }

                if isComplete {
                    conn.cancel(); self.connection = nil
                    return
                }

                readNext()
            }
        }
        readNext()
    }

    // MARK: - PDU consumers

    // MARK: - NLA helpers

    private func consumeTSRequest(buf: inout Data) -> TSRequest? {
        // We need to find where the DER sequence starts
        // A TSRequest is a SEQUENCE, so find the first 0x30 and try to parse
        guard !buf.isEmpty else { return nil }

        // Use CredSSP.parseTSRequest which handles DER
        guard let tsReq = CredSSP.parseTSRequest(buf) else { return nil }

        // We need to determine how many bytes consumed from buf
        // Re-encode to figure out consumed length (not perfect but works for testing)
        // Better: estimate from the data — we know the negoTokens contain the NTLM messages
        // For simplicity, find the total DER length by re-wrapping
        let consumed = estimateTSRequestLength(buf)
        if consumed > 0 && consumed <= buf.count {
            buf = Data(buf.dropFirst(consumed))
        } else {
            // Fallback: consume all we have
            buf = Data()
        }
        return tsReq
    }

    /// Estimate the total DER length of the TSRequest at the start of `buf`.
    /// Parse the top-level SEQUENCE header to get total length.
    private static func estimateTSRequestLength(_ buf: Data) -> Int {
        guard buf.count >= 2 else { return 0 }
        guard buf[0] == 0x30 else { return 0 }
        var offset = 1
        let firstLen = Int(buf[offset])
        offset += 1
        var contentLen = 0
        if firstLen < 0x80 {
            contentLen = firstLen
            return offset + contentLen
        }
        let numBytes = firstLen & 0x7F
        guard offset + numBytes <= buf.count else { return 0 }
        contentLen = 0
        for i in 0..<numBytes {
            contentLen = (contentLen << 8) | Int(buf[offset + i])
        }
        return offset + numBytes + contentLen
    }

    private func estimateTSRequestLength(_ buf: Data) -> Int {
        return MockRDPHost.estimateTSRequestLength(buf)
    }

    private func buildNLAChallenge(from tsReq: TSRequest) -> (serverChallenge: Data, targetInfo: Data, challengeTS: Data) {
        // Generate 8-byte random server challenge
        var challenge = Data(count: 8)
        _ = challenge.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 8, ptr.baseAddress!)
        }

        // Build target info for NTLM CHALLENGE
        let targetInfo = buildTargetInfo()

        // Build NTLM CHALLENGE message
        let ntlmChallenge = buildNTLMChallenge(serverChallenge: challenge, targetInfo: targetInfo)

        // Wrap in TSRequest as negoTokens[0]
        let challengeTS = CredSSP.wrapTSRequest(negoTokens: [ntlmChallenge])
        return (challenge, targetInfo, challengeTS)
    }

    private func buildNTLMChallenge(serverChallenge: Data, targetInfo: Data) -> Data {
        var msg = Data()

        // Signature "NTLMSSP\0"
        msg.append(contentsOf: [0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00])

        // MessageType = 2
        msg.append(contentsOf: withUnsafeBytes(of: UInt32(2).littleEndian) { Array($0) })

        // TargetName fields (Len=0, MaxLen=0, BufferOffset=56)
        msg.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // Len + MaxLen
        msg.append(contentsOf: withUnsafeBytes(of: UInt32(56).littleEndian) { Array($0) }) // BufferOffset

        // NegotiateFlags
        let flags: UInt32 = 0x00020201 | 0x00800001 | 0x02000000 | 0x00080000 | 0x00200000 | 0x20000000 | 0x80000000
        msg.append(contentsOf: withUnsafeBytes(of: flags.littleEndian) { Array($0) })

        // Server challenge (8 bytes)
        msg.append(contentsOf: serverChallenge)

        // Reserved (8 bytes)
        msg.append(contentsOf: [UInt8](repeating: 0, count: 8))

        // TargetInfo fields
        let targetInfoOffset = 56
        msg.append(contentsOf: withUnsafeBytes(of: UInt16(targetInfo.count).littleEndian) { Array($0) }) // Len
        msg.append(contentsOf: withUnsafeBytes(of: UInt16(targetInfo.count).littleEndian) { Array($0) }) // MaxLen
        msg.append(contentsOf: withUnsafeBytes(of: UInt32(targetInfoOffset).littleEndian) { Array($0) }) // BufferOffset

        // Version (8 bytes)
        msg.append(contentsOf: [0x0A, 0x00, 0x63, 0x00, 0x00, 0x00, 0x0F, 0x00])

        // TargetName (empty) + TargetInfo
        msg.append(targetInfo)

        return msg
    }

    private func buildTargetInfo() -> Data {
        // Minimal target info with NetBIOS computer name and domain
        var info = Data()
        // MsvAvNbComputerName
        info.append(contentsOf: [0x01, 0x00]) // type
        let name = "MOCKHOST".data(using: .utf16LittleEndian) ?? Data()
        info.append(contentsOf: withUnsafeBytes(of: UInt16(name.count).littleEndian) { Array($0) }) // len
        info.append(name)
        // MsvAvNbDomainName
        info.append(contentsOf: [0x02, 0x00]) // type
        let domain = "WORKGROUP".data(using: .utf16LittleEndian) ?? Data()
        info.append(contentsOf: withUnsafeBytes(of: UInt16(domain.count).littleEndian) { Array($0) }) // len
        info.append(domain)
        // Terminator
        info.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        return info
    }

    private func validateNLAAuth(_ tsReq: TSRequest) -> Bool {
        // Extract the AUTHENTICATE message from negoTokens
        guard let authMsg = tsReq.negoTokens.first else {
            // Fall back: check password from authInfo (for compatibility)
            return checkAuthInfoPassword(tsReq)
        }

        // Validate NTLMv2 response
        return NTLMv2.verifyAuthenticate(data: authMsg,
                                          username: mockUsername,
                                          password: mockPassword,
                                          challenge: serverChallengeData,
                                          targetInfo: targetInfoData)
    }

    private func checkAuthInfoPassword(_ tsReq: TSRequest) -> Bool {
        guard let authInfo = tsReq.authInfo, authInfo.count >= 6 else { return false }
        var off = 0
        guard authInfo.count >= off + 2 else { return false }
        let domainLen = Int(readLE16(data: authInfo, offset: off))
        off += 2
        guard authInfo.count >= off + domainLen else { return false }
        off += domainLen
        guard authInfo.count >= off + 2 else { return false }
        let userLen = Int(readLE16(data: authInfo, offset: off))
        off += 2
        guard authInfo.count >= off + userLen else { return false }
        off += userLen
        guard authInfo.count >= off + 2 else { return false }
        let passLen = Int(readLE16(data: authInfo, offset: off))
        off += 2
        guard authInfo.count >= off + passLen else { return false }
        let passData = authInfo.subdata(in: off..<(off + passLen))
        let receivedPassword = String(data: passData, encoding: .utf16LittleEndian) ?? ""
        return receivedPassword == mockPassword
    }

    private func readLE16(data: Data, offset: Int) -> UInt16 {
        guard offset + 1 < data.count else { return 0 }
        return UInt16(data[offset]) | (UInt16(data[offset + 1]) << 8)
    }

    private func buildNLASuccess() -> Data {
        // TSRequest with errorCode=0 (success)
        return CredSSP.buildTSRequest(
            version: 6,
            negoTokens: [],
            authInfo: nil,
            pubKeyAuth: Data(repeating: 0, count: 16), // dummy pubKeyAuth
            errorCode: 0,
            nonce: nil
        )
    }

    private func buildNLAFailure() -> Data {
        return CredSSP.buildTSRequest(
            version: 6,
            negoTokens: [],
            authInfo: nil,
            pubKeyAuth: nil,
            errorCode: 0xC000006D, // STATUS_LOGON_FAILURE
            nonce: nil
        )
    }

    // MARK: - PDU consumers

    private func consumeX224CR(buf: inout Data) -> Bool {
        guard buf.count >= 11 else { return false }
        guard buf[0] == 0x03 else { return false }
        let tpktLen = (Int(buf[2]) << 8) | Int(buf[3])
        guard tpktLen >= 7 else { return false }
        guard tpktLen <= buf.count else { return false } // must be complete
        let li = buf[4]
        guard li >= 5 else { return false }
        guard buf[5] == 0xE0 else { return false }
        buf = Data(buf.dropFirst(tpktLen))
        return true
    }

    private func consumeMCSConnect(buf: inout Data) -> Bool {
        guard buf.count >= 11 else { return false }
        guard buf[0] == 0x03 else { return false }
        let tpktLen = (Int(buf[2]) << 8) | Int(buf[3])
        guard tpktLen >= 7 else { return false }
        guard tpktLen <= buf.count else { return false } // must be complete
        guard buf[4] >= 2 else { return false }
        guard (buf[5] & 0xF0) == 0xF0 else { return false }
        let mcsStart = 7
        guard mcsStart < buf.count, buf[mcsStart] == 0x61 else { return false }
        buf = Data(buf.dropFirst(tpktLen))
        return true
    }

    private func consumeCapabilities(buf: inout Data) -> Bool {
        // Must have at least one complete TPKT + X.224 data PDU
        guard buf.count >= 7 else { return false }
        guard buf[0] == 0x03 else { return false }
        // Count how many complete TPKT packets are in the buffer
        var offset = 0
        var completePackets = 0
        while offset + 4 <= buf.count {
            guard buf[offset] == 0x03 else { break }
            let thisLen = (Int(buf[offset + 2]) << 8) | Int(buf[offset + 3])
            guard thisLen >= 7 else { break }
            guard offset + thisLen <= buf.count else { break } // must be complete
            // Verify X.224 data TPDU: LI >= 2, type 0xF0
            guard buf[offset + 4] >= 2 else { break }
            guard (buf[offset + 5] & 0xF0) == 0xF0 else { break }
            offset += thisLen
            completePackets += 1
        }
        guard completePackets > 0 else { return false }
        buf = Data(buf.dropFirst(offset))
        return true
    }

    // MARK: - PDU builders

    private func buildCC(negotiatedProtocol: UInt32 = 0) -> Data {
        let x224: [UInt8] = [0xD0, 0x00, 0x00, 0x00, 0x00, 0x00]
        let neg: [UInt8] = [
            0x02,             // TYPE_RDP_NEG_RSP
            0x00,             // flags
            0x08, 0x00,       // length = 8
            UInt8((negotiatedProtocol >> 24) & 0xFF),
            UInt8((negotiatedProtocol >> 16) & 0xFF),
            UInt8((negotiatedProtocol >> 8) & 0xFF),
            UInt8(negotiatedProtocol & 0xFF)
        ]
        var tpdu = x224; tpdu.append(contentsOf: neg)
        let totalLen = 4 + 1 + tpdu.count
        let tpkt: [UInt8] = [0x03, 0x00, UInt8((totalLen >> 8) & 0xFF), UInt8(totalLen & 0xFF)]
        var pkt = Data(tpkt)
        pkt.append(UInt8(1 + tpdu.count))
        pkt.append(contentsOf: tpdu)
        return pkt
    }

    private func buildMCSResponse() -> Data {
        // MCS Connect Response BER [APPLICATION 102]
        let result: [UInt8] = [0xA0, 0x01, 0x00] // success
        let connectId = Data([0x02, 0x01, 0x00])
        let domainParams = buildDomainParams()
        let gccRsp = buildGCCResponse()
        let userData = berOctetString(gccRsp)
        let seq = Data(result) + connectId + domainParams + userData
        let mcsBER = berWrap(tag: 0x62, content: seq)
        return wrapTPKT(payload: mcsBER)
    }

    private func buildDomainParams() -> Data {
        let fields = [berInt(34), berInt(3), berInt(0), berInt(1),
                      berInt(0), berInt(1), berInt(65535), berInt(2)]
        return berSequence(fields.reduce(Data()) { $0 + $1 })
    }

    private func buildGCCResponse() -> Data {
        // Minimal GCC Conference Create Response
        return Data([
            0x00, 0x14, 0x00, 0x00, // H.221 non-std key
            0x0C, 0x19, // ConnectPDU
            0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x14, 0x79, 0x70,
            0x04, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00
        ])
    }

    private func buildDemandActive() -> Data {
        let shareID: UInt32 = 0x03EA03EA
        var body = Data()
        body.append(contentsOf: withUnsafeBytes(of: shareID.littleEndian) { Array($0) })
        body.append(contentsOf: [0x04, 0x00]) // lengthSource
        body.append(contentsOf: [0x00, 0x00]) // combinedCapLen placeholder
        body.append(contentsOf: [0x01, 0x00]) // numCaps
        body.append(contentsOf: Array("RDP ".utf8))
        // General capability set
        body.append(contentsOf: [0x01, 0x00, 0x18, 0x00])
        body.append(contentsOf: [0x01, 0x00, 0x03, 0x00, 0x20, 0x00, 0x00, 0x00])
        body.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00])
        body.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        body.append(0x00) // pad
        let ccLen = body.count - 8
        body[10] = UInt8(ccLen & 0xFF)
        body[11] = UInt8((ccLen >> 8) & 0xFF)

        let pduSource: UInt16 = 0x03E9
        let totalLen = 6 + 4 + body.count
        var sc = Data()
        sc.append(UInt8(totalLen & 0xFF))
        sc.append(UInt8((totalLen >> 8) & 0xFF))
        sc.append(0x11) // PDUTYPE2_DEMANDACTIVE
        sc.append(UInt8(pduSource & 0xFF))
        sc.append(UInt8((pduSource >> 8) & 0xFF))
        sc.append(0x01) // streamID
        sc.append(UInt8((body.count + 12) & 0xFF))
        sc.append(UInt8(((body.count + 12) >> 8) & 0xFF))
        sc.append(0x11) // pduType2
        sc.append(0x00) // compression

        return wrapTPKT(payload: sc + body)
    }

    // MARK: - BER helpers

    private func berWrap(tag: UInt8, content: Data) -> Data {
        var r = Data([tag])
        r.append(berLength(content.count))
        r.append(content)
        return r
    }

    private func berSequence(_ c: Data) -> Data { berWrap(tag: 0x30, content: c) }
    private func berOctetString(_ d: Data) -> Data { berWrap(tag: 0x04, content: d) }
    private func berInt(_ v: Int) -> Data {
        if v >= 0 && v < 128 { return Data([0x02, 0x01, UInt8(v)]) }
        return Data([0x02, 0x02, UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)])
    }

    private func berLength(_ n: Int) -> Data {
        if n < 128 { return Data([UInt8(n)]) }
        if n <= 0xFF { return Data([0x81, UInt8(n)]) }
        return Data([0x82, UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)])
    }

    private func wrapTPKT(payload: Data) -> Data {
        let hdr: [UInt8] = [UInt8(2 + payload.count), 0xF0, 0x80]
        let tpktLen = 4 + hdr.count + payload.count
        let tpkt: [UInt8] = [0x03, 0x00, UInt8((tpktLen >> 8) & 0xFF), UInt8(tpktLen & 0xFF)]
        var pkt = Data(tpkt)
        pkt.append(contentsOf: hdr)
        pkt.append(payload)
        return pkt
    }
}
