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
        var lastKeys: [[String: Any]] = []
    var lastMouse: [[String: Any]] = []
    var lastText: String = ""



    func start(nla: Bool, username: String, password: String,
               width: Int, height: Int, bpp: Int,
               tlsIdentity: sec_identity_t?) throws {
        self.width = width
        self.height = height
        self.bpp = bpp
        self.nlaEnabled = nla
        self.mockUsername = username
        self.mockPassword = password

        let params = NWParameters.tcp

        listener = try NWListener(using: params, on: .any)
        listener?.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                if let p = self?.listener?.port {
                }
            case .failed(let err):
                NSLog("MockRDPHost listener failed: \(err)")
            default:
                break
            }
        }
        listener?.newConnectionHandler = { [weak self] conn in
            self?.handleConnection(conn)
        }
        listener?.start(queue: queue)

        // Wait for listener to be ready using a semaphore
        let sema = DispatchSemaphore(value: 0)
        let checkTimer = DispatchSource.makeTimerSource(queue: queue)
        checkTimer.schedule(deadline: .now(), repeating: .milliseconds(10))
        var ready = false
        checkTimer.setEventHandler { [weak self] in
            if let p = self?.listener?.port, p != .any {
                ready = true
                sema.signal()
            }
            if let s = self?.listener?.state, case .failed = s {
                sema.signal()
            }
        }
        checkTimer.resume()
        let waitResult = sema.wait(timeout: .now() + 5.0)
        checkTimer.cancel()

        guard ready, let p = listener?.port, p != .any else {
            listener?.cancel()
            listener = nil
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

    /// Parse and record an input PDU from the client (TS_INPUT_PDU = PDUTYPE2_INPUT 0x001C).
    /// packet is a complete TPKT packet (starts with 0x03,0x00,tpktLen...).
    private func handleInputPDU(packet: Data) {
        guard packet.count >= 4 else { return }
        // The TPKT packet: 0x03 0x00 lenHI lenLO LI ...
        var off = 4
        guard off < packet.count else { return }
        let li = packet[off]
        off += 1
        var hdrLen = 1
        var liVal = Int(li)
        if li == 0x81 {
            guard off < packet.count else { return }
            liVal = Int(packet[off]); off += 1; hdrLen = 2
        } else if li == 0x82 {
            guard off + 1 < packet.count else { return }
            liVal = (Int(packet[off]) << 8) | Int(packet[off + 1])
            off += 2; hdrLen = 3
        }
        // LI encodes bytes after the LI field. X.224 TPDU is inside:
        // off currently points at TPDU type (0xF0). Skip TPDU type + EOT = 2 bytes.
        off += 2
        guard off + 6 <= packet.count else { return }
        // Share Control Header: totalLen(2) + pduType2(2) + PDUSource(2)
        // totalLen at off..off+1 (unused, skip)
        let pduType2 = (Int(packet[off + 3]) << 8) | Int(packet[off + 2])
        off += 6
        // PDUTYPE2_INPUT = 0x001C ; PDUTYPE2_SYNCHRONISE = 0x1D; we only handle INPUT here
        guard pduType2 == 0x001C, off + 4 <= packet.count else { return }
        // TS_INPUT_PDU_DATA: numberEvents(2) + pad(2)
        let numberEvents = (Int(packet[off + 1]) << 8) | Int(packet[off])
        off += 4
        for _ in 0..<numberEvents {
            guard off + 8 <= packet.count else { return }
            off += 4 // eventTime
            let messageType = (Int(packet[off + 1]) << 8) | Int(packet[off])
            off += 2
            if messageType == 0x8001, off + 6 <= packet.count {
                // TS_POINTER_EVENT
                let pointerFlags = (Int(packet[off + 1]) << 8) | Int(packet[off])
                off += 2
                let xPos = (Int(packet[off + 1]) << 8) | Int(packet[off])
                off += 2
                let yPos = (Int(packet[off + 1]) << 8) | Int(packet[off])
                off += 2
                var button = "left"
                var action = "down"
                if pointerFlags & 0x0800 != 0 {
                    action = "move"
                } else if pointerFlags & 0x8000 != 0 {
                    if pointerFlags & 0x1000 != 0 { button = "left" }
                    else if pointerFlags & 0x2000 != 0 { button = "right" }
                    else if pointerFlags & 0x4000 != 0 { button = "middle" }
                } else {
                    // button up
                    if pointerFlags & 0x1000 != 0 { button = "left" }
                    else if pointerFlags & 0x2000 != 0 { button = "right" }
                    else if pointerFlags & 0x4000 != 0 { button = "middle" }
                    action = "up"
                }
                // For the client's "click" action, we receive a single down+button PDU.
                // Map "down" with a button to "click" per acceptance probe expectation.
                let recordAction = (action == "down") ? "click" : action
                lastMouse.append(["x": xPos, "y": yPos, "button": button, "action": recordAction])
            } else if messageType == 0x0001, off + 8 <= packet.count {
                // TS_KEYBOARD_EVENT: keyboardFlags(2) + pad(2) + keyCode(2) + flags(2)
                let keyboardFlags = (Int(packet[off + 1]) << 8) | Int(packet[off])
                off += 2 + 2 + 2 + 2
                let keyCode = (Int(packet[off - 3]) << 8) | Int(packet[off - 4])
                let down = (keyboardFlags & 0x8000) == 0
                lastKeys.append(["scancode": keyCode, "down": down])
            } else {
                break
            }
        }
    }

    func pushSolid(r: UInt8, g: UInt8, b: UInt8, x: Int = 0, y: Int = 0,
                    width: Int = -1, height: Int = -1) {
        guard let conn = connection else { return }

        let w = width < 0 ? self.width : width
        let h = height < 0 ? self.height : height
        let destX = x
        let destY = y

        guard w > 0, h > 0 else { return }

        let bytesPerPixel = bpp / 8
        guard bytesPerPixel > 0 else { return }

        // Build a solid-color pixel row
        let rowBytes = w * bytesPerPixel
        let paddedRowBytes = ((rowBytes + 3) / 4) * 4
        var solidRow = Data(count: paddedRowBytes)
        for col in 0..<w {
            let off = col * bytesPerPixel
            writeSolidPixel(data: &solidRow, offset: off, bytesPerPixel: bytesPerPixel, r: r, g: g, b: b)
        }

        // RDP totalLength and bitmapDataLength are 16-bit fields.
        // Send one TPKT packet per horizontal strip to stay within limits.
        // Each strip = one TS_BITMAP_DATA rectangle.
        // Max rows per strip so that: 6(header) + 4(update) + 18(bitmap_hdr) + rows*paddedRowBytes <= 65535
        let maxRowsPerStrip = max(1, (65535 - 6 - 4 - 18) / paddedRowBytes)
        var remainingRows = h
        var currentRow = 0 // 0 = top of rect

        while remainingRows > 0 {
            let stripRows = min(remainingRows, maxRowsPerStrip)
            let stripDestY = destY + currentRow
            let stripDestLeft = UInt16(destX)
            let stripDestTop = UInt16(stripDestY)
            let stripDestRight = UInt16(destX + w - 1)
            let stripDestBottom = UInt16(stripDestY + stripRows - 1)
            let stripW = UInt16(w)
            let stripH = UInt16(stripRows)
            let bppVal = UInt16(bpp)
            let rawFlags: UInt16 = 0

            var stripBitmapData = Data()
            for _ in 0..<stripRows {
                stripBitmapData.append(solidRow)
            }
            let bitmapDataLen = UInt16(stripBitmapData.count)

            // TS_BITMAP_DATA
            var bitmapBody = Data()
            bitmapBody.append(contentsOf: withUnsafeBytes(of: stripDestLeft.littleEndian) { Array($0) })
            bitmapBody.append(contentsOf: withUnsafeBytes(of: stripDestTop.littleEndian) { Array($0) })
            bitmapBody.append(contentsOf: withUnsafeBytes(of: stripDestRight.littleEndian) { Array($0) })
            bitmapBody.append(contentsOf: withUnsafeBytes(of: stripDestBottom.littleEndian) { Array($0) })
            bitmapBody.append(contentsOf: withUnsafeBytes(of: stripW.littleEndian) { Array($0) })
            bitmapBody.append(contentsOf: withUnsafeBytes(of: stripH.littleEndian) { Array($0) })
            bitmapBody.append(contentsOf: withUnsafeBytes(of: bppVal.littleEndian) { Array($0) })
            bitmapBody.append(contentsOf: withUnsafeBytes(of: rawFlags.littleEndian) { Array($0) })
            bitmapBody.append(contentsOf: withUnsafeBytes(of: bitmapDataLen.littleEndian) { Array($0) })
            bitmapBody.append(contentsOf: stripBitmapData)

            // TS_UPDATE_DATA: updateType=UPDATETYPE_BITMAP, numRects=1
            var updateBody = Data()
            updateBody.append(contentsOf: withUnsafeBytes(of: UInt16(0x0001).littleEndian) { Array($0) })
            updateBody.append(contentsOf: withUnsafeBytes(of: UInt16(1).littleEndian) { Array($0) })
            updateBody.append(bitmapBody)

            // Share Data Header: totalLen includes share control header (6) + update body
            let encodedPduType: UInt16 = 0x0002 // PDUTYPE2_UPDATE
            let pduSource: UInt16 = 0x03E9
            let shareDataLen = 6 + updateBody.count
            var shareData = Data()
            shareData.append(contentsOf: withUnsafeBytes(of: UInt16(shareDataLen).littleEndian) { Array($0) })
            shareData.append(contentsOf: withUnsafeBytes(of: encodedPduType.littleEndian) { Array($0) })
            shareData.append(contentsOf: withUnsafeBytes(of: pduSource.littleEndian) { Array($0) })
            shareData.append(updateBody)

            // Wrap in TPKT + X.224 and send synchronously
            let packet = wrapTPKT(payload: shareData)
            let sendDone = DispatchSemaphore(value: 0)
            var sendError: Error?
            conn.send(content: packet, completion: .contentProcessed { err in
                sendError = err
                sendDone.signal()
            })
            sendDone.wait()
            if let err = sendError {
                NSLog("MockRDPHost pushSolid send error: \(err)")
                return
            }

            currentRow += stripRows
            remainingRows -= stripRows
        }
    }

    /// Write a single solid-color pixel into a byte buffer at the given offset.
    private func writeSolidPixel(data: inout Data, offset: Int, bytesPerPixel: Int, r: UInt8, g: UInt8, b: UInt8) {
        if bytesPerPixel == 4 {
            data[offset]     = b
            data[offset + 1] = g
            data[offset + 2] = r
            data[offset + 3] = 0
        } else if bytesPerPixel == 3 {
            data[offset]     = b
            data[offset + 1] = g
            data[offset + 2] = r
        } else if bytesPerPixel == 2 {
            let r5 = (r >> 3) & 0x1F
            let g6 = (g >> 2) & 0x3F
            let b5 = (b >> 3) & 0x1F
            let pixel565 = (r5 << 11) | (g6 << 5) | b5
            data[offset]     = UInt8(pixel565 & 0xFF)
            data[offset + 1] = UInt8((pixel565 >> 8) & 0xFF)
        }
    }

    // MARK: - Self-signed cert → sec_identity_t

    // MARK: - Connection handling

    private func handleConnection(_ conn: NWConnection) {
        connection = conn
        conn.start(queue: queue)
        handleHandshakePhase(conn)
    }

    private enum Phase { case waitingCR, waitingNLA, waitingNLAAuth, waitingMCS, waitingCaps, active }

    private func handleHandshakePhase(_ conn: NWConnection) {
        // Always start at .waitingCR; after CR+CC, transition to either .waitingMCS or .waitingNLA
        var phase: Phase = .waitingCR
        var buf = Data()

        func tryProcess() -> Bool {
            switch phase {
            case .waitingCR:
                if self.consumeX224CR(buf: &buf) {
                    let proto: UInt32 = self.nlaEnabled ? 0x01 : 0x00
                    conn.send(content: self.buildCC(negotiatedProtocol: proto), completion: .contentProcessed { _ in
                    })
                    if self.nlaEnabled {
                        phase = .waitingNLA
                    } else {
                        phase = .waitingMCS
                    }
                    return true
                }
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
                        conn.send(content: successTS, completion: .contentProcessed { _ in
                        })
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
                // Process any buffered complete TPKT packets as input
                return self.processActiveBuffer(buf: &buf)
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
                    // Enter active phase: continue reading input PDUs
                    self.readActivePhase(conn: conn, buf: &buf)
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

    /// Parse a complete TPKT packet from the buffer if one is present.
    /// Returns true if a complete TPKT was found.
    private func parseOneTPKT(buf: inout Data) -> Data? {
        guard buf.count >= 4, buf[0] == 0x03 else { return nil }
        let tpktLen = (Int(buf[2]) << 8) | Int(buf[3])
        guard tpktLen >= 7, tpktLen <= buf.count else { return nil }
        let packet = Data(buf.prefix(tpktLen))
        buf = Data(buf.dropFirst(tpktLen))
        return packet
    }

    /// Process any complete TPKT packets already buffered during phase transition.
    private func processActiveBuffer(buf: inout Data) -> Bool {
        var consumed = false
        while let packet = parseOneTPKT(buf: &buf) {
            handleInputPDU(packet: packet)
            consumed = true
        }
        return consumed
    }

    /// Active-phase reader loop: receive data from the client, parse TPKT packets,
    /// and record input events.
    private func readActivePhase(conn: NWConnection, buf: inout Data) {
        // Drain buffered data synchronously first
        while let packet = self.parseOneTPKT(buf: &buf) {
            self.handleInputPDU(packet: packet)
        }
        self.activeConn = conn
        self.activeBuf = buf
        self.continueActiveRead()
    }

    private var activeConn: NWConnection?
    private var activeBuf = Data()

    private func continueActiveRead() {
        guard let conn = activeConn else { return }
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, _ in
            guard let self else { return }
            if let d = data, !d.isEmpty { self.activeBuf.append(d) }
            while let packet = self.parseOneTPKT(buf: &self.activeBuf) {
                self.handleInputPDU(packet: packet)
            }
            if isComplete {
                conn.cancel()
                self.connection = nil
                self.activeConn = nil
                return
            }
            self.continueActiveRead()
        }
    }

    // MARK: - PDU consumers

    // MARK: - NLA helpers

    private func consumeTSRequest(buf: inout Data) -> TSRequest? {
        guard !buf.isEmpty else { return nil }
        // Try to parse the TSRequest from the buffer
        guard let tsReq = CredSSP.parseTSRequest(buf) else { return nil }
        // Figure out how many bytes were consumed by parsing the DER length
        let consumed = MockRDPHost.estimateDERTotalLength(buf)
        if consumed > 0 && consumed <= buf.count {
            buf = Data(buf.dropFirst(consumed))
        } else {
            buf = Data()
        }
        return tsReq
    }

    /// Parse the DER length at the start of a SEQUENCE (0x30) and return total bytes.
    private static func estimateDERTotalLength(_ buf: Data) -> Int {
        guard buf.count >= 2 else { return 0 }
        guard buf[0] == 0x30 else { return 0 }
        var off = 1
        let lenByte = Int(buf[off])
        off += 1
        if lenByte < 0x80 {
            // Short form: total = tag(1) + len(1) + content
            return off + lenByte
        }
        // Long form
        let numBytes = lenByte & 0x7F
        guard numBytes > 0 && off + numBytes <= buf.count else { return 0 }
        var contentLen = 0
        for i in 0..<numBytes {
            contentLen = (contentLen << 8) | Int(buf[off + i])
        }
        return off + numBytes + contentLen
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
        // TSRequest with errorCode=0 (success), no pubKeyAuth to simplify client processing
        return CredSSP.buildTSRequest(
            version: 6,
            negoTokens: [],
            authInfo: nil,
            pubKeyAuth: nil,
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
            UInt8(negotiatedProtocol & 0xFF),
            UInt8((negotiatedProtocol >> 8) & 0xFF),
            UInt8((negotiatedProtocol >> 16) & 0xFF),
            UInt8((negotiatedProtocol >> 24) & 0xFF)
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
        // X.224 data TPDU header: LI + 0xF0 + 0x80(EOT)
        // LI encodes the length of bytes after the LI byte (0xF0 + 0x80 + payload).
        // For payloads > 253 bytes, use extended LI: 0x82 + 2-byte LE length.
        let x224PayloadLen = 2 + payload.count // 0xF0 + 0x80 + payload
        var x224Hdr = Data()
        if x224PayloadLen < 128 {
            x224Hdr.append(UInt8(x224PayloadLen))
        } else {
            // Extended length: 0x82 + 2-byte LE length
            x224Hdr.append(0x82)
            x224Hdr.append(UInt8(x224PayloadLen & 0xFF))
            x224Hdr.append(UInt8((x224PayloadLen >> 8) & 0xFF))
        }
        x224Hdr.append(0xF0) // data TPDU
        x224Hdr.append(0x80) // EOT
        let tpktLen = 4 + x224Hdr.count + payload.count
        let tpkt: [UInt8] = [0x03, 0x00, UInt8((tpktLen >> 8) & 0xFF), UInt8(tpktLen & 0xFF)]
        var pkt = Data(tpkt)
        pkt.append(contentsOf: x224Hdr)
        pkt.append(payload)
        return pkt
    }
}
