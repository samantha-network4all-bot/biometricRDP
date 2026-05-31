import Foundation

final class RDPSession {

    enum State: String {
        case disconnected
        case connecting
        case tcp
        case tls
        case nla
        case x224
        case mcs
        case capabilities
        case active
        case failed
    }

    private(set) var state: State = .disconnected
    var errorReason: String = ""
    private let stateLock = NSLock()

    internal var transport: Transport
    var width: Int = 0
    var height: Int = 0
    var bpp: Int = 0
    var host: String = ""
    var port: UInt16 = 0
    var security: String = ""

    private(set) var framebuffer: Framebuffer

    // Virtual channel: cliprdr
    let clipboardChannelID: UInt16 = 0x0010
    var clipboardMessageHandler: ((Data) -> Void)?

    // Virtual channel: rdpsnd (audio)
    let audioChannelID: UInt16 = 0x0011
    var audioMessageHandler: ((Data) -> Void)?

    // Virtual channel: rdpdr (drive/device redirection)
    let drivesChannelID: UInt16 = 0x0012
    var drivesMessageHandler: ((Data) -> Void)?
    private var readerActive = false
    private let readerQueue = DispatchQueue(label: "rdp-session-reader")
    private var recvBuffer = Data()

    private static let connectTimeout: TimeInterval = 10.0

    init(transport: Transport) {
        self.transport = transport
        self.framebuffer = Framebuffer(width: 1, height: 1)
    }

    private func setState(_ newState: State) {
        stateLock.lock()
        state = newState
        stateLock.unlock()
    }

    func connect(host: String, port: UInt16, username: String, password: String,
                 width: Int, height: Int, bpp: Int, nla: Bool = true) {
        self.host = host
        self.port = port
        self.width = width
        self.height = height
        self.bpp = bpp
        self.security = ""
        self.errorReason = ""
        self.readerActive = false

        // Resize framebuffer
        framebuffer = Framebuffer(width: width, height: height)

        let semaphore = DispatchSemaphore(value: 0)
        DispatchQueue.global().async { [weak self] in
            guard let self else { semaphore.signal(); return }
            do {
                self.setState(.tcp)
                try self.transport.connect(host: host, port: port)

                self.setState(.tls)

                self.setState(.x224)
                let crData = X224.buildConnectionRequest()
                try self.transport.send(crData)
                let ccData = try self.transport.recv(minLength: 1, maxLength: 65536)
                guard let negotiatedProto = X224.parseConnectionConfirm(ccData) else {
                    self.setState(.failed)
                    self.errorReason = "X.224: connection rejected (got \(ccData.count) bytes)"
                    return
                }

                let supportsNLA = (negotiatedProto & 0x01) != 0
                if nla && !username.isEmpty && supportsNLA {
                    do {
                        self.setState(.nla)
                        try NLA.performNLA(transport: self.transport,
                                           username: username,
                                           password: password)
                        self.security = "tls+nla"
                    } catch {
                        self.setState(.failed)
                        self.errorReason = "NLA: \(error.localizedDescription)"
                        semaphore.signal()
                        return
                    }
                } else if supportsNLA {
                    self.security = "tls+nla"
                }

                self.setState(.mcs)
                try self.transport.send(MCS.buildConnectInitial(width: width, height: height, bpp: bpp))
                let mcsData = try self.transport.recv(minLength: 1, maxLength: 65536)
                guard let mcsResult = MCS.parseConnectResponse(mcsData) else {
                    self.setState(.failed)
                    self.errorReason = "MCS: invalid connect response"
                    semaphore.signal()
                    return
                }
                guard mcsResult.result == 0 else {
                    self.setState(.failed)
                    self.errorReason = "MCS: rejected (result=\(mcsResult.result))"
                    semaphore.signal()
                    return
                }

                self.setState(.capabilities)
                try self.transport.send(Capabilities.buildConfirmActivePDU(width: width, height: height, bpp: bpp))
                try self.transport.send(Capabilities.buildSynchronisePDU())
                try self.transport.send(Capabilities.buildControlCooperatePDU())
                try self.transport.send(Capabilities.buildControlRequestPDU())
                try self.transport.send(Capabilities.buildFontListPDU())

                let finalData = try self.transport.recv(minLength: 1, maxLength: 65536)
                if !finalData.isEmpty {
                    recvBuffer.append(finalData)
                }

                // Join virtual channel (cliprdr)
                try self.sendChannelJoin(self.clipboardChannelID)

                // Join virtual channel (rdpsnd audio)
                try self.sendChannelJoin(self.audioChannelID)

                // Join virtual channel (rdpdr drive redirection)
                try self.sendChannelJoin(self.drivesChannelID)

                // Send clipboard monitor ready
                let monitorReady = ClipRDR.buildMonitorReady()
                try self.sendVirtualChannel(data: monitorReady, channelID: self.clipboardChannelID)

                self.setState(.active)
                if self.security.isEmpty {
                    self.security = "tls"
                }
                semaphore.signal()
            } catch {
                self.setState(.failed)
                self.errorReason = error.localizedDescription
                semaphore.signal()
            }
        }

        let waitResult = semaphore.wait(timeout: .now() + Self.connectTimeout + 2.0)
        if waitResult == .timedOut && state != .active && state != .failed {
            setState(.failed)
            errorReason = "connect timeout"
        }

        // Process any TPKT packets already buffered from the handshake
        // (e.g. audio/virtual-channel data piggybacked on the capability exchange)
        while processOnePacket() {}

        // Start background reader if active
        if state == .active {
            startBackgroundReader()
        }

        if state == .failed || state == .disconnected {
            transport.close()
        }
    }

    private func startBackgroundReader() {
        readerActive = true
        readerQueue.async { [weak self] in
            self?.readerLoop()
        }
    }

    /// Try to extract and process one complete TPKT packet from the receive buffer.
    /// Returns true if a packet was processed.
    private func processOnePacket() -> Bool {
        // TPKT header: version(1) + reserved(1) + length(2) = 4 bytes
        guard recvBuffer.count >= 4 else { return false }
        guard recvBuffer[0] == 0x03 else {
            // Unknown data; discard to next TPKT or clear
            if let next = recvBuffer.dropFirst().firstIndex(of: 0x03) {
                recvBuffer = Data(recvBuffer.dropFirst(next))
            } else {
                recvBuffer.removeAll()
            }
            return false
        }
        let tpktLen = (Int(recvBuffer[2]) << 8) | Int(recvBuffer[3])
        guard tpktLen >= 7 else {
            // Bad header; skip this byte and retry
            recvBuffer = Data(recvBuffer.dropFirst())
            return false
        }
        guard recvBuffer.count >= tpktLen else {
            return false // incomplete, wait for more data
        }
        // Extract one complete TPKT packet
        let packet = recvBuffer.prefix(tpktLen)
        recvBuffer = Data(recvBuffer.dropFirst(tpktLen))
        handleIncomingData(Data(packet))
        return true
    }

    private func readerLoop() {
        while readerActive && state == .active {
            guard transport.isConnected else {
                readerActive = false
                setState(.disconnected)
                return
            }

            let hadData = processOnePacket()
            if hadData {
                continue // process more buffered packets before reading again
            }

            do {
                let data = try transport.recv(minLength: 1, maxLength: 65536)
                if !data.isEmpty {
                    recvBuffer.append(data)
                }
            } catch {
                readerActive = false
                setState(.failed)
                errorReason = "read error: \(error.localizedDescription)"
                return
            }
        }
    }

    /// Parse the X.224 LI field at the given offset (just past TPKT header).
    /// Returns the total X.224 header size (including LI), or nil if invalid.
    /// X.224 header: LI(1 or 2 or 3) + TPDU type(1) + EOT(1).
    private static func x224HeaderSize(_ data: Data, liOffset: Int) -> Int? {
        guard liOffset < data.count else { return nil }
        let li = data[liOffset]
        let liSize: Int
        if li < 0x80 {
            liSize = 1
        } else if li == 0x81 {
            guard liOffset + 1 < data.count else { return nil }
            liSize = 2
        } else if li == 0x82 {
            guard liOffset + 2 < data.count else { return nil }
            liSize = 3
        } else {
            return nil
        }
        // X.224 header = LI bytes + TPDU type(1) + EOT(1)
        return liSize + 2
    }

    private func handleIncomingData(_ data: Data) {
        // TPKT header is 4 bytes. Payload starts at offset 4.
        guard data.count >= 5 else { return }

        // Parse X.224 header to find the MCS type byte offset.
        // Check for MCS Send Data Indication (0x64) or Send Data Request (0x68)
        // which are used for virtual channel data.
        if let hdrSize = Self.x224HeaderSize(data, liOffset: 4) {
            let mcsOff = 4 + hdrSize
            if mcsOff < data.count {
                let mcsType = data[mcsOff]
                if mcsType == 0x64 || mcsType == 0x68 {
                    handleMCSSendData(data, x224HdrSize: hdrSize)
                    return
                }
            }
        }

        // Detect fast-path output: action byte = 0x00 (FASTPATH_OUTPUT_ACTION)
        // Fast-path skips X.224 — TPKT payload is directly the fast-path update PDU
        if data[4] == 0x00 {
            guard let rects = parseFastPathBitmapOutput(data) else { return }
            for rect in rects {
                BitmapCodec.decodeRaw(
                    bitmapData: rect.bitmapData,
                    destX: rect.destX, destY: rect.destY,
                    width: rect.width, height: rect.height,
                    bpp: rect.bpp, into: framebuffer)
            }
            return
        }

        // Slow-path: BitmapUpdate handles TPKT + X.224 + Share Data Header
        guard let rects = BitmapUpdate.parseBitmapUpdate(data) else { return }

        for rect in rects {
            if rect.isCompressed {
                BitmapCodec.decodeInterleavedRLE(
                    bitmapData: rect.bitmapData,
                    destX: rect.destX, destY: rect.destY,
                    width: rect.width, height: rect.height,
                    bpp: rect.bpp, into: framebuffer)
            } else {
                BitmapCodec.decodeRaw(
                    bitmapData: rect.bitmapData,
                    destX: rect.destX, destY: rect.destY,
                    width: rect.width, height: rect.height,
                    bpp: rect.bpp, into: framebuffer)
            }
        }
    }

    /// Parse a fast-path bitmap update PDU.
    /// Format after TPKT header: fpHeader(1) + length(2) + updateHeader(1) + numRects(2) + bitmapData...
    private func parseFastPathBitmapOutput(_ data: Data) -> [(destX: Int, destY: Int, width: Int, height: Int, bpp: Int, bitmapData: Data)]? {
        var off = 4 // skip TPKT header (4 bytes)

        guard off < data.count else { return nil }
        let fpHeader = data[off]; off += 1
        // action = bits 0-1 should be 0 (FASTPATH_OUTPUT_ACTION)
        guard (fpHeader & 0x03) == 0 else { return nil }

        // Length encoding: bit 7 of first length byte = 1 means 2-byte length
        guard off < data.count else { return nil }
        let len1 = data[off]; off += 1
        var fpLen: Int
        if len1 & 0x80 != 0 {
            guard off < data.count else { return nil }
            let len2 = data[off]; off += 1
            fpLen = ((Int(len1) & 0x7F) << 8) | Int(len2)
        } else {
            fpLen = Int(len1)
        }
        // Validate length against remaining data
        guard fpLen > 0 && off + fpLen <= data.count else { return nil }

        // Skip compression header (bits 6-7 of fpHeader), no compression for now
        let _ = (fpHeader >> 6) & 0x03

        // TS_FP_UPDATE header
        guard off < data.count else { return nil }
        let updateHeader = data[off]; off += 1
        let updateCode = updateHeader & 0x0F
        guard updateCode == 2 else { return nil } // 2 = UPDATETYPE_BITMAP
        let fragmentation = (updateHeader >> 4) & 0x03
        guard fragmentation == 0 else { return nil }
        // Bits 6-7: compression — not handling compressed fast-path yet
        guard (updateHeader >> 6) & 0x03 == 0 else { return nil }

        // numRects (little-endian 16-bit)
        guard off + 2 <= data.count else { return nil }
        let numRects = (Int(data[off + 1]) << 8) | Int(data[off])
        off += 2

        // Parse the first rectangle's bitmap data
        // TS_UPDATE_BITMAP_DATA: left(2) + top(2) + right(2) + bottom(2) + width(2) + height(2) +
        //                         bpp(2) + flags(2) + dataLen(2) + pixelData
        guard off + 18 <= data.count else { return nil }
        let left = (Int(data[off + 1]) << 8) | Int(data[off])
        off += 2
        let top = (Int(data[off + 1]) << 8) | Int(data[off])
        off += 2
        let right = (Int(data[off + 1]) << 8) | Int(data[off])
        off += 2
        let bottom = (Int(data[off + 1]) << 8) | Int(data[off])
        off += 2
        let width = (Int(data[off + 1]) << 8) | Int(data[off])
        off += 2
        let height = (Int(data[off + 1]) << 8) | Int(data[off])
        off += 2
        let bppVal = (Int(data[off + 1]) << 8) | Int(data[off])
        off += 2
        let _flags = (Int(data[off + 1]) << 8) | Int(data[off])
        off += 2
        let dataLen = (Int(data[off + 1]) << 8) | Int(data[off])
        off += 2

        guard dataLen >= 0 && off + dataLen <= data.count else { return nil }
        let bitmapData = data.subdata(in: off..<(off + dataLen))

        return [(destX: left, destY: top, width: width, height: height, bpp: bppVal, bitmapData: bitmapData)]
    }

    func disconnect() {
        readerActive = false
        transport.close()
        setState(.disconnected)
        errorReason = ""
    }

    func sendInput(_ data: Data) throws {
        guard state == .active else { throw TransportError.notConnected }
        try transport.send(data)
    }

    /// Send data over a virtual channel using MCS Send Data Request.
    func sendVirtualChannel(data: Data, channelID: UInt16) throws {
        let pdu = buildMCSSendDataRequest(data: data, channelID: channelID)
        try transport.send(pdu)
    }

    /// Send an MCS Channel Join Request for the given channel.
    private func sendChannelJoin(_ channelID: UInt16) throws {
        var pdu = Data()
        // MCS Channel Join Request [MCSEACHANNELJOINREQUEST] tag 0x38
        pdu.append(0x38)
        pdu.append(contentsOf: withUnsafeBytes(of: UInt16(1).littleEndian) { Array($0) }) // initiator = userID 1
        pdu.append(contentsOf: withUnsafeBytes(of: channelID.littleEndian) { Array($0) }) // channelID
        // Wrap in TPKT + X.224 data TPDU
        try transport.send(wrapMCS(pdu))
    }

    /// Build an MCS Send Data Request PDU.
    private func buildMCSSendDataRequest(data: Data, channelID: UInt16) -> Data {
        var pdu = Data()
        // MCS Send Data Request header
        pdu.append(0x68) // SendDataRequest
        pdu.append(contentsOf: withUnsafeBytes(of: UInt16(1).littleEndian) { Array($0) }) // initiator
        pdu.append(contentsOf: withUnsafeBytes(of: channelID.littleEndian) { Array($0) }) // channelID
        pdu.append(0x00) // priority = top
        pdu.append(0x01) // segmentation = begin+end
        // User data length (BER encoded)
        let lenBytes = berLength(data.count)
        pdu.append(contentsOf: lenBytes)
        pdu.append(data)
        return wrapMCS(pdu)
    }

    /// Handle an MCS Send Data Indication/Request (virtual channel data).
    /// Layout: TPKT(4) + X.224(variable) + MCS(type(1) + initiator(2) + channelID(2) + prio(1) + seg(1) + berLen + userData)
    private func handleMCSSendData(_ data: Data, x224HdrSize: Int) {
        var off = 4 + x224HdrSize // skip TPKT(4) + X.224(variable) to reach MCS type byte
        guard off + 6 <= data.count else { return }
        off += 1 // skip MCS type byte (0x64 or 0x68)
        off += 2 // initiator (2 bytes)
        let channelID = UInt16(data[off]) | (UInt16(data[off + 1]) << 8)
        off += 2
        guard off + 2 <= data.count else { return }
        off += 2 // priority + segmentation
        // BER length of user data
        guard off < data.count else { return }
        var berOff = off
        var userDataLen = Int(data[berOff])
        berOff += 1
        if userDataLen & 0x80 != 0 {
            let nb = userDataLen & 0x7F
            guard nb > 0, berOff + nb <= data.count else { return }
            userDataLen = 0
            for j in 0..<nb {
                userDataLen = (userDataLen << 8) | Int(data[berOff + j])
            }
            berOff += nb
        }
        guard berOff + userDataLen <= data.count else { return }
        let channelData = data.subdata(in: berOff..<(berOff + userDataLen))

        if channelID == clipboardChannelID {
            clipboardMessageHandler?(channelData)
        }
        if channelID == audioChannelID {
            audioMessageHandler?(channelData)
        }
        if channelID == drivesChannelID {
            drivesMessageHandler?(channelData)
        }
    }

    /// Wrap an MCS payload in TPKT + X.224.
    private func wrapMCS(_ payload: Data) -> Data {
        let x224PayloadLen = 2 + payload.count
        let li: UInt8
        if x224PayloadLen <= 255 {
            li = UInt8(x224PayloadLen)
        } else {
            li = 0xFF
        }
        let x224Hdr: [UInt8] = [li, 0xF0, 0x80]
        let tpktLen = 4 + x224Hdr.count + payload.count
        let tpkt: [UInt8] = [0x03, 0x00, UInt8((tpktLen >> 8) & 0xFF), UInt8(tpktLen & 0xFF)]
        var packet = Data(tpkt)
        packet.append(contentsOf: x224Hdr)
        packet.append(payload)
        return packet
    }

    private func berLength(_ n: Int) -> Data {
        if n < 128 { return Data([UInt8(n)]) }
        if n <= 0xFF { return Data([0x81, UInt8(n)]) }
        return Data([0x82, UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)])
    }
}
