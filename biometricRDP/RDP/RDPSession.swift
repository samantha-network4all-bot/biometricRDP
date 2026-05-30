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

    var transport: Transport
    var width: Int = 0
    var height: Int = 0
    var bpp: Int = 0
    var host: String = ""
    var port: UInt16 = 0
    var security: String = ""

    private(set) var framebuffer: Framebuffer
    private var readerActive = false
    private let readerQueue = DispatchQueue(label: "rdp-session-reader")

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

                let _ = try self.transport.recv(minLength: 1, maxLength: 65536)

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

    private func readerLoop() {
        while readerActive && state == .active {
            guard transport.isConnected else {
                readerActive = false
                setState(.disconnected)
                return
            }

            do {
                let data = try transport.recv(minLength: 1, maxLength: 65536)
                if !data.isEmpty {
                    handleIncomingData(data)
                }
            } catch {
                readerActive = false
                setState(.failed)
                errorReason = "read error: \(error.localizedDescription)"
                return
            }
        }
    }

    private func handleIncomingData(_ data: Data) {
        guard let rects = BitmapUpdate.parseBitmapUpdate(data) else { return }

        for rect in rects {
            if rect.isCompressed {
                // RLE decode not yet implemented in this slice
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

    func disconnect() {
        readerActive = false
        transport.close()
        setState(.disconnected)
        errorReason = ""
    }
}
