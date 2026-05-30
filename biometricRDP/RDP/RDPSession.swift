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

    var transport: Transport
    var width: Int = 0
    var height: Int = 0
    var bpp: Int = 0
    var host: String = ""
    var port: UInt16 = 0
    var security: String = ""

    private static let connectTimeout: TimeInterval = 10.0

    init(transport: Transport) {
        self.transport = transport
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

        let semaphore = DispatchSemaphore(value: 0)
        // Run the full handshake on a background queue; semaphore signals done
        DispatchQueue.global().async { [weak self] in
            guard let self else { semaphore.signal(); return }
            do {
                self.state = .tcp
                try self.transport.connect(host: host, port: port)

                // TLS (handled by NetworkTransport; state reflects post-TLS)
                self.state = .tls

                // NLA (CredSSP + NTLMv2) — happens over TLS before X.224
                if nla && !username.isEmpty {
                    do {
                        self.state = .nla
                        try NLA.performNLA(transport: self.transport,
                                           username: username,
                                           password: password)
                        self.security = "tls+nla"
                    } catch {
                        self.state = .failed
                        self.errorReason = "NLA: \(error.localizedDescription)"
                        semaphore.signal()
                        return
                    }
                }

                // X.224 — send CR with PROTOCOL_HYBRID requested
                self.state = .x224
                try self.transport.send(X224.buildConnectionRequest())
                let ccData = try self.transport.recv(minLength: 1, maxLength: 65536)
                guard X224.parseConnectionConfirm(ccData) != nil else {
                    self.state = .failed
                    self.errorReason = "X.224: connection rejected"
                    semaphore.signal()
                    return
                }

                // MCS
                self.state = .mcs
                try self.transport.send(MCS.buildConnectInitial(width: width, height: height, bpp: bpp))
                let mcsData = try self.transport.recv(minLength: 1, maxLength: 65536)
                guard let mcsResult = MCS.parseConnectResponse(mcsData) else {
                    self.state = .failed
                    self.errorReason = "MCS: invalid connect response"
                    semaphore.signal()
                    return
                }
                guard mcsResult.result == 0 else {
                    self.state = .failed
                    self.errorReason = "MCS: rejected (result=\(mcsResult.result))"
                    semaphore.signal()
                    return
                }

                // Capabilities
                self.state = .capabilities
                try self.transport.send(Capabilities.buildConfirmActivePDU(width: width, height: height, bpp: bpp))
                try self.transport.send(Capabilities.buildSynchronisePDU())
                try self.transport.send(Capabilities.buildControlCooperatePDU())
                try self.transport.send(Capabilities.buildControlRequestPDU())
                try self.transport.send(Capabilities.buildFontListPDU())

                // Read server demand active (or any response)
                let _ = try self.transport.recv(minLength: 1, maxLength: 65536)

                self.state = .active
                if self.security.isEmpty {
                    self.security = "tls"
                }
                semaphore.signal()
            } catch {
                self.state = .failed
                self.errorReason = error.localizedDescription
                semaphore.signal()
            }
        }

        let waitResult = semaphore.wait(timeout: .now() + Self.connectTimeout + 2.0)
        if waitResult == .timedOut && state != .active && state != .failed {
            state = .failed
            errorReason = "connect timeout"
        }
        if state == .failed || state == .disconnected {
            transport.close()
        }
    }

    func disconnect() {
        transport.close()
        state = .disconnected
        errorReason = ""
    }
}
