import Foundation

final class RDPSession {

    enum State: String {
        case disconnected
        case connecting
        case tcp
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
    private var handshakeSemaphore: DispatchSemaphore?

    init(transport: Transport) {
        self.transport = transport
    }

    func connect(host: String, port: UInt16, username: String, password: String,
                 width: Int, height: Int, bpp: Int) {
        self.host = host
        self.port = port
        self.width = width
        self.height = height
        self.bpp = bpp
        self.security = ""
        self.errorReason = ""

        state = .connecting
        transport.stateChangeHandler = { [weak self] tState in
            guard let self else { return }
            switch tState {
            case .failed(let err):
                self.state = .failed
                self.errorReason = err.localizedDescription
            case .cancelled:
                self.state = .disconnected
            case .ready:
                break
            }
        }

        let semaphore = DispatchSemaphore(value: 0)
        self.handshakeSemaphore = semaphore

        DispatchQueue.global().async { [weak self] in
            guard let self else {
                semaphore.signal()
                return
            }
            do {
                try self.transport.connect(host: host, port: port)
            } catch {
                self.state = .failed
                self.errorReason = error.localizedDescription
                semaphore.signal()
                return
            }
            self.performHandshake()
        }

        let waitResult = semaphore.wait(timeout: .now() + Self.connectTimeout)
        if waitResult == .timedOut {
            if state != .active && state != .failed {
                state = .failed
                errorReason = "connect timeout"
            }
            transport.disconnect()
        }
        handshakeSemaphore = nil
    }

    func disconnect() {
        transport.disconnect()
        state = .disconnected
        errorReason = ""
    }

    // MARK: - Handshake

    private func fail(_ reason: String) {
        state = .failed
        errorReason = reason
        handshakeSemaphore?.signal()
    }

    private func succeed() {
        state = .active
        security = "tcp"
        handshakeSemaphore?.signal()
    }

    private func performHandshake() {
        state = .tcp
        transport.send(X224.buildConnectionRequest())

        transport.recv { [weak self] data in
            guard let self else { return }
            guard !data.isEmpty else {
                self.fail("X.224: empty connection confirm")
                return
            }
            guard X224.parseConnectionConfirm(data) != nil else {
                self.fail("X.224: invalid connection confirm")
                return
            }
            self.state = .x224
            self.performMCS()
        }

        let deadline = DispatchTime.now() + Self.connectTimeout
        let result = handshakeSemaphore?.wait(timeout: deadline)
        if result == .timedOut && state == .tcp {
            fail("X.224: receive timeout")
            transport.disconnect()
        }
    }

    private func performMCS() {
        transport.send(MCS.buildConnectInitial(width: width, height: height, bpp: bpp))

        transport.recv { [weak self] data in
            guard let self else { return }
            guard !data.isEmpty else {
                self.fail("MCS: empty response")
                return
            }
            guard let mcsResult = MCS.parseConnectResponse(data) else {
                self.fail("MCS: invalid connect response")
                return
            }
            guard mcsResult.result == 0 else {
                self.fail("MCS: rejected (result=\(mcsResult.result))")
                return
            }
            self.state = .mcs
            self.performCapabilities()
        }

        let deadline = DispatchTime.now() + Self.connectTimeout
        let result = handshakeSemaphore?.wait(timeout: deadline)
        if result == .timedOut && state == .mcs {
            fail("MCS: receive timeout")
            transport.disconnect()
        }
    }

    private func performCapabilities() {
        transport.send(Capabilities.buildConfirmActivePDU(width: width, height: height, bpp: bpp))
        transport.send(Capabilities.buildSynchronisePDU())
        transport.send(Capabilities.buildControlCooperatePDU())
        transport.send(Capabilities.buildControlRequestPDU())
        transport.send(Capabilities.buildFontListPDU())

        transport.recv { [weak self] data in
            guard let self else { return }
            if !data.isEmpty {
                self.succeed()
            } else {
                self.fail("Capabilities: empty response")
            }
        }

        let deadline = DispatchTime.now() + Self.connectTimeout
        let result = handshakeSemaphore?.wait(timeout: deadline)
        if result == .timedOut && state == .mcs {
            state = .capabilities
            fail("Capabilities: receive timeout")
            transport.disconnect()
        }
    }
}
