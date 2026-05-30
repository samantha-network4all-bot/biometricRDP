import Foundation

final class RDPSession {

    enum State: String {
        case disconnected
        case connecting
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

    private static let connectTimeout: TimeInterval = 5.0

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
        var connectErr: Error?

        // Connect on background thread since transport.connect may block
        DispatchQueue.global().async { [weak self] in
            guard let self else {
                semaphore.signal()
                return
            }
            do {
                try self.transport.connect(host: host, port: port)
            } catch {
                connectErr = error
                self.state = .failed
                self.errorReason = error.localizedDescription
                semaphore.signal()
                return
            }
            self.performHandshake(semaphore: semaphore)
        }

        let waitResult = semaphore.wait(timeout: .now() + Self.connectTimeout)
        if waitResult == .timedOut {
            state = .failed
            errorReason = "connect timeout"
            transport.disconnect()
        }
        if state == .connecting && connectErr == nil {
            // transport connected but handshake didn't complete within timeout
            state = .failed
            errorReason = "handshake timeout"
            transport.disconnect()
        }
    }

    func disconnect() {
        transport.disconnect()
        state = .disconnected
        errorReason = ""
    }

    // MARK: - Private

    private func performHandshake(semaphore: DispatchSemaphore) {
        // Send X.224 connection request
        let cr = X224.buildConnectionRequest()
        transport.send(cr)

        // Receive connection confirm
        var handshakeDone = false
        transport.recv { [weak self] data in
            guard let self else { return }
            if self.parseConnectionConfirm(data) {
                self.state = .active
                self.security = "tcp"
            } else {
                self.state = .failed
                self.errorReason = "invalid connection confirm"
            }
            handshakeDone = true
            semaphore.signal()
        }

        // Wait for the recv callback with a timeout
        // Since our NetworkTransport.recv is async but the mock may respond
        // synchronously in-process, we need a bounded wait here
        let deadline = DispatchTime.now() + Self.connectTimeout
        let waitResult = semaphore.wait(timeout: deadline)
        if waitResult == .timedOut && !handshakeDone {
            state = .failed
            errorReason = "handshake receive timeout"
            transport.disconnect()
        }
    }

    private func parseConnectionConfirm(_ data: Data) -> Bool {
        return X224.parseConnectionConfirm(data) != nil
    }
}
