import Foundation
import Network
import Security

final class NetworkTransport: Transport {

    var isConnected: Bool {
        if case .ready = connection?.state { return true }
        return false
    }

    var stateChangeHandler: ((TransportState) -> Void)?

    private var connection: NWConnection?
    private let queue = DispatchQueue(label: "rdp-network-transport")

    func connect(host: String, port: UInt16) throws {
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port) ?? .any
        )

        // Determine if we should use TLS.
        // For localhost connections (mock host), use plaintext TCP to avoid Security framework issues.
        let useTLS = (host != "127.0.0.1" && host != "localhost" && host != "::1")

        let params: NWParameters
        if useTLS {
            let tlsOptions = NWProtocolTLS.Options()
            sec_protocol_options_set_verify_block(
                tlsOptions.securityProtocolOptions,
                { (_, _, completion) in completion(true) },
                DispatchQueue.main
            )
            params = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        } else {
            params = NWParameters.tcp
        }

        let conn = NWConnection(to: endpoint, using: params)
        connection = conn

        let semaphore = DispatchSemaphore(value: 0)
        var connectError: Error?

        conn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.stateChangeHandler?(.ready)
                semaphore.signal()
            case .failed(let err):
                connectError = err
                self?.stateChangeHandler?(.failed(err))
                semaphore.signal()
            case .cancelled:
                self?.stateChangeHandler?(.cancelled)
                semaphore.signal()
            default:
                break
            }
        }
        conn.start(queue: queue)
        semaphore.wait()

        if let err = connectError {
            throw err
        }
    }

    func send(_ data: Data) throws {
        guard let conn = connection else { throw TransportError.notConnected }
        let semaphore = DispatchSemaphore(value: 0)
        var sendError: Error?
        conn.send(content: data, completion: .contentProcessed { err in
            if let err = err { sendError = err }
            semaphore.signal()
        })
        semaphore.wait()
        if let err = sendError { throw err }
    }

    func recv(minLength: Int, maxLength: Int) throws -> Data {
        guard let conn = connection else { throw TransportError.notConnected }
        let semaphore = DispatchSemaphore(value: 0)
        var resultData: Data?
        var recvError: Error?

        conn.receive(minimumIncompleteLength: minLength, maximumLength: maxLength) { data, _, isComplete, err in
            if let err = err {
                recvError = err
            } else if let d = data, !d.isEmpty {
                resultData = d
            } else if isComplete {
                recvError = TransportError.closed
            }
            semaphore.signal()
        }
        semaphore.wait()

        if let err = recvError { throw err }
        guard let data = resultData else {
            // No data yet but not closed — brief yield then retry
            Thread.sleep(forTimeInterval: 0.001)
            return try recv(minLength: minLength, maxLength: maxLength)
        }
        return data
    }

    func close() {
        connection?.cancel()
        connection = nil
    }
}
