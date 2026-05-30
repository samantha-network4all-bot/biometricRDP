import Foundation
import Network

final class NetworkTransport: Transport {

    var isConnected: Bool {
        if case .ready = connection?.state { return true }
        return false
    }

    var stateChangeHandler: ((TransportState) -> Void)?

    private var connection: NWConnection?
    private let queue = DispatchQueue(label: "rdp-network-transport")
    private var recvBuffer = Data()

    func connect(host: String, port: UInt16) throws {
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port) ?? .any
        )
        let params = NWParameters.tcp
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

    func send(_ data: Data) {
        guard let conn = connection else { return }
        conn.send(content: data, completion: .contentProcessed { _ in })
    }

    func recv(completion: @escaping (Data) -> Void) {
        guard let conn = connection else { return }
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, _ in
            guard let self else { return }
            if let data = data, !data.isEmpty {
                self.recvBuffer.append(data)
            }
            if !self.recvBuffer.isEmpty {
                let chunk = self.recvBuffer
                self.recvBuffer = Data()
                completion(chunk)
            }
            if !isComplete {
                self.recv(completion: completion)
            }
        }
    }

    func disconnect() {
        connection?.cancel()
        connection = nil
        recvBuffer = Data()
    }
}
