import Foundation

protocol Transport {
    var isConnected: Bool { get }
    var stateChangeHandler: ((TransportState) -> Void)? { get set }
    func connect(host: String, port: UInt16) throws
    func send(_ data: Data)
    func recv(completion: @escaping (Data) -> Void)
    func disconnect()
}

enum TransportState {
    case ready
    case failed(Error)
    case cancelled
}
