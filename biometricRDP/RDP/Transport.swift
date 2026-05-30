import Foundation

enum TransportError: Error {
    case notConnected
    case closed
    case invalidData
}

enum TransportState {
    case ready
    case failed(Error)
    case cancelled
}

protocol Transport: AnyObject {
    var isConnected: Bool { get }
    var stateChangeHandler: ((TransportState) -> Void)? { get set }
    func connect(host: String, port: UInt16) throws
    func send(_ data: Data) throws
    func recv(minLength: Int, maxLength: Int) throws -> Data
    func close()
}
