import Foundation

enum WindowSessionState: String {
    case disconnected
    case connecting
    case active
    case failed
}

final class WindowState {
    var sessionState: WindowSessionState = .disconnected
}
