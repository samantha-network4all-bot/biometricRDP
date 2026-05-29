import Foundation

protocol TestAPIControllerRoutes: AnyObject {
    static var routePrefix: String { get }
    func registerRoutes(on router: TestAPIRouter)
}

final class TestAPIRouter {
    static let shared = TestAPIRouter()
    private var handlers: [String: (TestAPIRequest) -> TestAPIResponse] = [:]

    private init() {}

    func register<C: TestAPIControllerRoutes>(controller: C) {
        controller.registerRoutes(on: self)
    }

    func registerTopLevel(path: String, method: String, _ h: @escaping (TestAPIRequest) -> TestAPIResponse) {
        handlers["\(method) \(path)"] = h
    }

    func get(prefix: String, path: String, _ h: @escaping (TestAPIRequest) -> TestAPIResponse) {
        handlers["GET /\(prefix)\(path)"] = h
    }

    func post(prefix: String, path: String, _ h: @escaping (TestAPIRequest) -> TestAPIResponse) {
        handlers["POST /\(prefix)\(path)"] = h
    }

    func dispatch(_ req: TestAPIRequest) -> TestAPIResponse {
        if let handler = handlers["\(req.method) \(req.path)"] {
            return handler(req)
        }
        return .notFound(req)
    }
}
