import AppKit

final class MockController: NSViewController, TestAPIControllerRoutes {

    static var routePrefix: String { "mock" }

    private let mockHost = MockRDPHost()

    init() {
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func loadView() {
        view = NSView(frame: .zero)
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        TestAPIRouter.shared.register(controller: self)
    }

    func registerRoutes(on router: TestAPIRouter) {
        router.post(prefix: Self.routePrefix, path: "/start") { [weak self] req in
            guard let self else { return .notFound }
            struct StartBody: Decodable {
                let nla: Bool
                let username: String
                let password: String
                let width: Int
                let height: Int
                let bpp: Int
            }
            guard let body = try? JSONDecoder().decode(StartBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }
            do {
                try self.mockHost.start(
                    nla: body.nla,
                    username: body.username,
                    password: body.password,
                    width: body.width,
                    height: body.height,
                    bpp: body.bpp)
            } catch {
                return .badRequest("start failed: \(error.localizedDescription)")
            }
            let port = Int(self.mockHost.port.rawValue)
            let resp: [String: Any] = [
                "ok": true,
                "host": "127.0.0.1",
                "port": port
            ]
            let data = try! JSONSerialization.data(withJSONObject: resp)
            return .ok(json: data)
        }

        router.post(prefix: Self.routePrefix, path: "/stop") { [weak self] _ in
            guard let self else { return .notFound }
            self.mockHost.stop()
            return .ok(json: Data(#"{"ok":true}"#.utf8))
        }

        router.post(prefix: Self.routePrefix, path: "/push") { [weak self] req in
            guard let self else { return .notFound }
            struct PushBody: Decodable {
                let pattern: String
                let color: String
                let rect: [Int]
            }
            guard let body = try? JSONDecoder().decode(PushBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }
            if body.pattern == "solid" {
                let r = Self.parseHex(body.color, offset: 0)
                let g = Self.parseHex(body.color, offset: 2)
                let b = Self.parseHex(body.color, offset: 4)
                self.mockHost.pushSolid(r: r, g: g, b: b)
            }
            return .ok(json: Data(#"{"ok":true}"#.utf8))
        }

        router.get(prefix: Self.routePrefix, path: "/lastInput") { [weak self] _ in
            guard let self else { return .notFound }
            let keys = self.mockHost.lastInputKeys()
            let mouse = self.mockHost.lastInputMouse()
            let text = self.mockHost.lastInputText()
            let resp: [String: Any] = [
                "keys": keys,
                "mouse": mouse,
                "text": text
            ]
            let data = try! JSONSerialization.data(withJSONObject: resp)
            return .ok(json: data)
        }
    }

    private static func parseHex(_ s: String, offset: Int) -> UInt8 {
        var str = s
        if str.hasPrefix("#") {
            str = String(str.dropFirst())
        }
        guard str.count == 6 else { return 0 }
        let start = str.index(str.startIndex, offsetBy: offset)
        let end = str.index(start, offsetBy: 2)
        let byteStr = String(str[start..<end])
        return UInt8(byteStr, radix: 16) ?? 0
    }
}
