import AppKit

final class InputController: NSViewController, TestAPIControllerRoutes {
    static var routePrefix: String { "input" }

    weak var sessionController: SessionController?

    init(sessionController: SessionController) {
        self.sessionController = sessionController
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func loadView() { view = NSView(frame: .zero) }

    override func viewDidLoad() {
        super.viewDidLoad()
        TestAPIRouter.shared.register(controller: self)
    }

    func registerRoutes(on router: TestAPIRouter) {
        // ---- /input/key (scancode-based) ----
        router.post(prefix: Self.routePrefix, path: "/key") { [weak self] req in
            guard let self, let sc = self.sessionController else { return .notFound }
            guard let session = sc.rdpSession,
                  case .active = session.state else {
                return .ok(json: Data("{\"error\":\"not active\"}".utf8))
            }
            struct KeyBody: Decodable {
                let scancode: Int
                let down: Bool
            }
            guard let body = try? JSONDecoder().decode(KeyBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }
            let pdu = InputPDU.buildKeyboardEvent(keyCode: UInt16(body.scancode), down: body.down)
            do {
                try session.sendInput(pdu)
            } catch {
                return .internalError
            }
            return .ok(json: Data("{\"ok\":true}".utf8))
        }

        // ---- /input/type (unicode text) ----
        router.post(prefix: Self.routePrefix, path: "/type") { [weak self] req in
            guard let self, let sc = self.sessionController else { return .notFound }
            guard let session = sc.rdpSession,
                  case .active = session.state else {
                return .ok(json: Data("{\"error\":\"not active\"}".utf8))
            }
            struct TypeBody: Decodable {
                let text: String
            }
            guard let body = try? JSONDecoder().decode(TypeBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }
            for scalar in body.text.unicodeScalars {
                let code = UInt16(scalar.value)
                let pdu = InputPDU.buildUnicodeEvent(unicodeCode: code)
                do {
                    try session.sendInput(pdu)
                } catch {
                    return .internalError
                }
            }
            return .ok(json: Data("{\"ok\":true}".utf8))
        }

        router.post(prefix: Self.routePrefix, path: "/mouse") { [weak self] req in
            guard let self, let sc = self.sessionController else { return .notFound }
            guard let session = sc.rdpSession,
                  case .active = session.state else {
                return .ok(json: Data("{\"error\":\"not active\"}".utf8))
            }
            struct MouseBody: Decodable {
                let x: Int
                let y: Int
                let button: String?  // "left", "right", "middle"
                let action: String   // "move", "down", "up", "click"
                let wheel: Int?
            }
            guard let body = try? JSONDecoder().decode(MouseBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }
            var flags: UInt16 = 0
            switch body.action {
            case "move": flags = 0x0800 // PTRFLAGS_MOVE
            case "down":
                flags = 0x8000 // PTRFLAGS_DOWN
                switch body.button {
                case "left": flags |= 0x1000
                case "right": flags |= 0x2000
                case "middle": flags |= 0x4000
                default: flags |= 0x1000
                }
            case "up":
                switch body.button {
                case "left": flags |= 0x1000
                case "right": flags |= 0x2000
                case "middle": flags |= 0x4000
                default: flags |= 0x1000
                }
            case "click":
                flags = 0x8000
                switch body.button {
                case "left": flags |= 0x1000
                case "right": flags |= 0x2000
                case "middle": flags |= 0x4000
                default: flags |= 0x1000
                }
            default: return .badRequest("invalid action")
            }
            let pdu = InputPDU.buildMouseEvent(destX: body.x, destY: body.y, flags: flags)
            do {
                try session.sendInput(pdu)
            } catch {
                return .internalError
            }
            return .ok(json: Data("{\"ok\":true}".utf8))
        }
    }
}
