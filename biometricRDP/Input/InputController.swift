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
        router.post(prefix: Self.routePrefix, path: "/mouse") { [weak self] req in
            guard let self, let sc = self.sessionController else { return .notFound }
            guard let session = sc.value(forKey: "rdpSession") as? RDPSession else {
                return .badRequest("no session")
            }
            guard case .active = session.state else {
                return .badRequest("not active")
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
                try session.transport.send(pdu)
            } catch {
                return .internalError
            }
            return .ok(json: Data("{\"ok\":true}".utf8))
        }
    }
}
