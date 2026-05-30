import AppKit

final class InputController: NSViewController, TestAPIControllerRoutes {
    static var routePrefix: String { "input" }

    weak var sessionController: SessionController?

    /// USB HID keyboard scancode map (usage page 0x07, codes 0x04–0x1D).
    private static let keyToScancode: [Character: UInt16] = [
        "a": 0x04, "b": 0x05, "c": 0x06, "d": 0x07, "e": 0x08,
        "f": 0x09, "g": 0x0A, "h": 0x0B, "i": 0x0C, "j": 0x0D,
        "k": 0x0E, "l": 0x0F, "m": 0x10, "n": 0x11, "o": 0x12,
        "p": 0x13, "q": 0x14, "r": 0x15, "s": 0x16, "t": 0x17,
        "u": 0x18, "v": 0x19, "w": 0x1A, "x": 0x1B, "y": 0x1C,
        "z": 0x1D
    ]

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
                return .badRequest("not active")
            }
            struct KeyBody: Decodable {
                let scancode: Int?
                let key: String?
                let down: Bool?
            }
            guard let body = try? JSONDecoder().decode(KeyBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }
            let scancode: UInt16
            if let s = body.scancode {
                scancode = UInt16(s)
            } else if let k = body.key, let first = k.lowercased().first, let mapped = Self.keyToScancode[first] {
                scancode = mapped
            } else {
                return .badRequest("need scancode or key")
            }
            let down = body.down ?? true
            var flags: UInt16 = 0
            if !down {
                flags |= InputPDU.KBDFLAGS_RELEASE
            }
            let pdu = InputPDU.buildKeyboardEvent(scancode: scancode, flags: flags)
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
                return .badRequest("not active")
            }
            struct TypeBody: Decodable {
                let text: String
            }
            // Try JSON body first, then fall back to raw text
            let text: String
            if let body = try? JSONDecoder().decode(TypeBody.self, from: req.body), !body.text.isEmpty {
                text = body.text
            } else if let raw = String(data: req.body, encoding: .utf8), !raw.isEmpty {
                text = raw
            } else {
                return .badRequest("invalid body")
            }
            for scalar in text.unicodeScalars {
                let code = UInt16(scalar.value)
                // key-down (flags=0x00) then key-up (flags=0x8000)
                for flags in [UInt16(0x00), InputPDU.KBDFLAGS_RELEASE] {
                    let pdu = InputPDU.buildUnicodeEvent(unicodeCode: code, flags: flags)
                    do {
                        try session.sendInput(pdu)
                    } catch {
                        return .internalError
                    }
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
