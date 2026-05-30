import AppKit

final class SessionController: NSViewController, TestAPIControllerRoutes {

    static var routePrefix: String { "session" }

    var state: WindowSessionState = .disconnected {
        didSet {
            DispatchQueue.main.async { [weak self] in
                self?.updateDesktop()
            }
        }
    }
    var currentHost: String = ""
    var currentPort: UInt16 = 0
    var width: Int = 0
    var height: Int = 0
    var bpp: Int = 0
    var security: String = ""

    private let framebuffer: Framebuffer
    private weak var desktopView: DesktopView?
    private var rdpSession: RDPSession?

    // Store last connect response for async delivery
    private var lastConnectOK = false
    private var lastConnectState = ""
    private var lastConnectWidth = 0
    private var lastConnectHeight = 0
    private var lastConnectBPP = 0

    init(desktopView: DesktopView) {
        self.framebuffer = Framebuffer(width: 1, height: 1)
        self.desktopView = desktopView
        desktopView.framebuffer = framebuffer
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
        // POST /session/connect
        router.post(prefix: Self.routePrefix, path: "/connect") { [weak self] req in
            guard let self else { return .notFound }
            struct ConnectBody: Decodable {
                let host: String
                let port: Int
                let username: String
                let password: String
                let width: Int
                let height: Int
                let bpp: Int
                let nla: Bool?
            }
            guard let body = try? JSONDecoder().decode(ConnectBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }

            // Resolve port: port 0 means use running mock host
            var connectPort = body.port
            if connectPort == 0 {
                if let mc = AppDelegate.shared?.mockController,
                   mc.mockHost.isRunning {
                    connectPort = Int(mc.mockHost.port.rawValue)
                } else {
                    return .badRequest("no running mock host")
                }
            }

            // Tear down any existing session
            self.rdpSession?.disconnect()
            self.rdpSession = nil

            let transport = NetworkTransport()
            let session = RDPSession(transport: transport)

            self.rdpSession = session
            self.width = body.width
            self.height = body.height
            self.bpp = body.bpp
            self.currentHost = body.host
            self.currentPort = UInt16(connectPort)
            self.state = .connecting

            // Resize framebuffer
            self.framebuffer.width = body.width
            self.framebuffer.height = body.height
            self.framebuffer.pixels = [UInt8](repeating: 0,
                count: body.width * body.height * 4)
            self.desktopView?.framebuffer = self.framebuffer
            self.desktopView?.needsDisplay = true

            session.connect(
                host: body.host,
                port: UInt16(connectPort),
                username: body.username,
                password: body.password,
                width: body.width,
                height: body.height,
                bpp: body.bpp,
                nla: body.nla ?? true
            )

            let ok: Bool
            switch session.state {
            case .active:
                self.state = .active
                self.security = session.security.isEmpty ? "tls" : session.security
                ok = true
            case .failed:
                self.state = .failed
                ok = false
            default:
                self.state = .disconnected
                ok = false
            }

            let resp: [String: Any] = [
                "ok": ok,
                "state": self.state.rawValue,
                "width": self.width,
                "height": self.height,
                "bpp": self.bpp
            ]
            guard let data = try? JSONSerialization.data(withJSONObject: resp) else {
                return .internalError
            }
            return .ok(json: data)
        }

        // POST /session/disconnect
        router.post(prefix: Self.routePrefix, path: "/disconnect") { [weak self] _ in
            guard let self else { return .notFound }
            self.rdpSession?.disconnect()
            self.rdpSession = nil
            self.state = .disconnected
            self.security = ""
            self.currentHost = ""
            self.currentPort = 0
            return .ok(json: Data(#"{"ok":true}"#.utf8))
        }

        router.get(prefix: Self.routePrefix, path: "/state") { [weak self] _ in
            guard let self else { return .notFound }
            struct Body: Encodable {
                let state: String
                let host: String
                let width: Int
                let height: Int
                let bpp: Int
                let security: String
            }
            let body = Body(state: self.state.rawValue,
                            host: self.currentHost,
                            width: self.width,
                            height: self.height,
                            bpp: self.bpp,
                            security: self.security)
            let data = try! JSONEncoder().encode(body)
            return .ok(json: data)
        }

        router.get(prefix: Self.routePrefix, path: "/pixel") { [weak self] req in
            guard let self else { return .notFound }
            guard let x = Int(req.queryItems.first(where: { $0.name == "x" })?.value ?? ""),
                  let y = Int(req.queryItems.first(where: { $0.name == "y" })?.value ?? "") else {
                return .badRequest("missing x or y")
            }
            let color = self.pixelColor(x: x, y: y)
            let body = try! JSONSerialization.data(withJSONObject: ["x": x, "y": y, "color": color])
            return .ok(json: body)
        }

        router.get(prefix: Self.routePrefix, path: "/screenshot") { [weak self] _ in
            guard let self else { return .notFound }
            guard let png = self.framebuffer.pngData() else {
                return .internalError
            }
            return .ok(data: png, contentType: "image/png")
        }
    }

    func connect(host: String) {
        currentHost = host
        state = .disconnected
        updateDesktop()
    }

    func disconnect() {
        state = .disconnected
        currentHost = ""
        updateDesktop()
    }

    private func updateDesktop() {
        desktopView?.needsDisplay = true
    }

    private func pixelColor(x: Int, y: Int) -> String {
        guard x >= 0, x < framebuffer.width, y >= 0, y < framebuffer.height else {
            return "#000000"
        }
        let offset = (y * framebuffer.width + x) * 4
        let r = framebuffer.pixels[offset]
        let g = framebuffer.pixels[offset + 1]
        let b = framebuffer.pixels[offset + 2]
        return String(format: "#%02X%02X%02X", r, g, b)
    }
}
