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

    private weak var desktopView: DesktopView?
    internal var rdpSession: RDPSession?

    init(desktopView: DesktopView) {
        self.desktopView = desktopView
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func loadView() {
        view = NSView(frame: .zero)
    }

    private var inputController: InputController?
    private var clipboardController: ClipboardController?
    private var audioController: AudioController?

    override func viewDidLoad() {
        super.viewDidLoad()
        TestAPIRouter.shared.register(controller: self)
        ensureInputController()
        ensureClipboardController()
        ensureAudioController()
    }

    func ensureInputController() {
        guard inputController == nil else { return }
        let ctrl = InputController(sessionController: self)
        _ = ctrl.view // load view
        inputController = ctrl
    }

    func ensureClipboardController() {
        guard clipboardController == nil else { return }
        let ctrl = ClipboardController(sessionController: self)
        _ = ctrl.view // load view
        clipboardController = ctrl
    }

    func ensureAudioController() {
        guard audioController == nil else { return }
        let ctrl = AudioController(sessionController: self)
        _ = ctrl.view
        audioController = ctrl
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

            // Point desktop view at session's framebuffer
            self.desktopView?.framebuffer = session.framebuffer
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
            self.ensureInputController()
            self.ensureClipboardController()
            // Wire clipboard handler
            session.clipboardMessageHandler = { [weak self] channelData in
                self?.handleClipboardData(channelData)
            }
            // Wire audio handler
            session.audioMessageHandler = { [weak self] channelData in
                self?.audioController?.handleAudioChannelData(channelData)
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
                let errorReason: String
            }
            let body = Body(state: self.state.rawValue,
                            host: self.currentHost,
                            width: self.width,
                            height: self.height,
                            bpp: self.bpp,
                            security: self.security,
                            errorReason: self.rdpSession?.errorReason ?? ""
            )
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
            guard let fb = self.rdpSession?.framebuffer else {
                let body = try! JSONSerialization.data(withJSONObject: ["ok": false, "error": "no session"])
                return .ok(json: body)
            }
            let view = FramebufferView(fb: fb)
            guard let png = view.pngData() else {
                let body = try! JSONSerialization.data(withJSONObject: ["ok": false, "error": "render failed"])
                return .ok(json: body)
            }
            let b64 = png.base64EncodedString()
            let resp: [String: Any] = ["ok": true, "png": b64]
            let body = try! JSONSerialization.data(withJSONObject: resp)
            return .ok(json: body)
        }
    }

    func connect(host: String) {
        currentHost = host
        state = .disconnected
        updateDesktop()
    }

    func disconnect() {
        clipboardController?.setRemoteText("")
        state = .disconnected
        currentHost = ""
        updateDesktop()
    }

    private func handleClipboardData(_ channelData: Data) {
        guard let msg = ClipRDR.parseClipMessage(channelData) else { return }
        switch msg.msgType {
        case ClipRDR.CB_MSG_TYPE_FORMAT_LIST_RESPONSE:
            break // acknowledge
        case ClipRDR.CB_MSG_TYPE_FORMAT_DATA_RESPONSE:
            if let text = ClipRDR.parseFormatDataResponse(msg.payload) {
                clipboardController?.setRemoteText(text)
            }
        default:
            break
        }
    }

    private func updateDesktop() {
        desktopView?.needsDisplay = true
    }

    private func pixelColor(x: Int, y: Int) -> String {
        guard let fb = rdpSession?.framebuffer else { return "#000000" }
        guard x >= 0, x < fb.width, y >= 0, y < fb.height else {
            return "#000000"
        }
        let offset = (y * fb.width + x) * 4
        let r = fb.pixels[offset]
        let g = fb.pixels[offset + 1]
        let b = fb.pixels[offset + 2]
        return String(format: "#%02X%02X%02X", r, g, b)
    }
}
