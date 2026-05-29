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
    var width: Int = 0
    var height: Int = 0
    var bpp: Int = 0
    var security: String = ""

    private let framebuffer: Framebuffer
    private weak var desktopView: DesktopView?

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
