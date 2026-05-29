import AppKit

final class WindowController: NSViewController, TestAPIControllerRoutes {

    static var routePrefix: String { "window" }

    let windowState = WindowState()
    var rdpWindow: RDPWindow?

    private var rootView: RootView!
    private var sessionController: SessionController!

    init() {
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func loadView() {
        rootView = RootView(frame: NSRect(x: 0, y: 0, width: 1280, height: 800))
        view = rootView
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        sessionController = SessionController(desktopView: rootView.desktopView)
        rootView.onConnect = { [weak self] host in
            self?.sessionController.connect(host: host)
        }
        rootView.onDisconnect = { [weak self] in
            self?.sessionController.disconnect()
        }
        TestAPIRouter.shared.register(controller: self)
    }

    func registerRoutes(on router: TestAPIRouter) {
        router.get(prefix: Self.routePrefix, path: "/list") { [weak self] _ in
            guard let self else { return .notFound }
            let title = self.rdpWindow?.title ?? "biometricRDP"
            let entry: [String: Any] = [
                "id": "w1",
                "title": title,
                "isKey": self.rdpWindow?.isKeyWindow ?? false
            ]
            let body = try! JSONSerialization.data(withJSONObject: [entry])
            return .ok(json: body)
        }
    }
}
