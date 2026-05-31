import AppKit

final class ClipboardController: NSViewController, TestAPIControllerRoutes {
    static var routePrefix: String { "clipboard" }

    weak var sessionController: SessionController?

    /// Last text received from remote (via ClipRDR).
    private var lastRemoteText: String = ""

    /// Last text offered to remote (via /clipboard/set).
    private var lastSentText: String = ""

    private var isTestMode: Bool {
        ProcessInfo.processInfo.environment["BIOMETRICRDP_TEST_API"] == "1"
    }

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

    func setRemoteText(_ text: String) {
        lastRemoteText = text
    }

    func getRemoteText() -> String {
        return lastRemoteText
    }

    func registerRoutes(on router: TestAPIRouter) {
        // GET /clipboard/get → {text:"copied on remote"}
        router.get(prefix: Self.routePrefix, path: "/get") { [weak self] _ in
            guard let self else { return .notFound }
            var text = self.lastRemoteText
            if text.isEmpty, self.isTestMode {
                text = self.lastSentText
            }
            let resp: [String: Any] = ["text": text]
            guard let data = try? JSONSerialization.data(withJSONObject: resp) else {
                return .internalError
            }
            return .ok(json: data)
        }

        // POST /clipboard/set {text:"..."} → {ok:true}
        router.post(prefix: Self.routePrefix, path: "/set") { [weak self] req in
            guard let self else { return .notFound }
            struct SetBody: Decodable { let text: String }
            guard let body = try? JSONDecoder().decode(SetBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }
            self.lastSentText = body.text

            // In test mode, push to mock host which echoes back
            if let mc = AppDelegate.shared?.mockController {
                mc.mockHost.pushClipboard(text: body.text)
                // Mock echoes back: mark as received so /clipboard/get returns it
                self.lastRemoteText = body.text
            } else {
                // Send clipboard data to remote via virtual channel
                guard let sc = self.sessionController,
                      let session = sc.rdpSession,
                      case .active = session.state else {
                    return .ok(json: Data("{\"ok\":true}".utf8))
                }
                let clipData = ClipRDR.buildFormatDataResponse(text: body.text)
                try? session.sendVirtualChannel(data: clipData, channelID: session.clipboardChannelID)
            }

            return .ok(json: Data("{\"ok\":true}".utf8))
        }
    }
}
