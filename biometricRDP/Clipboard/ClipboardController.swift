import AppKit

final class ClipboardController: NSViewController, TestAPIControllerRoutes {
    static var routePrefix: String { "clipboard" }

    weak var sessionController: SessionController?

    /// Last text received from remote (via ClipRDR).
    private var lastRemoteText: String = ""

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
            let text = self.getRemoteText()
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
            // Send clipboard data to remote via virtual channel
            guard let sc = self.sessionController,
                  let session = sc.rdpSession,
                  case .active = session.state else {
                return .ok(json: Data("{\"ok\":true}".utf8))
            }
            let clipData = ClipRDR.buildFormatDataResponse(text: body.text)
            try? session.sendVirtualChannel(data: clipData, channelID: session.clipboardChannelID)
            return .ok(json: Data("{\"ok\":true}".utf8))
        }
    }
}
