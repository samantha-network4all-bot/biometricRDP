import AppKit

final class PrintersController: NSViewController, TestAPIControllerRoutes {
    static var routePrefix: String { "printers" }

    weak var sessionController: SessionController?

    /// Announced printers: name -> deviceID
    private var printers: [String: UInt32] = [:]
    private var nextDeviceID: UInt32 = 100

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
        // GET /printers/list → [{"name":"PDF"}]
        router.get(prefix: Self.routePrefix, path: "/list") { [weak self] _ in
            guard let self else { return .notFound }
            let items: [[String: String]] = self.printers.keys
                .sorted()
                .map { ["name": $0] }
            guard let data = try? JSONSerialization.data(withJSONObject: items) else {
                return .internalError
            }
            return .ok(json: data)
        }

        // POST /printers/add {"name":"PDF"} → {ok:true}
        router.post(prefix: Self.routePrefix, path: "/add") { [weak self] req in
            guard let self else { return .notFound }
            struct AddBody: Decodable { let name: String }
            guard let body = try? JSONDecoder().decode(AddBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }
            let deviceID = self.nextDeviceID
            self.nextDeviceID += 1
            self.printers[body.name] = deviceID

            // Announce the printer to the remote via RDPDR
            guard let sc = self.sessionController,
                  let session = sc.rdpSession,
                  case .active = session.state else {
                return .ok(json: Data("{\"ok\":true}".utf8))
            }
            let announce = RDPDR.buildPrinterDeviceListAnnounce(
                deviceID: deviceID, deviceName: body.name)
            do {
                try session.sendVirtualChannel(data: announce, channelID: 0x0012)
            } catch {
                return .internalError
            }
            return .ok(json: Data("{\"ok\":true}".utf8))
        }
    }
}
