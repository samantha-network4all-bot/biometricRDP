import AppKit

final class DrivesController: NSViewController, TestAPIControllerRoutes {
    static var routePrefix: String { "drives" }

    weak var sessionController: SessionController?

    /// Mapped drives: name -> localPath
    private var mappedDrives: [String: String] = [:]
    private var nextDeviceID: UInt32 = 1

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
        // POST /drives/map {localPath:"/tmp/share", name:"share"} → {ok:true}
        router.post(prefix: Self.routePrefix, path: "/map") { [weak self] req in
            guard let self else { return .notFound }
            struct MapBody: Decodable {
                let localPath: String
                let name: String
            }
            guard let body = try? JSONDecoder().decode(MapBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }
            self.mappedDrives[body.name] = body.localPath
            let deviceID = self.nextDeviceID
            self.nextDeviceID += 1

            // Announce the drive to the remote via RDPDR
            guard let sc = self.sessionController,
                  let session = sc.rdpSession,
                  case .active = session.state else {
                return .ok(json: Data("{\"ok\":true}".utf8))
            }
            let announce = RDPDR.buildDeviceListAnnounce(
                deviceID: deviceID, deviceName: body.name, localPath: body.localPath)
            do {
                try session.sendVirtualChannel(data: announce, channelID: 0x0012)
            } catch {
                return .internalError
            }
            return .ok(json: Data("{\"ok\":true}".utf8))
        }

        // GET /drives/list → [{name:"share", localPath:"/tmp/share"}]
        router.get(prefix: Self.routePrefix, path: "/list") { [weak self] _ in
            guard let self else { return .notFound }
            let items: [[String: String]] = self.mappedDrives.map { (name, path) in
                ["name": name, "localPath": path]
            }.sorted { $0["name"]! < $1["name"]! }
            guard let data = try? JSONSerialization.data(withJSONObject: items) else {
                return .internalError
            }
            return .ok(json: data)
        }

        // POST /drives/unmap {name:"share"} → {ok:true}
        router.post(prefix: Self.routePrefix, path: "/unmap") { [weak self] req in
            guard let self else { return .notFound }
            struct UnmapBody: Decodable { let name: String }
            guard let body = try? JSONDecoder().decode(UnmapBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }
            self.mappedDrives.removeValue(forKey: body.name)
            return .ok(json: Data("{\"ok\":true}".utf8))
        }
    }
}
