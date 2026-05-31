import AppKit

final class ProfilesController: NSViewController, TestAPIControllerRoutes {
    static var routePrefix: String { "profiles" }

    private var profilesDir: URL {
        if ProcessInfo.processInfo.environment["BIOMETRICRDP_TEST_API"] == "1" {
            return URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("biometricRDP-profiles")
        }
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        return appSupport.appendingPathComponent("biometricRDP/Profiles")
    }

    init() {
        super.init(nibName: nil, bundle: nil)
    }
    required init?(coder: NSCoder) { fatalError() }

    override func loadView() { view = NSView(frame: .zero) }

    override func viewDidLoad() {
        super.viewDidLoad()
        TestAPIRouter.shared.register(controller: self)
        try? FileManager.default.createDirectory(at: profilesDir, withIntermediateDirectories: true)
    }

    private func profileURL(name: String) -> URL {
        return profilesDir.appendingPathComponent("\(name).rdp")
    }

    func registerRoutes(on router: TestAPIRouter) {
        // GET /profiles/list → [{"name":"work"}]
        router.get(prefix: Self.routePrefix, path: "/list") { [weak self] _ in
            guard let self else { return .notFound }
            let fm = FileManager.default
            guard let urls = try? fm.contentsOfDirectory(at: self.profilesDir, includingPropertiesForKeys: nil) else {
                return .ok(json: Data("[]".utf8))
            }
            var names: [[String: Any]] = []
            for url in urls {
                if url.pathExtension == "rdp" {
                    let name = url.deletingPathExtension().lastPathComponent
                    names.append(["name": name])
                }
            }
            let data = try! JSONSerialization.data(withJSONObject: names)
            return .ok(json: data)
        }

        // POST /profiles/save {name, fields} → {ok:true}
        router.post(prefix: Self.routePrefix, path: "/save") { [weak self] req in
            guard let self else { return .notFound }
            struct SaveBody: Decodable {
                let name: String
                let fields: [String: String]
            }
            guard let body = try? JSONDecoder().decode(SaveBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }
            let rdp = RDPFile(fields: body.fields)
            let data = rdp.serialize().data(using: .utf8) ?? Data()
            do {
                try data.write(to: self.profileURL(name: body.name))
            } catch {
                return .internalError
            }
            return .ok(json: Data("{\"ok\":true}".utf8))
        }

        // GET /profiles/load?name=work → {fields:{...}}
        router.get(prefix: Self.routePrefix, path: "/load") { [weak self] req in
            guard let self else { return .notFound }
            guard let name = req.queryItems.first(where: { $0.name == "name" })?.value else {
                return .badRequest("missing name")
            }
            let url = self.profileURL(name: name)
            guard let data = try? Data(contentsOf: url) else {
                return .ok(json: try! JSONSerialization.data(withJSONObject: ["fields": [:]]))
            }
            let rdp = RDPFile(data: data)
            let resp = ["fields": rdp.fields]
            let respData = try! JSONSerialization.data(withJSONObject: resp)
            return .ok(json: respData)
        }

        // POST /profiles/delete {name} → {ok:true}
        router.post(prefix: Self.routePrefix, path: "/delete") { [weak self] req in
            guard let self else { return .notFound }
            struct DeleteBody: Decodable { let name: String }
            guard let body = try? JSONDecoder().decode(DeleteBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }
            try? FileManager.default.removeItem(at: self.profileURL(name: body.name))
            return .ok(json: Data("{\"ok\":true}".utf8))
        }

        // POST /profiles/import {rdp:"full address:s:host\n..."} → {ok:true, name:"host"}
        router.post(prefix: Self.routePrefix, path: "/import") { [weak self] req in
            guard let self else { return .notFound }
            struct ImportBody: Decodable { let rdp: String }
            guard let body = try? JSONDecoder().decode(ImportBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }
            let rdp = RDPFile(data: Data(body.rdp.utf8))
            // Derive name from full address host, or use "imported"
            let host = rdp.fullAddress ?? "imported"
            let shortName = host.replacingOccurrences(of: ".", with: "_")
            let data = rdp.serialize().data(using: .utf8) ?? Data()
            do {
                try data.write(to: self.profileURL(name: shortName))
            } catch {
                return .internalError
            }
            let resp: [String: Any] = ["ok": true, "name": shortName]
            let respData = try! JSONSerialization.data(withJSONObject: resp)
            return .ok(json: respData)
        }

        // GET /profiles/export?name=work → {rdp:"..."}
        router.get(prefix: Self.routePrefix, path: "/export") { [weak self] req in
            guard let self else { return .notFound }
            guard let name = req.queryItems.first(where: { $0.name == "name" })?.value else {
                return .badRequest("missing name")
            }
            let url = self.profileURL(name: name)
            guard let data = try? Data(contentsOf: url),
                  let text = String(data: data, encoding: .utf8) else {
                return .ok(json: try! JSONSerialization.data(withJSONObject: ["rdp": ""]))
            }
            let resp = ["rdp": text]
            let respData = try! JSONSerialization.data(withJSONObject: resp)
            return .ok(json: respData)
        }
    }
}
