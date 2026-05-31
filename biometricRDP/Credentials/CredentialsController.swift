import AppKit
import CryptoKit

final class CredentialsController: NSViewController, TestAPIControllerRoutes {
    static var routePrefix: String { "credentials" }

    private var vault: Vault { .shared }
    private var isTestMode: Bool {
        ProcessInfo.processInfo.environment["BIOMETRICRDP_TEST_API"] == "1"
    }

    init() {
        super.init(nibName: nil, bundle: nil)
    }
    required init?(coder: NSCoder) { fatalError() }

    override func loadView() { view = NSView(frame: .zero) }

    override func viewDidLoad() {
        super.viewDidLoad()
        TestAPIRouter.shared.register(controller: self)
        // Set vault storage path
        let vaultDir: URL
        if isTestMode {
            vaultDir = URL(fileURLWithPath: NSTemporaryDirectory())
                .appendingPathComponent("biometricRDP-vault")
        } else {
            let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            vaultDir = appSupport.appendingPathComponent("biometricRDP")
        }
        try? FileManager.default.createDirectory(at: vaultDir, withIntermediateDirectories: true)
        vault.setStorageURL(vaultDir.appendingPathComponent("vault.bin"))
    }

    func registerRoutes(on router: TestAPIRouter) {
        // POST /credentials/unlock {testSecret:"t"} → {ok:true}
        router.post(prefix: Self.routePrefix, path: "/unlock") { [weak self] req in
            guard let self else { return .notFound }
            struct UnlockBody: Decodable { let testSecret: String? }
            guard let body = try? JSONDecoder().decode(UnlockBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }
            if self.isTestMode {
                guard let secret = body.testSecret else {
                    return .badRequest("testSecret required in test mode")
                }
                let key = Biometric.deriveKeyFromTestSecret(secret)
                self.vault.unlock(key: key)
            } else {
                // Normal mode: Touch ID gate (deferred — accept any secret for now)
                return .badRequest("biometric unlock not yet implemented")
            }
            return .ok(json: Data("{\"ok\":true}".utf8))
        }

        // POST /credentials/lock → {ok:true}
        router.post(prefix: Self.routePrefix, path: "/lock") { [weak self] _ in
            guard let self else { return .notFound }
            self.vault.lock()
            return .ok(json: Data("{\"ok\":true}".utf8))
        }

        // POST /credentials/save {host,username,password} → {ok:true,id:"c1"}
        router.post(prefix: Self.routePrefix, path: "/save") { [weak self] req in
            guard let self else { return .notFound }
            struct SaveBody: Decodable {
                let host: String
                let username: String
                let password: String
            }
            guard let body = try? JSONDecoder().decode(SaveBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }
            let id = "c" + UUID().uuidString.prefix(8).lowercased()
            let cred = StoredCredential(id: id, host: body.host,
                                        username: body.username, password: body.password)
            do {
                try self.vault.save(credential: cred)
            } catch VaultError.notUnlocked {
                return .badRequest("vault locked")
            } catch {
                return .internalError
            }
            let resp: [String: Any] = ["ok": true, "id": id]
            guard let data = try? JSONSerialization.data(withJSONObject: resp) else {
                return .internalError
            }
            return .ok(json: data)
        }

        // GET /credentials/list → [{id,host,username}]
        router.get(prefix: Self.routePrefix, path: "/list") { [weak self] _ in
            guard let self else { return .notFound }
            do {
                let items = try self.vault.list()
                let arr: [[String: String]] = items.map { ["id": $0.id, "host": $0.host, "username": $0.username] }
                guard let data = try? JSONSerialization.data(withJSONObject: arr) else {
                    return .internalError
                }
                return .ok(json: data)
            } catch {
                return .ok(json: Data("[]".utf8))
            }
        }

        // GET /credentials/get?id=c1 → {password:"p"} (test-only)
        router.get(prefix: Self.routePrefix, path: "/get") { [weak self] req in
            guard let self else { return .notFound }
            guard self.isTestMode else { return .notFound }
            guard let id = req.queryItems.first(where: { $0.name == "id" })?.value else {
                return .badRequest("missing id")
            }
            do {
                let cred = try self.vault.get(id: id)
                let resp: [String: Any] = ["password": cred.password]
                guard let data = try? JSONSerialization.data(withJSONObject: resp) else {
                    return .internalError
                }
                return .ok(json: data)
            } catch {
                return .badRequest("not found")
            }
        }

        // POST /credentials/delete {id:"c1"} → {ok:true}
        router.post(prefix: Self.routePrefix, path: "/delete") { [weak self] req in
            guard let self else { return .notFound }
            struct DeleteBody: Decodable { let id: String }
            guard let body = try? JSONDecoder().decode(DeleteBody.self, from: req.body) else {
                return .badRequest("invalid body")
            }
            do {
                try self.vault.delete(id: body.id)
            } catch {
                return .badRequest("not found or locked")
            }
            return .ok(json: Data("{\"ok\":true}".utf8))
        }
    }
}
