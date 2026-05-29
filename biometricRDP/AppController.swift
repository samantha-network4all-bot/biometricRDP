import AppKit

final class AppController: NSObject {

    var windowController: WindowController?

    func registerRoutes(on router: TestAPIRouter) {
        router.registerTopLevel(path: "/healthz", method: "GET") { _ in
            return .ok(json: Data(#"{"ok":true}"#.utf8))
        }
        router.registerTopLevel(path: "/shutdown", method: "POST") { _ in
            DispatchQueue.main.async {
                NSApplication.shared.terminate(nil)
            }
            return .ok(json: Data(#"{"ok":true}"#.utf8))
        }
        router.registerTopLevel(path: "/screenshot", method: "GET") { _ in
            guard let wc = AppDelegate.shared?.appController?.windowController,
                  let win = wc.rdpWindow ?? NSApplication.shared.windows.first,
                  let cv = win.contentView else {
                return .internalError
            }
            guard let rep = cv.bitmapImageRepForCachingDisplay(in: cv.bounds) else {
                return .internalError
            }
            cv.cacheDisplay(in: cv.bounds, to: rep)
            guard let png = rep.representation(using: .png, properties: [:]) else {
                return .internalError
            }
            return .ok(data: png, contentType: "image/png")
        }
    }
}
