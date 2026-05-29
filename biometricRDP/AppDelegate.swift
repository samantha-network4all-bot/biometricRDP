import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    static var shared: AppDelegate?

    var appController: AppController!

    func applicationDidFinishLaunching(_ notification: Notification) {
        AppDelegate.shared = self

        appController = AppController()
        appController.registerRoutes(on: TestAPIRouter.shared)

        let wc = WindowController()
        appController.windowController = wc

        let window = RDPWindow(contentRect: NSRect(x: 100, y: 100, width: 1280, height: 800),
                               styleMask: [.titled, .closable, .miniaturizable, .resizable],
                               backing: .buffered,
                               defer: false)
        window.title = "biometricRDP"
        window.contentViewController = wc
        window.makeKeyAndOrderFront(nil)
        wc.rdpWindow = window

        if ProcessInfo.processInfo.environment["BIOMETRICRDP_TEST_API"] == "1" {
            do {
                let server = TestAPIServer()
                try server.start()
            } catch {
                NSLog("Failed to start TestAPIServer: \(error)")
            }
        }

        DispatchQueue.main.async {
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        true
    }
}
