import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    static var shared: AppDelegate?

    var appController: AppController!
    var testAPIServer: TestAPIServer?
    var mockController: MockController?

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
        // Force view load so WindowController.viewDidLoad registers window + session routes
        _ = wc.view
        window.makeKeyAndOrderFront(nil)
        wc.rdpWindow = window

        if ProcessInfo.processInfo.environment["BIOMETRICRDP_TEST_API"] == "1" {
            do {
                let server = TestAPIServer()
                try server.start()
                testAPIServer = server
            } catch {
                NSLog("Failed to start TestAPIServer: \(error)")
            }

            let mc = MockController()
            _ = mc.view
            mockController = mc
        }

        DispatchQueue.main.async {
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        true
    }
}
