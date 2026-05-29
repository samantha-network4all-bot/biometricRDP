import AppKit

final class RootView: NSView {

    let desktopView: DesktopView
    var onConnect: ((String) -> Void)?
    var onDisconnect: (() -> Void)?

    private var hostField: NSTextField!
    private var connectButton: NSButton!
    private var disconnectButton: NSButton!

    override init(frame: NSRect) {
        desktopView = DesktopView(frame: .zero)
        super.init(frame: frame)
        setupUI()
    }

    required init?(coder: NSCoder) { fatalError() }

    private func setupUI() {
        wantsLayer = true

        let barHeight: CGFloat = 40
        let bar = NSView(frame: NSRect(x: 0, y: bounds.height - barHeight,
                                        width: bounds.width, height: barHeight))
        bar.autoresizingMask = [.width, .minYMargin]
        bar.wantsLayer = true
        bar.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor

        hostField = NSTextField(frame: NSRect(x: 8, y: 8, width: 260, height: 24))
        hostField.placeholderString = "Host"
        hostField.autoresizingMask = [.width, .maxYMargin]
        bar.addSubview(hostField)

        connectButton = NSButton(frame: NSRect(x: 276, y: 8, width: 90, height: 24))
        connectButton.title = "Connect"
        connectButton.bezelStyle = .rounded
        connectButton.target = self
        connectAction(connectButton)
        connectButton.autoresizingMask = [.maxXMargin, .maxYMargin]
        bar.addSubview(connectButton)

        disconnectButton = NSButton(frame: NSRect(x: 374, y: 8, width: 100, height: 24))
        disconnectButton.title = "Disconnect"
        disconnectButton.bezelStyle = .rounded
        disconnectButton.target = self
        disconnectButton.action = #selector(disconnectAction)
        disconnectButton.autoresizingMask = [.maxXMargin, .maxYMargin]
        bar.addSubview(disconnectButton)

        addSubview(bar)

        desktopView.frame = NSRect(x: 0, y: 0,
                                   width: bounds.width,
                                   height: bounds.height - barHeight)
        desktopView.autoresizingMask = [.width, .height]
        addSubview(desktopView)
    }

    @objc private func connectAction(_ sender: Any?) {
        onConnect?(hostField.stringValue)
    }

    @objc private func disconnectAction(_ sender: Any?) {
        onDisconnect?()
    }
}
