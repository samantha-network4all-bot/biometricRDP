import AppKit

final class DesktopView: NSView {

    var framebuffer: Framebuffer?

    override var isFlipped: Bool { true }

    override func draw(_ dirtyRect: NSRect) {
        NSColor.black.setFill()
        dirtyRect.fill()

        guard let fb = framebuffer else { return }
        let view = FramebufferView(fb: fb)
        guard let img = view.cgImage else { return }
        let rep = NSBitmapImageRep(cgImage: img)
        rep.draw(in: bounds)
    }
}
