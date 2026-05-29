import AppKit

final class DesktopView: NSView {

    var framebuffer: Framebuffer?

    override var isFlipped: Bool { true }

    override func draw(_ dirtyRect: NSRect) {
        NSColor.black.setFill()
        dirtyRect.fill()

        guard let fb = framebuffer else { return }
        guard let rep = fb.cgImage.flatMap({ NSBitmapImageRep(cgImage: $0) }) else { return }
        rep.draw(in: bounds)
    }
}
