import Foundation
import CoreGraphics
import AppKit

/// Thin wrapper around RDP/Bitmap/Framebuffer that adds AppKit/CoreGraphics rendering.
final class FramebufferView {
    let buffer: Framebuffer

    init(_ width: Int, _ height: Int) {
        self.buffer = Framebuffer(width: width, height: height)
    }

    init(fb: Framebuffer) {
        self.buffer = fb
    }

    var cgImage: CGImage? {
        let colorSpace = CGColorSpaceCreateDeviceRGB()
        let bitmapInfo = CGBitmapInfo(rawValue: CGImageAlphaInfo.premultipliedLast.rawValue)
        guard let provider = CGDataProvider(data: Data(buffer.pixels) as CFData) else { return nil }
        return CGImage(width: buffer.width, height: buffer.height,
                       bitsPerComponent: 8, bitsPerPixel: 32,
                       bytesPerRow: buffer.width * 4,
                       space: colorSpace, bitmapInfo: bitmapInfo,
                       provider: provider, decode: nil,
                       shouldInterpolate: false, intent: .defaultIntent)
    }

    func pngData() -> Data? {
        guard let img = cgImage else { return nil }
        let rep = NSBitmapImageRep(cgImage: img)
        return rep.representation(using: .png, properties: [:])
    }
}
