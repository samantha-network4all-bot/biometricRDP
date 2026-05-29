import Foundation
import CoreGraphics
import AppKit

final class Framebuffer {
    var width: Int
    var height: Int
    var pixels: [UInt8] // RGBA

    init(width: Int, height: Int) {
        self.width = width
        self.height = height
        self.pixels = [UInt8](repeating: 0, count: width * height * 4)
    }

    var cgImage: CGImage? {
        let colorSpace = CGColorSpaceCreateDeviceRGB()
        let bitmapInfo = CGBitmapInfo(rawValue: CGImageAlphaInfo.premultipliedLast.rawValue)
        guard let provider = CGDataProvider(data: Data(pixels) as CFData) else { return nil }
        return CGImage(width: width,
                       height: height,
                       bitsPerComponent: 8,
                       bitsPerPixel: 32,
                       bytesPerRow: width * 4,
                       space: colorSpace,
                       bitmapInfo: bitmapInfo,
                       provider: provider,
                       decode: nil,
                       shouldInterpolate: false,
                       intent: .defaultIntent)
    }

    func pngData() -> Data? {
        guard let img = cgImage else { return nil }
        let rep = NSBitmapImageRep(cgImage: img)
        return rep.representation(using: .png, properties: [:])
    }

    func setPixel(x: Int, y: Int, r: UInt8, g: UInt8, b: UInt8) {
        guard x >= 0, x < width, y >= 0, y < height else { return }
        let offset = (y * width + x) * 4
        pixels[offset] = r
        pixels[offset + 1] = g
        pixels[offset + 2] = b
        pixels[offset + 3] = 255
    }
}
