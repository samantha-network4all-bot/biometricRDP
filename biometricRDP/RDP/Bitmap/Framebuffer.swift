import Foundation

public final class Framebuffer {
    public private(set) var width: Int
    public private(set) var height: Int
    public private(set) var pixels: [UInt8] // RGBA

    public init(width: Int, height: Int) {
        self.width = width
        self.height = height
        self.pixels = [UInt8](repeating: 0, count: width * height * 4)
    }

    public func setPixel(x: Int, y: Int, r: UInt8, g: UInt8, b: UInt8) {
        guard x >= 0, x < width, y >= 0, y < height else { return }
        let offset = (y * width + x) * 4
        pixels[offset] = r
        pixels[offset + 1] = g
        pixels[offset + 2] = b
        pixels[offset + 3] = 255
    }

    public func colorAt(x: Int, y: Int) -> (r: UInt8, g: UInt8, b: UInt8) {
        guard x >= 0, x < width, y >= 0, y < height else { return (0, 0, 0) }
        let offset = (y * width + x) * 4
        return (pixels[offset], pixels[offset + 1], pixels[offset + 2])
    }
}
