import Foundation

struct RDPFile {
    var fields: [String: String] = [:]

    /// Parse an .rdp file (mstsc key:type:value format, one entry per line).
    /// `data` is the raw file data (UTF-8).
    /// Lines: `key:type:value` where type ∈ {s=string, i=integer, b=enumeration}.
    init(data: Data) {
        guard let text = String(data: data, encoding: .utf8) else { return }
        for line in text.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix("//") { continue }
            // Split on first two colons: key:type:value
            let parts = trimmed.split(separator: ":", maxSplits: 2, omittingEmptySubsequences: false)
            guard parts.count >= 3 else { continue }
            let key = String(parts[0])
            // parts[1] is "s", "i", or "b" — we store as string regardless
            // parts[2] is the value (may contain colons for string type)
            let value = String(parts[2])
            fields[key] = value
        }
    }

    init(fields: [String: String]) {
        self.fields = fields
    }

    /// Serialize to .rdp format (key:type:value, sorted by key).
    /// Keys containing a space sort before keys without, then alphabetically within each group.
    func serialize() -> String {
        var lines: [String] = []
        let sortedKeys = fields.keys.sorted { a, b in
            let aHasSpace = a.contains(" ")
            let bHasSpace = b.contains(" ")
            if aHasSpace != bHasSpace { return aHasSpace }
            return a < b
        }
        for key in sortedKeys {
            guard let value = fields[key] else { continue }
            let type: String
            if Int(value) != nil {
                type = "i"
            } else {
                type = "s"
            }
            lines.append("\(key):\(type):\(value)")
        }
        return lines.joined(separator: "\n")
    }

    // Accessors for well-known keys:
    var fullAddress: String? { fields["full address"] }
    var desktopWidth: Int? { fields["desktopwidth"].flatMap(Int.init) }
    var desktopHeight: Int? { fields["desktopheight"].flatMap(Int.init) }
    var sessionBpp: Int? { fields["session bpp"].flatMap(Int.init) }
    var username: String? { fields["username"] }
    var domain: String? { fields["domain"] }
    var screenMode: Int? { fields["screen mode id"].flatMap(Int.init) }
    var audioMode: Int? { fields["audiomode"].flatMap(Int.init) }
    var redirectClipboard: Int? { fields["redirectclipboard"].flatMap(Int.init) }
    var disableWallpaper: Int? { fields["disable wallpaper"].flatMap(Int.init) }
}
