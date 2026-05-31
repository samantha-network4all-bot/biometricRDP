import Foundation

/// Audio Virtual Channel (rdpsnd) message types and serialization.
/// Protocol reference: MS-RDPSND
enum RDPSND {
    // Message types
    static let SNDC_FORMATS: UInt16 = 0x0002
    static let SNDC_TRAINING: UInt16 = 0x0006
    static let SNDC_WAVE: UInt16 = 0x0007
    static let SNDC_CLOSE: UInt16 = 0x0001
    static let SNDC_CRYPTKEY: UInt16 = 0x0008
    static let SNDC_WAVEENCRYPT: UInt16 = 0x0009
    static let SNDC_UDPRESEND: UInt16 = 0x0003
    static let SNDC_QUALITYMODE: UInt16 = 0x000C
    static let SNDC_WAVEINFO: UInt16 = 0x0005

    // Audio format tags
    static let WAVE_FORMAT_PCM: UInt16 = 0x0001

    /// Build SNDC_FORMATS message advertising PCM 16-bit 44100Hz stereo.
    static func buildFormats() -> Data {
        var body = Data()
        body.append(contentsOf: withUnsafeBytes(of: UInt32(1).littleEndian) { Array($0) }) // dwFlags = SNDC_FORMATS
        body.append(contentsOf: withUnsafeBytes(of: UInt32(0).littleEndian) { Array($0) }) // dwVolume
        body.append(contentsOf: withUnsafeBytes(of: UInt32(0).littleEndian) { Array($0) }) // dwPitch
        body.append(contentsOf: [0x00, 0x00]) // wDGramPort (unused)
        body.append(contentsOf: withUnsafeBytes(of: UInt16(1).littleEndian) { Array($0) }) // wNumberOfFormats
        body.append(0x00) // cLastBlockConfirmed
        body.append(contentsOf: withUnsafeBytes(of: UInt16(1).littleEndian) { Array($0) }) // wVersion = 1
        body.append(0x00) // bPad
        // One format entry: PCM 16-bit 44100Hz stereo
        body.append(contentsOf: withUnsafeBytes(of: WAVE_FORMAT_PCM.littleEndian) { Array($0) }) // wFormatTag
        body.append(contentsOf: withUnsafeBytes(of: UInt16(2).littleEndian) { Array($0) }) // nChannels = 2
        body.append(contentsOf: withUnsafeBytes(of: UInt32(44100).littleEndian) { Array($0) }) // nSamplesPerSec
        body.append(contentsOf: withUnsafeBytes(of: UInt32(44100 * 2 * 2).littleEndian) { Array($0) }) // nAvgBytesPerSec
        body.append(contentsOf: withUnsafeBytes(of: UInt16(4).littleEndian) { Array($0) }) // nBlockAlign
        body.append(contentsOf: withUnsafeBytes(of: UInt16(16).littleEndian) { Array($0) }) // wBitsPerSample
        body.append(contentsOf: [0x00, 0x00]) // cbSize = 0
        return buildMessage(msgType: SNDC_FORMATS, body: body)
    }

    /// Build SNDC_TRAINING response.
    static func buildTrainingResponse() -> Data {
        var body = Data()
        body.append(contentsOf: withUnsafeBytes(of: UInt16(0x00FE).littleEndian) { Array($0) }) // wTimeStamp
        body.append(contentsOf: withUnsafeBytes(of: UInt16(0).littleEndian) { Array($0) }) // wPackSize
        return buildMessage(msgType: SNDC_TRAINING, body: body)
    }

    /// Build SNDC_WAVE message with PCM data.
    static func buildWave(pcmData: Data) -> Data {
        var body = Data()
        body.append(contentsOf: withUnsafeBytes(of: UInt16(0).littleEndian) { Array($0) }) // wTimeStamp
        body.append(contentsOf: withUnsafeBytes(of: UInt16(1).littleEndian) { Array($0) }) // wFormatNo
        body.append(0x00) // bPad
        body.append(pcmData)
        return buildMessage(msgType: SNDC_WAVE, body: body)
    }

    /// Parse an rdpsnd message. Returns (msgType, body) or nil.
    static func parseMessage(_ data: Data) -> (msgType: UInt16, body: Data)? {
        guard data.count >= 4 else { return nil }
        let msgType = UInt16(data[0]) | (UInt16(data[1]) << 8)
        let bodyLen = Int(data[2]) | (Int(data[3]) << 8)
        guard 4 + bodyLen <= data.count else { return nil }
        let body = data.subdata(in: 4..<(4 + bodyLen))
        return (msgType, body)
    }

    /// Build an rdpsnd message header + body.
    private static func buildMessage(msgType: UInt16, body: Data) -> Data {
        var msg = Data()
        msg.append(contentsOf: withUnsafeBytes(of: msgType.littleEndian) { Array($0) })
        msg.append(contentsOf: withUnsafeBytes(of: UInt16(body.count).littleEndian) { Array($0) })
        msg.append(body)
        return msg
    }
}
