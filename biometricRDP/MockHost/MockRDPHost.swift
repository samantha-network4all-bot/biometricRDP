import Foundation
import Network

final class MockRDPHost {

    private(set) var port: NWEndpoint.Port = .any
    var width: Int = 1280
    var height: Int = 800
    var bpp: Int = 32

    private var listener: NWListener?
    private var connection: NWConnection?
    private let queue = DispatchQueue(label: "mock-rdp-host")
    private var lastKeys: [[String: Any]] = []
    private var lastMouse: [[String: Any]] = []
    private var lastText: String = ""

    func start(nla: Bool, username: String, password: String,
               width: Int, height: Int, bpp: Int) throws {
        self.width = width
        self.height = height
        self.bpp = bpp

        let params = NWParameters.tcp
        listener = try NWListener(using: params, on: .any)
        listener?.stateUpdateHandler = { state in
            if case .failed(let err) = state {
                NSLog("MockRDPHost listener failed: \(err)")
            }
        }
        listener?.newConnectionHandler = { [weak self] conn in
            self?.handleConnection(conn)
        }
        listener?.start(queue: queue)

        var waited = 0
        while (listener?.port ?? .any) == .any && waited < 100 {
            Thread.sleep(forTimeInterval: 0.01)
            waited += 1
        }
        guard let p = listener?.port, p != .any else {
            throw NSError(domain: "MockRDPHost", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "no port assigned"])
        }
        self.port = p
    }

    var isRunning: Bool { listener != nil }
    var hasClientConnected: Bool { connection != nil }

    func stop() {
        connection?.cancel()
        connection = nil
        listener?.cancel()
        listener = nil
        port = .any
        lastKeys = []
        lastMouse = []
        lastText = ""
    }

    func lastInputKeys() -> [[String: Any]] { lastKeys }
    func lastInputMouse() -> [[String: Any]] { lastMouse }
    func lastInputText() -> String { lastText }
    func pushSolid(r: UInt8, g: UInt8, b: UInt8) { /* S2 placeholder */ }

    // MARK: - Connection handling

    private func handleConnection(_ conn: NWConnection) {
        connection = conn
        conn.start(queue: queue)
        handleHandshakePhase(conn)
    }

    private enum Phase { case waitingCR, waitingMCS, waitingCaps, active }

    private func handleHandshakePhase(_ conn: NWConnection) {
        var phase: Phase = .waitingCR
        var buf = Data()

        func readNext() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, _ in
                guard let self else { return }
                if let d = data, !d.isEmpty { buf.append(d) }

                switch phase {
                case .waitingCR:
                    if self.consumeX224CR(buf: &buf) {
                        conn.send(content: self.buildCC(), completion: .contentProcessed { _ in })
                        phase = .waitingMCS
                    }
                case .waitingMCS:
                    if self.consumeMCSConnect(buf: &buf) {
                        conn.send(content: self.buildMCSResponse(), completion: .contentProcessed { _ in })
                        phase = .waitingCaps
                    }
                case .waitingCaps:
                    if self.consumeCapabilities(buf: &buf) {
                        conn.send(content: self.buildDemandActive(), completion: .contentProcessed { _ in })
                        phase = .active
                    }
                case .active:
                    if isComplete { conn.cancel(); self.connection = nil; return }
                    buf = Data()
                    readNext()
                    return
                }

                if isComplete {
                    if phase != .active { conn.cancel(); self.connection = nil }
                    return
                }
                readNext()
            }
        }
        readNext()
    }

    // MARK: - PDU consumers

    private func consumeX224CR(buf: inout Data) -> Bool {
        guard buf.count >= 11 else { return false }
        guard buf[0] == 0x03 else { return false }
        let tpktLen = (Int(buf[2]) << 8) | Int(buf[3])
        guard tpktLen >= 7 else { return false }
        guard tpktLen <= buf.count else { return false } // must be complete
        let li = buf[4]
        guard li >= 5 else { return false }
        guard buf[5] == 0xE0 else { return false }
        buf = Data(buf.dropFirst(tpktLen))
        return true
    }

    private func consumeMCSConnect(buf: inout Data) -> Bool {
        guard buf.count >= 11 else { return false }
        guard buf[0] == 0x03 else { return false }
        let tpktLen = (Int(buf[2]) << 8) | Int(buf[3])
        guard tpktLen >= 7 else { return false }
        guard tpktLen <= buf.count else { return false } // must be complete
        guard buf[4] >= 2 else { return false }
        guard (buf[5] & 0xF0) == 0xF0 else { return false }
        let mcsStart = 7
        guard mcsStart < buf.count, buf[mcsStart] == 0x61 else { return false }
        buf = Data(buf.dropFirst(tpktLen))
        return true
    }

    private func consumeCapabilities(buf: inout Data) -> Bool {
        // Must have at least one complete TPKT + X.224 data PDU
        guard buf.count >= 7 else { return false }
        guard buf[0] == 0x03 else { return false }
        // Count how many complete TPKT packets are in the buffer
        var offset = 0
        var completePackets = 0
        while offset + 4 <= buf.count {
            guard buf[offset] == 0x03 else { break }
            let thisLen = (Int(buf[offset + 2]) << 8) | Int(buf[offset + 3])
            guard thisLen >= 7 else { break }
            guard offset + thisLen <= buf.count else { break } // must be complete
            // Verify X.224 data TPDU: LI >= 2, type 0xF0
            guard buf[offset + 4] >= 2 else { break }
            guard (buf[offset + 5] & 0xF0) == 0xF0 else { break }
            offset += thisLen
            completePackets += 1
        }
        guard completePackets > 0 else { return false }
        buf = Data(buf.dropFirst(offset))
        return true
    }

    // MARK: - PDU builders

    private func buildCC() -> Data {
        let x224: [UInt8] = [0xD0, 0x00, 0x00, 0x00, 0x00, 0x00]
        let neg: [UInt8] = [0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]
        var tpdu = x224; tpdu.append(contentsOf: neg)
        let totalLen = 4 + 1 + tpdu.count
        let tpkt: [UInt8] = [0x03, 0x00, UInt8((totalLen >> 8) & 0xFF), UInt8(totalLen & 0xFF)]
        var pkt = Data(tpkt)
        pkt.append(UInt8(1 + tpdu.count))
        pkt.append(contentsOf: tpdu)
        return pkt
    }

    private func buildMCSResponse() -> Data {
        // MCS Connect Response BER [APPLICATION 102]
        let result: [UInt8] = [0xA0, 0x01, 0x00] // success
        let connectId = Data([0x02, 0x01, 0x00])
        let domainParams = buildDomainParams()
        let gccRsp = buildGCCResponse()
        let userData = berOctetString(gccRsp)
        let seq = Data(result) + connectId + domainParams + userData
        let mcsBER = berWrap(tag: 0x62, content: seq)
        return wrapTPKT(payload: mcsBER)
    }

    private func buildDomainParams() -> Data {
        let fields = [berInt(34), berInt(3), berInt(0), berInt(1),
                      berInt(0), berInt(1), berInt(65535), berInt(2)]
        return berSequence(fields.reduce(Data()) { $0 + $1 })
    }

    private func buildGCCResponse() -> Data {
        // Minimal GCC Conference Create Response
        return Data([
            0x00, 0x14, 0x00, 0x00, // H.221 non-std key
            0x0C, 0x19, // ConnectPDU
            0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x14, 0x79, 0x70,
            0x04, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00
        ])
    }

    private func buildDemandActive() -> Data {
        let shareID: UInt32 = 0x03EA03EA
        var body = Data()
        body.append(contentsOf: withUnsafeBytes(of: shareID.littleEndian) { Array($0) })
        body.append(contentsOf: [0x04, 0x00]) // lengthSource
        body.append(contentsOf: [0x00, 0x00]) // combinedCapLen placeholder
        body.append(contentsOf: [0x01, 0x00]) // numCaps
        body.append(contentsOf: Array("RDP ".utf8))
        // General capability set
        body.append(contentsOf: [0x01, 0x00, 0x18, 0x00])
        body.append(contentsOf: [0x01, 0x00, 0x03, 0x00, 0x20, 0x00, 0x00, 0x00])
        body.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00])
        body.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        body.append(0x00) // pad
        let ccLen = body.count - 8
        body[10] = UInt8(ccLen & 0xFF)
        body[11] = UInt8((ccLen >> 8) & 0xFF)

        let pduSource: UInt16 = 0x03E9
        let totalLen = 6 + 4 + body.count
        var sc = Data()
        sc.append(UInt8(totalLen & 0xFF))
        sc.append(UInt8((totalLen >> 8) & 0xFF))
        sc.append(0x11) // PDUTYPE2_DEMANDACTIVE
        sc.append(UInt8(pduSource & 0xFF))
        sc.append(UInt8((pduSource >> 8) & 0xFF))
        sc.append(0x01) // streamID
        sc.append(UInt8((body.count + 12) & 0xFF))
        sc.append(UInt8(((body.count + 12) >> 8) & 0xFF))
        sc.append(0x11) // pduType2
        sc.append(0x00) // compression

        return wrapTPKT(payload: sc + body)
    }

    // MARK: - BER helpers

    private func berWrap(tag: UInt8, content: Data) -> Data {
        var r = Data([tag])
        r.append(berLength(content.count))
        r.append(content)
        return r
    }

    private func berSequence(_ c: Data) -> Data { berWrap(tag: 0x30, content: c) }
    private func berOctetString(_ d: Data) -> Data { berWrap(tag: 0x04, content: d) }
    private func berInt(_ v: Int) -> Data {
        if v >= 0 && v < 128 { return Data([0x02, 0x01, UInt8(v)]) }
        return Data([0x02, 0x02, UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)])
    }

    private func berLength(_ n: Int) -> Data {
        if n < 128 { return Data([UInt8(n)]) }
        if n <= 0xFF { return Data([0x81, UInt8(n)]) }
        return Data([0x82, UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)])
    }

    private func wrapTPKT(payload: Data) -> Data {
        let hdr: [UInt8] = [UInt8(2 + payload.count), 0xF0, 0x80]
        let tpktLen = 4 + hdr.count + payload.count
        let tpkt: [UInt8] = [0x03, 0x00, UInt8((tpktLen >> 8) & 0xFF), UInt8(tpktLen & 0xFF)]
        var pkt = Data(tpkt)
        pkt.append(contentsOf: hdr)
        pkt.append(payload)
        return pkt
    }
}
