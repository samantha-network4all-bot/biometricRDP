import Foundation
import Network

final class MockRDPHost {

    // MARK: - Instance state

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

    var isRunning: Bool {
        return listener != nil
    }

    var hasClientConnected: Bool {
        return connection != nil
    }

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

        // Perform X.224 handshake
        handleHandshake(conn)
    }

    private func handleHandshake(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, isComplete, _ in
            guard let self else { return }
            guard let data = data, !data.isEmpty else {
                if isComplete {
                    conn.cancel()
                    self.connection = nil
                }
                return
            }

            // Check if we got a valid X.224 CR
            if self.isConnectionRequest(data) {
                // Send X.224 CC
                let cc = self.buildConnectionConfirm()
                conn.send(content: cc, completion: .contentProcessed { _ in })
            }

            // Continue draining
            if !isComplete {
                self.drainConnection(conn)
            }
        }
    }

    private func drainConnection(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) {
            [weak self] data, _, isComplete, _ in
            if let data = data, !data.isEmpty {
                self?.processIncoming(data)
            }
            if isComplete {
                conn.cancel()
                self?.connection = nil
                return
            }
            self?.drainConnection(conn)
        }
    }

    private func processIncoming(_ data: Data) {
        // S2 placeholder: real RDP input parsing deferred to later slices.
    }

    // MARK: - X.224

    private func isConnectionRequest(_ data: Data) -> Bool {
        // TPKT: version=3, reserved=0, length(2); LI >= 5; CR=0xE0
        guard data.count >= 11 else { return false }
        guard data[0] == 0x03 else { return false }
        let li = data[4]
        guard li >= 5 else { return false }
        let tpduCode = data[5]
        return tpduCode == 0xE0 // CR
    }

    private func buildConnectionConfirm() -> Data {
        // X.224 CC-TPDU
        let x224: [UInt8] = [
            0xD0, // CC code
            0x00, 0x00, // DST-REF
            0x00, 0x00, // SRC-REF
            0x00  // CLASS 0
        ]

        // RDP Negotiation Response: type=0x02, protocols=0 (standard RDP security)
        let rdpNegRsp: [UInt8] = [
            0x02, // TYPE_RDP_NEG_RSP
            0x00, // flags
            0x08, 0x00, // length = 8
            0x00, 0x00, 0x00, 0x00  // selected protocol = 0 (standard RDP)
        ]

        var tpdu = x224
        tpdu.append(contentsOf: rdpNegRsp)

        // TPKT header
        let totalLen = 4 + 1 + tpdu.count
        let tpkt: [UInt8] = [
            0x03, 0x00,
            UInt8((totalLen >> 8) & 0xFF),
            UInt8(totalLen & 0xFF)
        ]

        var packet = tpkt
        packet.append(UInt8(1 + tpdu.count)) // LI
        packet.append(contentsOf: tpdu)
        return Data(packet)
    }
}
