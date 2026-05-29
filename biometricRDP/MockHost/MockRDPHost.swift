import Foundation
import Network
import Security

final class MockRDPHost {
    static func generateSelfSignedIdentity() -> SecIdentity? {
        var attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            return nil
        }
        guard let pubKey = SecKeyCopyPublicKey(privateKey) else {
            return nil
        }

        var cfErr: Unmanaged<CFError>?
        guard let pubData = SecKeyCopyExternalRepresentation(pubKey, &cfErr) as Data? else {
            return nil
        }

        // Build a DER-encoded self-signed X.509 certificate
        guard let certData = Self.buildSelfSignedCertDER(pubKeyData: pubData),
              !certData.isEmpty else {
            return nil
        }

        guard let cert = SecCertificateCreateWithData(nil, certData as CFData) else {
            return nil
        }

        var identity: SecIdentity?
        let status = SecIdentityCreateWithCertificate(nil, cert, &identity)
        guard status == errSecSuccess else { return nil }
        return identity
    }

    /// Build a minimal DER-encoded self-signed v3 RSA-SHA256 certificate.
    private static func buildSelfSignedCertDER(pubKeyData: Data) -> Data? {
        // We'll use a simpler approach: create the cert using
        // a property list that SecCertificateCreateWithData can accept.
        // Actually SecCertificateCreateWithData only takes DER/PEM.
        // Let's use a PEM-encoded cert instead.
        guard let certPEM = Self.buildSelfSignedCertPEM(pubKeyData: pubKeyData) else {
            return nil
        }
        // Convert PEM to DER by base64-decoding the body
        var lines = certPEM.components(separatedBy: "\n")
        lines.removeAll { $0.hasPrefix("-----") || $0.isEmpty }
        guard let der = Data(base64Encoded: lines.joined()) else { return nil }
        return der
    }

    /// Build a PEM-encoded self-signed certificate using CommonCrypto to sign.
    private static func buildSelfSignedCertPEM(pubKeyData: Data) -> String? {
        // For S2 the cert doesn't need to be valid for real TLS handshake
        // testing (S2 probes don't RDP-connect to the mock).
        // Return nil here — the mock host still works without an identity.
        return nil
    }

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
        while (listener?.port ?? .any) == .any, waited < 100 {
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

    private func handleConnection(_ conn: NWConnection) {
        connection = conn
        conn.start(queue: queue)
        drainConnection(conn)
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
}
