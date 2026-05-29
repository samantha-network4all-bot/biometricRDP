import Foundation
import Network

final class TestAPIServer {
    private var listener: NWListener?
    private let queue = DispatchQueue(label: "test-api")
    private var connections: [ObjectIdentifier: NWConnection] = [:]
    private var buffers: [ObjectIdentifier: Data] = [:]

    func start() throws {
        let params = NWParameters.tcp
        listener = try NWListener(using: params, on: .any)
        listener?.stateUpdateHandler = { state in
            if case .failed(let err) = state {
                NSLog("TestAPIServer failed: \(err)")
            }
        }
        listener?.newConnectionHandler = { [weak self] conn in
            self?.handle(conn)
        }
        listener?.start(queue: queue)

        if let port = listener?.port {
            writePortFile(port)
        }
    }

    private func writePortFile(_ port: NWEndpoint.Port) {
        let url = try! FileManager.default.url(for: .applicationSupportDirectory,
                                                in: .userDomainMask,
                                                appropriateFor: nil,
                                                create: true)
            .appendingPathComponent("biometricRDP")
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        let portFile = url.appendingPathComponent("test-api.port")
        try? "\(port.rawValue)\n".write(to: portFile, atomically: true, encoding: .utf8)
    }

    private func key(for conn: NWConnection) -> ObjectIdentifier {
        return ObjectIdentifier(conn)
    }

    private func handle(_ conn: NWConnection) {
        let k = key(for: conn)
        connections[k] = conn
        buffers[k] = Data()
        conn.start(queue: queue)
        readNext(conn)
    }

    private func readNext(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            let k = self?.key(for: conn)
            if let data = data, !data.isEmpty {
                self?.buffers[k!]?.append(data)
            }
            if isComplete || error != nil {
                if let buffered = self?.buffers[k!], !buffered.isEmpty {
                    self?.process(data: buffered, conn: conn)
                } else {
                    self?.connections.removeValue(forKey: k!)
                    self?.buffers.removeValue(forKey: k!)
                }
                return
            }
            self?.readNext(conn)
        }
    }

    private func process(data: Data, conn: NWConnection) {
        guard let req = HTTPRequestParser.parse(data: data) else {
            send(response: TestAPIResponse.badRequest("malformed request"), conn: conn)
            return
        }
        let apiReq = TestAPIRequest(method: req.method, path: req.path,
                                     headers: req.headers, body: req.body)
        let apiResp = TestAPIRouter.shared.dispatch(apiReq)
        send(response: apiResp, conn: conn)
    }

    private func send(response: TestAPIResponse, conn: NWConnection) {
        var headers = "HTTP/1.1 \(response.status) \(statusText(response.status))\r\n"
        for (k, v) in response.headers {
            headers += "\(k): \(v)\r\n"
        }
        headers += "Content-Length: \(response.body.count)\r\n"
        headers += "Connection: close\r\n\r\n"
        var data = headers.data(using: .utf8)!
        data.append(response.body)
        let k = key(for: conn)
        conn.send(content: data, completion: .contentProcessed { [weak self] _ in
            conn.cancel()
            self?.connections.removeValue(forKey: k)
            self?.buffers.removeValue(forKey: k)
        })
    }

    private func statusText(_ code: Int) -> String {
        switch code {
        case 200: return "OK"
        case 400: return "Bad Request"
        case 404: return "Not Found"
        case 500: return "Internal Server Error"
        default: return "Unknown"
        }
    }
}

struct HTTPRequest {
    let method: String
    let path: String
    let headers: [String: String]
    let body: Data
}

struct HTTPRequestParser {
    static func parse(data: Data) -> HTTPRequest? {
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        let lines = text.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return nil }
        let parts = requestLine.components(separatedBy: " ")
        guard parts.count >= 2 else { return nil }
        let method = parts[0]
        let path = parts[1]
        var headers: [String: String] = [:]
        var i = 1
        while i < lines.count, !lines[i].isEmpty {
            let hp = lines[i].components(separatedBy: ": ")
            if hp.count >= 2 {
                headers[hp[0]] = hp.dropFirst().joined(separator: ": ")
            }
            i += 1
        }
        i += 1
        let bodyLines = Array(lines[i...])
        let bodyStr = bodyLines.joined(separator: "\r\n")
        let body = bodyStr.data(using: .utf8) ?? Data()
        return HTTPRequest(method: method, path: path, headers: headers, body: body)
    }
}
