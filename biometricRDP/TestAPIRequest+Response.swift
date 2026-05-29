import Foundation

struct TestAPIRequest {
    let method: String
    let path: String
    let queryItems: [URLQueryItem]
    let headers: [String: String]
    let body: Data

    init(method: String, path: String, headers: [String: String] = [:], body: Data = Data()) {
        self.method = method
        var comps = URLComponents(string: path)!
        self.queryItems = comps.queryItems ?? []
        comps.query = nil
        self.path = comps.path
        self.headers = headers
        self.body = body
    }
}

struct TestAPIResponse {
    let status: Int
    let headers: [String: String]
    let body: Data

    static func ok(json data: Data) -> TestAPIResponse {
        return TestAPIResponse(status: 200,
                        headers: ["Content-Type": "application/json"],
                        body: data)
    }

    static func ok(data: Data, contentType: String) -> TestAPIResponse {
        return TestAPIResponse(status: 200,
                        headers: ["Content-Type": contentType],
                        body: data)
    }

    static var notFound: TestAPIResponse {
        let body = try! JSONSerialization.data(withJSONObject: ["error": "not found"])
        return TestAPIResponse(status: 404,
                        headers: ["Content-Type": "application/json"],
                        body: body)
    }

    static func notFound(_ req: TestAPIRequest) -> TestAPIResponse {
        return notFound
    }

    static func badRequest(_ msg: String) -> TestAPIResponse {
        let body = try! JSONSerialization.data(withJSONObject: ["error": msg])
        return TestAPIResponse(status: 400,
                        headers: ["Content-Type": "application/json"],
                        body: body)
    }

    static var internalError: TestAPIResponse {
        let body = try! JSONSerialization.data(withJSONObject: ["error": "internal error"])
        return TestAPIResponse(status: 500,
                        headers: ["Content-Type": "application/json"],
                        body: body)
    }
}
