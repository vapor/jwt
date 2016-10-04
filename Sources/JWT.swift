import JSON

struct JWT {

    enum Header: String {
        case algorithm = "alg"
        case type = "typ"
    }

    private let algorithmHeaderValue: String
    let header: JSON
    let payload: JSON
    let signature: String

    init(payload: JSON, algorithm: Algorithm, extraHeaders: JSON = JSON([:])) throws {
        header = JSON([Header.algorithm.rawValue: .string(algorithm.headerValue),
                       Header.type.rawValue: "JWT"])
        self.algorithmHeaderValue = algorithm.headerValue
        self.payload = payload
        let encodedHeaderAndPayload = "\(try header.base64String()).\(try payload.base64String())"
        signature = try algorithm.encrypt(encodedHeaderAndPayload)
    }

    init(token: String) throws {
        let segments = token.components(separatedBy: ".")
        guard segments.count == 3 else {
            throw JWTError.incorrectNumberOfSegments
        }
        header = try JSON(base64Encoded: segments[0])
        guard let alg = header.object?[Header.algorithm.rawValue]?.string else {
            throw JWTError.missingAlgorithm
        }
        algorithmHeaderValue = alg
        payload = try JSON(base64Encoded: segments[1])
        signature = segments[2]
    }

    func tokenString() throws -> String {
        return "\(try header.base64String()).\(try payload.base64String()).\(signature)"
    }

    func verifySignature(key: String) throws -> Bool {
        let algorithm = try Algorithm(algorithmHeaderValue, key: key)

        let encodedHeaderAndPayload = "\(try header.base64String()).\(try payload.base64String())"

        return try algorithm.verifySignature(signature, message: encodedHeaderAndPayload)
    }
}
