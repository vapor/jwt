import JSON

public struct JWT {

    private let algorithmHeaderValue: String
    let header: JSON
    let payload: JSON
    let signature: String

    public init(payload: JSON, algorithm: Algorithm, extraHeaders: [String: Node] = [:]) throws {
        header = JSON(.object(
            Header.algorithm(algorithm).object +
            Header.type.object +
            extraHeaders))

        self.algorithmHeaderValue = algorithm.headerValue
        self.payload = payload
        let encodedHeaderAndPayload = "\(try header.base64String()).\(try payload.base64String())"
        signature = try algorithm.encrypt(encodedHeaderAndPayload)
    }

    public init(token: String) throws {
        let segments = token.components(separatedBy: ".")
        guard segments.count == 3 else {
            throw JWTError.incorrectNumberOfSegments
        }
        header = try JSON(base64Encoded: segments[0])
        guard let alg = header.object?[Header.algorithmKey]?.string else {
            throw JWTError.missingAlgorithm
        }
        algorithmHeaderValue = alg
        payload = try JSON(base64Encoded: segments[1])
        signature = segments[2]
    }

    public func tokenString() throws -> String {
        return "\(try header.base64String()).\(try payload.base64String()).\(signature)"
    }

    public func verifySignature(key: String) throws -> Bool {
        let algorithm = try Algorithm(algorithmHeaderValue, key: key)

        let encodedHeaderAndPayload = "\(try header.base64String()).\(try payload.base64String())"

        return try algorithm.verifySignature(signature, message: encodedHeaderAndPayload)
    }
}

private func + (lhs: [String: Node], rhs: [String: Node]) -> [String: Node] {
    var result = lhs
    rhs.forEach {
        result[$0.key] = $0.value
    }
    return result
}

private enum Header {

    static let algorithmKey = "alg"
    static let typeKey = "typ"

    case algorithm(Algorithm)
    case type

    var key: String {
        switch self {
        case .algorithm: return Header.algorithmKey
        case .type: return Header.typeKey
        }
    }

    var object: [String: Node] {
        return [key: .string(value)]

    }

    var value: String {
        switch self {
        case .algorithm(let algorithm): return algorithm.headerValue
        case .type: return "JWT"
        }
    }
}
