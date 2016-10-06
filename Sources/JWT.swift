import Core
import Foundation
import JSON

public struct JWT {

    private static let separator = "."

    private let algorithmHeaderValue: String
    private let encoding: Encoding

    public let header: JSON
    public let payload: JSON
    public let signature: String

    public init(payload: JSON,
                header: JSON,
                algorithm: Algorithm,
                encoding: Encoding = .base64) throws {
        self.payload = payload
        self.header = header
        self.algorithmHeaderValue = algorithm.headerValue
        self.encoding = encoding

        let encoded = try [header, payload].map(encoding.encode)
        let message = encoded.joined(separator: JWT.separator)
        let bytes = try algorithm.encrypt(message)
        signature = try encoding.encode(bytes)
    }

    public init(payload: JSON,
                extraHeaders: [String: Node] = [:],
                algorithm: Algorithm,
                encoding: Encoding = .base64) throws {
        let header = JSON(.object(
            Header.algorithm(algorithm).object +
            Header.type.object +
            extraHeaders))

        try self.init(payload: payload, header: header, algorithm: algorithm, encoding: encoding)
    }

    public init(token: String, encoding: Encoding = .base64) throws {
        let segments = token.components(separatedBy: JWT.separator)

        guard segments.count == 3 else {
            throw JWTError.incorrectNumberOfSegments
        }

        header = try encoding.decode(segments[0])

        guard let alg = header.object?[Header.algorithmKey]?.string else {
            throw JWTError.missingAlgorithm
        }

        algorithmHeaderValue = alg
        payload = try encoding.decode(segments[1])
        signature = segments[2]
        self.encoding = encoding
    }

    public func token() throws -> String {
        let encoded = try [header, payload].map(encoding.encode)

        return (encoded + [signature]).joined(separator: JWT.separator)
    }

    public func verifySignature(key: String) throws -> Bool {
        let algorithm = try Algorithm(algorithmHeaderValue, key: key)
        let message = try [header, payload]
            .map(encoding.encode)
            .joined(separator: JWT.separator)

        return try algorithm
            .verifySignature(encoding.decode(signature),
                             message: message)
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
