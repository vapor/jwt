import Core
import Foundation
import JSON

public struct JWT {

    private static let separator = "."

    private let algorithmName: String
    private let encoding: Encoding

    public let headers: JSON
    public let payload: JSON
    public let signature: String

    public init(payload: JSON,
                headers: JSON,
                algorithm: Algorithm,
                encoding: Encoding = Base64()) throws {
        self.payload = payload
        self.headers = headers
        self.algorithmName = algorithm.name
        self.encoding = encoding

        let encoded = try [headers, payload].map(encoding.encode)
        let message = encoded.joined(separator: JWT.separator)
        let bytes = try algorithm.encrypt(message)
        signature = try encoding.encode(bytes)
    }

    public init(payload: JSON,
                headers: [Header],
                algorithm: Algorithm,
                encoding: Encoding = Base64()) throws {
        let headerObject = headers.reduce([:]) { (dict: [String: Node], header: Header) in
            var result = dict
            result[type(of: header).headerKey] = .string(header.headerValue)
            return result
        }

        try self.init(payload: payload,
                      headers: JSON(.object(headerObject)),
                      algorithm: algorithm,
                      encoding: encoding)
    }

    public init(payload: JSON,
                algorithm: Algorithm,
                encoding: Encoding = Base64()) throws {
        try self.init(payload: payload,
                      headers: [Type(), algorithm],
                      algorithm: algorithm,
                      encoding: encoding)
    }

    public init(token: String,
                encoding: Encoding = Base64()) throws {
        let segments = token.components(separatedBy: JWT.separator)

        guard segments.count == 3 else {
            throw JWTError.incorrectNumberOfSegments
        }

        headers = try encoding.decode(segments[0])

        guard let alg = headers.object?[Algorithm.headerKey]?.string else {
            throw JWTError.missingAlgorithm
        }

        algorithmName = alg
        payload = try encoding.decode(segments[1])
        signature = segments[2]
        self.encoding = encoding
    }

    public func token() throws -> String {
        let encoded = try [headers, payload].map(encoding.encode)

        return (encoded + [signature]).joined(separator: JWT.separator)
    }

    public func verifySignature(key: String) throws -> Bool {
        let algorithm = try Algorithm(algorithmName, key: key)
        let message = try [headers, payload]
            .map(encoding.encode)
            .joined(separator: JWT.separator)

        return try algorithm.verifySignature(encoding.decode(signature), message: message)
    }
}
