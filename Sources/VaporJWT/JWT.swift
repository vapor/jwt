import Core
import Foundation
import JSON

public struct JWT {

    private static let separator = "."

    fileprivate let encoding: Encoding

    public let headers: JSON
    public let payload: JSON
    public let signature: String

    public init(headers: JSON,
                payload: JSON,
                encoding: Encoding = Base64Encoding(),
                signer: Signer) throws {
        self.headers = headers
        self.payload = payload
        self.encoding = encoding

        let encoded = try [headers, payload].map(encoding.encode)
        let message = encoded.joined(separator: JWT.separator)
        let bytes = try signer.sign(message.bytes)
        signature = try encoding.encode(bytes)
    }

    public init(headers: [Header],
                payload: JSON,
                encoding: Encoding = Base64Encoding(),
                signer: Signer) throws {
        let headerObject = headers.reduce([:]) { (dict: [String: Node], header: Header) in
            var result = dict
            result[type(of: header).headerKey] = .string(header.headerValue)
            return result
        }

        try self.init(headers: JSON(.object(headerObject)),
                      payload: payload,
                      encoding: encoding,
                      signer: signer)
    }

    public init(payload: JSON,
                encoding: Encoding = Base64Encoding(),
                signer: Signer) throws {
        try self.init(headers: [TypeHeader(), AlgorithmHeader(signer: signer)],
                      payload: payload,
                      encoding: encoding,
                      signer: signer)
    }

    public init(token: String,
                encoding: Encoding = Base64Encoding()) throws {
        let segments = token.components(separatedBy: JWT.separator)

        guard segments.count == 3 else {
            throw JWTError.incorrectNumberOfSegments
        }

        headers = try encoding.decode(segments[0])
        payload = try encoding.decode(segments[1])
        signature = segments[2]
        self.encoding = encoding
    }

    public func createMessage() throws -> Bytes {
        return try [headers, payload]
            .map(encoding.encode)
            .joined(separator: JWT.separator)
            .bytes
    }

    public func token() throws -> String {
        return [try createMessage().string(), signature].joined(separator: JWT.separator)
    }
}

extension JWT: ClaimsVerifiable {

    public var node: Node {
        return payload.node
    }
}

extension JWT: SignatureVerifiable {

    public var algorithmName: String? {
        return headers.object?[AlgorithmHeader.headerKey]?.string
    }

    public func createSignature() throws -> Bytes {
        return try encoding.decode(signature)
    }
}
