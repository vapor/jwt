import Core
import Crypto
import Foundation

/// A JSON Web Token
public struct JWT<Payload> where Payload: JWTPayload {
    /// The headers linked to this message
    public var header: JWTHeader

    /// The JSON payload within this message
    public var payload: Payload

    /// Creates a new JSON Web Signature from predefined data
    public init(header: JWTHeader = .init(), payload: Payload) {
        self.header = header
        self.payload = payload
    }

    /// Parses a JWT string into a JSON Web Token
    public init(from string: String, verifiedUsing signer: JWTSigner) throws {
        try self.init(from: Data(string.utf8), verifiedUsing: signer)
    }

    /// Parses a JWT string into a JSON Web Signature
    public init(from string: String, verifiedUsing signers: JWTSigners) throws {
        try self.init(from: Data(string.utf8), verifiedUsing: signers)
    }

    /// Parses a JWT string into a JSON Web Signature
    public init(from data: Data, verifiedUsing signer: JWTSigner) throws {
        let parts = data.split(separator: .period)
        guard parts.count == 3 else {
            throw JWTError(identifier: "invalidJWT", reason: "Malformed JWT")
        }

        let headerData = Data(parts[0])
        let payloadData = Data(parts[1])
        let signatureData = Data(parts[2])

        guard try signer.verify(signatureData, header: headerData, payload: payloadData) else {
            throw JWTError(identifier: "invalidSignature", reason: "Invalid JWT signature")
        }

        let jsonDecoder = JSONDecoder()
        jsonDecoder.dateDecodingStrategy = .secondsSince1970

        guard let decodedHeader = Data(base64URLEncoded: headerData) else {
            throw JWTError(identifier: "base64", reason: "JWT header is not valid base64-url")
        }
        guard let decodedPayload = Data(base64URLEncoded: payloadData) else {
            throw JWTError(identifier: "base64", reason: "JWT payload is not valid base64-url")
        }
        
        self.header = try jsonDecoder.decode(JWTHeader.self, from: decodedHeader)
        self.payload = try jsonDecoder.decode(Payload.self, from: decodedPayload)
        try payload.verify()
    }

    /// Parses a JWT string into a JSON Web Signature
    public init(from data: Data, verifiedUsing signers: JWTSigners) throws {
        let parts = data.split(separator: .period)
        guard parts.count == 3 else {
            throw JWTError(identifier: "invalidJWT", reason: "Malformed JWT")
        }

        let headerData = Data(parts[0])
        let payloadData = Data(parts[1])
        let signatureData = Data(parts[2])

        let jsonDecoder = JSONDecoder()
        jsonDecoder.dateDecodingStrategy = .secondsSince1970

        guard let decodedHeader = Data(base64URLEncoded: headerData) else {
            throw JWTError(identifier: "base64", reason: "JWT header is not valid base64-url")
        }

        let header = try jsonDecoder.decode(JWTHeader.self, from: decodedHeader)
        guard let kid = header.kid else {
            throw JWTError(identifier: "missingKID", reason: "`kid` header property required to identify signer")
        }

        let signer = try signers.requireSigner(kid: kid)
        guard try signer.verify(signatureData, header: headerData, payload: payloadData) else {
            throw JWTError(identifier: "invalidSignature", reason: "Invalid JWT signature")
        }

        guard let decodedPayload = Data(base64URLEncoded: payloadData) else {
            throw JWTError(identifier: "base64", reason: "JWT payload is not valid base64-url")
        }

        self.header = header
        self.payload = try jsonDecoder.decode(Payload.self, from: decodedPayload)
        try payload.verify()
    }

    /// Parses a JWT string into a JSON Web Signature
    public init(unverifiedFrom data: Data) throws {
        let parts = data.split(separator: .period)
        guard parts.count == 3 else {
            throw JWTError(identifier: "invalidJWT", reason: "Malformed JWT")
        }

        let headerData = Data(parts[0])
        let payloadData = Data(parts[1])

        let jsonDecoder = JSONDecoder()
        jsonDecoder.dateDecodingStrategy = .secondsSince1970

        guard let decodedHeader = Data(base64URLEncoded: headerData) else {
            throw JWTError(identifier: "base64", reason: "JWT header is not valid base64-url")
        }
        guard let decodedPayload = Data(base64URLEncoded: payloadData) else {
            throw JWTError(identifier: "base64", reason: "JWT payload is not valid base64-url")
        }

        self.header = try jsonDecoder.decode(JWTHeader.self, from: decodedHeader)
        self.payload = try jsonDecoder.decode(Payload.self, from: decodedPayload)
    }

    /// Signs the message and returns the serialized JSON web token
    public mutating func sign(using signers: JWTSigners) throws -> Data {
        guard let kid = header.kid else {
            throw JWTError(identifier: "missingKID", reason: "`kid` header property required to identify signer")
        }

        let signer = try signers.requireSigner(kid: kid)
        return try signer.sign(&self)
    }

    /// Signs the message and returns the serialized JSON web token
    public mutating func sign(using signer: JWTSigner) throws -> Data {
        return try signer.sign(&self)
    }
}
