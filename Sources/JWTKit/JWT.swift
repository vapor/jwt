import class Foundation.JSONEncoder
import class Foundation.JSONDecoder
import struct Foundation.Data

/// A JSON Web Token with a generic, codable payload.
///
///     let jwt = JWT(payload: ...)
///     let data = try jwt.sign(using: ...)
///
/// Learn more at https://jwt.io.
/// Read specification (RFC 7519) https://tools.ietf.org/html/rfc7519.
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
    
    /// Parses a JWT string into a JSON Web Signature
    public init<Message>(message: Message, using signer: JWTSigner) throws
        where Message: DataProtocol
    {
        let message = message.copyBytes().split(separator: .period)
        guard message.count == 3 else {
            throw JWTError(identifier: "invalidJWT", reason: "Malformed JWT")
        }
        
        let encodedHeader = message[0]
        let encodedPayload = message[1]
        let encodedSignature = message[2]
        
        
        let jsonDecoder = JSONDecoder()
        jsonDecoder.dateDecodingStrategy = .secondsSince1970
        let header = try jsonDecoder.decode(JWTHeader.self, from: Data(encodedHeader.base64URLDecodedBytes()))
        let payload = try jsonDecoder.decode(Payload.self, from: Data(encodedPayload.base64URLDecodedBytes()))
        
        guard try signer.verify(
            encodedSignature.base64URLDecodedBytes(),
            signs: encodedHeader + [.period] + encodedPayload,
            header: header
        ) else {
            throw JWTError(identifier: "invalidSignature", reason: "Invalid JWT signature")
        }
        
        self.header = header
        self.payload = payload
        
        try self.payload.verify(using: signer)
    }

    /// Signs the message and returns the serialized JSON web token
    public func sign(using signer: JWTSigner) throws -> [UInt8] {
        let jsonEncoder = JSONEncoder()
        jsonEncoder.dateEncodingStrategy = .secondsSince1970
        
        // encode header, copying header struct to mutate alg
        var header = self.header
        header.alg = signer.algorithm.jwtAlgorithmName
        let headerData = try jsonEncoder.encode(header)
        let encodedHeader = headerData.base64URLEncodedBytes()
        
        // encode payload
        let payloadData = try jsonEncoder.encode(self.payload)
        let encodedPayload = payloadData.base64URLEncodedBytes()
        
        // combine header and payload to create signature
        let signatureData = try signer.algorithm.sign(encodedHeader + [.period] + encodedPayload)
        
        // yield complete jwt
        return encodedHeader
                + [.period]
                + encodedPayload
                + [.period]
                + signatureData.base64URLEncodedBytes()
    }
}
