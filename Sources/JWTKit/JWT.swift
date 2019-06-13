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

    private struct JWTComponents {
        var header: JWTHeader
        var payload: Payload
        var signature: [UInt8]
        var message: [UInt8]
    }

    private static func parse<Message>(message: Message) throws -> JWTComponents
        where Message: DataProtocol
    {
        let message = message.copyBytes().split(separator: .period)
        guard message.count == 3 else {
            throw JWTError.malformedToken
        }

        let encodedHeader = message[0]
        let encodedPayload = message[1]
        let encodedSignature = message[2]

        let jsonDecoder = JSONDecoder()
        jsonDecoder.dateDecodingStrategy = .secondsSince1970
        let header = try jsonDecoder.decode(JWTHeader.self, from: Data(encodedHeader.base64URLDecodedBytes()))
        let payload = try jsonDecoder.decode(Payload.self, from: Data(encodedPayload.base64URLDecodedBytes()))

        return .init(
            header: header,
            payload: payload,
            signature: encodedSignature.base64URLDecodedBytes(),
            message: .init(encodedHeader) + [.period] + .init(encodedPayload)
        )
    }

    public init(header: JWTHeader = .init(), payload: Payload) {
        self.header = header
        self.payload = payload
    }

    public init<Message>(fromUnverified message: Message) throws
        where Message: DataProtocol
    {
        let components = try JWT<Payload>.parse(message: message)
        self.header = components.header
        self.payload = components.payload
    }

    public init<Message>(from message: Message, verifiedBy signer: JWTSigner) throws
        where Message: DataProtocol
    {
        let components = try JWT<Payload>.parse(message: message)
        guard try signer.algorithm.verify(components.signature, signs: components.message) else {
            throw JWTError.signatureVerifictionFailed
        }
        self.header = components.header
        self.payload = components.payload
        try self.payload.verify(using: signer)
    }

    public init<Message>(from message: Message, verifiedBy signers: JWTSigners) throws
        where Message: DataProtocol
    {
        let components = try JWT<Payload>.parse(message: message)
        guard let kid = components.header.kid else {
            throw JWTError.missingKIDHeader
        }
        guard let signer = signers.signer(kid: kid) else {
            throw JWTError.unknownKID(kid)
        }
        guard try signer.algorithm.verify(components.signature, signs: components.message) else {
            throw JWTError.signatureVerifictionFailed
        }
        self.header = components.header
        self.payload = components.payload
        try self.payload.verify(using: signer)
    }

    /// Signs the message and returns the serialized JSON web token
    public func sign(using signer: JWTSigner) throws -> [UInt8] {
        let jsonEncoder = JSONEncoder()
        jsonEncoder.dateEncodingStrategy = .secondsSince1970
        
        // encode header, copying header struct to mutate alg
        var header = self.header
        header.alg = signer.algorithm.name
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
