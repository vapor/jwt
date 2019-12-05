import Vapor

public final class JWTProvider: Provider {
    public let application: Application
    public var signers: JWTSigners

    public init(_ application: Application) {
        self.application = application
        self.signers = .init()
    }
}

public struct JWTRequest {
    let request: Request

    public func sign<Payload>(_ payload: Payload, kid: String? = nil) throws -> String
        where Payload: JWTPayload
    {
        try self.sign(JWT(payload: payload), kid: kid)
    }

    public func sign<Payload>(_ jwt: JWT<Payload>, kid: String? = nil) throws -> String {
        try String(decoding: self.sign(jwt, kid: kid), as: UTF8.self)
    }

    public func sign<Payload>(_ jwt: JWT<Payload>, kid: String? = nil) throws -> [UInt8] {
        var jwt = jwt
        jwt.header.kid = kid
        return try jwt.sign(
            using: self.request.application.jwt.signers.requireSigner(kid: kid)
        )
    }
}

extension Request {
    public var jwt: JWTRequest {
        .init(request: self)
    }
}

extension Application {
    public var jwt: JWTProvider {
        self.providers.require(JWTProvider.self)
    }
}
