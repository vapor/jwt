import struct Foundation.Data

/// A JWT signer.
public final class JWTSigner {
    public let algorithm: JWTAlgorithm

    public init(algorithm: JWTAlgorithm) {
        self.algorithm = algorithm
    }
}

extension JWTSigner {
    public func verify<S, H, P>(_ signature: S, header: H, payload: P) throws -> Bool
        where S: DataProtocol, H: DataProtocol, P: DataProtocol
    {
        let message = Array(header) + Array([.period]) + Array(payload)
        guard let signature = Data(base64Encoded: Data(signature)) else {
            throw JWTError.malformedToken
        }

        return try self.algorithm.verify(signature, signs: message)
    }
}
