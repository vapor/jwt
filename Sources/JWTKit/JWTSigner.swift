import class Foundation.JSONEncoder

/// A JWT signer.
public final class JWTSigner {
    public let algorithm: JWTAlgorithm

    public init(algorithm: JWTAlgorithm) {
        self.algorithm = algorithm
    }
}
