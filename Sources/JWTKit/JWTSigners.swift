/// A collection of signers labeled by `kid`.
public final class JWTSigners {
    /// Internal storage.
    private var storage: [String: JWTSigner]

    /// Create a new `JWTSigners`.
    public init() {
        self.storage = [:]
    }

    /// Adds a new signer.
    public func use(_ signer: JWTSigner, kid: String) {
        storage[kid] = signer
    }

    /// Gets a signer for the supplied `kid`, if one exists.
    public func signer(kid: String) -> JWTSigner? {
        return storage[kid]
    }
}
