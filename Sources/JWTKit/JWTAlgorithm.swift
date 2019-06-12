/// Algorithm powering a `JWTSigner`.
public protocol JWTAlgorithm {
    /// Unique JWT-standard name for this algorithm.
    var jwtAlgorithmName: String { get }

    /// Creates a signature from the supplied plaintext.
    ///
    ///     let sig = try alg.sign("hello")
    ///
    /// - parameters:
    ///     - plaintext: Plaintext data to sign.
    /// - returns: Signature unique to the supplied data.
    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol

    /// Returns `true` if the signature was creating by signing the plaintext.
    ///
    ///     let sig = try alg.sign("hello")
    ///
    ///     if alg.verify(sig, signs: "hello") {
    ///         print("signature is valid")
    ///     } else {
    ///         print("signature is invalid")
    ///     }
    ///
    /// The above snippet should print `"signature is valid"`.
    ///
    /// - parameters:
    ///     - signature: Signature data resulting from a previous call to `sign(:_)`.
    ///     - plaintext: Plaintext data to check signature against.
    /// - returns: Returns `true` if the signature was created by the supplied plaintext data.
    func verify<Signature, Plaintext>(_ signature: Signature, signs plaintext: Plaintext) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
}

extension JWTAlgorithm {
    /// See `JWTAlgorithm`.
    func verify<Signature, Plaintext>(_ signature: Signature, signs plaintext: Plaintext) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        // create test signature
        let check = try self.sign(plaintext)

        // byte-by-byte comparison to avoid timing attacks
        var match = true
        for (a, b) in zip(check, signature) {
            if a != b {
                match = false
            }
        }

        // finally, if the counts match then we can accept the result
        if check.count == signature.count {
            return match
        } else {
            return false
        }
    }
}
