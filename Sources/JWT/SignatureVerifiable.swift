import Core

public protocol SignatureVerifiable {
    var algorithmName: String? { get }
    func createMessage() throws -> Bytes
    func createSignature() throws -> Bytes
}

extension SignatureVerifiable {
    /// Verifies signature
    ///
    /// - parameter signer: used to verify the signature
    ///
    /// - throws: 
    ///     - `JWTError.wrongAlgorithm` if the algorithm does not match.
    ///     - `JWTError.verificationFailed` if the signer cannot verify the JWT.
    ///     - Any error thrown while signing or encoding.
    public func verifySignature(using signer: Signer) throws {
        guard signer.name == algorithmName else {
            throw JWTError.wrongAlgorithm
        }

        try signer.verify(
            signature: try createSignature(),
            message: try createMessage()
        )
    }
}
