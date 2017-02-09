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
    /// - throws: JWTError.wrongAlgorithm if the algorithm does not match. Throws any error thrown while signing or encoding.
    ///
    /// - returns: True is the signature was verified, false otherwise.
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
