import Core

public protocol SignatureVerifiable {
    var algorithmName: String? { get }
    func createMessage() throws -> Bytes
    func createSignature() throws -> Bytes
}

extension SignatureVerifiable {

    @available(*, deprecated, message: "Use `verifySignature(using:)` instead")
    public func verifySignatureWith(_ signer: Signer) throws -> Bool {
        return try verifySignature(using: signer)
    }

    /// Verifies signature
    ///
    /// - parameter signer: used to verify the signature
    ///
    /// - throws: JWTError.wrongAlgorithm if the algorithm does not match. Throws any error thrown while signing or encoding.
    ///
    /// - returns: True is the signature was verified, false otherwise.
    public func verifySignature(using signer: Signer) throws -> Bool {
        guard signer.name == algorithmName else {
            throw JWTError.wrongAlgorithm
        }
        return try signer.verifySignature(
            try createSignature(), message: try createMessage())
    }
}
