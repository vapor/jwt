import Core

public protocol SignatureVerifiable {
    var algorithmName: String? { get }
    func createSignature() throws -> Bytes
    func createMessage() throws -> Bytes
}

extension SignatureVerifiable {

    /// Verifies signature
    ///
    /// - parameter signer: used to verify the signature
    ///
    /// - throws: JWTError.wrongAlgorithm if the algorithm does not match. Throws any error thrown while signing or encoding.
    ///
    /// - returns: True is the signature was verified, false otherwise.
    public func verifySignatureWith(_ signer: Signer) throws -> Bool {
        guard signer.name == algorithmName else {
            throw JWTError.wrongAlgorithm
        }
        return try signer.verifySignature(
            try createSignature(), message: try createMessage())
    }
}
