import Core

public protocol SignatureVerifiable {
    var algorithmName: String? { get }
    func createSignature() throws -> Bytes
    func createMessage() throws -> Bytes
}

extension SignatureVerifiable {

    public func verifySignatureWith(_ signer: Signer) throws -> Bool {
        guard signer.name == algorithmName else {
            throw JWTError.wrongAlgorithm
        }
        return try signer.verifySignature(
            try createSignature(), message: try createMessage())
    }
}
