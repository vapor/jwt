public enum JWTError: Error {
    case createKey
    case createPublicKey
    case decoding
    case encoding
    case incorrectNumberOfSegments
    case missingAlgorithm
    case privateKeyRequired
    case signing
    case wrongAlgorithm
    case verificationFailed
    // allow for future additions
    case unknown(Error)
}
