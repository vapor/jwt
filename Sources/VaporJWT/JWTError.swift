public enum JWTError: Error {
    case createKey
    case createPublicKey
    case decoding
    case encoding
    case incorrectNumberOfSegments
    case missingAlgorithm
    case signing
    case wrongAlgorithm
}
