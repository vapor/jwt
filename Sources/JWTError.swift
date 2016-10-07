enum JWTError: Error {
    case couldNotGenerateKey
    case decoding
    case encoding
    case incorrectNumberOfSegments
    case missingAlgorithm
    case unsupportedAlgorithm
}
