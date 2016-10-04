enum JWTError: Error {
    case couldNotGenerateKey
    case incorrectNumberOfSegments
    case missingAlgorithm
    case notBase64Encoded
    case unsupportedAlgorithm
}
