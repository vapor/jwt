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

extension JWTError: CustomStringConvertible {
    public var description: String {
        let reason: String

        switch self {
        case .createKey:
            reason = "Could not create key"
        case .createPublicKey:
            reason = "Could not create public key"
        case .decoding:
            reason = "Could not decode"
        case .encoding:
            reason = "Could not encode"
        case .incorrectNumberOfSegments:
            reason = "Incorrect number of segments"
        case .missingAlgorithm:
            reason = "Missing algorithm"
        case .privateKeyRequired:
            reason = "Private key required"
        case .signing:
            reason = "Could not sign"
        case .wrongAlgorithm:
            reason = "Wrong algorithm"
        case .verificationFailed:
            reason = "Verification failed"
        case .unknown(let error):
            reason = "\(error)"
        }

        return "JWT error: \(reason)"
    }
}
