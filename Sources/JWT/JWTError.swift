public enum JWTError: Error {
    case createKey
    case createPublicKey
    case decoding
    case encoding
    case incorrectNumberOfSegments
    case incorrectPayloadForClaimVerification
    case missingAlgorithm
    case missingClaim(withName: String)
    case privateKeyRequired
    case signatureVerificationFailed
    case signing
    case verificationFailedForClaim(withName: String)
    case wrongAlgorithm
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
        case .incorrectPayloadForClaimVerification:
            reason = "Payload is not of type `[String: Node]`"
        case .missingAlgorithm:
            reason = "Missing algorithm"
        case .missingClaim(withName: let name):
            reason = "Missing claim with name: \(name)"
        case .privateKeyRequired:
            reason = "Private key required"
        case .signing:
            reason = "Could not sign"
        case .wrongAlgorithm:
            reason = "Wrong algorithm"
        case .verificationFailedForClaim(withName: let name):
            reason = "Claim verification failed for claim with name: \(name)"
        case .signatureVerificationFailed:
            reason = "Signature verification failed"
        case .unknown(let error):
            reason = "\(error)"
        }

        return "JWT error: \(reason)"
    }
}
