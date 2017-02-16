import JSON

public protocol ClaimsVerifiable {
    var node: Node { get }
}

extension ClaimsVerifiable {

    /// Verifies all claims.
    ///
    /// - parameter claims: Claims to verify
    ///
    /// - throws:
    ///     - `JWTError.incorrectPayloadForClaimVerification` if the payload is not of type `[String: Node]`
    ///     - `JWTError.verificationFailedForClaim` if any of the claims failed
    public func verifyClaims(_ claims: [Claim]) throws {
        guard case .object(let object) = node else {
            throw JWTError.incorrectPayloadForClaimVerification
        }

        try claims.forEach { claim in
            try claim.verify(object)
        }
    }
}
 
extension JSON: ClaimsVerifiable {}
extension Node: ClaimsVerifiable {}
