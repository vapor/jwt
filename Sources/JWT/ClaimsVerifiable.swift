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
        guard let object = node.object else {
            throw JWTError.incorrectPayloadForClaimVerification
        }

        try claims.forEach { claim in
            try claim.verify(object)
        }
    }
}
 
extension JSON: ClaimsVerifiable {
    public var node: Node {
        return makeNode(in: nil)
    }
}
extension Node: ClaimsVerifiable {
    public var node: Node {
        return self
    }
}
