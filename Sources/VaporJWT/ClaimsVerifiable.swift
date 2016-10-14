import JSON

protocol ClaimsVerifiable {
    var node: Node { get }
}

extension ClaimsVerifiable {

    /// Verifies all claims.
    ///
    /// - parameter claims: Claims to verify
    ///
    /// - returns: True if all claims where verified, false otherwise. Also returns false if node is
    ///            not an object.
    public func verifyClaims(_ claims: [Claim]) -> Bool {
        guard case .object(let object) = node else {
            return false
        }

        return claims.reduce(true) { (verified, claim) -> Bool in
            verified && claim.verify(object)
        }
    }
}
 
extension JSON: ClaimsVerifiable {}
extension Node: ClaimsVerifiable {}
