import JSON

public protocol ClaimsVerifiable {
    var node: Node { get }
}

extension ClaimsVerifiable {

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
