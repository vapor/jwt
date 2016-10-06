import JSON

public protocol ClaimsVerifying {
    var node: Node { get }
}

extension ClaimsVerifying {

    public func verify(_ claims: [Claim]) -> Bool {
        guard case .object(let object) = node else {
            return false
        }

        return claims.reduce(true) { (verified, claim) -> Bool in
            verified && claim.verify(object)
        }
    }
}

extension JWT: ClaimsVerifying {

    public var node: Node {
        return payload.node
    }
}

extension JSON: ClaimsVerifying {}
extension Node: ClaimsVerifying {}
