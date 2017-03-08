import Foundation
import Node

public protocol Claim: Storable {
    func verify(_ polymorphic: Polymorphic) -> Bool
}

extension Claim {
    func verify(node: Node) -> Bool {
        return verify(node)
    }
}

extension Claim {
    func verify(_ dict: [String: Polymorphic]) throws {
        let name = type(of: self).name

        guard let claim = dict[name] else {
            throw JWTError.missingClaim(withName: name)
        }

        guard verify(claim) else {
            throw JWTError.verificationFailedForClaim(withName: name)
        }
    }
}
