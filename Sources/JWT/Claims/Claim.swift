import Foundation
import Node

public protocol Claim: Storable {
    func verify(_ node: Node) -> Bool
}

extension Claim {
    func verify(object: Node) throws {
        let name = type(of: self).name

        guard case .object(let object) = object.wrapped else {
            throw JWTError.missingClaim(withName: name)
        }

        guard let data = object[name] else {
            throw JWTError.missingClaim(withName: name)
        }
        let claim = Node(data, in: nil)

        guard verify(claim) else {
            throw JWTError.verificationFailedForClaim(withName: name)
        }
    }
}
