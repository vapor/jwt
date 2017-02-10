import Foundation
import Node

public protocol Claim: Storable {
    func verify(_ : Node) -> Bool
}

extension Claim {
    func verify(_ dict: [String: Node]) throws {
        let name = type(of: self).name

        guard let claim = dict[name] else {
            throw JWTError.missingClaim(withName: name)
        }

        guard verify(claim) else {
            throw JWTError.verificationFailedForClaim(withName: name)
        }
    }
}
