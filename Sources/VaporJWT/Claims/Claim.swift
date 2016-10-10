import Foundation
import Node

public protocol Claim: JWTStorable {
    func verify(_ : Node) -> Bool
}

extension Claim {
    func verify(_ dict: [String: Node]) -> Bool {
        return dict[type(of: self).name].map(verify) ?? false
    }
}
