import Foundation
import Node

public protocol Claim: Storable {
    func verify(_ : Node) -> Bool
}

extension Claim {
    func verify(_ dict: [String: Node]) -> Bool {
        return dict[type(of: self).name].map(verify) ?? false
    }
}
