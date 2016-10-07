import Foundation
import Node

public protocol Claim {
    static var name: String { get }
    func verify(_ : Node) -> Bool
}

extension Claim {

    public func verify(_ dict: [String: Node]) -> Bool {
        return dict[type(of: self).name].map(verify) ?? false
    }
}
