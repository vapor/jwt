import Foundation
import Node

public protocol StringBacked: NodeFailableInitializable {
    var value: String { get }
    init(string: String)
}

extension StringBacked {
    public init?(_ node: Node) {
        guard let string = node.string else {
            return nil
        }

        self.init(string: string)
    }

    public var node: Node {
        return .string(value)
    }
}
