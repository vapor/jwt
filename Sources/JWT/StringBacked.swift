import Foundation
import Node

protocol StringBacked: NodeInitializable {
    var value: String { get }
    init(string: String)
}

extension StringBacked {
    public init(node: Node) throws {
        guard let string = node.string else {
            throw JWTError.incorrectNodeType
        }

        self.init(string: string)
    }

    public var node: Node {
        return .string(value)
    }
}

