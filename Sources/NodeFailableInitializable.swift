import Foundation
import Node

public protocol NodeFailableInitializable {
    init?(_ node: Node)
}

public protocol StringBacked: NodeFailableInitializable {
    var value: String { get }
    init(_ value: String)
}

extension StringBacked {

    public init?(_ node: Node) {
        guard case .string(let string) = node else {
            return nil
        }

        self.init(string)
    }
}

public protocol DateBacked: NodeFailableInitializable {
    var value: Date { get }
    init(_ value: Date)
}

extension DateBacked {

    public init?(_ node: Node) {
        guard case .number(let number) = node else {
            return nil
        }

        self.init(Date(timeIntervalSince1970: number.double))
    }
}
