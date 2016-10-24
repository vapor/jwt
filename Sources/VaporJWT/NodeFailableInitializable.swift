import Foundation
import Node

public protocol NodeFailableInitializable {
    init?(_ node: Node)
}

public protocol StringBacked: NodeFailableInitializable {
    var value: String { get }
    init(_ : String)
}

extension StringBacked {
    public init?(_ node: Node) {
        guard case .string(let string) = node else {
            return nil
        }

        self.init(string)
    }

    public var node: Node {
        return .string(value)
    }
}

public typealias Seconds = Int

public protocol SecondsBacked: NodeFailableInitializable {
    var value: Seconds { get }
    init(_ : Seconds)
}

extension SecondsBacked {
    public init?(_ node: Node) {
        guard case .number(let number) = node else {
            return nil
        }

        self.init(number.int)
    }

    public init(_ date: Date = Date()) {
        self.init(Int(date.timeIntervalSince1970))
    }

    public var node: Node {
        return Node(value)
    }
}
