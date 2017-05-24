import Foundation
import Node

public protocol NodeFailableInitializable {
    init?(_ node: Node)
}

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

public typealias Seconds = Int

public protocol SecondsBacked: NodeFailableInitializable {
    var value: Seconds { get }
    init(seconds: Seconds)
}

extension SecondsBacked {
    public init?(_ node: Node) {
        guard let int = node.int else {
            return nil
        }

        self.init(seconds: int)
    }

    public init(date: Date = Date()) {
        self.init(seconds: Int(date.timeIntervalSince1970))
    }

    public var node: Node {
        return Node(value)
    }
}
