public typealias Seconds = Int

public protocol SecondsBacked: NodeInitializable {
    var value: Seconds { get }
    init(seconds: Seconds)
}

extension SecondsBacked {
    public init(node: Node) throws {
        guard let int = node.int else {
            throw JWTError.incorrectNodeType
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
