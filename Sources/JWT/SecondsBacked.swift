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
