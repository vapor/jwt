import Foundation
import Node

protocol PolymorphicInitializable {
    init?(_ polymorphic: Polymorphic)
}

protocol StringBacked: PolymorphicInitializable {
    var value: String { get }
    init(string: String)
}

extension StringBacked {
    init?(_ polymorphic: Polymorphic) {
        guard let string = polymorphic.string else {
            return nil
        }

        self.init(string: string)
    }

    public var node: Node {
        return .string(value)
    }
}

public typealias Seconds = Int

protocol SecondsBacked: PolymorphicInitializable {
    var value: Seconds { get }
    init(seconds: Seconds)
}

extension SecondsBacked {
    init?(_ polymorphic: Polymorphic) {
        guard let int = polymorphic.int else {
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
