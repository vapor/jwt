import JSON
import Node

public protocol Storable {
    static var name: String { get }
    var node: Node { get }
}

extension JSON {
    init(_ storables: [Storable]) {
        let dict = storables.reduce([:]) { (dict: [String: Node], storable: Storable) in
            var result = dict
            result[type(of: storable).name] = storable.node
            return result
        }

        self.init(Node(dict))
    }
}

extension JSON: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: Storable...) {
        self.init(elements)
    }
}
