import Node

public protocol Storable {
    static var name: String { get }
    var node: Node { get }
}

extension Node {
    public init(_ storable: Storable) {
        self = .object([type(of: storable).name: storable.node])
    }

    public init(_ storables: [Storable]) {
        let dict = storables.reduce([:]) { (dict: [String: Node], storable: Storable) in
            var result = dict
            result[type(of: storable).name] = storable.node
            return result
        }

        self = .object(dict)
    }
}
