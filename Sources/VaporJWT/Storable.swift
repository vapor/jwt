import JSON
import Node

public protocol JWTStorable {
    static var name: String { get }
    var node: Node { get }
}

extension JSON {

    init(_ storables: [JWTStorable]) {
        let dict = storables.reduce([:]) { (dict: [String: Node], storable: JWTStorable) in
            var result = dict
            result[type(of: storable).name] = storable.node
            return result
        }

        self.init(Node(dict))
    }
}
