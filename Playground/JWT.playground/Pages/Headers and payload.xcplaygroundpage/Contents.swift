//: [Previous](@previous)
//: ## Headers and payload
//: JWTs can be created from Nodes. Nodes in turn can be created from (arrays of) `Storable`s. `Claim`s and `Header`s conform to `Storable` but it is also possible to store your own values that conform to `Storable` in either the header or the payload.
import JWT
import Node
//: Using a custom Header
struct MyHeader: Header {
    static let name = "my"
    let node = Node.string("header")
}

let jwt1 = try JWT(
    headers: Node(MyHeader()),
    payload: EmptyNode,
    signer: Unsigned())
//: Using a custom Storable in the payload
struct User: Storable {
    static let name = "user_id"
    let node: Node = 42
}

let jwt2 = try JWT(
    payload: Node(User()),
    signer: Unsigned())
//: Using Node
let jwt3 = try JWT(
    headers: Node(["my": .string("header")]),
    payload: Node(["user_id": .number(.int(42))]),
    signer: Unsigned())
//: [Next](@next)
