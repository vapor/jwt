//: [Previous](@previous)
//: ## Headers and payload
//: JWTs can be created from raw `JSON` or from arrays of `Storable`s. `Claim`s and `Header`s conform to `Storable` but it is also possible to store your own values that conform to `Storable` in either the header or the payload.
import JSON
import VaporJWT
//: Using a custom Header
struct MyHeader: Header {
    static let name = "my"
    let node = Node.string("header")
}

let jwt1 = try JWT(headers: [MyHeader()],
                   payload: [],
                   signer: Unsigned())
//: Using a custom Storable in the payload
struct User: Storable {
    static let name = "user_id"
    let node = Node.number(.int(42))
}

let jwt2 = try JWT(payload: [User()],
                   signer: Unsigned())
//: Using JSON
let jwt3 = try JWT(headers: JSON(["my": .string("header")]),
                   payload: JSON(["user_id": .number(.int(42))]),
                   signer: Unsigned())
//: [Next](@next)
