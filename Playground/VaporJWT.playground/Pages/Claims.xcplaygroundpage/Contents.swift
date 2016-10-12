//: [Previous](@previous)
//: ## Claims
//: `Claim`s are used to constrain the validity of a token.
import VaporJWT
import Foundation
import Node
//: These are all the claims that come with `VaporJWT`
let claims: [Claim] = [
    AudienceClaim("some audience"),
    ExpirationTimeClaim(Date() + 300), // valid until 5 minutes from now
    IssuedAtClaim(),
    IssuerClaim("VaporJWT"),
    JWTIDClaim(UUID().uuidString),
    NotBeforeClaim(Date() + 60), // valid in 1 minute from now
    SubjectClaim("some subject")
]

let jwt = try JWT(payload: claims, signer: Unsigned())
jwt.verifyClaims([AudienceClaim("some audience")])
jwt.verifyClaims([SubjectClaim("another subject")])
//: Like with signers, headers, and encodings it is possible to create your own claims.
//: The following made-up claim only verifies `JWT`s with user ids below a given number.
struct UserIDClaim: Claim {
    static let name = "user_id"

    var node: Node {
        return .number(.int(userID))
    }

    let userID: Int

    init(userID: Int) {
        self.userID = userID
    }

    func verify(_ node: Node) -> Bool {
        guard let otherID = node.int else {
            return false
        }
        return otherID < userID
    }
}
//: `Node`, like `JWT`, conforms to `ClaimsVerifying`
let payload: Node = ["user_id": .number(.int(6))]
payload.verifyClaims([UserIDClaim(userID: 10)])
payload.verifyClaims([UserIDClaim(userID: 5)])
//: [Next](@next)
