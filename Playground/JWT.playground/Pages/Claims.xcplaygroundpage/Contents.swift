//: [Previous](@previous)
//: ## Claims
//: `Claim`s are used to constrain the validity of a token.
import Foundation
import JWT
//: These are all the claims that come with `JWT`
let claims: [Claim] = [
    AudienceClaim(string: "some audience"),
    ExpirationTimeClaim(date: Date() + 300), // valid until 5 minutes from now
    IssuedAtClaim(),
    IssuerClaim(string: "JWT"),
    JWTIDClaim(string: UUID().uuidString),
    NotBeforeClaim(date: Date() + 60), // valid in 1 minute from now
    SubjectClaim(string: "some subject")
]

let jwt = try JWT(payload: JSON(claims), signer: Unsigned())
try jwt.verifyClaims([AudienceClaim(string: "some audience")])
do {
    try jwt.verifyClaims([SubjectClaim(string: "another subject")])
} catch {
    error
}

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
try payload.verifyClaims([UserIDClaim(userID: 10)])
do {
    try payload.verifyClaims([UserIDClaim(userID: 5)])
} catch {
    error
}
//: [Next](@next)
