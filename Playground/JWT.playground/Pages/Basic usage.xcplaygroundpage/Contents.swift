/*:
 # JWT
 ## Basic usage
 Learn how to create and verify signed tokens with expiration time claims.
 */
import Foundation
import Node
import JWT

//: Create an signed token that expires 1 minute from now.
let jwt = try JWT(payload: Node(ExpirationTimeClaim(Date() + 60)),
                  signer: HS256(key: "secret"))
let token = try jwt.createToken()
//: Decode the token on the receiving end.
let receivedJWT = try JWT(token: token)

//: Try to verify signature using a `Signer` with an incorrect algorithm.
do {
    try receivedJWT.verifySignature(using: Unsigned())
} catch {
    error
}
//: Verify against correct `Signer` (algorithm + key).
try receivedJWT.verifySignature(using: HS256(key: "secret"))
//: Trying to verify claims against expiration time claim that expires now will fail.
receivedJWT.verifyClaims([ExpirationTimeClaim()])
//: However, if we add a leeway of 2 minutes, it passes.
receivedJWT.verifyClaims([ExpirationTimeClaim(leeway: 120)])
//: [Next](@next)
