/*:
 # JWT
 ## Basic usage
 Learn how to create and verify signed tokens with expiration time claims.
 */
import Foundation
import JWT
import Node
//: Create an signed token that expires 1 minute from now.
let jwt = try JWT(
    payload: Node(ExpirationTimeClaim(date: Date() + 60)),
    signer: HS256(key: "secret".bytes))
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
try receivedJWT.verifySignature(using: HS256(key: "secret".bytes))
//: Trying to verify claims against expiration time claim 100 seconds in the future will fail.
do {
    try receivedJWT.verifyClaims([ExpirationTimeClaim(date: Date() + 100)])
} catch {
    // expect an error
    error
}
//: However, if we add a leeway of 2 minutes, it passes.
try receivedJWT.verifyClaims([ExpirationTimeClaim(date: Date() + 100, leeway: 120)])
//: [Next](@next)
