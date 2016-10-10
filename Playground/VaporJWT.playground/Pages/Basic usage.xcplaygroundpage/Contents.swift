/*:
 # VaporJWT
 ## Basic usage
 In this playground page you can read how to create and verify signed tokens with expiration time claims.
 */
import Foundation
import VaporJWT
//: Create an signed token that expires 1 minute from now.
let sentJWT = try JWT(claims: [ExpirationTimeClaim(Date() + 60)],
                      signer: HS256(key: "secret"))
let token = try sentJWT.createToken()
//: Decode the token on the receiving end.
let receivedJWT = try JWT(token: token)

//: Try to verify signature using signer with incorrect algorithm.
do {
    try receivedJWT.verifySignatureWith(Unsigned())
} catch {
    error
}
//: Verify against correct signer (algorithm + key).
try receivedJWT.verifySignatureWith(HS256(key: "secsret"))
//: Trying to verify claims against expiration time claim that expires now will fail.
try receivedJWT.verifyClaims([ExpirationTimeClaim()])
//: However, if we add a leeway of 2 minutes, it passes.
try receivedJWT.verifyClaims([ExpirationTimeClaim(leeway: 120)])    
//: [Next](@next)

