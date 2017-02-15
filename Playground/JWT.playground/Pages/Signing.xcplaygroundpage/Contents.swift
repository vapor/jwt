//: [Previous](@previous)
//: ## Signing
import Core
import JWT
//: `JWT` includes 7 signers:
//: * HS256
//: * HS384
//: * HS512
//: * ES256
//: * ES384
//: * ES512
//: * Unsigned
//:
//: To create your own signer, adapt to the `Signer` protocol.
struct XOR: Signer {
    let key: Byte

    init(key: Byte) {
        self.key = key
    }

    func sign(message: Bytes) throws -> Bytes {
        return message.map { $0 ^ key }
    }

    func verify(signature: Bytes, message: Bytes) throws {
        guard signature.map({ $0 ^ key }) == message else {
            throw JWTError.signatureVerificationFailed
        }
    }
}

let xor = XOR(key: 87)
let message = "secret message".bytes
let signature = try xor.sign(message: message)
try xor.verify(signature: signature, message: message)
//: [Next](@next)
