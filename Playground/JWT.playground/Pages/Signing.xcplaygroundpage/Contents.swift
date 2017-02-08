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

    func sign(_ message: Bytes) throws -> Bytes {
        return message.map { $0 ^ key }
    }

    func verifySignature(_ signature: Bytes, message: Bytes) throws -> Bool {
        return signature.map { $0 ^ key } == message
    }
}

let xor = XOR(key: 87)
let message = "secret message".bytes
let signature = try xor.sign(message)
try xor.verifySignature(signature, message: message)
//: [Next](@next)
