@testable import VaporJWT
import Core
import XCTest

final class SignerTests: XCTestCase {
    let encoder = Base64Encoding()

    func testUnsigned() {
        let signer = Unsigned()
        XCTAssertEqual(signer.name, "none")
        XCTAssertEqual(try signer.sign("a".bytes), [])
        XCTAssertTrue(try signer.verifySignature("a".bytes, message: "b".bytes))
    }

    func checkHMACSigner(createSigner: (Bytes) -> HMACSigner,
                         name: String,
                         message: Bytes = "message".bytes,
                         key: Bytes = "secret".bytes,
                         signed: String,
                         file: StaticString = #file,
                         line: UInt = #line) {
        let signer = createSigner(key)
        XCTAssertEqual(signer.name, name, file: file, line: line)
        XCTAssertEqual(try encoder.encode(try signer.sign(message)), signed, file: file, line: line)
        XCTAssertTrue(try signer.verifySignature(try encoder.decode(signed), message: message),
                      file: file, line: line)
    }

    func testHS256() {
        checkHMACSigner(createSigner: HS256.init,
                        name: "HS256",
                        signed: "i19IcCmVwVmMVz2x4hhmqbgl1KeU0WnXBgoDYFeWNgs=")
    }

    func testHS384() {
        checkHMACSigner(createSigner: HS384.init,
                        name: "HS384",
                        signed: "rQ706A2kJ7KjPURXyXK/dZ9Qdm+7ZlaQ1Qt8s43VIX21Wck+p8vuSOKuGltKr9NL")
    }

    func testHS512() {
        checkHMACSigner(createSigner: HS512.init,
                        name: "HS512",
                        signed: "i19IcCmVwVmMVz2x4hhmqbgl1KeU0WnXBgoDYFeWNgs=")
    }

    func checkECDSASigner(createSigner: (Bytes) -> ECDSASigner,
                          name: String,
                          message: String = "message",
                          privateKey: String,
                          publicKey: String,
                          file: StaticString = #file,
                          line: UInt = #line) {
        do {
            let signer = createSigner(try encoder.decode(privateKey))
            let verifier = createSigner(try encoder.decode(publicKey))
            XCTAssertEqual(signer.name, name, file: file, line: line)

            let signature = try signer.sign(message.bytes)
            XCTAssertTrue(try verifier.verifySignature(signature, message: message.bytes),
                          file: file, line: line)
        } catch {
            XCTFail("\(error)", file: file, line: line)
        }
    }

    func testES256() {
        checkECDSASigner(createSigner: ES256.init,
                         name: "ES256",
                         privateKey: "AL3BRa7llckPgUw3Si2KCy1kRUZJ/pxJ29nlr86xlm0=",
                         publicKey: "BIMulrzGbr8b4Dzj/lR5/m69XXLXfFCU0hkXr9jvpsXzNovbyb0gJYkMxrrCyYqd9ofDcTSSIWxxEtL8h5KcNBY=")
    }

    func testES384() {
        checkECDSASigner(createSigner: ES384.init,
                         name: "ES384",
                         privateKey: "BVjgIwqB1PeIv0YP3ZeQ7CTqW+9+yJ7Y/jXPr1tfrb3ne5TQNMU2rOxYtf6M6IN9",
                         publicKey: "BAV9NUl1v488eXcDhStPTK57Dg4Cm+XCjmFGD1IXjkF+LJNG963oUkYjV1xxNQgxJka7tsXjadei25PdZatX3GS6KivPiNu1YdeSpXxr5d73sdLU/rq/OgDLUUcic77g3A==")
    }

    func testES512() {
        checkECDSASigner(createSigner: ES512.init,
                         name: "ES512",
                         privateKey: "AdcqLUGC+4OlxqGRJkz6++BD9tfDtNM1NvTQh7M0stzvMMvcaNio87YUD6Gaks0eS9Krvs1Bkqo/T7k9DW8Eyoec",
                         publicKey: "BACJKkoouMqhbgZtTSyQJHECDf/V2ArN7VwuaIUIKsx/OFiF79ccrzCSZ1MrGOmQgPAez6pqjUIjhwoHr5tRH65BggEUhC7SNvRvfMeElOrZNac9uTVnfGJ1DywnL+JtD49ytuD9GjifUPHJi4RcN36RHLXyBpF0u1+RRFbKCNhnJ132Pw==")
    }

    static let all = [
        ("testUnsigned", testUnsigned),
        ("testHS256", testHS256),
        ("testHS384", testHS384),
        ("testHS512", testHS512),
        ("testES256", testES256),
        ("testES384", testES384),
        ("testES512", testES512),
    ]
}
