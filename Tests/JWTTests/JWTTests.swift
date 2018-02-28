import XCTest
@testable import JWT
import Crypto

class JWTTests: XCTestCase {
    func testParse() throws {
        let data = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6OTk5OTk5OTk5OTk5fQ.Ks7KcdjrlUTYaSNeAO5SzBla_sFCHkUh4vvJYn6q29U"

        let signer = JWTSigner.hs256(key: Data("secret".utf8))
        let jwt = try JWT<TestPayload>(from: data, verifiedUsing: signer)
        XCTAssertEqual(jwt.payload.name, "John Doe")
        XCTAssertEqual(jwt.payload.sub.value, "1234567890")
        XCTAssertEqual(jwt.payload.admin, true)
    }

    func testExpired() throws {
        let data = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6MX0.-x_DAYIg4R4R9oZssqgWyJP_oWO1ESj8DgKrGCk7i5o"

        let signer = JWTSigner.hs256(key: Data("secret".utf8))
        do {
            _ = try JWT<TestPayload>(from: data, verifiedUsing: signer)
        } catch let error as JWTError {
            XCTAssertEqual(error.identifier, "exp")
        }
    }

    func testExpirationDecoding() throws {
        let data = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIwMDAwMDAwMDB9.JgCO_GqUQnbS0z2hCxJLE9Tpt5SMoZObHBxzGBWuTYQ"

        let signer = JWTSigner.hs256(key: Data("secret".utf8))
        let jwt = try JWT<ExpirationPayload>(from: data, verifiedUsing: signer)

        XCTAssertEqual(jwt.payload.exp.value, Date(timeIntervalSince1970: 2_000_000_000))
    }

    func testExpirationEncoding() throws {
        let exp = ExpirationClaim(value: Date(timeIntervalSince1970: 2_000_000_000))
        var jwt = JWT(payload: ExpirationPayload(exp: exp))

        let signer = JWTSigner.hs256(key: Data("secret".utf8))
        let data = try signer.sign(&jwt)

        XCTAssertEqual(String(data: data, encoding: .utf8), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIwMDAwMDAwMDB9.JgCO_GqUQnbS0z2hCxJLE9Tpt5SMoZObHBxzGBWuTYQ")
    }

    func testSigners() throws {
        let data = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZvbyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6OTk5OTk5OTk5OTk5OTl9.Gf7leJ8i30LmMI7GBTpWDMXV60y1wkTOCOBudP9v9ms"

        let signer = JWTSigner.hs256(key: Data("bar".utf8))
        let signers = JWTSigners()
        signers.use(signer, kid: "foo")

        let jwt = try! JWT<TestPayload>(from: data, verifiedUsing: signers)
        XCTAssertEqual(jwt.payload.name, "John Doe")
    }

    func testRSA() throws {
        let privateKey = try Base64Decoder(encoding: .base64).decode(string: privateKeyString)
        let publicKey = try Base64Decoder(encoding: .base64).decode(string: publicKeyString)
        let privateSigner = JWTSigner.rs256(key: .private2048(privateKey))
        let publicSigner = JWTSigner.rs256(key: .public2048(publicKey))

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        var jwt = JWT(payload: payload)
        do {
            _ = try jwt.sign(using: publicSigner)
            XCTFail("cannot sign with public signer")
        } catch {
            // pass
        }
        let privateSigned = try jwt.sign(using: privateSigner)
        let publicVerified = try JWT<TestPayload>(from: privateSigned, verifiedUsing: publicSigner)
        let privateVerified = try JWT<TestPayload>(from: privateSigned, verifiedUsing: privateSigner)
        XCTAssertEqual(publicVerified.payload.name, "Foo")
        XCTAssertEqual(privateVerified.payload.name, "Foo")
    }
    
    static var allTests = [
        ("testParse", testParse),
        ("testExpired", testExpired),
        ("testExpirationDecoding", testExpirationDecoding),
        ("testExpirationEncoding", testExpirationEncoding),
        ("testSigners", testSigners),
        ("testRSA", testRSA),
    ]
}

struct TestPayload: JWTPayload {
    var sub: SubjectClaim
    var name: String
    var admin: Bool
    var exp: ExpirationClaim

    func verify() throws {
        try exp.verify()
    }
}

struct ExpirationPayload: JWTPayload {
    var exp: ExpirationClaim

    func verify() throws {
        try exp.verify()
    }
}

/// MARK: RSA

let privateKeyString = """
MIIEpAIBAAKCAQEAk+dWlCTQIr85rtUi56yD6FT6vuG68Q9xJ4B9bAo4wys+ndlP
SX0UQkrPOpnNZcsHOob6DbRI5Cc4qce00nNJAlCxYqAJDDDryyQEtUv8ghGGWnjU
gBRytm39UM9s/UxyLfGWk3P1Z1us8q5RvsrceC28uG94Lr+w2XmcBwxP020qJIiU
qOff8me1vI7vogvec3yO6pLvb1zcqMioKIdQ/kWjgMvhVyFyg44IqEI1iApjt05C
jTQ30W1xyN/9b/cedQzEg8Nq2MQdhKCIZJh2vjSUuWOBCnx+ttErIYt0roisNj1O
howtSM6k0vV1LPDrCjV7lFPmE1njwTfdV/vlcQIDAQABAoIBAGBwjt6oJmMRx139
sfXYYmZiyuEeNRQsGn9EZAPHon14PCsW4IEtosEbIIa4dNq0CPGbw36eGI1UGbly
86/p5igxT4jciym82HMr+Dny4yI4pR9m/EDLlITpsSw5JHsBls3oYmOhT9nmSB4x
ljHO+vUN9alZXcc1zO3xQtDBsWdNG73YFRAv2HJ6us50wQXw4cEsuQo6X/fUREkB
nznkArTcm/VcnZFaRUg4sXQBBQdy3LhRh3zQ5V64iBe9AWgenDv7tO5Bk8xhrLE/
kBdvyrTsWKaKSSnes28oB5YLfbFpRYnYGGuaWbu5f0deOuQlS5F5HxuaHHsdRxaU
Xee7BLECgYEA60QxWsXdeIWXmMhOoCapq6OTdaPVVzZfZc57s82xy5IgghBJj3up
QbOIcfcBNTmpG4ohtB5EEmOozBKEm3dg09RF9aQ/t4Gx4TOmbtCt8IiuNAr4zj7+
xsLWh1sWGK0UvZ1hkkKoFxHU7ienXCfhfiEjBLWtNGzVHieoIc1Ly00CgYEAoPAr
Txegn2ZreU4vn6CP9pHIxY6JV7nFPbGng6q8hkMMCu7CY/w9UP9iZG6uvQcoSqGt
7rIUUqYWUcf8qcAtvWyLTZmtkCm+LIHiJak4PZXwTrpYOZQScpBTw8ViuVREsJSw
5oHgworZg3rD9oLbiSt+Iy//U14g7gzA7mJVyLUCgYEA6pHoX6gOpH8WYme9NSK3
YwHKIa4DJVx6C2ivn9uD3QPKU8PnhB746CAX+AEd/DKMcH/uEMdoealSAH6qJtQE
/8+THVLxkIbIk1BLLgv0kXHFtvAFmKXoosZa3UQtKNdRaakEQq8hJzdJRVbWICVH
R9nEL4rwseedKd7CXUlyu7UCgYBrjnbzQfAn95QGGxm6zdzIxb9vQIZLaa0HQS6Z
0UZzWGW4/L5Pgikcc8E3K71+OUVVM16BsuPgJH2wJD6Y2AX5nYwvzW/wc+VT623P
C5u5lPZoNyN1P59gj1Jb+RO0ljvd41Gii9RBT/h0ZVyH6AZ+UuHW9GHoPnU1grKB
3phELQKBgQDOWrOLmd/v43r99fxqrkZv9twFkAPlcpYOMn/SDpmJfWR3sGWCz5eI
czQFrr4k36C5HwgornNShezXpbU9bGaG7zAdd3egdqjYeWQeqj/WQFAoP6+jA+yL
hR/bpssdZZaF7Ah0AR/IHGgbNLAfdpGBjyEl1WRoq+tuJ9oMcbKezQ==
""".replacingOccurrences(of: "\n", with: "")

let publicKeyString = """
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk+dWlCTQIr85rtUi56yD
6FT6vuG68Q9xJ4B9bAo4wys+ndlPSX0UQkrPOpnNZcsHOob6DbRI5Cc4qce00nNJ
AlCxYqAJDDDryyQEtUv8ghGGWnjUgBRytm39UM9s/UxyLfGWk3P1Z1us8q5Rvsrc
eC28uG94Lr+w2XmcBwxP020qJIiUqOff8me1vI7vogvec3yO6pLvb1zcqMioKIdQ
/kWjgMvhVyFyg44IqEI1iApjt05CjTQ30W1xyN/9b/cedQzEg8Nq2MQdhKCIZJh2
vjSUuWOBCnx+ttErIYt0roisNj1OhowtSM6k0vV1LPDrCjV7lFPmE1njwTfdV/vl
cQIDAQAB
""".replacingOccurrences(of: "\n", with: "")
