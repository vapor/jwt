import XCTest
@testable import JWT
import Bits
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
        jwt.header.typ = nil // set to nil to avoid dictionary re-ordering causing probs
        let data = try signer.sign(jwt)

        XCTAssertEqual(String(data: data, encoding: .utf8), "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjIwMDAwMDAwMDB9.4W6egHvMSp9bBiGUnE7WhVfXazOfg-ADcjvIYILgyPU")
    }

    func testSigners() throws {
        let data = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZvbyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6OTk5OTk5OTk5OTk5OTl9.Gf7leJ8i30LmMI7GBTpWDMXV60y1wkTOCOBudP9v9ms"

        let signer = JWTSigner.hs256(key: Data("bar".utf8))
        let signers = JWTSigners()
        signers.use(signer, kid: "foo")

        let jwt = try JWT<TestPayload>(from: data, verifiedUsing: signers)
        XCTAssertEqual(jwt.payload.name, "John Doe")
    }

    func testRSA() throws {
        let privateSigner = try JWTSigner.rs256(key: .private(pem: privateKeyString))
        let publicSigner = try JWTSigner.rs256(key: .public(pem: publicKeyString))

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let jwt = JWT(payload: payload)
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

    func testThreadSafety() throws {
        let signer = JWTSigner.hs256(key: "test")

        let start = DispatchGroup()
        start.enter()
        start.enter()

        let done = DispatchGroup()
        done.enter()
        done.enter()

        Thread.async {
            start.leave()
            start.wait()
            for _ in 0..<100 {
                _ = try? signer.verify("foo", header: "bar", payload: "baz")
            }
            done.leave()
        }
        Thread.async {
            start.leave()
            start.wait()
            for _ in 0..<100 {
                _ = try? signer.verify("foo", header: "bar", payload: "baz")
            }
            done.leave()
        }
        done.wait()
    }
    
    static var allTests = [
        ("testParse", testParse),
        ("testExpired", testExpired),
        ("testExpirationDecoding", testExpirationDecoding),
        ("testExpirationEncoding", testExpirationEncoding),
        ("testSigners", testSigners),
        ("testRSA", testRSA),
        ("testThreadSafety", testThreadSafety),
    ]
}

struct TestPayload: JWTPayload {
    var sub: SubjectClaim
    var name: String
    var admin: Bool
    var exp: ExpirationClaim

    func verify(using signer: JWTSigner) throws {
        try exp.verifyNotExpired()
    }
}

struct ExpirationPayload: JWTPayload {
    var exp: ExpirationClaim

    func verify(using signer: JWTSigner) throws {
        try exp.verifyNotExpired()
    }
}

/// MARK: RSA

let privateKeyString = """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC0cOtPjzABybjzm3fCg1aCYwnxPmjXpbCkecAWLj/CcDWEcuTZ
kYDiSG0zgglbbbhcV0vJQDWSv60tnlA3cjSYutAv7FPo5Cq8FkvrdDzeacwRSxYu
Iq1LtYnd6I30qNaNthntjvbqyMmBulJ1mzLI+Xg/aX4rbSL49Z3dAQn8vQIDAQAB
AoGBAJeBFGLJ1EI8ENoiWIzu4A08gRWZFEi06zs+quU00f49XwIlwjdX74KP03jj
H14wIxMNjSmeixz7aboa6jmT38pQIfE3DmZoZAbKPG89SdP/S1qprQ71LgBGOuNi
LoYTZ96ZFPcHbLZVCJLPWWWX5yEqy4MS996E9gMAjSt8yNvhAkEA38MufqgrAJ0H
VSgL7ecpEhWG3PHryBfg6fK13RRpRM3jETo9wAfuPiEodnD6Qcab52H2lzMIysv1
Ex6nGv2pCQJBAM5v9SMbMG20gBzmeZvjbvxkZV2Tg9x5mWQpHkeGz8GNyoDBclAc
BFEWGKVGYV6jl+3F4nqQ6YwKBToE5KIU5xUCQEY9Im8norgCkrasZ3I6Sa4fi8H3
PqgEttk5EtVe/txWNJzHx3JsCuD9z5G+TRAwo+ex3JIBtxTRiRCDYrkaPuECQA2W
vRI0hfmSuiQs37BtRi8DBNEmFrX6oyg+tKmMrDxXcw8KrNWtInOb+r9WZK5wIl4a
epAK3fTD7Bgnnk01BwkCQHQwEdGNGN3ntYfuRzPA4KiLrt8bpACaHHr2wn9N3fRI
bxEd3Ax0uhHVqKRWNioL7UBvd4lxoReY8RmmfghZHEA=
-----END RSA PRIVATE KEY-----
"""

let publicKeyString = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
PmjXpbCkecAWLj/CcDWEcuTZkYDiSG0zgglbbbhcV0vJQDWSv60tnlA3cjSYutAv
7FPo5Cq8FkvrdDzeacwRSxYuIq1LtYnd6I30qNaNthntjvbqyMmBulJ1mzLI+Xg/
aX4rbSL49Z3dAQn8vQIDAQAB
-----END PUBLIC KEY-----
"""
