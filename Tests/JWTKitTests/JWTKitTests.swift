import XCTest
import JWTKit

class JWTKitTests: XCTestCase {
    func testParse() throws {
        let data = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6OTk5OTk5OTk5OTk5fQ.Ks7KcdjrlUTYaSNeAO5SzBla_sFCHkUh4vvJYn6q29U"

        let jwt = try JWT<TestPayload>(from: data.bytes, verifiedBy: .hs256(key: "secret".bytes))
        XCTAssertEqual(jwt.payload.name, "John Doe")
        XCTAssertEqual(jwt.payload.sub.value, "1234567890")
        XCTAssertEqual(jwt.payload.admin, true)
    }

    func testExpired() throws {
        let data = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6MX0.-x_DAYIg4R4R9oZssqgWyJP_oWO1ESj8DgKrGCk7i5o"

        do {
            let _ = try JWT<TestPayload>(from: data.bytes, verifiedBy: .hs256(key: "secret".bytes))
        } catch let error as JWTError {
            switch error {
            case .claimVerificationFailure(let name, _):
                XCTAssertEqual(name, "exp")
            default:
                XCTFail("wrong error")
            }
        }
    }

    func testExpirationDecoding() throws {
        let data = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIwMDAwMDAwMDB9.JgCO_GqUQnbS0z2hCxJLE9Tpt5SMoZObHBxzGBWuTYQ"

        let jwt = try JWT<ExpirationPayload>(from: data.bytes, verifiedBy: .hs256(key: "secret".bytes))
        XCTAssertEqual(jwt.payload.exp.value, Date(timeIntervalSince1970: 2_000_000_000))
    }

    func testExpirationEncoding() throws {
        let exp = ExpirationClaim(value: Date(timeIntervalSince1970: 2_000_000_000))
        var jwt = JWT(payload: ExpirationPayload(exp: exp))

        jwt.header.typ = nil // set to nil to avoid dictionary re-ordering causing probs
        let data = try jwt.sign(using: .hs256(key: "secret".bytes))

        XCTAssertEqual(
            String(decoding: data, as: UTF8.self),
            "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjIwMDAwMDAwMDB9.4W6egHvMSp9bBiGUnE7WhVfXazOfg-ADcjvIYILgyPU"
        )
    }

    func testSigners() throws {
        let data = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZvbyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6OTk5OTk5OTk5OTk5OTl9.Gf7leJ8i30LmMI7GBTpWDMXV60y1wkTOCOBudP9v9ms"

        let signers = JWTSigners()
        signers.use(.hs256(key: "bar".bytes), kid: "foo")

        let jwt = try JWT<TestPayload>(from: data.bytes, verifiedBy: signers)
        XCTAssertEqual(jwt.payload.name, "John Doe")
    }

    func testRSA() throws {
        let privateSigner = try JWTSigner.rs256(key: .private(pem: rsaPrivateKey.bytes))
        let publicSigner = try JWTSigner.rs256(key: .public(pem: rsaPublicKey.bytes))

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let jwt = JWT(payload: payload)
        let privateSigned = try jwt.sign(using: privateSigner)
        try XCTAssertEqual(JWT<TestPayload>(from: privateSigned, verifiedBy: publicSigner).payload, payload)
        try XCTAssertEqual(JWT<TestPayload>(from: privateSigned, verifiedBy: privateSigner).payload, payload)
    }

    func testRSASignWithPublic() throws {
        let publicSigner = try JWTSigner.rs256(key: .public(pem: rsaPublicKey.bytes))
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
    }

    func testECDSAGenerate() throws {
        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let jwt = JWT(payload: payload)
        let signer = try JWTSigner.es256(key: .generate())
        let data = try jwt.sign(using: signer)
        try XCTAssertEqual(JWT<TestPayload>(from: data, verifiedBy: signer).payload, payload)
    }

    func testECDSAPublicPrivate() throws {
        let publicSigner = try JWTSigner.es256(key: .public(pem: ecdsaPublicKey.bytes))
        let privateSigner = try JWTSigner.es256(key: .private(pem: ecdsaPrivateKey.bytes))

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let jwt = JWT(payload: payload)
        
        for _ in 0..<1_000 {
            let data = try jwt.sign(using: privateSigner)
            // test private signer decoding
            try XCTAssertEqual(JWT<TestPayload>(from: data, verifiedBy: privateSigner).payload, payload)
            // test public signer decoding
            try XCTAssertEqual(JWT<TestPayload>(from: data, verifiedBy: publicSigner).payload, payload)
        }
    }

    func testJWTioExample() throws {
        let token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA"
        let corruptedToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HwP_3cYHBw7AhHale5wky6-sVA"

        let publicKey = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
        q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
        -----END PUBLIC KEY-----
        """

        // {
        //   "sub": "1234567890",
        //   "name": "John Doe",
        //   "admin": true,
        //   "iat": 1516239022
        // }
        struct JWTioPayload: JWTPayload {
            var sub: SubjectClaim
            var name: String
            var admin: Bool
            var iat: IssuedAtClaim

            func verify(using signer: JWTSigner) throws {
                // no verifiable claims
            }
        }

        // create public key signer (verifier)
        let publicSigner = try JWTSigner.es256(key: .public(pem: publicKey.bytes))

        // decode jwt and test payload contents
        let jwt = try JWT<JWTioPayload>(from: token.bytes, verifiedBy: publicSigner)
        XCTAssertEqual(jwt.payload.sub, "1234567890")
        XCTAssertEqual(jwt.payload.name, "John Doe")
        XCTAssertEqual(jwt.payload.admin, true)
        XCTAssertEqual(jwt.payload.iat.value, .init(timeIntervalSince1970: 1516239022))

        // test corrupted token
        // this should fail
        do {
            _ = try JWT<JWTioPayload>(from: corruptedToken.bytes, verifiedBy: publicSigner)
        } catch let error as JWTError {
            switch error {
            case .signatureVerifictionFailed:
                // pass
                XCTAssert(true)
            default:
                XCTFail("unexpected error: \(error)")
            }
        }
    }
}

struct TestPayload: JWTPayload, Equatable {
    var sub: SubjectClaim
    var name: String
    var admin: Bool
    var exp: ExpirationClaim

    func verify(using signer: JWTSigner) throws {
        try self.exp.verifyNotExpired()
    }
}

struct ExpirationPayload: JWTPayload {
    var exp: ExpirationClaim

    func verify(using signer: JWTSigner) throws {
        try self.exp.verifyNotExpired()
    }
}

let ecdsaPrivateKey = """
-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg2sD+kukkA8GZUpmm
jRa4fJ9Xa/JnIG4Hpi7tNO66+OGgCgYIKoZIzj0DAQehRANCAATZp0yt0btpR9kf
ntp4oUUzTV0+eTELXxJxFvhnqmgwGAm1iVW132XLrdRG/ntlbQ1yzUuJkHtYBNve
y+77Vzsd
-----END PRIVATE KEY-----
"""
let ecdsaPublicKey = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2adMrdG7aUfZH57aeKFFM01dPnkx
C18ScRb4Z6poMBgJtYlVtd9ly63URv57ZW0Ncs1LiZB7WATb3svu+1c7HQ==
-----END PUBLIC KEY-----
"""

let rsaPrivateKey = """
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

let rsaPublicKey = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
PmjXpbCkecAWLj/CcDWEcuTZkYDiSG0zgglbbbhcV0vJQDWSv60tnlA3cjSYutAv
7FPo5Cq8FkvrdDzeacwRSxYuIq1LtYnd6I30qNaNthntjvbqyMmBulJ1mzLI+Xg/
aX4rbSL49Z3dAQn8vQIDAQAB
-----END PUBLIC KEY-----
"""

extension String {
    var bytes: [UInt8] {
        return .init(self.utf8)
    }
}
