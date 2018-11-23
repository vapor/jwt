import XCTest
@testable import JWT

class JWKTests: XCTestCase {

    static let allTests = [
        ("testJWKSigner", testJWKSigner)
    ]

    func testJWKSigner() throws {

        let jsonDecoder = JSONDecoder()

        let privateJWK = try jsonDecoder.decode(JWK.self, from: "{\"kty\":\"RSA\",\"d\":\"L4z0tz7QWE0aGuOA32YqCSnrSYKdBTPFDILCdfHonzfP7WMPibz4jWxu_FzNk9s4Dh-uN2lV3NGW10pAsnqffD89LtYanRjaIdHnLW_PFo5fEL2yltK7qMB9hO1JegppKCfoc79W4-dr-4qy1Op0B3npOP-DaUYlNamfDmIbQW32UKeJzdGIn-_ryrBT7hQW6_uHLS2VFPPk0rNkPPKZYoNaqGnJ0eaFFF-dFwiThXIpPz--dxTAL8xYf275rjG8C9lh6awOfJSIdXMVuQITWf62E0mSQPR2-219bShMKriDYcYLbT3BJEgOkRBBHGuHo9R5TN298anxZqV1u5jtUQ\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"1234\",\"alg\":\"RS256\",\"n\":\"gWu7yhI35FScdKARYboJoAm-T7yJfJ9JTvAok_RKOJYcL8oLIRSeLqQX83PPZiWdKTdXaiGWntpDu6vW7VAb-HWPF6tNYSLKDSmR3sEu2488ibWijZtNTCKOSb_1iAKAI5BJ80LTqyQtqaKzT0XUBtMsde8vX1nKI05UxujfTX3kqUtkZgLv1Yk1ZDpUoLOWUTtCm68zpjtBrPiN8bU2jqCGFyMyyXys31xFRzz4MyJ5tREHkQCzx0g7AvW0ge_sBTPQ2U6NSkcZvQyDbfDv27cMUHij1Sjx16SY9a2naTuOgamjtUzyClPLVpchX-McNyS0tjdxWY_yRL9MYuw4AQ\"}".convertToData())

        let publicJWK = try jsonDecoder.decode(JWK.self, from: "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"1234\",\"alg\":\"RS256\",\"n\":\"gWu7yhI35FScdKARYboJoAm-T7yJfJ9JTvAok_RKOJYcL8oLIRSeLqQX83PPZiWdKTdXaiGWntpDu6vW7VAb-HWPF6tNYSLKDSmR3sEu2488ibWijZtNTCKOSb_1iAKAI5BJ80LTqyQtqaKzT0XUBtMsde8vX1nKI05UxujfTX3kqUtkZgLv1Yk1ZDpUoLOWUTtCm68zpjtBrPiN8bU2jqCGFyMyyXys31xFRzz4MyJ5tREHkQCzx0g7AvW0ge_sBTPQ2U6NSkcZvQyDbfDv27cMUHij1Sjx16SY9a2naTuOgamjtUzyClPLVpchX-McNyS0tjdxWY_yRL9MYuw4AQ\"}".convertToData())

        let privateSigner = try JWTSigner.jwk(key: privateJWK)
        let publicSigner = try JWTSigner.jwk(key: publicJWK)

        let jwt = JWT(payload: TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        ))

        let signature = try privateSigner.sign(jwt)

        let publicVerified = try JWT<TestPayload>(from: signature, verifiedUsing: publicSigner)
        let privateVerified = try JWT<TestPayload>(from: signature, verifiedUsing: privateSigner)

        XCTAssertEqual(publicVerified.payload.name, "Foo")
        XCTAssertEqual(privateVerified.payload.name, "Foo")
    }
}
