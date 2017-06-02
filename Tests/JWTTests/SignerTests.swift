import JWT
import Core
import XCTest

final class SignerTests: XCTestCase {
    func testUnsigned() throws {
        let signer = Unsigned()
        XCTAssertEqual(signer.name, "none")
        XCTAssertEqual(try signer.sign(message: "a".makeBytes()), [])
        try signer.verify(signature: "a".makeBytes(), message: "b".makeBytes())
    }

    func checkHMACSigner(
        createSigner: (Bytes) -> HMACSigner,
        name: String,
        message: Bytes = "message".makeBytes(),
        key: Bytes = "secret".makeBytes(),
        signed: String,
        file: StaticString = #file,
        line: UInt = #line
    ) throws {
        let signer = createSigner(key)
        XCTAssertEqual(signer.name, name, file: file, line: line)
        XCTAssertEqual(try signer.sign(message: message).base64URLEncoded.makeString(), signed, file: file, line: line)
        try signer.verify(
            signature: signed.makeBytes().base64URLDecoded,
            message: message
        )
    }

    func testHS256() throws {
        try checkHMACSigner(
            createSigner: HS256.init,
            name: "HS256",
            signed: "i19IcCmVwVmMVz2x4hhmqbgl1KeU0WnXBgoDYFeWNgs"
        )
    }

    func testHS384() throws {
        try checkHMACSigner(
            createSigner: HS384.init,
            name: "HS384",
            signed: "rQ706A2kJ7KjPURXyXK_dZ9Qdm-7ZlaQ1Qt8s43VIX21Wck-p8vuSOKuGltKr9NL"
        )
    }

    func testHS512() throws {
        try checkHMACSigner(
            createSigner: HS512.init,
            name: "HS512",
            signed: "G7pYfHMO7box9Tq7C2ylieCd5OiU7kVeYUCAc5l1mtqvoGnux8AWR7sXPcsX9V0ir0mhgHG3SMXC7df3qCnGMg"
        )
    }

    func checkSigner(
        createSigner: (Bytes) throws -> Signer,
        createVerifier: ((Bytes) throws -> Signer)? = nil,
        name: String,
        message: String = "message",
        privateKey: String,
        publicKey: String,
        file: StaticString = #file,
        line: UInt = #line

    ) throws {
        let signer = try createSigner(privateKey.makeBytes().base64URLDecoded)

        let publicBytes = publicKey.makeBytes().base64URLDecoded
        let verifier = try createVerifier?(publicBytes) ?? createSigner(publicBytes)

        XCTAssertEqual(signer.name, name, file: file, line: line)

        let signature = try signer.sign(message: message.makeBytes())
        try verifier.verify(signature: signature, message: message.makeBytes())
    }

    func testES256() throws {
        try checkSigner(
            createSigner: ES256.init,
            name: "ES256",
            privateKey: "AL3BRa7llckPgUw3Si2KCy1kRUZJ/pxJ29nlr86xlm0=",
            publicKey: "BIMulrzGbr8b4Dzj/lR5/m69XXLXfFCU0hkXr9jvpsXzNovbyb0gJYkMxrrCyYqd9ofDcTSSIWxxEtL8h5KcNBY="
        )
    }

    func testES384() throws {
        try checkSigner(
            createSigner: ES384.init,
            name: "ES384",
            privateKey: "BVjgIwqB1PeIv0YP3ZeQ7CTqW+9+yJ7Y/jXPr1tfrb3ne5TQNMU2rOxYtf6M6IN9",
            publicKey: "BAV9NUl1v488eXcDhStPTK57Dg4Cm+XCjmFGD1IXjkF+LJNG963oUkYjV1xxNQgxJka7tsXjadei25PdZatX3GS6KivPiNu1YdeSpXxr5d73sdLU/rq/OgDLUUcic77g3A=="
        )
    }

    func testES512() throws {
        try checkSigner(
            createSigner: ES512.init,
            name: "ES512",
            privateKey: "AdcqLUGC+4OlxqGRJkz6++BD9tfDtNM1NvTQh7M0stzvMMvcaNio87YUD6Gaks0eS9Krvs1Bkqo/T7k9DW8Eyoec",
            publicKey: "BACJKkoouMqhbgZtTSyQJHECDf/V2ArN7VwuaIUIKsx/OFiF79ccrzCSZ1MrGOmQgPAez6pqjUIjhwoHr5tRH65BggEUhC7SNvRvfMeElOrZNac9uTVnfGJ1DywnL+JtD49ytuD9GjifUPHJi4RcN36RHLXyBpF0u1+RRFbKCNhnJ132Pw=="
        )
    }


    let privateRSAKey = "MIIEpQIBAAKCAQEAq9IyIvhllcz9dTubJair9stTDR/3OQtO87NeWwk/7/Pte13c5s4gQariuX+Q7KMAqjvR4s2Fn3Q7bNLroRkWEV0LpQA/ft056DVO4z3iqcplTGnGR1VHfKAKFquazV8QSgjq4+cD2A0rHCfk1PcAP0fB3Xc52f6yoYzZyW7tJvfd3QamHOu3zAXbpAkpUk0N5fn4bumL4rF4j5jiKcZDspNfhSrhDZpXW7TyWiMmDQLYtSvCj9MK6JW79fTr8WyRrXVmRXBnGFktKrnmkbsQba1GKwVDUCx6E+nm5ZStE8vcwuOy0U1EtrcjiDprM1uGCCvjcOOb40voxXoRN9szdwIDAQABAoIBABOc/d4iDq6H5NLSCAbHd0HHueZApN7dHJkS+41Ww/anGI/BiirKksIMOK9GEYwBm1zTUUUbgspN4U6t0PnlvDAlN+QQ4C6iIC8Sjru/37TUBrYvSNPxtyRRvHUUB6qz1E8vL2jugPDTp/0hzKxGub9/eHDIYFEzEr8ALgghYm7VIpl7WRp+hd028lhokGmeDzU+aoDH3DiNFwARG2Rsjbs4AQU065wHy7lrqP5Cjj9WFE5ycEcSqpup8GCklClJwrPTlj5rVa6QwDFs5tRS3R4c8dBnEtWgxjUeLjnbvZJEIp3tcjekIC0NYQ3NscW9+s1WYF6i0CXucUEYRC6fBMECgYEA1bIBqBx3fNcurAULg4nRCWYTAXAhRYU+N1nD8jzNIobPqMOF73b78DBBQTsbiH9LGSVP2Tt1AzSVMx5Wa5lseeJLGH56Ayah7HtOYYlyzdxrD5pa/0RndklWi0J4xFOcrG3n35dJNpsOjiMcZfoGbs73R1KfZKxhCmyIM283BCECgYEAzdYEzRKRtzfiUpTu56aFo65IgCRyNiFzrkOeaLRFvi4ifsPnpRL14LY8NQIGz58FnG8nRfrZgcExOmydWDVNzpOvR8nZ8zoTjWaHMed5y6dUFBf5lGehKGkRygeUhSLRBPBXJ0ScwEkeMbSv+7rl22VgoHa4Ds816B2xLldvRJcCgYEAs8IWhKzVko2MdCWWRuMylV5pFGeXhVyNNpBrNSUSRj3zBvraetKzIZvl+JJZGdxCdvedEJZkWvrrmuGlPsQDrQ+/re4OgwIHad9b0s6FZUhKQwjMDTkkcytEAsc6waO4ApA9Yidn7ehHOSet5taIfMPa3QNSk6QxyUv80o92TyECgYEAu3c4WC2ZWO0ky2GpVIFtJW4NyednvbUpzoT3ORU2j8ck059I0ic6mLZgj0aRPXbvfVIeyrV0c6CoXTWe+D9T5djLwu4r+kHinN3MM79GRhzXjpVnUaowNMW81euhcMAM7hqWxcTPnrD5NvwBa5sEzZS/NGXrrFE8H3Mrc7FePXECgYEAofgTcuhSGNoiWlwsiBHpXbe75fzG2QxDGBVK6AdL0gTM2hoeTGdsmM7V/0HFkXDViw9wOb4SaWG5wnGLmk3iJEo5DW1gJY6TVXRtzrqfGLK/kui1h+QzrfI7Hvgv6iX5cmA0Wf7oBvXq3HjnaTiquqJdoQQHlzU52kbJX5cLbYo="
    let publicRSAKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq9IyIvhllcz9dTubJair9stTDR/3OQtO87NeWwk/7/Pte13c5s4gQariuX+Q7KMAqjvR4s2Fn3Q7bNLroRkWEV0LpQA/ft056DVO4z3iqcplTGnGR1VHfKAKFquazV8QSgjq4+cD2A0rHCfk1PcAP0fB3Xc52f6yoYzZyW7tJvfd3QamHOu3zAXbpAkpUk0N5fn4bumL4rF4j5jiKcZDspNfhSrhDZpXW7TyWiMmDQLYtSvCj9MK6JW79fTr8WyRrXVmRXBnGFktKrnmkbsQba1GKwVDUCx6E+nm5ZStE8vcwuOy0U1EtrcjiDprM1uGCCvjcOOb40voxXoRN9szdwIDAQAB"

    func testRS256() throws {
        try checkSigner(
            createSigner: RS256.init(key:),
            name: "RS256",
            privateKey: privateRSAKey,
            publicKey: publicRSAKey
        )
    }

    func testRS384() throws {
        try checkSigner(
            createSigner: RS384.init(key:),
            name: "RS384",
            privateKey: privateRSAKey,
            publicKey: publicRSAKey
        )
    }

    func testRS512() throws {
        try checkSigner(
            createSigner: RS512.init(key:),
            name: "RS512",
            privateKey: privateRSAKey,
            publicKey: publicRSAKey
        )
    }

    func testRSAPublicKeySignFails() throws {
        let signer = try RS512(bytes: publicRSAKey.makeBytes().base64URLDecoded)

        XCTAssertThrowsError(
            try signer.sign(message: "foo")
        ) {
            guard let error = $0 as? JWTError, case .privateKeyRequired = error else {
                XCTFail("Wrong error: \($0)")
                return
            }
        }
    }

    let privateKeyX509 = "MIIBOgIBAAJBAPnZE7Om9gDGaYgC5bszVridpL/6LeSPPxaDc3/wa+HNzydMjpxfmDMxg8hdCfMuhGyQLtqNqfIAK2oL7x20APkCAwEAAQJAa0w3ctLEGScckSW1ZUSx/IzvAOc/KEYAcPm483vbyNeR3wrwRWl3ZkNy+z1pr+ND1tnVYpHKEdzlMOUOY+5TNQIhAP/OBHEH/fQCd4dPExG1WwPVsIqHvxtvc+f+NY4qHisPAiEA+gnlS+IGcKED1RnhRznvAqYDDKzmEo5hvX9M0i9GM3cCIAuJs1GV1rKG2fVUb7vAvlYx8UCOVuRZ5pR0Nt4usCWpAiAHJ09TG3VZtZGZgDMMyaCH7934d93hPAeZ11GIVefpQwIhAN9cZc9wZDUdz6/2+pXpdozzbXcowWZZbID+FDdclQ9/"
    let publicCert = "MIICWTCCAgOgAwIBAgIJANM5K91tjScPMA0GCSqGSIb3DQEBCwUAMFQxCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhDb2xvcmFkbzEPMA0GA1UEBxMGRGVudmVyMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTcwNTIyMDMxMDI2WhcNMTcwNjIxMDMxMDI2WjBUMQswCQYDVQQGEwJVUzERMA8GA1UECBMIQ29sb3JhZG8xDzANBgNVBAcTBkRlbnZlcjEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAPnZE7Om9gDGaYgC5bszVridpL/6LeSPPxaDc3/wa+HNzydMjpxfmDMxg8hdCfMuhGyQLtqNqfIAK2oL7x20APkCAwEAAaOBtzCBtDAdBgNVHQ4EFgQUJoHhyknL7sHyLZMR+EbDLWPTaYEwgYQGA1UdIwR9MHuAFCaB4cpJy+7B8i2TEfhGwy1j02mBoVikVjBUMQswCQYDVQQGEwJVUzERMA8GA1UECBMIQ29sb3JhZG8xDzANBgNVBAcTBkRlbnZlcjEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkggkA0zkr3W2NJw8wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAANBAAAkIvlASbRx7ORKYNixdpUw8tHdFRlzcQJ/QHCZAjOqvDp7jPmMrUwIDjHGOfSiWgU2bd2tljnzp5HVdqahzWA="

    func testRS256x509() throws {
        try checkSigner(
            createSigner: RS256.init(key:),
            createVerifier: RS256.init(x509Cert:),
            name: "RS256",
            privateKey: privateKeyX509,
            publicKey: publicCert
        )
    }

    static let all = [
        ("testUnsigned", testUnsigned),
        ("testHS256", testHS256),
        ("testHS384", testHS384),
        ("testHS512", testHS512),
        ("testES256", testES256),
        ("testES384", testES384),
        ("testES512", testES512),
        ("testRS256", testRS256),
        ("testRS384", testRS384),
        ("testRS512", testRS512),
        ("testRS256x509", testRS256x509),
    ]
}
