@testable import VaporJWT
import Node
import XCTest

struct TestClaim: Claim {
    static var name = "tst"
    let verified: Bool

    init(verified: Bool = true) {
        self.verified = verified
    }

    func verify(_ node: Node) -> Bool {
        return verified
    }
}

final class ClaimTests: XCTestCase {

    let date = Date(timeIntervalSince1970: 1000)

    func testMissingClaim() {
        XCTAssertFalse(Node([:]).verify([TestClaim(verified: true)]))
    }

    func testFailingClaim() {
        XCTAssertFalse(Node(["tst": ""]).verify([TestClaim(verified: false)]))
    }

    func testValidClaim() {
        XCTAssertTrue(Node(["tst": ""]).verify([TestClaim(verified: true)]))
    }

    func testMultipleValidClaims() {
        XCTAssertTrue(Node(["tst": ""]).verify([TestClaim(verified: true),
                                                TestClaim(verified: true)]))
    }

    func testMixedClaims() {
        XCTAssertFalse(Node(["tst": ""]).verify([TestClaim(verified: true),
                                                 TestClaim(verified: false)]))
    }

    func testAudienceClaim() {
        XCTAssertEqual([Audience.name], ["aud"])

        XCTAssertTrue(Audience("a").verify("a"))
        XCTAssertFalse(Audience("a").verify("b"))
        XCTAssertTrue(Audience(["a", "b"]).verify("b"))
        XCTAssertFalse(Audience(["a", "b"]).verify("c"))
        XCTAssertTrue(Audience(["a", "b", "c"]).verify(["b", "c"]))
        XCTAssertFalse(Audience(["a", "b", "c"]).verify(["c", "d"]))
    }

    func testExpirationTimeClaim() {
        XCTAssertEqual([ExpirationTime.name], ["exp"])

        let claim = ExpirationTime(date, leeway: 1)

        XCTAssertTrue(claim.verify(.number(Node.Number(date.timeIntervalSince1970))))
        XCTAssertTrue(claim.verify(.number(Node.Number(date.timeIntervalSince1970 + 1))))
        XCTAssertFalse(claim.verify(.number(Node.Number(date.timeIntervalSince1970 + 2))))
    }

    func testIssuedAtClaim() {
        XCTAssertEqual([IssuedAt.name], ["iat"])

        let claim = IssuedAt(date)

        XCTAssertTrue(claim.verify(.number(Node.Number(date.timeIntervalSince1970))))
        XCTAssertFalse(claim.verify(.number(Node.Number(date.timeIntervalSince1970 + 1))))
    }

    func testIssuerClaim() {
        XCTAssertEqual([Issuer.name], ["iss"])

        XCTAssertTrue(Issuer("a").verify("a"))
        XCTAssertFalse(Issuer("a").verify("b"))
    }

    func testJWTIDClaim() {
        XCTAssertEqual([JWTID.name], ["jti"])

        XCTAssertTrue(JWTID("a").verify("a"))
        XCTAssertFalse(JWTID("a").verify("b"))
    }

    func testNotBeforeClaim() {
        XCTAssertEqual([NotBefore.name], ["nbf"])

        let claim = NotBefore(date, leeway: 1)

        XCTAssertTrue(claim.verify(.number(Node.Number(date.timeIntervalSince1970))))
        XCTAssertTrue(claim.verify(.number(Node.Number(date.timeIntervalSince1970 - 1))))
        XCTAssertFalse(claim.verify(.number(Node.Number(date.timeIntervalSince1970 - 2))))
    }

    func testSubjectClaim() {
        XCTAssertEqual([Subject.name], ["sub"])

        XCTAssertTrue(Subject("a").verify("a"))
        XCTAssertFalse(Subject("a").verify("b"))
    }

    static var all = [
        testMissingClaim,
        testFailingClaim,
        testValidClaim,
        testAudienceClaim,
        testIssuedAtClaim,
        testIssuerClaim,
        testJWTIDClaim,
        testNotBeforeClaim,
        testSubjectClaim,
    ]
}
