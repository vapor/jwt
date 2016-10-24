@testable import VaporJWT
import Foundation
import Node
import XCTest

struct TestClaim: Claim {
    static var name = "tst"
    let node: Node = .null
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
        XCTAssertFalse(EmptyNode.verifyClaims([TestClaim(verified: true)]))
    }

    func testFailingClaim() {
        XCTAssertFalse(Node(["tst": ""]).verifyClaims([TestClaim(verified: false)]))
    }

    func testValidClaim() {
        XCTAssertTrue(Node(["tst": ""]).verifyClaims([TestClaim(verified: true)]))
    }

    func testMultipleValidClaims() {
        XCTAssertTrue(Node(["tst": ""]).verifyClaims([TestClaim(verified: true),
                                                      TestClaim(verified: true)]))
    }

    func testMixedClaims() {
        XCTAssertFalse(Node(["tst": ""]).verifyClaims([TestClaim(verified: true),
                                                       TestClaim(verified: false)]))
    }

    func testVerifyInvalidPayloadFails() {
        XCTAssertFalse(Node(.string("")).verifyClaims([]))
    }

    func testAudienceClaim() {
        XCTAssertEqual([AudienceClaim.name], ["aud"])

        XCTAssertTrue(AudienceClaim("a").verify("a"))
        XCTAssertFalse(AudienceClaim("a").verify("b"))
        XCTAssertTrue(AudienceClaim(["a", "b"]).verify("b"))
        XCTAssertFalse(AudienceClaim(["a", "b"]).verify("c"))
        XCTAssertTrue(AudienceClaim(["a", "b", "c"]).verify(["b", "c"]))
        XCTAssertFalse(AudienceClaim(["a", "b", "c"]).verify(["c", "d"]))
    }

    func testExpirationTimeClaim() {
        XCTAssertEqual([ExpirationTimeClaim.name], ["exp"])

        let claim = ExpirationTimeClaim(date, leeway: 1)

        XCTAssertTrue(claim.verify(Node(date.timeIntervalSince1970)))
        XCTAssertTrue(claim.verify(Node(date.timeIntervalSince1970 - 1)))
        XCTAssertFalse(claim.verify(Node(date.timeIntervalSince1970 - 2)))
    }

    func testIssuedAtClaim() {
        XCTAssertEqual([IssuedAtClaim.name], ["iat"])

        let claim = IssuedAtClaim(date)

        XCTAssertTrue(claim.verify(Node(date.timeIntervalSince1970)))
        XCTAssertFalse(claim.verify(Node(date.timeIntervalSince1970 + 1)))
    }

    func testIssuerClaim() {
        XCTAssertEqual([IssuerClaim.name], ["iss"])

        XCTAssertTrue(IssuerClaim("a").verify("a"))
        XCTAssertFalse(IssuerClaim("a").verify("b"))
    }

    func testJWTIDClaim() {
        XCTAssertEqual([JWTIDClaim.name], ["jti"])

        XCTAssertTrue(JWTIDClaim("a").verify("a"))
        XCTAssertFalse(JWTIDClaim("a").verify("b"))
    }

    func testNotBeforeClaim() {
        XCTAssertEqual([NotBeforeClaim.name], ["nbf"])

        let claim = NotBeforeClaim(date, leeway: 1)

        XCTAssertTrue(claim.verify(Node(date.timeIntervalSince1970)))
        XCTAssertTrue(claim.verify(Node(date.timeIntervalSince1970 + 1)))
        XCTAssertFalse(claim.verify(Node(date.timeIntervalSince1970 + 2)))
    }

    func testSubjectClaim() {
        XCTAssertEqual([SubjectClaim.name], ["sub"])

        XCTAssertTrue(SubjectClaim("a").verify("a"))
        XCTAssertFalse(SubjectClaim("a").verify("b"))
    }

    static var all = [
        testMissingClaim,
        testFailingClaim,
        testValidClaim,
        testMultipleValidClaims,
        testMixedClaims,
        testVerifyInvalidPayloadFails,
        testAudienceClaim,
        testExpirationTimeClaim,
        testIssuedAtClaim,
        testIssuerClaim,
        testJWTIDClaim,
        testNotBeforeClaim,
        testSubjectClaim,
        ]
}
