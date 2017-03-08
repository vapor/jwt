@testable import JWT
import Foundation
import Node
import XCTest

public let EmptyNode = Node.object([:])

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
        XCTAssertThrowsError(
            try EmptyNode.verifyClaims([TestClaim(verified: true)])
        ) {
            guard let error = $0 as? JWTError, case .missingClaim(withName: let name) = error else {
                XCTFail("Wrong error: \($0)")
                return
            }
            XCTAssertEqual(name, TestClaim.name)
        }
    }

    func testFailingClaim() {
        XCTAssertThrowsError(
            try Node(["tst": ""]).verifyClaims([TestClaim(verified: false)])
        ) {
            guard let error = $0 as? JWTError, case .verificationFailedForClaim(withName: let name) = error else {
                XCTFail("Wrong error: \($0)")
                return
            }
            XCTAssertEqual(name, TestClaim.name)
        }
    }

    func testValidClaim() throws {
        let claims = [TestClaim(verified: true)]
        try Node(["tst": ""]).verifyClaims(claims)
    }

    func testMultipleValidClaims() throws {
        let claims = [TestClaim(verified: true), TestClaim(verified: true)]
        try Node(["tst": ""]).verifyClaims(claims)
    }

    func testMixedClaims() {
        let claims = [TestClaim(verified: true), TestClaim(verified: false)]
        XCTAssertThrowsError(
            try Node(["tst": ""]).verifyClaims(claims)
        ) {
            guard let error = $0 as? JWTError, case .verificationFailedForClaim(withName: let name) = error else {
                XCTFail("Wrong error: \($0)")
                return
            }
            XCTAssertEqual(name, TestClaim.name)
        }
    }

    func testVerifyInvalidPayloadFails() {
        XCTAssertThrowsError(
            try Node(.string("")).verifyClaims([])
        ) {
            guard let error = $0 as? JWTError, case .incorrectPayloadForClaimVerification = error else {
                XCTFail("Wrong error: \($0)")
                return
            }
        }
    }

    func testAudienceClaim() {
        XCTAssertEqual([AudienceClaim.name], ["aud"])
        XCTAssertTrue(AudienceClaim(string: "a").verify("a"))
        XCTAssertFalse(AudienceClaim(string: "a").verify("b"))
        XCTAssertTrue(AudienceClaim(strings: ["a", "b"]).verify("b"))
        XCTAssertFalse(AudienceClaim(strings: ["a", "b"]).verify("c"))
        XCTAssertTrue(AudienceClaim(strings: ["a", "b", "c"]).verify(["b", "c"]))
        XCTAssertFalse(AudienceClaim(strings: ["a", "b", "c"]).verify(["c", "d"]))
    }

    func testExpirationTimeClaim() {
        XCTAssertEqual([ExpirationTimeClaim.name], ["exp"])

        let claim = ExpirationTimeClaim(date: date, leeway: 1)

        XCTAssertTrue(claim.verify(Node(date.timeIntervalSince1970)))
        XCTAssertTrue(claim.verify(Node(date.timeIntervalSince1970 - 1)))
        XCTAssertFalse(claim.verify(Node(date.timeIntervalSince1970 - 2)))
    }

    func testIssuedAtClaim() {
        XCTAssertEqual([IssuedAtClaim.name], ["iat"])

        let claim = IssuedAtClaim(date: date)

        XCTAssertTrue(claim.verify(Node(date.timeIntervalSince1970)))
        XCTAssertFalse(claim.verify(Node(date.timeIntervalSince1970 + 1)))
    }

    func testIssuerClaim() {
        XCTAssertEqual([IssuerClaim.name], ["iss"])

        XCTAssertTrue(IssuerClaim(string: "a").verify("a"))
        XCTAssertFalse(IssuerClaim(string: "a").verify("b"))
    }

    func testJWTIDClaim() {
        XCTAssertEqual([JWTIDClaim.name], ["jti"])

        XCTAssertTrue(JWTIDClaim(string: "a").verify("a"))
        XCTAssertFalse(JWTIDClaim(string: "a").verify("b"))
    }

    func testNotBeforeClaim() {
        XCTAssertEqual([NotBeforeClaim.name], ["nbf"])

        let claim = NotBeforeClaim(date: date, leeway: 1)

        XCTAssertTrue(claim.verify(Node(date.timeIntervalSince1970)))
        XCTAssertTrue(claim.verify(Node(date.timeIntervalSince1970 + 1)))
        XCTAssertFalse(claim.verify(Node(date.timeIntervalSince1970 + 2)))
    }

    func testSubjectClaim() {
        XCTAssertEqual([SubjectClaim.name], ["sub"])

        XCTAssertTrue(SubjectClaim(string: "a").verify("a"))
        XCTAssertFalse(SubjectClaim(string: "a").verify("b"))
    }

    static let all = [
        ("testMissingClaim", testMissingClaim),
        ("testFailingClaim", testFailingClaim),
        ("testValidClaim", testValidClaim),
        ("testMultipleValidClaims", testMultipleValidClaims),
        ("testMixedClaims", testMixedClaims),
        ("testVerifyInvalidPayloadFails", testVerifyInvalidPayloadFails),
        ("testAudienceClaim", testAudienceClaim),
        ("testExpirationTimeClaim", testExpirationTimeClaim),
        ("testIssuedAtClaim", testIssuedAtClaim),
        ("testIssuerClaim", testIssuerClaim),
        ("testJWTIDClaim", testJWTIDClaim),
        ("testNotBeforeClaim", testNotBeforeClaim),
        ("testSubjectClaim", testSubjectClaim),
    ]
}
