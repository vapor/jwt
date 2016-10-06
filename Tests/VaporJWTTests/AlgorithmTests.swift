@testable import VaporJWT
import XCTest

final class AlgorithmTests: XCTestCase {

    func testHeaderKeys() {
        let all: [Algorithm] = [
            .none,
            .hs(._256("")),
            .hs(._384("")),
            .hs(._512("")),
            .es(._256("")),
            .es(._384("")),
            .es(._512(""))
        ]
        XCTAssertEqual(all.map { $0.headerValue }, [
            "none",
            "HS256",
            "HS384",
            "HS512",
            "ES256",
            "ES384",
            "ES512"
            ])
    }

    func testEmptyAlgorithm() {
        XCTAssertTrue(throwsError(
            .unsupportedAlgorithm,
            for: try Algorithm("", key: "")))
    }

    func testInvalidAlgorithm() {
        XCTAssertTrue(throwsError(
            .unsupportedAlgorithm,
            for: try Algorithm("AB256", key: "")))
    }

    func testInvalidHashSize() {
        XCTAssertTrue(throwsError(
            .unsupportedAlgorithm,
            for: try Algorithm("ES123", key: "")))
    }

    static var all = [
        testHeaderKeys,
        testEmptyAlgorithm,
        testInvalidAlgorithm,
        testInvalidHashSize,
    ]
}
