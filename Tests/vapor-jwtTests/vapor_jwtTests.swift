import XCTest
@testable import vapor_jwt

class vapor_jwtTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        XCTAssertEqual(vapor_jwt().text, "Hello, World!")
    }


    static var allTests : [(String, (vapor_jwtTests) -> () throws -> Void)] {
        return [
            ("testExample", testExample),
        ]
    }
}
