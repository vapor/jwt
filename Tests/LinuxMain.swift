import XCTest
@testable import JWTTests

XCTMain([
    testCase(JWTTests.allTests),
    testCase(JWKTests.allTests)    
])
