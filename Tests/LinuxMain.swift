import XCTest
@testable import JWTTests

XCTMain([
     testCase(ClaimTests.all),
     testCase(JWTTests.all),
     testCase(SignerTests.all),
])
