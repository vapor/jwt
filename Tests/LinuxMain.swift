import XCTest
@testable import JWTTests

XCTMain([
     testCase(ClaimTests.all),
     testCase(EncodingTests.all),
     testCase(JWTTests.all),
     testCase(SignerTests.all),
])
