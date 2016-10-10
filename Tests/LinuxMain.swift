import XCTest
@testable import VaporJWTTests

XCTMain([
     testCase(Base64TranscoderTests.all),
     testCase(ClaimTests.all),
     testCase(EncodingTests.all),
     testCase(JWTTests.all),
     testCase(SignerTests.all),
])
