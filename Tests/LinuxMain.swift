import XCTest
@testable import VaporJWTTests

XCTMain([
     testCase(AlgorithmTests.all),
     testCase(Base64Tests.all),
     testCase(EncodingTests.all),
     testCase(JWTTests.all),
])
