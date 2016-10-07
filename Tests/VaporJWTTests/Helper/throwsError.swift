@testable import VaporJWT
import XCTest

func assert<E: Error>(_ expression: @autoclosure () throws -> Any,
    throws expected: E,
    file: StaticString = #file,
    line: UInt = #line)
    where E: Equatable {
        do {
            _ = try expression()
            XCTFail(file: file, line: line)
        } catch {
            XCTAssertEqual(error as? E, expected, file: file, line: line)
        }
}

