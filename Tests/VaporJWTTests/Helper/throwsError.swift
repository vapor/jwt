@testable import VaporJWT

func throwsError<T>(_ expected: JWTError, for expression: @autoclosure () throws -> T) -> Bool {
    do {
        _ = try expression()
    } catch {
        return (error as? JWTError) == expected
    }
    return false
}

func doesNotThrow(_ expression: @autoclosure () throws -> Bool) -> Bool {
    do {
        return try expression()
    } catch {
        return false
    }
}
