import Vapor

extension JWTError: @retroactive AbortError {
    public var status: HTTPResponseStatus {
        .unauthorized
    }
}
