import Vapor

extension JWTError: @retroactive AbortError {
    public var status: HTTPResponseStatus {
        .unauthorized
    }

    @_implements(AbortError,reason) public var abortErrorReason: String {
        self.reason ?? self.description
    }
}
