import Testing
import Vapor

func withApp<ReturnType>(_ body: (Application) async throws -> ReturnType) async throws -> ReturnType {
    let app = try await Application.make(.testing)
    try #require(isLoggingConfigured == true)
    let result = try await body(app)
    try await app.asyncShutdown()
    return result
}
