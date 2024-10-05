import Testing
import Vapor

func withApp(_ body: (Application) async throws -> Void) async throws {
    let app = try await Application.make(.testing)
    try #require(isLoggingConfigured == true)
    try await body(app)
    try await app.asyncShutdown()
}
