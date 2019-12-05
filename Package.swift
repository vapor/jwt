// swift-tools-version:5.1
import PackageDescription

let package = Package(
    name: "jwt",
    platforms: [
       .macOS(.v10_14)
    ],
    products: [
        .library(name: "JWT", targets: ["JWT"]),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/jwt-kit.git", .branch("master")),
        .package(url: "https://github.com/vapor/vapor.git", .branch("master")),
    ],
    targets: [
        .target(name: "JWT", dependencies: ["JWTKit", "Vapor"]),
        .testTarget(name: "JWTTests", dependencies: ["JWT", "XCTVapor"]),
    ]
)
