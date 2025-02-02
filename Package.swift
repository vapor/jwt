// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "jwt",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
    ],
    products: [
        .library(name: "JWT", targets: ["JWT"])
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/jwt-kit.git", from: "5.1.0"),
        .package(url: "https://github.com/vapor/vapor.git", from: "4.110.2"),
    ],
    targets: [
        .target(
            name: "JWT",
            dependencies: [
                .product(name: "JWTKit", package: "jwt-kit"),
                .product(name: "Vapor", package: "vapor"),
            ]
        ),
        .testTarget(
            name: "JWTTests",
            dependencies: [
                .target(name: "JWT"),
                .product(name: "VaporTesting", package: "vapor"),
            ]
        ),
    ]
)
