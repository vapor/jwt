// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "JWT",
    products: [
    	.library(name: "JWT", targets: ["JWT"]),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/crypto.git", .upToNextMajor(from: "2.0.0")),
        .package(url: "https://github.com/vapor/json.git", .upToNextMajor(from: "2.0.0")),
    ],
    targets: [
    	.target(name: "JWT", dependencies: ["Crypto", "JSON"]),
    	.testTarget(name: "JWTTests", dependencies: ["JWT"]),
    ]
)
