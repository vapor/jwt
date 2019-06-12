// swift-tools-version:5.0
import PackageDescription

let package = Package(
    name: "jwt-kit",
    products: [
        .library(name: "JWTKit", targets: ["JWTKit"]),
    ],
    dependencies: [ ],
    targets: [
        .systemLibrary(
            name: "CJWTKitOpenSSL",
            pkgConfig: "openssl",
            providers: [
                .apt(["openssl libssl-dev"]),
                .brew(["openssl@1.1"])
            ]
        ),
        .target(name: "JWTKit", dependencies: ["CJWTKitOpenSSL"]),
        .testTarget(name: "JWTKitTests", dependencies: ["JWTKit"]),
    ]
)
