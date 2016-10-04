import PackageDescription

let package = Package(
    name: "VaporJWT",
    dependencies: [
        .Package(url: "https://github.com/vapor/Crypto.git", majorVersion: 1, minor: 0),
        .Package(url: "https://github.com/vapor/json.git", majorVersion: 1, minor: 0),
    ]
)
