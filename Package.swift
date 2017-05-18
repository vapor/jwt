import PackageDescription

let package = Package(
    name: "JWT",
    dependencies: [
        .Package(url: "https://github.com/vapor/crypto.git", majorVersion: 2),
        .Package(url: "https://github.com/vapor/json.git", majorVersion: 2),
    ],
    exclude: [
        "Playground"
    ]
)
