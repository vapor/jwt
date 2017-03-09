import PackageDescription

let package = Package(
    name: "JWT",
    dependencies: [
        .Package(url: "https://github.com/vapor/crypto.git", Version(2,0,0, prereleaseIdentifiers: ["alpha"])),
        .Package(url: "https://github.com/vapor/json.git", Version(2,0,0, prereleaseIdentifiers: ["alpha"]))
    ],
    exclude: [
        "Playground"
    ]
)
