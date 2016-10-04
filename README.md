# VaporJWT

![Swift](http://img.shields.io/badge/swift-3.0-brightgreen.svg)
![Vapor](https://img.shields.io/badge/Vapor-1.0-green.svg)

JWT implementation for Vapor

##  Installation (Swift package manager)
Add the following package to `Package.swift`
```swift
.Package(url:"https://github.com/siemensikkema/vapor-jwt.git", majorVersion: 0)
```

## Usage
Import the library:
```swift
import VaporJWT
```
### Create a new token
```swift
let privateKey = ...
try JWT(payload: JSON(["user_id", .string("1")]), algorithm: .hs(._256(privateKey)))
```
You can optionally add extra header fields like this:
```swift
try JWT(payload: JSON(["user_id", .string("1")]), algorithm: .hs(._256(privateKey)), extraHeaders: ["extra": "header"])
```
### Validate an existing token string
```swift
let jwt = try JWT(token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67/QGs52AzC8Ru8=")
let isValid = jwt.verifySignature(key: "secret)
```

## Motivation
Existing libraries were pretty great already but I wanted a library that felt more native to Vapor by supporting the JSON type for payloads. Further, I wanted better encryption support, with ES256 in particular because it is needed by for Apple's new [token based push notifications](https://developer.apple.com/library/content/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/ApplePushService.html#//apple_ref/doc/uid/TP40008194-CH100-SW11).

## Roadmap
See [the project board](https://github.com/siemensikkema/vapor-jwt/projects/1).

## Contribute
Yes please! Issues and pull requests are more than welcome.

## Resources / Acknowledgements
* https://github.com/kylef/JSONWebToken.swift
* http://davidederosa.com/basic-blockchain-programming/elliptic-curve-keys/
* http://davidederosa.com/basic-blockchain-programming/elliptic-curve-digital-signatures/
* https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25
* https://kjur.github.io/jsrsasign/sample-ecdsa.html
