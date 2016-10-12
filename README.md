# VaporJWT

![Swift](http://img.shields.io/badge/swift-3.0-brightgreen.svg)
![Vapor](https://img.shields.io/badge/Vapor-1.0-green.svg)

JWT* implementation for Vapor

\* _pronounced "jot"_

##  Installation (Swift package manager)
Add the following package to `Package.swift`
```swift
.Package(url:"https://github.com/siemensikkema/vapor-jwt.git", majorVersion: 0, minor: 3)
```

## Usage
For detailed info on how to use this library see the [tests](https://github.com/siemensikkema/vapor-jwt/tree/master/Tests/VaporJWTTests) and the [included playground](https://github.com/siemensikkema/vapor-jwt/tree/master/Playground) if you run macOS.

### Playground
To run the playground:
* run `vapor xcode`
* open the workspace 'Playground/VaporJWT.xcworkspace' in Xcode
* select the playground
* build the 'VaporJWT' scheme

### Create a new token
Import the library:
```swift
import VaporJWT
```
Create an signed token that expires 1 minute from now.
```swift
let jwt = try JWT(claims: [ExpirationTimeClaim(Date() + 60)],
                  signer: HS256(key: "secret"))
let token = try jwt.createToken()
```
VaporJWT creates default headers (*"typ"* and *"alg"*) when none are provided. VaporJWT provides convenient ways to configure a JWT with custom headers and claims. For full control you can set the headers and payload as JSON.
```swift
let jwt = try JWT(headers: JSON(["my": .string("header")]),
                  payload: JSON(["user_id": .number(.int(42))]),
                  signer: Unsigned())
```

### Validate an existing token string
```swift
let jwt3 = try JWT(token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67/QGs52AzC8Ru8=")
let isValid = try jwt3.verifySignatureWith(HS256(key: "secret"))
```

## Signing support
VaporJWT currently support HMAC and ECDSA signing. The available signers are:
* HS256
* HS284
* HS512
* ES256
* ES384
* ES512

The HMAC (HS\*) signers take the same private key for both signing and verifying. The ECDSA (ES\*) signers on the other hand take a private key for signing and a matching public key for verifying. A private/public key pair for ECDSA can be generated using the `openssl` command line tool. To create a new key pair for ES256 issue the following command:
```
openssl ecparam -name prime256v1 -genkey | openssl ec -in /dev/stdin -text -noout`
```
The resulting keys should be encoded (eg. using Base64) to enable storing them in a text file. This can be done using this [handy online tool](http://tomeko.net/online_tools/hex_to_base64.php).

Besides the included signers it is possible to create your own by adhering to the `Signer` protocol:

```swift
public protocol Signer {
    var name: String { get }
    func sign(_ message: Bytes) throws -> Bytes
    func verifySignature(_ signature: Bytes, message: Bytes) throws -> Bool
}
```

## Encoding support
By default VaporJWT uses Base64 encoding. A Base64URL encoder/decoder is also available and can be used like so:

```swift
let jwt = try JWT(claims: [],
                  encoding: Base64URLEncoding(),
                  signer: Unsigned())
```
Any custom encoding that adheres to the `Encoding` protocol can be used

```swift
public protocol Encoding {
    func decode(_ : String) throws -> Bytes
    func encode(_ : Bytes) throws -> String
}
```

## Motivation
Existing libraries were pretty great already but I wanted a more extensible library that felt native to Vapor. I also wanted better encryption support, with ES256 in particular because it is needed by for Apple's new [token based push notifications](https://developer.apple.com/library/content/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/ApplePushService.html#//apple_ref/doc/uid/TP40008194-CH100-SW11), see [VaporAPNS](https://github.com/matthijs2704/vapor-apns).

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
