<p align="center">
    <img 
        src="https://cloud.githubusercontent.com/assets/1049951/22862150/fce4ecbe-f120-11e6-84c6-7a0282f3d015.png" 
        align="center" 
        alt="Form"
        width="349px"
    >
</p>

# JWT

![Swift](http://img.shields.io/badge/swift-3.0-brightgreen.svg)
[![Vapor](https://img.shields.io/badge/Vapor-1.1-green.svg)](http://vapor.codes)
[![Build Status](https://travis-ci.org/siemensikkema/vapor-jwt.svg?branch=master)](https://travis-ci.org/siemensikkema/vapor-jwt)
[![Code Coverage](https://codecov.io/gh/siemensikkema/vapor-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/siemensikkema/vapor-jwt)

JWT is a library for JSON Web Tokens (JWT) designed with the following goals in mind:
- clean API
- native to Vapor
- many features
- highly extensible

## What is a JWT and when should I use it?
A JWT (pronounced *"jot"*) provides a secure way to grant access to a resource based on certain constraints. The constraints are expressed as unencrypted claims and can be used to constrain access to a certain time or audience among other things. Tokens are signed to protect against tampering.

The unencrypted nature of the claims makes it possible for the validity of the token to be evaluated on the client without having access to the private key or having to access the server. When the server receives a JWT (e.g. in the bearer Authorization header), it can quickly reject any invalid tokens without having to do a database lookup.

The structure of a JWT is `base64Encoded(headerJSON).base64Encoded(payloadJSON).signature`.

## Installation (Swift package manager)

Add the following package to `Package.swift`
```swift
.Package(url:"https://github.com/vapor/jwt.git", majorVersion: 0, minor: 6)
```

## Usage
For detailed info on how to use this library see the [tests](https://github.com/vapor/jwt/tree/master/Tests/JWTTests) and, if you run macOS, the [included playground](https://github.com/vapor/jwt/tree/master/Playground).

### Playground
To run the playground:
* run `vapor xcode`
* open the workspace 'Playground/JWT.xcworkspace' in Xcode
* select the playground
* build the 'JWT' scheme

### Create a new token
Import the library:
```swift
import JWT
```
Create an signed token that expires 1 minute from now.
```swift
let jwt = try JWT(payload: Node(ExpirationTimeClaim(Date() + 60)),
                  signer: HS256(key: "secret"))
let token = try jwt.createToken()
```
JWT creates default headers (*"typ"* and *"alg"*) when none are provided. JWT provides convenient ways to configure a JWT with custom headers and claims. For full control you can set the headers and payload as `Node`s.
```swift
let jwt = try JWT(headers: Node(["my": .string("header")]),
                  payload: Node(["user_id": .number(.int(42))]),
                  signer: Unsigned())
```

### Validate an existing token string
```swift
let jwt3 = try JWT(token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67/QGs52AzC8Ru8=")
let isValid = try jwt3.verifySignature(using: HS256(key: "secret"))
```

## Signing support
JWT supports HMAC, ECDSA, and RSA signing. The available signers are:
* HS256
* HS284
* HS512
* ES256
* ES384
* ES512
* RS256
* RS384
* RS512

The HMAC (HS\*) signers take the same private key for both signing and verifying. The ECDSA and RSA (ES\*/RS\*) signers on the other hand take a private key for signing and a matching public key for verifying.

### Creating ECDSA keys

Create a new key pair for ES256:
```
openssl ecparam -name prime256v1 -genkey | openssl ec -in /dev/stdin -noout -text
```

(For the ES384 signer substitute `prime256v1` with `secp384r1` and for ES512 use `secp521r1`.)

The output will be something like:
```
read EC key
Private-Key: (256 bit)
priv:
    30:04:6d:98:63:e4:4c:8c:b2:37:88:c4:bc:f3:c2:
    5c:f9:5e:f1:d8:d3:69:81:96:ed:0f:54:d1:53:66:
    1f:7c
pub:
    04:01:b8:4e:8e:76:1d:b3:bf:76:c5:f4:61:8f:58:
    38:d6:93:db:72:3c:32:5e:43:d6:64:95:75:43:da:
    7d:0d:00:38:53:b1:16:c6:89:56:56:08:f1:09:35:
    5f:9d:7f:16:5d:40:f7:d0:13:ff:b1:ae:47:ec:b6:
    04:48:7c:4f:92
ASN1 OID: prime256v1
```
#### Extracting the keys
For each section ('priv' and 'pub'):
* copy the hex data (don't worry about multiple lines or white space) (eg. "30:04 ... 1f:7c")
* use [this tool](http://tomeko.net/online_tools/hex_to_base64.php) to convert the key to base64

### Creating RSA keys

To generate a 4096 bit private/public key pair for RSA use the following command:
```
openssl genrsa -out private.pem 4096
```
Extract the private key:
```
openssl rsa -in private.pem -outform der -out private.der
openssl base64 -in private.der -out /dev/stdout
```
Extract the public key:
```
openssl rsa -in private.pem -outform der -pubout -out public.der
openssl base64 -in public.der -out /dev/stdout
```

### Custom

Besides the included signers it is possible to create your own by adhering to the `Signer` protocol:

```swift
public protocol Signer {
    var name: String { get }
    func sign(_ message: Bytes) throws -> Bytes
    func verifySignature(_ signature: Bytes, message: Bytes) throws -> Bool
}
```

## Encoding support
By default JWT uses Base64 encoding. A Base64URL encoder/decoder is also available and can be used like so:

```swift
let jwt = try JWT(payload: [],
                  encoding: Base64URLEncoding(),
                  signer: Unsigned())
```
Any custom encoding that adheres to the `Encoding` protocol can be used as well.

```swift
public protocol Encoding {
    func decode(_ : String) throws -> Bytes
    func encode(_ : Bytes) throws -> String
}
```

## Motivation
Existing libraries were pretty great already but I wanted a more extensible library that felt native to Vapor. I also wanted better encryption support, with ES256 in particular because it is needed by for Apple's new [token based push notifications](https://developer.apple.com/library/content/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/ApplePushService.html#//apple_ref/doc/uid/TP40008194-CH100-SW11), see [VaporAPNS](https://github.com/matthijs2704/vapor-apns).

## Roadmap
See [the project board](https://github.com/vapor/jwt/projects/1).

## Contribute
Yes please! Issues and pull requests are more than welcome.

## Resources / Acknowledgements
* https://github.com/kylef/JSONWebToken.swift
* http://davidederosa.com/basic-blockchain-programming/elliptic-curve-keys/
* http://davidederosa.com/basic-blockchain-programming/elliptic-curve-digital-signatures/
* https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25
* https://kjur.github.io/jsrsasign/sample-ecdsa.html

## Author

Siemen Sikkema - https://github.com/siemensikkema
