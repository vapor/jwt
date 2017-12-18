#
#  Be sure to run `pod spec lint UserTrackingButton.podspec' to ensure this is a
#  valid spec and to remove all comments including this before submitting the spec.
#
#  To learn more about Podspec attributes see http://docs.cocoapods.org/specification.html
#  To see working Podspecs in the CocoaPods repo see https://github.com/CocoaPods/Specs/
#

Pod::Spec.new do |s|

  s.name         = "JWT"
  s.version      = "2.3.0"
  s.summary      = ""

  s.description  = <<-DESC
                   # JWT

                   An implementation of JWT - https://jwt.io/ - for swift
 
                   ## Installation

                   #### Carthage

                   ...

                   #### Cocoapods

                   Add `pod 'jwt', :git => 'https://github.com/vapor/jwt.git'` to you `Podfile` and run `pod install`.

                   ## Setup

                   To use JWT

                   ```
                   let token = "eyJhbGciOiJ0aWxkZSJ9.WyJwYXlsb2FkIl0.fmV5SmhiR2NpT2lKMGFXeGtaU0o5Lld5SndZWGxzYjJGa0lsMH4"
        		   let jwt = try JWT(token: token)
                   ```
                   
                   DESC

  s.homepage     = "https://github.com/vapor/jwt.git"

  s.license      = { :type => "MIT", :file => "LICENSE" }

  s.authors            = { "Vapor" => "github@vapor.codes" }
  s.social_media_url   = "http://vapor.codes/"

  s.platform     = :ios, "8.0"
  s.source       = { :git => "https://github.com/vapor/jwt.git", :tag => s.version }
  s.source_files  = "Sources/JWT/*.swift"

  s.requires_arc = false

end
