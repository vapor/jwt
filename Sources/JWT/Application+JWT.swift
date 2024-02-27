import JWTKit
import Vapor
import NIOConcurrencyHelpers

public extension Application {
    var jwt: JWT {
        .init(_application: self)
    }

    struct JWT: Sendable {
        private final class Storage: Sendable {
            private struct SendableBox: Sendable {
                var keys: JWTKeyCollection
            }
            
            private let sendableBox: NIOLockedValueBox<SendableBox>
            
            var keys: JWTKeyCollection {
                get {
                    self.sendableBox.withLockedValue { box in
                        box.keys
                    }
                }
                set {
                    self.sendableBox.withLockedValue { box in
                        box.keys = newValue
                    }
                }
            }
            
            init() {
                let box = SendableBox(keys: .init())
                self.sendableBox = .init(box)
            }
        }

        private struct Key: StorageKey {
            typealias Value = Storage
        }

        public let _application: Application

        public var keys: JWTKeyCollection {
            get { self.storage.keys }
            set { self.storage.keys = newValue }
        }

        private var storage: Storage {
            if let existing = self._application.storage[Key.self] {
                return existing
            } else {
                let new = Storage()
                self._application.storage[Key.self] = new
                return new
            }
        }
    }
}
