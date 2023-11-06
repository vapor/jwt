import JWTKit
import Vapor

public extension Application {
    var jwt: JWT {
        .init(_application: self)
    }

    struct JWT {
        private final class Storage {
            var keys: JWTKeyCollection
            init() {
                self.keys = .init()
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
