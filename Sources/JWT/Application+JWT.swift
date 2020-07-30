import Vapor
import JWTKit

extension Application {
    public var jwt: JWT {
        .init(_application: self)
    }

    public struct JWT {
        private final class Storage {
            var signers: JWTSigners
            init() {
                self.signers = .init()
            }
        }

        private struct Key: StorageKey {
            typealias Value = Storage
        }

        public let _application: Application

        public var signers: JWTSigners {
            get { self.storage.signers }
            set { self.storage.signers = newValue }
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
