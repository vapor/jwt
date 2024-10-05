import Vapor

extension ByteBuffer {
    var string: String {
        .init(decoding: self.readableBytesView, as: UTF8.self)
    }
}
