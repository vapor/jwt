extension DataProtocol {
    func copyBytes() -> [UInt8] {
        if let array = self.withContiguousStorageIfAvailable({ buffer in
            return [UInt8](buffer)
        }) {
            return array
        } else {
            var buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: self.count)
            self.copyBytes(to: buffer)
            defer { buffer.deallocate() }
            return [UInt8](buffer)
        }
    }
}



extension UInt8 {
    static var period: UInt8 {
        return Character(".").asciiValue!
    }
}

// pointer hacks

func convert(_ pointer: OpaquePointer) -> OpaquePointer {
    return pointer
}

func convert<T>(_ pointer: UnsafePointer<T>) -> OpaquePointer {
    return .init(pointer)
}

func convert<T>(_ pointer: UnsafeMutablePointer<T>) -> OpaquePointer {
    return .init(pointer)
}

func convert<T>(_ pointer: OpaquePointer) -> UnsafePointer<T> {
    return .init(pointer)
}

func convert<T>(_ pointer: OpaquePointer) -> UnsafeMutablePointer<T> {
    return .init(pointer)
}
