public struct AlgorithmHeader: Header {

    public static let headerKey = "alg"

    public let headerValue: String

    init(signer: Signer) {
        self.headerValue = signer.name
    }
}
