import Node

public struct AlgorithmHeader: Header {

    public static let name = "alg"
    public let node: Node

    init(signer: Signer) {
        node = .string(signer.name)
    }
}
