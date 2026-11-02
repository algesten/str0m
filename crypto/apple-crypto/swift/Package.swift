// swift-tools-version: 5.7
import PackageDescription

let package = Package(
    name: "Str0mCryptoKit",
    platforms: [.macOS(.v10_15), .iOS(.v13)],
    products: [.library(name: "Str0mCryptoKit", type: .static, targets: ["Str0mCryptoKit"])],
    targets: [.target(name: "Str0mCryptoKit")]
)
