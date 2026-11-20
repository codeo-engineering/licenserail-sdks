// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "LicenseRail",
    platforms: [.macOS(.v12), .iOS(.v15)],
    products: [.library(name: "LicenseRail", targets: ["LicenseRail"])],
    targets: [
        .target(name: "LicenseRail"),
        .testTarget(name: "LicenseRailTests", dependencies: ["LicenseRail"]),
    ]
)
