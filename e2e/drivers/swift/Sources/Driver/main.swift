import Foundation
import LicenseRail

let e = ProcessInfo.processInfo.environment
let d = (e["LR_DEVICE"] ?? "").split(separator: ",").map(String.init)
let client = try LicenseClient(options: .init(
    serverURL: URL(string: e["LR_URL"]!)!, vendor: e["LR_VENDOR"]!, product: e["LR_PRODUCT"]!, appVersion: "1.2.3",
    publicKeyPEM: try String(contentsOfFile: e["LR_PUBLIC_KEY_FILE"]!, encoding: .utf8),
    storageDirectory: URL(fileURLWithPath: e["LR_STORAGE"]!, isDirectory: true),
    fingerprint: d.count == 4 ? Fingerprint(machineId: d[0], diskId: d[1], hostName: d[2], boardId: d[3], os: "linux") : nil))

func put(_ r: ActivationResult) -> [String: Any] {
    ["success": r.success, "errorCode": r.errorCode ?? "", "message": r.message]
}

let args = CommandLine.arguments
var out: [String: Any]
switch args[1] {
case "activate": out = put(await client.activate(licenseKey: args[2]))
case "deactivate": out = put(await client.deactivate())
case "refresh":
    do {
        try await client.refresh()
        out = ["success": true]
    } catch {
        out = ["success": false, "errorCode": "network", "message": "\(error)"]
    }
default:
    let r = await client.check()
    out = ["status": r.status.rawValue, "features": r.license?.entitlements ?? [], "test": r.license?.isTest ?? false]
}
print(String(data: try JSONSerialization.data(withJSONObject: out), encoding: .utf8)!)
