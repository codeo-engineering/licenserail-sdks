import CryptoKit
import Foundation
#if canImport(IOKit)
import IOKit
#endif
#if canImport(UIKit)
import UIKit
#endif

public struct ActivationResult {
    public let success: Bool
    public let errorCode: String?
    public let message: String
}

public struct CheckResult {
    public let status: LicenseStatus
    public let license: LicensePayload?
    public var isValid: Bool { status == .valid }
}

/// Licensing for macOS and iOS apps. Needs only the public key; never ship an API key.
public final class LicenseClient {
    public struct Options {
        public var serverURL: URL
        /// Your organization ID from the dashboard (ten_...; part of every device identity).
        public var vendor: String
        public var product: String
        public var appVersion: String?
        public var publicKeyPEM: String
        public var storageDirectory: URL?
        public var refreshOnStartup = false
        public var fingerprint: Fingerprint?

        public init(serverURL: URL, vendor: String, product: String, appVersion: String? = nil, publicKeyPEM: String, storageDirectory: URL? = nil,
                    refreshOnStartup: Bool = false, fingerprint: Fingerprint? = nil) {
            self.serverURL = serverURL; self.vendor = vendor; self.product = product; self.appVersion = appVersion; self.publicKeyPEM = publicKeyPEM
            self.storageDirectory = storageDirectory; self.refreshOnStartup = refreshOnStartup; self.fingerprint = fingerprint
        }
    }

    private let options: Options
    private let key: P256.Signing.PublicKey
    private let dir: URL
    private lazy var fp: Fingerprint = options.fingerprint ?? LicenseClient.collectFingerprint(vendor: options.vendor, product: options.product)
    public private(set) var lastServerMessage: String?

    public init(options: Options) throws {
        self.options = options
        key = try Licensing.publicKey(pem: options.publicKeyPEM)
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first ?? FileManager.default.temporaryDirectory
        dir = options.storageDirectory ?? base.appendingPathComponent("licenserail/\(options.product)", isDirectory: true)
    }

    public var license: LicensePayload? { read("license.lic").flatMap { Licensing.verify(token: $0, key: key) } }

    public func evaluateLocal() -> CheckResult {
        guard let token = read("license.lic") else { return CheckResult(status: .missing, license: nil) }
        let p = Licensing.verify(token: token, key: key)
        let last = decodeHistory(read("license.seen"))
        let now = Date()
        let s = Licensing.evaluate(p, product: options.product, machine: fp, now: now, lastSeen: last)
        if [.valid, .expired, .offlineTooLong].contains(s), last.map({ now > $0 }) ?? true { write("license.seen", encodeHistory(now)) }
        return CheckResult(status: s, license: p)
    }

    /// Call on startup: evaluates offline, refreshes online when due or when only the server can clear the state.
    public func check() async -> CheckResult {
        var r = evaluateLocal()
        let due = r.isValid && (options.refreshOnStartup || Date() >= r.license!.refreshAfter)
        if due || [.expired, .suspended, .offlineTooLong, .clockTampered, .unverified].contains(r.status) {
            let anomalies: [String]? = r.status == .clockTampered ? ["clock_rollback"] : r.status == .unverified ? ["history_missing"] : nil
            try? await refresh(anomalies: anomalies)
            r = evaluateLocal()
        }
        if r.license?.isTest == true { print("[licenserail] Test license: not for production use.") }
        return r
    }

    public func activate(licenseKey: String, machineName: String? = nil) async -> ActivationResult {
        let k = licenseKey.trimmingCharacters(in: .whitespaces)
        guard !k.isEmpty else { return ActivationResult(success: false, errorCode: "bad_request", message: "Enter the license key.") }
        var body: [String: Any] = ["licenseKey": k, "product": options.product, "fingerprint": fpJSON(),
                                   "machineName": machineName ?? ProcessInfo.processInfo.hostName]
        body["appVersion"] = options.appVersion
        do {
            var (ok, data) = try await post("/api/client/v2/activate", body)
            if !ok, data["code"] as? String == "bad_request", (data["message"] as? String ?? "").lowercased().contains("floating") {
                (ok, data) = try await post("/api/client/v2/floating/checkout", body)
            }
            guard ok else { return ActivationResult(success: false, errorCode: data["code"] as? String, message: data["message"] as? String ?? "Server error.") }
            guard saveIfValid(data["token"] as? String ?? "") else {
                return ActivationResult(success: false, errorCode: "invalid_token", message: "The server returned an invalid license.")
            }
        } catch {
            return ActivationResult(success: false, errorCode: "network", message: "Could not connect to the license server.")
        }
        let r = evaluateLocal()
        return r.isValid ? ActivationResult(success: true, errorCode: nil, message: "The license has been activated.")
            : ActivationResult(success: false, errorCode: r.status.rawValue, message: r.status.rawValue)
    }

    public func deactivate() async -> ActivationResult {
        guard let token = read("license.lic") else { return ActivationResult(success: true, errorCode: nil, message: "There is no license on this device.") }
        let floating = Licensing.verify(token: token, key: key)?.isFloating == true
        do {
            let (ok, data) = try await post(floating ? "/api/client/v2/floating/release" : "/api/client/v2/deactivate", ["token": token, "fingerprint": fpJSON()])
            let code = data["code"] as? String
            if !ok, !Licensing.revokingCodes.contains(code ?? "") {
                return ActivationResult(success: false, errorCode: code, message: data["message"] as? String ?? "Server error.")
            }
            delete("license.lic")
            return ActivationResult(success: true, errorCode: nil, message: "The license has been removed from this device.")
        } catch {
            return ActivationResult(success: false, errorCode: "network", message: "Removing the license needs an internet connection.")
        }
    }

    /// Fresh token now (floating: a heartbeat; call every lease/2 while running).
    public func refresh(anomalies: [String]? = nil) async throws {
        guard let token = read("license.lic") else { return }
        let floating = Licensing.verify(token: token, key: key)?.isFloating == true
        var body: [String: Any] = ["token": token, "fingerprint": fpJSON()]
        body["appVersion"] = options.appVersion
        body["anomalies"] = anomalies
        let (ok, data) = try await post(floating ? "/api/client/v2/floating/heartbeat" : "/api/client/v2/refresh", body)
        let code = data["code"] as? String ?? ""
        if ok { _ = saveIfValid(data["token"] as? String ?? "") }
        else if Licensing.revokingCodes.contains(code) || code == "lease_expired" {
            delete("license.lic")
            lastServerMessage = data["message"] as? String
        }
    }

    private func fpJSON() -> [String: Any] {
        var d: [String: Any] = ["machineId": fp.machineId, "diskId": fp.diskId, "hostName": fp.hostName, "boardId": fp.boardId]
        d["os"] = fp.os
        return d
    }

    private func post(_ path: String, _ body: [String: Any]) async throws -> (Bool, [String: Any]) {
        var req = URLRequest(url: options.serverURL.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        req.timeoutInterval = 10
        let (data, response) = try await URLSession.shared.data(for: req)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        let json = data.isEmpty ? [:] : (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        return (status < 400, json)
    }

    private func saveIfValid(_ token: String) -> Bool {
        guard let p = Licensing.verify(token: token, key: key), p.product.lowercased() == options.product.lowercased() else { return false }
        write("license.lic", token)
        write("license.seen", encodeHistory(Date()))
        return true
    }

    private func encodeHistory(_ at: Date) -> String {
        let ms = String(Int64(at.timeIntervalSince1970 * 1000))
        return "\(ms).\(Licensing.historyMac(ms, vendor: options.vendor, product: options.product, machine: fp))"
    }

    private func decodeHistory(_ v: String?) -> Date? {
        guard let parts = v?.split(separator: "."), parts.count == 2, let ms = Int64(parts[0]),
              String(parts[1]) == Licensing.historyMac(String(parts[0]), vendor: options.vendor, product: options.product, machine: fp) else { return nil }
        return Date(timeIntervalSince1970: Double(ms) / 1000)
    }

    private func read(_ name: String) -> String? {
        (try? String(contentsOf: dir.appendingPathComponent(name), encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
    }

    private func write(_ name: String, _ value: String) {
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try? value.write(to: dir.appendingPathComponent(name), atomically: true, encoding: .utf8)
    }

    private func delete(_ name: String) { try? FileManager.default.removeItem(at: dir.appendingPathComponent(name)) }

    /// macOS: hardware serial (machine), IOPlatformUUID (board), host name. iOS: identifierForVendor (no hardware ids).
    public static func collectFingerprint(vendor: String, product: String) -> Fingerprint {
        #if os(macOS)
        func ioreg(_ key: String) -> String? {
            let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
            defer { IOObjectRelease(service) }
            return IORegistryEntryCreateCFProperty(service, key as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? String
        }
        return Fingerprint(machineId: Licensing.hashComponent(vendor: vendor, product: product, part: "machine", raw: ioreg(kIOPlatformSerialNumberKey)),
                           diskId: Licensing.unavailable,
                           hostName: Licensing.hashComponent(vendor: vendor, product: product, part: "host", raw: ProcessInfo.processInfo.hostName),
                           boardId: Licensing.hashComponent(vendor: vendor, product: product, part: "board", raw: ioreg(kIOPlatformUUIDKey)), os: "macos")
        #elseif canImport(UIKit)
        let installId = UIDevice.current.identifierForVendor?.uuidString
        return Fingerprint(machineId: Licensing.hashComponent(vendor: vendor, product: product, part: "machine", raw: installId), diskId: Licensing.unavailable,
                           hostName: Licensing.hashComponent(vendor: vendor, product: product, part: "host", raw: UIDevice.current.model),
                           boardId: Licensing.unavailable, os: "ios")
        #else
        return Fingerprint(machineId: Licensing.unavailable, diskId: Licensing.unavailable, hostName: Licensing.unavailable, boardId: Licensing.unavailable)
        #endif
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
