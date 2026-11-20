import CryptoKit
import Foundation

/// Hashed device components.
public struct Fingerprint: Codable, Equatable {
    public var machineId: String
    public var diskId: String
    public var hostName: String
    public var boardId: String
    public var os: String?

    public init(machineId: String, diskId: String, hostName: String, boardId: String, os: String? = nil) {
        self.machineId = machineId; self.diskId = diskId; self.hostName = hostName; self.boardId = boardId; self.os = os
    }

    /// Whether `presented` is the device this (registered) fingerprint was issued for.
    public func matches(_ presented: Fingerprint) -> Bool {
        if let a = os, let b = presented.os, !a.isEmpty, !b.isEmpty, a.lowercased() != b.lowercased() { return false }
        var n = 0
        if Licensing.same(machineId, presented.machineId) { n += 1 }
        if Licensing.same(diskId, presented.diskId) { n += 1 }
        if Licensing.same(hostName, presented.hostName) { n += 1 }
        return Licensing.available(boardId) ? Licensing.same(boardId, presented.boardId) && n >= 1 : n >= 2
    }
}

/// The signed license content. The raw JSON is kept for metadata and future fields.
public struct LicensePayload {
    public let json: [String: Any]
    public let product: String
    public let customer: String
    public let licenseKey: String
    public let kind: String
    public let expiresAt: Date?
    public let issuedAt: Date
    public let refreshAfter: Date
    public let offlineUntil: Date
    public let fingerprint: Fingerprint
    public let suspended: Bool
    public var entitlements: [String] { json["entitlements"] as? [String] ?? [] }
    public var metadata: [String: Any] { json["metadata"] as? [String: Any] ?? [:] }
    public var isTest: Bool { json["test"] as? Bool == true }
    public var isFloating: Bool { json["floating"] as? Bool == true }
    public func hasFeature(_ code: String) -> Bool { entitlements.contains(code) }

    init?(data: Data) {
        guard let j = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let fp = j["fingerprint"] as? [String: Any],
              let product = j["product"] as? String,
              let issued = Licensing.date(j["issuedAt"]), let refresh = Licensing.date(j["refreshAfter"]), let offline = Licensing.date(j["offlineUntil"])
        else { return nil }
        json = j
        self.product = product
        customer = j["customer"] as? String ?? ""
        licenseKey = j["licenseKey"] as? String ?? ""
        kind = j["kind"] as? String ?? ""
        expiresAt = Licensing.date(j["expiresAt"])
        issuedAt = issued; refreshAfter = refresh; offlineUntil = offline
        fingerprint = Fingerprint(machineId: fp["machineId"] as? String ?? "", diskId: fp["diskId"] as? String ?? "",
                                  hostName: fp["hostName"] as? String ?? "", boardId: fp["boardId"] as? String ?? "", os: fp["os"] as? String)
        suspended = j["suspended"] as? Bool ?? false
    }
}

public enum LicenseStatus: String {
    case valid = "Valid", missing = "Missing", invalidSignature = "InvalidSignature", wrongProduct = "WrongProduct", wrongMachine = "WrongMachine"
    case expired = "Expired", offlineTooLong = "OfflineTooLong", clockTampered = "ClockTampered", unverified = "Unverified", suspended = "Suspended"
}

public enum Licensing {
    public static let unavailable = "none"
    public static let revokingCodes: Set<String> = ["license_not_found", "license_suspended", "license_expired", "activation_revoked", "wrong_machine",
                                                    "invalid_token", "license_revoked"]

    static func available(_ v: String) -> Bool { !v.isEmpty && v != unavailable }
    static func same(_ a: String, _ b: String) -> Bool { available(a) && a == b }

    static func date(_ v: Any?) -> Date? {
        guard var s = v as? String else { return nil }
        // .NET writes up to 7 fractional digits; ISO8601DateFormatter reads 3.
        if let r = s.range(of: #"\.\d+"#, options: .regularExpression) {
            let digits = s[r].dropFirst()
            s.replaceSubrange(r, with: "." + String((digits + "000").prefix(3)))
        }
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: s) { return d }
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: s)
    }

    static func base64url(_ s: Substring) -> Data? {
        guard s.allSatisfy({ $0.isLetter && $0.isASCII || $0.isNumber && $0.isASCII || $0 == "-" || $0 == "_" }) else { return nil }
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        return Data(base64Encoded: t)
    }

    public static func publicKey(pem: String) throws -> P256.Signing.PublicKey {
        try P256.Signing.PublicKey(pemRepresentation: pem)
    }

    /// Verifies ECDSA P-256 / SHA-256 (IEEE P1363 r||s) over the ASCII encoded body; returns the payload or nil.
    public static func verify(token: String, key: P256.Signing.PublicKey) -> LicensePayload? {
        let parts = token.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2, let sigData = base64url(parts[1]), sigData.count == 64, let body = base64url(parts[0]),
              let sig = try? P256.Signing.ECDSASignature(rawRepresentation: sigData),
              key.isValidSignature(sig, for: Data(parts[0].utf8)) else { return nil }
        return LicensePayload(data: body)
    }

    /// hex(SHA256(vendor + ":" + product + ":" + part + ":" + upper(trim(raw)))); blank gives "none".
    /// `vendor` is the organization ID (ten_..., never changes).
    public static func hashComponent(vendor: String, product: String, part: String, raw: String?) -> String {
        guard let t = raw?.trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty else { return unavailable }
        let digest = SHA256.hash(data: Data("\(vendor):\(product):\(part):\(t.uppercased(with: Locale(identifier: "en_US_POSIX")))".utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// The offline check (identical in every SDK).
    public static func evaluate(_ p: LicensePayload?, product: String, machine: Fingerprint, now: Date, lastSeen: Date?) -> LicenseStatus {
        guard let p else { return .invalidSignature }
        if p.product.lowercased() != product.lowercased() { return .wrongProduct }
        if !p.fingerprint.matches(machine) { return .wrongMachine }
        if p.suspended { return .suspended }
        guard let seen = lastSeen else { return .unverified }
        if now.addingTimeInterval(86_400) < p.issuedAt || now.addingTimeInterval(600) < seen { return .clockTampered }
        if let e = p.expiresAt, now >= e { return .expired }
        if now >= p.offlineUntil { return .offlineTooLong }
        return .valid
    }

    static func historyMac(_ ms: String, vendor: String, product: String, machine: Fingerprint) -> String {
        let key = SymmetricKey(data: SHA256.hash(data: Data("\(vendor):run-history:\(product):\(machine.machineId):\(machine.boardId)".utf8)))
        let mac = HMAC<SHA256>.authenticationCode(for: Data(ms.utf8), using: key)
        return String(mac.map { String(format: "%02X", $0) }.joined().prefix(32))
    }
}
