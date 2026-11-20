import Foundation
import XCTest
@testable import LicenseRail

final class VectorTests: XCTestCase {
    private func load(_ name: String) throws -> [String: Any] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../../test-vectors/\(name)").standardized
        return try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    }

    private func fp(_ d: [String: Any]) -> Fingerprint {
        Fingerprint(machineId: d["machineId"] as! String, diskId: d["diskId"] as! String, hostName: d["hostName"] as! String,
                    boardId: d["boardId"] as! String, os: d["os"] as? String)
    }

    func testTokens() throws {
        let v = try load("tokens.json")
        let key = try Licensing.publicKey(pem: v["publicKeyPem"] as! String)
        for case let c as [String: Any] in v["cases"] as! [Any] {
            let expect = c["expect"] as! [String: Any]
            let p = Licensing.verify(token: c["token"] as! String, key: key)
            XCTAssertEqual(p != nil, expect["signatureValid"] as! Bool, c["name"] as! String)
            if let payload = expect["payload"] as? [String: Any], let p {
                XCTAssertEqual(p.product, payload["product"] as? String)
                XCTAssertEqual(p.customer, payload["customer"] as? String)
                XCTAssertEqual(p.entitlements, payload["entitlements"] as? [String] ?? [])
            }
        }
    }

    func testFingerprint() throws {
        for case let c as [String: Any] in try load("fingerprint.json")["cases"] as! [Any] {
            XCTAssertEqual(Licensing.hashComponent(product: c["product"] as! String, part: c["part"] as! String, raw: c["raw"] as? String), c["hash"] as! String)
        }
    }

    func testMatch() throws {
        for case let c as [String: Any] in try load("match.json")["cases"] as! [Any] {
            XCTAssertEqual(fp(c["registered"] as! [String: Any]).matches(fp(c["presented"] as! [String: Any])), c["matches"] as! Bool, c["name"] as! String)
        }
    }

    func testEvaluate() throws {
        let v = try load("evaluate.json")
        let key = try Licensing.publicKey(pem: v["publicKeyPem"] as! String)
        for case let c as [String: Any] in v["cases"] as! [Any] {
            let s = Licensing.evaluate(Licensing.verify(token: c["token"] as! String, key: key), product: c["product"] as! String,
                                       machine: fp(c["machine"] as! [String: Any]), now: Licensing.date(c["now"])!, lastSeen: Licensing.date(c["lastSeen"]))
            XCTAssertEqual(s.rawValue, c["status"] as! String, c["name"] as! String)
        }
    }
}
