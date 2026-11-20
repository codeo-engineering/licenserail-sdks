import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from licenserail.core import Fingerprint, evaluate, fingerprint_matches, hash_component, parse_time, verify_token  # noqa: E402

VECTORS = pathlib.Path(__file__).resolve().parents[2] / "test-vectors"


def load(name):
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


class Vectors(unittest.TestCase):
    def test_tokens(self):
        v = load("tokens.json")
        for c in v["cases"]:
            payload = verify_token(c["token"], v["publicKeyPem"])
            self.assertEqual(payload is not None, c["expect"]["signatureValid"], c["name"])
            for k, val in (c["expect"].get("payload") or {}).items():
                self.assertEqual(payload.get(k), val, f"{c['name']}: {k}")

    def test_fingerprint(self):
        for c in load("fingerprint.json")["cases"]:
            self.assertEqual(hash_component(c["vendor"], c["product"], c["part"], c["raw"]), c["hash"], c)

    def test_match(self):
        for c in load("match.json")["cases"]:
            self.assertEqual(fingerprint_matches(Fingerprint.from_json(c["registered"]), Fingerprint.from_json(c["presented"])), c["matches"], c["name"])

    def test_evaluate(self):
        v = load("evaluate.json")
        for c in v["cases"]:
            status = evaluate(verify_token(c["token"], v["publicKeyPem"]), c["product"], Fingerprint.from_json(c["machine"]),
                              parse_time(c["now"]), parse_time(c["lastSeen"]))
            self.assertEqual(status, c["status"], c["name"])


if __name__ == "__main__":
    unittest.main()
