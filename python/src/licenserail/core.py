"""Offline license logic shared by every LicenseRail SDK (see the test vectors)."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

UNAVAILABLE = "none"
CLOCK_TOLERANCE = timedelta(minutes=10)
ISSUED_AT_TOLERANCE = timedelta(days=1)

#: Error codes on which the local license is deleted; others (network, 402...) keep it.
REVOKING_CODES = frozenset({
    "license_not_found", "license_suspended", "license_expired", "activation_revoked", "wrong_machine", "invalid_token",
    "license_revoked",
})

STATUSES = ("Valid", "Missing", "InvalidSignature", "WrongProduct", "WrongMachine", "Expired", "OfflineTooLong",
            "ClockTampered", "Unverified", "Suspended")


@dataclass(frozen=True)
class Fingerprint:
    machine_id: str
    disk_id: str
    host_name: str
    board_id: str
    os: Optional[str] = None

    @staticmethod
    def from_json(d: dict) -> "Fingerprint":
        return Fingerprint(d.get("machineId", ""), d.get("diskId", ""), d.get("hostName", ""), d.get("boardId", ""), d.get("os"))

    def to_json(self) -> dict:
        d = {"machineId": self.machine_id, "diskId": self.disk_id, "hostName": self.host_name, "boardId": self.board_id}
        if self.os:
            d["os"] = self.os
        return d


def _b64url_decode(text: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", text) or len(text) % 4 == 1:
        raise ValueError("invalid base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def load_public_key(pem: str) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("not an EC public key")
    return key


def verify_token(token: str, public_key: Any) -> Optional[dict]:
    """Verifies the ECDSA P-256 / SHA-256 signature (IEEE P1363 r||s) and returns the payload dict, or None."""
    if not token or not isinstance(token, str):
        return None
    parts = token.strip().split(".")
    if len(parts) != 2:
        return None
    try:
        key = load_public_key(public_key) if isinstance(public_key, str) else public_key
        signature = _b64url_decode(parts[1])
        if len(signature) != 64:
            return None
        der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
        key.verify(der, parts[0].encode("ascii"), ec.ECDSA(hashes.SHA256()))
        payload = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        return payload if isinstance(payload, dict) and "fingerprint" in payload else None
    except (InvalidSignature, ValueError, binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
        return None


def hash_component(product: str, part: str, raw: Optional[str]) -> str:
    """hex(SHA256("codeo:" + product + ":" + part + ":" + upper(trim(raw)))); blank -> "none"."""
    if raw is None or raw.strip() == "":
        return UNAVAILABLE
    return hashlib.sha256(f"codeo:{product}:{part}:{raw.strip().upper()}".encode("utf-8")).hexdigest()


def _available(v: Optional[str]) -> bool:
    return bool(v) and v != UNAVAILABLE


def _same(a: Optional[str], b: Optional[str]) -> bool:
    return _available(a) and a == b


def fingerprint_matches(registered: Fingerprint, presented: Fingerprint) -> bool:
    if registered.os and presented.os and registered.os.lower() != presented.os.lower():
        return False
    matches = sum(1 for a, b in ((registered.machine_id, presented.machine_id), (registered.disk_id, presented.disk_id),
                                 (registered.host_name, presented.host_name)) if _same(a, b))
    if _available(registered.board_id):
        return _same(registered.board_id, presented.board_id) and matches >= 1
    return matches >= 2


def parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    # .NET writes up to 7 fractional digits; Python accepts 6.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    dt = datetime.fromisoformat(text)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def evaluate(payload: Optional[dict], product: str, machine: Fingerprint, now: datetime, last_seen: Optional[datetime]) -> str:
    if not payload:
        return "InvalidSignature"
    if str(payload.get("product", "")).lower() != product.lower():
        return "WrongProduct"
    if not fingerprint_matches(Fingerprint.from_json(payload["fingerprint"]), machine):
        return "WrongMachine"
    if payload.get("suspended"):
        return "Suspended"
    if last_seen is None:
        return "Unverified"
    if now + ISSUED_AT_TOLERANCE < parse_time(payload["issuedAt"]) or now + CLOCK_TOLERANCE < last_seen:
        return "ClockTampered"
    expires = parse_time(payload.get("expiresAt"))
    if expires is not None and now >= expires:
        return "Expired"
    if now >= parse_time(payload["offlineUntil"]):
        return "OfflineTooLong"
    return "Valid"


def _history_mac(ms: str, product: str, machine: Fingerprint) -> str:
    key = hashlib.sha256(f"codeo-run-history:{product}:{machine.machine_id}:{machine.board_id}".encode()).digest()
    return hmac.new(key, ms.encode(), hashlib.sha256).hexdigest()[:32].upper()


def encode_run_history(at: datetime, product: str, machine: Fingerprint) -> str:
    ms = str(int(at.timestamp() * 1000))
    return f"{ms}.{_history_mac(ms, product, machine)}"


def decode_run_history(value: Optional[str], product: str, machine: Fingerprint) -> Optional[datetime]:
    if not value:
        return None
    parts = value.strip().split(".")
    if len(parts) != 2 or not re.fullmatch(r"\d{1,15}", parts[0]):
        return None
    if not hmac.compare_digest(parts[1], _history_mac(parts[0], product, machine)):
        return None
    return datetime.fromtimestamp(int(parts[0]) / 1000, tz=timezone.utc)
