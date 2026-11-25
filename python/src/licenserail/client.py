"""The licensing client for a vendor's app (no secrets: only the environment's public key)."""
from __future__ import annotations

import http.client
import json
import os
import platform
import re
import socket
import subprocess
import threading
import urllib.error
import urllib.request
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .core import (
    REVOKING_CODES, Fingerprint, decode_run_history, encode_run_history, evaluate, fingerprint_matches, hash_component, load_public_key, parse_time,
    verify_token,
)

MESSAGES = {
    "Valid": "The license is valid.",
    "Missing": "No license is activated on this device.",
    "InvalidSignature": "The license file is invalid. Activate it again.",
    "WrongProduct": "The license is for another product.",
    "WrongMachine": "The license belongs to another device.",
    "Expired": "The license has expired.",
    "OfflineTooLong": "Connect to the internet to verify the license.",
    "ClockTampered": "The device's clock looks wrong. Correct it and connect to the internet.",
    "Unverified": "Connect to the internet to verify the license.",
    "Suspended": "The license has been suspended.",
}


@dataclass
class License:
    payload: dict

    key = property(lambda self: self.payload["licenseKey"])
    customer = property(lambda self: self.payload["customer"])
    kind = property(lambda self: self.payload["kind"])
    expires_at = property(lambda self: parse_time(self.payload.get("expiresAt")))
    offline_until = property(lambda self: parse_time(self.payload["offlineUntil"]))
    is_test = property(lambda self: self.payload.get("test") is True)
    is_floating = property(lambda self: self.payload.get("floating") is True)
    features = property(lambda self: list(self.payload.get("entitlements") or []))
    metadata = property(lambda self: dict(self.payload.get("metadata") or {}))

    def has_feature(self, code: str) -> bool:
        return code in self.features


@dataclass
class CheckResult:
    status: str
    license: Optional[License] = None

    @property
    def valid(self) -> bool:
        return self.status == "Valid"


@dataclass
class ActivationResult:
    success: bool
    message: str
    error_code: Optional[str] = None


def _run(cmd: list[str]) -> Optional[str]:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return None


def _read(path: str) -> Optional[str]:
    try:
        v = Path(path).read_text().strip()
        return v or None
    except OSError:
        return None


def collect_fingerprint(vendor: str, product: str) -> Fingerprint:
    """Hashed device fingerprint (Windows, macOS, Linux)."""
    system = platform.system()
    if system == "Windows":
        reg = _run(["reg", "query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid", "/reg:64"]) or ""
        m = re.search(r"MachineGuid\s+REG_SZ\s+(\S+)", reg)
        vol = _run(["cmd", "/c", "vol", os.environ.get("SystemDrive", "C:")]) or ""
        s = re.search(r"([0-9A-F]{4})-([0-9A-F]{4})", vol, re.I)
        board = (_run(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID"]) or "").strip()
        raw = (m.group(1) if m else None, (s.group(1) + s.group(2)).upper() if s else None, socket.gethostname(), board, "windows")
    elif system == "Darwin":
        io = _run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]) or ""
        uuid = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', io)
        serial = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', io)
        vol = re.search(r"Volume UUID:\s*([0-9A-F-]+)", _run(["diskutil", "info", "/"]) or "", re.I)
        host = (_run(["scutil", "--get", "LocalHostName"]) or "").strip() or socket.gethostname()
        raw = (serial and serial.group(1), vol and vol.group(1), host, uuid and uuid.group(1), "macos")
    else:
        machine = _read("/etc/machine-id") or _read("/var/lib/dbus/machine-id")
        disk = None
        for line in (_read("/proc/self/mountinfo") or "").splitlines():
            f = line.split(" ")
            if len(f) > 4 and f[4] == "/" and "-" in f:
                disk = (_run(["blkid", "-s", "UUID", "-o", "value", f[f.index("-") + 2]]) or "").strip() or None
                break
        raw = (machine, disk, socket.gethostname(), _read("/sys/class/dmi/id/product_uuid"), "linux")
    board = raw[3]
    if board and re.fullmatch(r"[0F-]+", board.replace("-", ""), re.I):
        board = None
    return Fingerprint(hash_component(vendor, product, "machine", raw[0]), hash_component(vendor, product, "disk", raw[1]),
                       hash_component(vendor, product, "host", raw[2]), hash_component(vendor, product, "board", board), raw[4])


def _default_dir(product: str) -> Path:
    if platform.system() == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif platform.system() == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "licenserail" / product


class LicenseClient:
    """Offline verification on every start, online refresh when due, activation, deactivation and floating leases."""

    def __init__(self, server_url: str, vendor: str, product: str, public_key_pem: str, storage_dir: Optional[str] = None,
                 app_version: Optional[str] = None, refresh_on_startup: bool = False, timeout: float = 10.0,
                 fingerprint: Optional[Callable[[], Fingerprint]] = None, now: Optional[Callable[[], datetime]] = None,
                 machine_name: Optional[str] = None):
        if not server_url or not product or not public_key_pem:
            raise ValueError("server_url, vendor, product and public_key_pem are required")
        #: The organization ID from the dashboard (ten_...; part of every device identity).
        self.vendor = vendor
        self.server_url = server_url.rstrip("/")
        self.product = product
        self._key = load_public_key(public_key_pem)
        self._dir = Path(storage_dir) if storage_dir else _default_dir(product)
        self.app_version = app_version
        self.refresh_on_startup = refresh_on_startup
        self.timeout = timeout
        self._fingerprint_factory = fingerprint or (lambda: collect_fingerprint(vendor, product))
        self._fp: Optional[Fingerprint] = None
        self._now = now or (lambda: datetime.now(timezone.utc))
        self.machine_name = machine_name or socket.gethostname()
        self.last_server_message: Optional[str] = None
        self._heartbeat: Optional[threading.Timer] = None
        self._warned_test = False

    # ---------------------------------------------------------------- state

    @property
    def fingerprint(self) -> Fingerprint:
        if self._fp is None:
            self._fp = self._fingerprint_factory()
        return self._fp

    @property
    def license(self) -> Optional[License]:
        payload = self._payload()
        return License(payload) if payload else None

    def message(self, status: str) -> str:
        return self.last_server_message if status == "Missing" and self.last_server_message else MESSAGES[status]

    def evaluate_local(self) -> CheckResult:
        token = self._read("license.lic")
        if not token:
            return CheckResult("Missing")
        payload = verify_token(token, self._key)
        last_seen = decode_run_history(self._read("license.seen"), self.vendor, self.product, self.fingerprint)
        now = self._now()
        status = evaluate(payload, self.product, self.fingerprint, now, last_seen)
        if status in ("Valid", "Expired", "OfflineTooLong") and (last_seen is None or now > last_seen):
            self._write("license.seen", encode_run_history(now, self.vendor, self.product, self.fingerprint))
        if payload and payload.get("test") and not self._warned_test:
            self._warned_test = True
            warnings.warn("licenserail: test license, not for production use")
        return CheckResult(status, License(payload) if payload else None)

    def check(self) -> CheckResult:
        """Call on startup: evaluates offline, refreshes online when due or when only the server can clear the state."""
        result = self.evaluate_local()
        due = result.valid and (self.refresh_on_startup or self._now() >= parse_time(result.license.payload["refreshAfter"]))
        if due or result.status in ("Expired", "Suspended", "OfflineTooLong", "ClockTampered", "Unverified"):
            anomalies = ["clock_rollback"] if result.status == "ClockTampered" else ["history_missing"] if result.status == "Unverified" else None
            try:
                self.refresh(anomalies)
            except OSError:
                pass
            result = self.evaluate_local()
        return result

    # ---------------------------------------------------------------- server calls

    def activate(self, license_key: str, machine_name: Optional[str] = None) -> ActivationResult:
        if not license_key or not license_key.strip():
            return ActivationResult(False, "Enter the license key.", "bad_request")
        if not fingerprint_matches(self.fingerprint, self.fingerprint):  # would only use up a seat
            return ActivationResult(False, "This device can't be identified, so a license can't be activated on it.", "device_not_identified")
        body = {"licenseKey": license_key.strip(), "product": self.product, "fingerprint": self.fingerprint.to_json(),
                "machineName": machine_name or self.machine_name, "appVersion": self.app_version}
        try:
            ok, data = self._post("/api/client/v2/activate", body)
            if not ok and data.get("code") == "bad_request" and "floating" in data.get("message", "").lower():
                ok, data = self._post("/api/client/v2/floating/checkout", body)
        except OSError:
            return ActivationResult(False, "Could not connect to the license server.", "network")
        if not ok:
            return ActivationResult(False, data.get("message", "Server error."), data.get("code"))
        if not self._save_if_valid(data.get("token", "")):
            return ActivationResult(False, "The server returned an invalid license.", "invalid_token")
        result = self.evaluate_local()
        if result.license and result.license.is_floating:
            self._start_heartbeat()
        return ActivationResult(True, "The license has been activated.") if result.valid else ActivationResult(False, MESSAGES[result.status], result.status)

    checkout = activate

    def release(self) -> ActivationResult:
        return self.deactivate()

    def deactivate(self) -> ActivationResult:
        self._stop_heartbeat()
        token = self._read("license.lic")
        if not token:
            return ActivationResult(True, "There is no license on this device.")
        floating = (verify_token(token, self._key) or {}).get("floating") is True
        try:
            ok, data = self._post("/api/client/v2/floating/release" if floating else "/api/client/v2/deactivate",
                                  {"token": token, "fingerprint": self.fingerprint.to_json()})
        except OSError:
            return ActivationResult(False, "Removing the license needs an internet connection.", "network")
        if not ok and data.get("code") not in REVOKING_CODES:
            return ActivationResult(False, data.get("message", "Server error."), data.get("code"))
        self._delete("license.lic")
        if not ok and data.get("code") == "wrong_machine":
            return ActivationResult(False, data["message"], "wrong_machine")
        return ActivationResult(True, "The license has been removed from this device.")

    def refresh(self, anomalies: Optional[list] = None) -> None:
        token = self._read("license.lic")
        if not token:
            return
        floating = (verify_token(token, self._key) or {}).get("floating") is True
        ok, data = self._post("/api/client/v2/floating/heartbeat" if floating else "/api/client/v2/refresh",
                              {"token": token, "fingerprint": self.fingerprint.to_json(), "appVersion": self.app_version, "anomalies": anomalies})
        if ok:
            self._save_if_valid(data.get("token", ""))
        elif data.get("code") in REVOKING_CODES or data.get("code") == "lease_expired":
            self._delete("license.lic")
            self.last_server_message = data.get("message")

    # ---------------------------------------------------------------- internals

    def _start_heartbeat(self) -> None:
        self._stop_heartbeat()
        payload = self._payload()
        if not payload or not payload.get("floating"):
            return
        interval = max(30.0, (parse_time(payload["offlineUntil"]) - parse_time(payload["issuedAt"])).total_seconds() / 2)

        def beat():
            try:
                self.refresh()
            except OSError:
                pass
            self._start_heartbeat()

        self._heartbeat = threading.Timer(interval, beat)
        self._heartbeat.daemon = True
        self._heartbeat.start()

    def _stop_heartbeat(self) -> None:
        if self._heartbeat:
            self._heartbeat.cancel()
            self._heartbeat = None

    def _post(self, path: str, body: dict) -> tuple[bool, dict]:
        request = urllib.request.Request(self.server_url + path, data=json.dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json", "User-Agent": "licenserail-python/0.1"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                text = response.read().decode()
                data = json.loads(text) if text else {}
        except urllib.error.HTTPError as e:
            try:
                data = json.loads(e.read().decode() or "{}")
            except (OSError, ValueError, http.client.HTTPException):
                data = None
            return False, data if isinstance(data, dict) else {"message": f"Server error ({e.code})."}
        except (ValueError, http.client.HTTPException) as e:
            # Not our server (a captive portal, a proxy) or a broken connection: the same as being offline.
            raise ConnectionError(f"unexpected response from the license server: {e}") from e
        if not isinstance(data, dict):
            raise ConnectionError("unexpected response from the license server")
        return True, data

    def _save_if_valid(self, token: str) -> bool:
        payload = verify_token(token, self._key)
        if not payload or str(payload.get("product", "")).lower() != self.product.lower():
            return False
        self._write("license.lic", token)
        self._write("license.seen", encode_run_history(self._now(), self.vendor, self.product, self.fingerprint))
        return True

    def _payload(self) -> Optional[dict]:
        token = self._read("license.lic")
        return verify_token(token, self._key) if token else None

    def _read(self, name: str) -> Optional[str]:
        return _read(str(self._dir / name))

    def _write(self, name: str, value: str) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        (self._dir / name).write_text(value)

    def _delete(self, name: str) -> None:
        try:
            (self._dir / name).unlink()
        except FileNotFoundError:
            pass
