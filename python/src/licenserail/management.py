"""Server-side client for the management API (/api/v2). Needs a secret API key: never ship it in an app."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Optional


class ApiRequestError(Exception):
    def __init__(self, status: int, code: str, message: str, body: Any):
        super().__init__(message)
        self.status, self.code, self.body = status, code, body


class ManagementClient:
    def __init__(self, api_key: str, base_url: str = "https://api.licenserail.com", environment: Optional[str] = None, timeout: float = 30):
        self.api_key, self.base_url, self.environment, self.timeout = api_key, base_url.rstrip("/"), environment, timeout

    def request(self, method: str, path: str, body: Any = None, headers: Optional[dict] = None) -> Any:
        h = {"Authorization": f"Bearer {self.api_key}", "User-Agent": "licenserail-python/0.1", **(headers or {})}
        if self.environment:
            h["X-Environment"] = self.environment
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        if method != "GET":
            h.setdefault("Idempotency-Key", str(uuid.uuid4()))
        req = urllib.request.Request(f"{self.base_url}/api/v2{path}", data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                text = r.read().decode()
                return json.loads(text) if text else None
        except urllib.error.HTTPError as e:
            text = e.read().decode()
            parsed = json.loads(text) if text.startswith("{") else {}
            err = parsed.get("error", {})
            raise ApiRequestError(e.code, err.get("code", "error"), err.get("message", f"HTTP {e.code}"), parsed) from None

    def create_product(self, code: str, name: str, **fields) -> dict:
        return self.request("POST", "/products", {"code": code, "name": name, **fields})

    def create_customer(self, name: str, **fields) -> dict:
        return self.request("POST", "/customers", {"name": name, **fields})

    def create_licenses(self, product_id: str, customer_id: str, **fields) -> dict:
        return self.request("POST", "/licenses", {"productId": product_id, "customerId": customer_id, **fields})

    def get_license(self, license_id: str) -> dict:
        return self.request("GET", f"/licenses/{license_id}")

    def update_license(self, license_id: str, **patch) -> dict:
        return self.request("PATCH", f"/licenses/{license_id}", patch)

    def revoke_license(self, license_id: str, approval_id: Optional[str] = None) -> dict:
        return self.request("POST", f"/licenses/{license_id}/revoke", headers={"Approval-Id": approval_id} if approval_id else None)


def verify_webhook(secret: str, headers: dict, body: str, tolerance: int = 300) -> bool:
    """Verifies a Standard Webhooks signature with the endpoint's whsec_ secret."""
    lower = {k.lower(): v for k, v in headers.items()}
    msg_id, ts, sig = lower.get("webhook-id"), lower.get("webhook-timestamp"), lower.get("webhook-signature")
    if not msg_id or not ts or not sig or abs(time.time() - int(ts)) > tolerance:
        return False
    key = base64.b64decode(secret[6:] if secret.startswith("whsec_") else secret)
    expected = base64.b64encode(hmac.new(key, f"{msg_id}.{ts}.{body}".encode(), hashlib.sha256).digest()).decode()
    return any(s.startswith("v1,") and hmac.compare_digest(s[3:], expected) for s in sig.split(" "))
