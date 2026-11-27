"""LicenseRail: licensing for your software."""
from .client import ActivationResult, CheckResult, License, LicenseClient, collect_fingerprint
from .core import (
    REVOKING_CODES, Fingerprint, evaluate, fingerprint_matches, hash_component, load_public_key, verify_token,
)
from .management import ApiRequestError, ManagementClient, verify_webhook

__all__ = [
    "ActivationResult", "ApiRequestError", "CheckResult", "Fingerprint", "License", "LicenseClient", "ManagementClient",
    "REVOKING_CODES", "collect_fingerprint", "evaluate", "fingerprint_matches", "hash_component", "load_public_key",
    "verify_token", "verify_webhook",
]
__version__ = "0.1.1"
