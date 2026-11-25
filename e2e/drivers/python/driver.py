import json
import os
import sys

from licenserail import LicenseClient
from licenserail.core import Fingerprint

e = os.environ
parts = e.get("LR_DEVICE", "").split(",")
options = {"fingerprint": lambda: Fingerprint(*parts, "linux")} if len(parts) == 4 else {}
with open(e["LR_PUBLIC_KEY_FILE"], encoding="utf-8") as f:
    pem = f.read()
client = LicenseClient(server_url=e["LR_URL"], vendor=e["LR_VENDOR"], product=e["LR_PRODUCT"], public_key_pem=pem, storage_dir=e["LR_STORAGE"],
                       app_version="1.2.3", timeout=float(e["LR_TIMEOUT"]), **options)


def out(r):
    return {"success": r.success, "errorCode": r.error_code, "message": r.message}


op = sys.argv[1]
if op == "activate":
    result = out(client.activate(sys.argv[2]))
elif op == "deactivate":
    result = out(client.deactivate())
elif op == "refresh":
    try:
        client.refresh()
        result = {"success": True}
    except OSError as x:
        result = {"success": False, "errorCode": "network", "message": str(x)}
else:
    s = client.check()
    result = {"status": s.status, "features": s.license.features if s.license else [], "test": s.license.is_test if s.license else False}
print(json.dumps(result))
