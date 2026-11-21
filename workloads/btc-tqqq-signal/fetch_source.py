"""Load the pinned private workload into the pod's memory volume."""

import base64
import json
import os
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


INFISICAL_API = "http://infisical-infisical-standalone-infisical.infisical.svc.cluster.local:8080/api"
REPO_API = "https://api.github.com/repos/web3-frozen/btc-tqqq-signal"
SOURCE_PATH = "workloads/btc-tqqq-signal"
SOURCE_REVISION = "9f8196facecf6b4f5830178b778969134dab886b"
SOURCE_FILES = ("history.csv.gz.b64", "market.py", "signal_monitor.py", "strategy.py")
TOKEN_PATH = Path("/var/run/infisical/token")
OUTPUT_DIR = Path("/app")
MAX_RESPONSE_BYTES = 512 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(url, headers, description, body=None):
    request = Request(url, headers=headers, data=body)
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            content = response.read(MAX_RESPONSE_BYTES + 1)
    except URLError as error:
        status = getattr(error, "code", "connection error")
        raise RuntimeError(f"{description} failed ({status})") from None
    if len(content) > MAX_RESPONSE_BYTES:
        raise RuntimeError(f"{description} response exceeds the size limit")
    try:
        return json.loads(content)
    except ValueError:
        raise RuntimeError(f"{description} returned invalid JSON") from None


def load_source():
    auth = request_json(
        INFISICAL_API + "/v1/auth/kubernetes-auth/login",
        {"Content-Type": "application/json"},
        "Infisical Kubernetes login",
        json.dumps({
            "identityId": os.environ["INFISICAL_IDENTITY_ID"],
            "jwt": TOKEN_PATH.read_text(encoding="utf-8").strip(),
        }).encode(),
    )
    scope = urlencode({
        "projectId": os.environ["INFISICAL_PROJECT_ID"],
        "environment": "prod",
        "secretPath": "/",
        "includeImports": "false",
    })
    secret = request_json(
        INFISICAL_API + "/v4/secrets/GITHUB_WEB3_FROZEN_READ_TOKEN?" + scope,
        {"Authorization": f"Bearer {auth['accessToken']}"},
        "Infisical GitHub credential lookup",
    )
    headers = {
        "Authorization": f"Bearer {secret['secret']['secretValue']}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "homelab-btc-tqqq-source-loader",
    }
    for name in SOURCE_FILES:
        url = f"{REPO_API}/contents/{SOURCE_PATH}/{name}?ref={SOURCE_REVISION}"
        result = request_json(url, headers, f"GitHub download of {name}")
        if result.get("encoding") != "base64":
            raise RuntimeError(f"GitHub returned unsupported encoding for {name}")
        content = base64.b64decode("".join(result["content"].split()), validate=True)
        (OUTPUT_DIR / name).write_bytes(content)


if __name__ == "__main__":
    try:
        load_source()
    except (KeyError, OSError, TypeError, ValueError):
        sys.exit("Source loading failed due to missing configuration, invalid data, or a volume error")
    except RuntimeError as error:
        sys.exit(str(error))
    print(f"Private source loaded at {SOURCE_REVISION}")
