#!/usr/bin/env python3
"""Exercise the built executable on loopback without OAuth accounts or client homes."""
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
KEY = "synthetic-binary-smoke-key"


def fetch(url, data=None, key=None):
    headers = {"Content-Type": "application/json", "thread-id": "smoke-local-thread"}
    if key is not None:
        headers["Authorization"] = "Bearer " + key
    request = urllib.request.Request(url, data=data, headers=headers)
    # Do not inherit the invoking shell's HTTP proxy for this local test.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as response:
        return response.code, json.load(response)


def main():
    with tempfile.TemporaryDirectory(prefix="codex-http-binary-") as directory:
        config = Path(directory) / "config.json"
        config.write_text(json.dumps({"listen": "127.0.0.1:0", "client_api_key": KEY, "accounts": []}))
        environment = dict(os.environ, NO_COLOR="1")
        process = subprocess.Popen(
            [str(ROOT / "target/debug/right-codex"), str(config)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=environment,
        )
        try:
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=10), "binary did not report readiness"
            line = process.stdout.readline()
            selector.close()
            address = re.search(r"127\.0\.0\.1:[0-9]+", line)
            assert address, "binary readiness did not contain its bound address"
            base = "http://" + address.group()
            status, body = fetch(base + "/health")
            assert status == 200 and body["runtime"] == "direct_protocol"
            assert body["codex_version"] == "0.160.0"
            results = ["unauthenticated_health"]
            for key, expected in [(None, 401), (KEY, 400)]:
                status, body = fetch(base + "/v1/responses", b"{", key)
                assert status == expected and " / " in body["error"]["message"]
            results.append("authentication_precedes_json_decoding")
            status, body = fetch(base + "/v1/responses", b'{"model":"fixture-model","input":[]}', KEY)
            assert status == 503 and body["error"]["code"] == "no_available_account"
            results.append("no_account_rejected_without_upstream")
            process.send_signal(signal.SIGINT)
            assert process.wait(timeout=5) == 0
            results.append("graceful_shutdown")
            print(json.dumps({"result": "pass", "checks": results, "external_network": False, "host_auth_read": False}, indent=2))
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
