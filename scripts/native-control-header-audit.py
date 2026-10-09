#!/usr/bin/env python3
"""Exercise pinned native response-control consumers through a loopback fixture.

The official app-server is solely the test driver, never a gateway dependency.
Every credential is a synthetic Pro OAuth fixture. Native RPC notifications,
model-catalog requests and native context-token traces are the observations;
merely receiving a successful response is not a control-semantics assertion.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import queue
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = "a956835d020762cb2b570053af06f643a11c0ecc"
CLIENT = ROOT / "var/verification/native-client-0.160.0/codex-aarch64-apple-darwin"
GATEWAY = ROOT / "target/debug/right-codex"
MODEL = "gpt-6.1-sol"
SERVER_MODEL = "gpt-5.2"
FASTER_MODEL = "gpt-6-sol"
CLIENT_ACCOUNT = "control-fixture-client-pro"
POOL_ACCOUNT = "control-fixture-pool-pro"
CLIENT_TOKEN = "control-fixture-client-access"
POOL_TOKEN = "control-fixture-pool-access"
ETAG_OLD = '"control-catalog-old"'
ETAG_NEW = '"control-catalog-new"'
ENCRYPTED_REASONING = "a" * 4096
DIAGNOSTIC_MESSAGE = "CONTROL_DIAGNOSTIC_BUSINESS_MESSAGE"
DIAGNOSTIC_SENTINELS = {
    "header_request_id": "DIAG_UPSTREAM_REQUEST_ID_61",
    "header_cf_ray": "DIAG_UPSTREAM_CF_RAY_62",
    "event_id": "DIAG_UPSTREAM_EVENT_ID_63",
    "error_id": "DIAG_UPSTREAM_ERROR_ID_64",
    "error_request_id": "DIAG_UPSTREAM_ERROR_REQUEST_ID_65",
    "error_trace_id": "DIAG_UPSTREAM_TRACE_ID_66",
    "error_account_id": "DIAG_UPSTREAM_ACCOUNT_ID_67",
    "metadata_session_id": "DIAG_UPSTREAM_SESSION_ID_68",
    "nested_header_request_id": "DIAG_UPSTREAM_NESTED_HEADER_ID_69",
}
SANDBOX = ('(version 1)(allow default)(deny network-outbound)'
           '(allow network-outbound (remote ip "localhost:*"))')
SOURCE_FILES = [
    "codex-rs/codex-api/src/sse/responses.rs",
    "codex-rs/codex-api/src/endpoint/responses_websocket.rs",
    "codex-rs/codex-api/src/rate_limits.rs",
    "codex-rs/codex-api/src/safety_buffering.rs",
    "codex-rs/codex-api/src/endpoint/models.rs",
    "codex-rs/codex-api/src/api_bridge.rs",
    "codex-rs/protocol/src/error.rs",
    "codex-rs/core/src/session/turn.rs",
    "codex-rs/core/src/context_manager/history.rs",
    "codex-rs/app-server-protocol/src/protocol/v2/account.rs",
    "codex-rs/models-manager/src/manager.rs",
    "codex-rs/models-manager/models.json",
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def private_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def load_wire_helpers():
    spec = importlib.util.spec_from_file_location("control_wire_helpers", ROOT / "scripts/native-wire-differential.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synthetic_pro_auth(path, account, token):
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=").decode()
    claims = {"email": "control-fixture@example.invalid", "exp": 3000000000,
              "https://api.openai.com/auth": {"chatgpt_account_id": account,
                                             "chatgpt_user_id": "fixture-" + account,
                                             "chatgpt_plan_type": "pro"}}
    value = {"auth_mode": "chatgpt", "tokens": {
        "id_token": encode({"alg": "none"}) + "." + encode(claims) + ".fixture",
        "access_token": token, "refresh_token": "fixture-refresh-" + account,
        "account_id": account}, "last_refresh": "2026-10-10T00:00:00Z"}
    private_file(path, json.dumps(value, separators=(",", ":")).encode())


def isolated_env(home):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("OPENAI_", "CODEX_", "CHATGPT_", "OTEL_"))
           and key.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
    env.update(CODEX_HOME=str(home), NO_COLOR="1", NO_PROXY="localhost,127.0.0.1",
               no_proxy="localhost,127.0.0.1", RUST_LOG="codex_core::session::turn=trace")
    return env


def verify_source(source_repo):
    lock = json.loads((ROOT / "vendor/codex-source-lock.json").read_text())
    if lock.get("source_commit") != SOURCE_COMMIT or lock.get("workspace_version") != "0.160.0":
        raise RuntimeError("source lock does not match fixed reference")
    evidence = {}
    catalog = None
    for name in SOURCE_FILES:
        data = subprocess.check_output(["git", "-C", str(source_repo), "show", SOURCE_COMMIT + ":" + name])
        digest = sha(data)
        if digest != lock["files"][name]["sha256"]:
            raise RuntimeError("fixed git object differs from export lock: " + name)
        evidence[name] = digest
        if name.endswith("/models.json"):
            catalog = data
    return evidence, catalog


def controls(enabled):
    if not enabled:
        return {}
    return {
        "openai-model": SERVER_MODEL,
        # The official consumer checks presence, not a truthy value.
        "x-reasoning-included": "false",
        "x-models-etag": ETAG_NEW,
        "x-codex-primary-used-percent": "23.5",
        "x-codex-primary-window-minutes": "300",
        "x-codex-primary-reset-at": "2000000000",
        "x-codex-secondary-used-percent": "7",
        "x-codex-secondary-window-minutes": "10080",
        "x-codex-secondary-reset-at": "2000000500",
        "x-codex-limit-name": "Fixture Pro quota",
        "x-codex-credits-has-credits": "true",
        "x-codex-credits-unlimited": "false",
        "x-codex-credits-balance": "19.25",
        # False must not suppress retry_model fallback or buffering UI.
        "x-codex-safety-buffering-enabled": "false",
        "x-codex-safety-buffering-faster-model": FASTER_MODEL,
    }


def diagnostic_event(status):
    """Sentinels occupy protocol positions only, never the business message."""
    return {"type": "error", "status": status, "id": DIAGNOSTIC_SENTINELS["event_id"],
            "headers": {"x-request-id": DIAGNOSTIC_SENTINELS["header_request_id"],
                        "cf-ray": DIAGNOSTIC_SENTINELS["header_cf_ray"]},
            "error": {"type": "invalid_request_error", "code": "fixture_diagnostic",
                      "message": DIAGNOSTIC_MESSAGE, "id": DIAGNOSTIC_SENTINELS["error_id"],
                      "request_id": DIAGNOSTIC_SENTINELS["error_request_id"],
                      "trace_id": DIAGNOSTIC_SENTINELS["error_trace_id"],
                      "account_id": DIAGNOSTIC_SENTINELS["error_account_id"],
                      "headers": {"x-request-id": DIAGNOSTIC_SENTINELS["nested_header_request_id"]},
                      "metadata": {"session_id": DIAGNOSTIC_SENTINELS["metadata_session_id"]}}}


def websocket_send(stream, payload, opcode=1):
    payload = payload.encode() if isinstance(payload, str) else payload
    length = len(payload)
    header = bytes([0x80 | opcode])
    if length < 126:
        header += bytes([length])
    elif length < 65536:
        header += bytes([126]) + struct.pack("!H", length)
    else:
        header += bytes([127]) + struct.pack("!Q", length)
    stream.write(header + payload)
    stream.flush()


def websocket_read(stream):
    def read_exact(count):
        result = b""
        while len(result) < count:
            part = stream.read(count - len(result))
            if not part:
                raise EOFError("websocket closed")
            result += part
        return result
    first, second = read_exact(2)
    if first & 0x70 or not first & 0x80:
        raise ValueError("fixture accepts uncompressed complete frames only")
    count = second & 127
    if count == 126:
        count = struct.unpack("!H", read_exact(2))[0]
    elif count == 127:
        count = struct.unpack("!Q", read_exact(8))[0]
    if count > 16 * 1024 * 1024:
        raise ValueError("fixture websocket frame too large")
    mask = read_exact(4) if second & 0x80 else None
    payload = read_exact(count)
    if mask:
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return first & 15, payload


class Fixture:
    def __init__(self, catalog, helpers):
        self.catalog = catalog
        self.helpers = helpers
        self.zstd = helpers.zstd_library()
        self.phase = "setup"
        self.transport = "http"
        self.enabled = True
        self.rows = []
        self.lock = threading.Lock()
        self.response_count = 0
        self.models_count = 0
        self.diagnostic_status = None

    def start_case(self, phase, transport, enabled, diagnostic_status=None):
        self.phase, self.transport, self.enabled = phase, transport, enabled
        self.response_count, self.models_count = 0, 0
        self.diagnostic_status = diagnostic_status

    def record(self, method, path, headers=None, **values):
        with self.lock:
            self.rows.append({"phase": self.phase, "method": method, "path": path,
                              "headers": headers or {}, **values})

    def response_events(self, body):
        if body.get("generate") is False:
            return [{"type": "response.created", "response": {"id": "resp_control_warmup", "status": "in_progress"}},
                    {"type": "response.completed", "response": {"id": "resp_control_warmup", "status": "completed", "output": [],
                       "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}}]
        with self.lock:
            self.response_count += 1
            ordinal = self.response_count
        if self.diagnostic_status:
            # UnexpectedStatus is retryable in the pinned client. Two 403s
            # expose its tracking-id diagnostic notification, then a terminal
            # 400 ends the bounded fixture without changing native retry policy.
            status = 400 if self.diagnostic_status == 403 and ordinal > 2 else self.diagnostic_status
            event = diagnostic_event(status)
            self.record("WS_ERROR_OFFERED", "/v1/responses", frame=event)
            return [event]
        response_id = "resp_control_%d" % ordinal
        items = []
        if ordinal == 1:
            items.append({"type": "reasoning", "id": "rs_control_first", "summary": [],
                          "encrypted_content": ENCRYPTED_REASONING})
        items.append({"type": "message", "role": "assistant", "id": "msg_control_%d" % ordinal,
                      "content": [{"type": "output_text", "text": "CONTROL_HEADER_OK", "annotations": []}]})
        events = [{"type": "response.created", "response": {"id": response_id, "status": "in_progress"}},
                  {"type": "response.metadata", "metadata": {
                      "type": "safety_buffering", "use_cases": ["fixture_control"],
                      "reasons": ["fixture_reason"]}}]
        events.extend({"type": "response.output_item.done", "item": item} for item in items)
        events.append({"type": "response.completed", "response": {
            "id": response_id, "status": "completed", "output": items,
            "usage": {"input_tokens": 7, "output_tokens": 3, "total_tokens": 10}}})
        return events


def fixture_handler(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def answer(self, status, body, kind="application/json", extra=None):
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def do_GET(self):
            headers = {key.lower(): value for key, value in self.headers.items()}
            path = self.path.split("?", 1)[0]
            if path.endswith("/responses") and headers.get("upgrade", "").lower() == "websocket":
                if state.transport == "http":
                    state.record("GET", self.path, headers, status=426)
                    self.answer(426, b'{"error":{"code":"fixture_http_fallback"}}')
                    return
                extra = controls(state.enabled)
                state.record("GET", self.path, headers, status=101, response_headers=extra)
                self.send_response(101)
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                accept = base64.b64encode(hashlib.sha1((headers["sec-websocket-key"] +
                    "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
                self.send_header("Sec-WebSocket-Accept", accept)
                for name, value in extra.items():
                    self.send_header(name, value)
                self.end_headers()
                try:
                    while True:
                        opcode, payload = websocket_read(self.rfile)
                        if opcode == 8:
                            websocket_send(self.wfile, payload, 8)
                            break
                        if opcode == 9:
                            websocket_send(self.wfile, payload, 10)
                            continue
                        if opcode != 1:
                            continue
                        body = json.loads(payload)
                        state.record("WS", path, body=body)
                        for event in state.response_events(body):
                            websocket_send(self.wfile, json.dumps(event, separators=(",", ":")))
                except (EOFError, ConnectionError, OSError):
                    pass
                except Exception as error:
                    state.record("WS_ERROR", path, error=type(error).__name__ + ":" + str(error))
                self.close_connection = True
                return
            if path.endswith("/models"):
                state.models_count += 1
                # Startup may request the catalog more than once. Change its
                # revision only after the first generation so the response
                # header, rather than a startup race, must cause the refresh.
                etag = ETAG_OLD if state.response_count == 0 else ETAG_NEW
                state.record("GET", self.path, headers, status=200, response_headers={"etag": etag})
                self.answer(200, state.catalog, extra={"ETag": etag})
                return
            if path.endswith("/wham/accounts/check"):
                account = CLIENT_ACCOUNT if headers.get("authorization") == "Bearer " + CLIENT_TOKEN else POOL_ACCOUNT
                data = {"accounts": [{"id": account, "workspace_backend_origin": "NO_CONSTRAINT",
                                       "account_routing_override": "NO_CONSTRAINT"}], "default_account_id": account}
                state.record("GET", self.path, headers, status=200)
                self.answer(200, json.dumps(data).encode())
                return
            if path.endswith("/wham/usage"):
                state.record("GET", self.path, headers, status=200)
                self.answer(200, b'{"plan_type":"pro","rate_limit":{"allowed":true,"limit_reached":false}}')
                return
            state.record("GET", self.path, headers, status=404)
            self.answer(404, b'{"error":{"code":"fixture_unknown_path"}}')

        def do_POST(self):
            headers = {key.lower(): value for key, value in self.headers.items()}
            length = int(headers.get("content-length", "0"))
            if length > 16 * 1024 * 1024:
                self.answer(413, b"")
                return
            wire = self.rfile.read(length)
            decoded = state.helpers.zstd_decode(state.zstd, wire) if headers.get("content-encoding") == "zstd" else wire
            body = json.loads(decoded)
            path = self.path.split("?", 1)[0]
            if path.endswith("/responses"):
                extra = controls(state.enabled)
                state.record("POST", self.path, headers, status=200, body=body, response_headers=extra)
                events = state.response_events(body)
                data = "".join("event: %s\ndata: %s\n\n" % (event["type"], json.dumps(event, separators=(",", ":")))
                               for event in events).encode()
                self.answer(200, data, "text/event-stream", extra)
                return
            state.record("POST", self.path, headers, body=body, status=404)
            self.answer(404, b'{"error":{"code":"fixture_unknown_path"}}')
    return Handler


class Rpc:
    def __init__(self, client, home, work, base, chatgpt_base, output):
        self.events, self.pending, self.counter = [], [], 0
        self.queue = queue.Queue()
        self.log = (output / "native-rpc.jsonl").open("x")
        self.stderr_path = output / "native-stderr.log"
        self.stderr = self.stderr_path.open("x")
        os.chmod(output / "native-rpc.jsonl", 0o600)
        os.chmod(self.stderr_path, 0o600)
        self.process = subprocess.Popen([
            "sandbox-exec", "-p", SANDBOX, str(client), "app-server",
            "-c", 'openai_base_url="%s"' % base, "-c", 'chatgpt_base_url="%s"' % chatgpt_base,
            "-c", 'model="%s"' % MODEL, "-c", 'otel.metrics_exporter="none"',
            "-c", 'analytics.enabled=false', "-c", 'model_post_turn_compact_threshold_percent=0'],
            cwd=work, env=isolated_env(home), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr, text=True)
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        for line in self.process.stdout:
            self.log.write(line)
            self.log.flush()
            try:
                event = json.loads(line)
                self.events.append(event)
                self.queue.put(event)
            except ValueError:
                pass
        self.queue.put({"audit_process_ended": True})

    def send(self, value):
        self.process.stdin.write(json.dumps(value) + "\n")
        self.process.stdin.flush()

    def wait(self, predicate, timeout=45):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for index, value in enumerate(self.pending):
                if predicate(value):
                    return self.pending.pop(index)
            try:
                value = self.queue.get(timeout=max(.01, deadline - time.monotonic()))
            except queue.Empty:
                break
            if value.get("audit_process_ended"):
                raise RuntimeError("official client exited")
            if "id" in value and "method" in value:
                self.send({"id": value["id"], "error": {"code": -32601,
                           "message": "Control audit does not approve interactive operations"}})
            else:
                self.pending.append(value)
        raise TimeoutError("official RPC observation deadline")

    def call(self, method, params):
        self.counter += 1
        ident = self.counter
        self.send({"id": ident, "method": method, "params": params})
        value = self.wait(lambda row: row.get("id") == ident)
        if "error" in value:
            raise RuntimeError("official RPC rejected " + method + ": " + json.dumps(value["error"]))
        return value["result"]

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.reader.join(timeout=5)
        self.log.close()
        self.stderr.close()


def without_ids(params):
    return {key: value for key, value in params.items() if key not in ("threadId", "turnId")}


def run_native(client, home, work, base, upstream_base, output):
    rpc = Rpc(client, home, work, base, upstream_base + "/backend-api", output)
    result = {"completed_turns": [], "error": None}
    try:
        rpc.call("initialize", {"clientInfo": {"name": "codex_cli_rs", "title": "Isolated control audit",
                    "version": "0.160.0"}, "capabilities": {"experimentalApi": True}})
        rpc.send({"method": "initialized", "params": {}})
        # account/read performs separate workspace-routing discovery requiring HTTPS;
        # it is outside this loopback response-consumer audit. Record the fixture's
        # signed-in claim without representing it as a real backend entitlement.
        encoded = json.loads((home / "auth.json").read_text())["tokens"]["id_token"].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        result["synthetic_account_plan_type"] = claims["https://api.openai.com/auth"]["chatgpt_plan_type"]
        started = rpc.call("thread/start", {"cwd": str(work), "model": MODEL,
                           "approvalPolicy": "never", "sandbox": "workspace-write"})
        thread_id = started["thread"]["id"]
        result["thread_id"] = thread_id
        for ordinal in (1, 2):
            turn = rpc.call("turn/start", {"threadId": thread_id, "input": [{"type": "text",
                "text": "CONTROL_HEADER_%d. Reply CONTROL_HEADER_OK. Do not call tools." % ordinal,
                "textElements": []}]})
            turn_id = turn["turn"]["id"]
            done = rpc.wait(lambda row: row.get("method") == "turn/completed" and
                row.get("params", {}).get("turn", {}).get("id") == turn_id)
            result["completed_turns"].append(done["params"]["turn"]["status"])
            if result["completed_turns"][-1] != "completed":
                break
    except Exception as error:
        result["error"] = type(error).__name__ + ": " + str(error)
    finally:
        rpc.close()
    result["exit_code"] = rpc.process.returncode
    result["native_error_notifications"] = [without_ids(row.get("params", {})) for row in rpc.events
                                             if row.get("method") == "error"]
    methods = {"model/rerouted": "model_reroutes", "model/safetyBuffering/updated": "safety_buffering",
               "account/rateLimits/updated": "rate_limits"}
    for method, name in methods.items():
        result[name] = [without_ids(row.get("params", {})) for row in rpc.events if row.get("method") == method]
    traces = rpc.stderr_path.read_text(errors="replace")
    for path in (home / "log").glob("*.log") if (home / "log").is_dir() else []:
        traces += "\n" + path.read_text(errors="replace")
    token_usage = []
    for line in traces.splitlines():
        if "post sampling token usage" not in line:
            continue
        try:
            fields = json.loads(line).get("fields", {})
        except ValueError:
            fields = {}
        if isinstance(fields.get("total_usage_tokens"), int):
            token_usage.append(fields["total_usage_tokens"])
        else:
            match = re.search(r"total_usage_tokens[=:\s]+(\d+)", line)
            if match:
                token_usage.append(int(match.group(1)))
    result["post_sampling_token_usage"] = token_usage
    result["native_rpc_sha256"] = sha((output / "native-rpc.jsonl").read_bytes())
    result["native_stderr_sha256"] = sha(rpc.stderr_path.read_bytes())
    # Inspect only this fixture's native diagnostics; the test never rewrites
    # source text and product code never receives a scanning rule from here.
    native_observations = (output / "native-rpc.jsonl").read_text() + "\n" + traces
    result["diagnostic_sentinel_observed"] = {name: value in native_observations
        for name, value in DIAGNOSTIC_SENTINELS.items()}
    return result


def summarize_diagnostic(result, rows, status, gateway):
    creates = [row for row in rows if row["method"] == "WS" and row.get("body", {}).get("generate") is not False]
    offered = [row for row in rows if row["method"] == "WS_ERROR_OFFERED"]
    errors = [entry.get("error", {}) for entry in result["native_error_notifications"]]
    messages = [entry.get("message", "") for entry in errors]
    diagnostics = messages + [entry["additionalDetails"] for entry in errors if entry.get("additionalDetails")]
    business_diagnostics = [value for value in diagnostics if DIAGNOSTIC_MESSAGE in value]
    expected_count = 3 if status == 403 else 1
    expected_statuses = [403, 403, 400] if status == 403 else [400]
    seen = result["diagnostic_sentinel_observed"]
    expected_header_seen = not gateway
    checks = {
        "synthetic_pro_identity": result.get("synthetic_account_plan_type") == "pro",
        "native_observed_failed_turn": result["completed_turns"] == ["failed"] and result["error"] is None,
        "bounded_native_ws_requests": len(creates) == expected_count and not any(row["method"] == "POST" and
            row["path"].endswith("/responses") for row in rows),
        "structured_errors_offered": [row["frame"] for row in offered] ==
                                      [diagnostic_event(code) for code in expected_statuses],
        "business_message_has_no_identity_sentinels": all(value not in DIAGNOSTIC_MESSAGE
                                                          for value in DIAGNOSTIC_SENTINELS.values()),
        "native_business_message_preserved": bool(business_diagnostics) and DIAGNOSTIC_MESSAGE in messages[-1],
        "native_header_diagnostic_consumer": seen["header_request_id"] == expected_header_seen and
                                              seen["header_cf_ray"] == expected_header_seen,
    }
    if status == 400:
        parsed = []
        for message in messages:
            try:
                parsed.append(json.loads(message))
            except ValueError:
                pass
        checks["native_invalid_request_body_preserved"] = bool(parsed) and all(
            body.get("error", {}).get("message") == DIAGNOSTIC_MESSAGE and
            body.get("error", {}).get("code") == "fixture_diagnostic" and body.get("status") == status
            for body in parsed)
        checks["native_structured_identity_observation"] = all(not value for value in seen.values()) if gateway else all(seen.values())
    elif status == 403:
        checks["native_request_tracking_suffix"] = (any(
            "request id: " + DIAGNOSTIC_SENTINELS["header_request_id"] in value and
            "cf-ray: " + DIAGNOSTIC_SENTINELS["header_cf_ray"] in value for value in diagnostics)
            if not gateway else all(not value for value in seen.values()))
    if gateway:
        requests = [row for row in rows if row["method"] == "GET" and row["path"].split("?")[0].endswith("/responses")]
        checks["pool_pro_auth_isolation"] = bool(requests) and all(
            row["headers"].get("authorization") == "Bearer " + POOL_TOKEN and
            row["headers"].get("chatgpt-account-id") == POOL_ACCOUNT for row in requests)
    result["expected_failure_status"] = status
    result["checks"] = checks
    result["passed"] = all(checks.values())


def summarize_case(result, rows, transport, enabled, gateway):
    model_gets = [row for row in rows if row["method"] == "GET" and row["path"].split("?")[0].endswith("/models")]
    response_posts = [row for row in rows if row["method"] == "POST" and row["path"].endswith("/responses")]
    ws_creates = [row for row in rows if row["method"] == "WS" and row.get("body", {}).get("generate") is not False]
    requests = response_posts if transport == "http" else ws_creates
    first_generation = next((index for index, row in enumerate(rows) if row in requests), len(rows))
    refresh_gets = [row for row in rows[first_generation + 1:] if row in model_gets]
    expected_model = SERVER_MODEL if enabled else None
    actual_models = [entry.get("toModel") for entry in result["model_reroutes"]]
    expected_faster = FASTER_MODEL if enabled and transport == "http" else None
    result["model_catalog_gets"] = len(model_gets)
    result["startup_model_catalog_gets"] = len(model_gets) - len(refresh_gets)
    result["model_catalog_refresh_gets"] = len(refresh_gets)
    result["http_response_posts"] = len(response_posts)
    result["websocket_generation_creates"] = len(ws_creates)
    result["websocket_handshakes"] = [row["status"] for row in rows if row["method"] == "GET" and
                                      row["path"].split("?")[0].endswith("/responses")]
    result["controls_scope"] = ("HTTP headers" if transport == "http" else
        "WS handshake model/reasoning; WS handshake rate/etag/safety are ignored by native reference")
    usage = result["post_sampling_token_usage"]
    checks = {
        "synthetic_pro_identity": result.get("synthetic_account_plan_type") == "pro",
        "two_native_turns_complete": result["completed_turns"] == ["completed", "completed"] and result["error"] is None,
        "two_generation_requests": len(requests) == 2,
        "server_model_consumer": (actual_models == [expected_model, expected_model] if enabled else not actual_models),
        "safety_header_fallback_consumer": len(result["safety_buffering"]) == 2 and all(
            entry.get("fasterModel") == expected_faster and entry.get("showBufferingUi") is True
            for entry in result["safety_buffering"]),
        "reasoning_presence_consumer": len(usage) == 2 and usage[0] == 10 and
            (usage[1] == 10 if enabled else usage[1] > 10),
        "models_etag_refresh_consumer": len(refresh_gets) == (1 if transport == "http" and enabled else 0),
        "expected_transport": (not ws_creates and len(response_posts) == 2 if transport == "http" else
                                not response_posts and bool(result["websocket_handshakes"]) and
                                all(code == 101 for code in result["websocket_handshakes"])),
    }
    rates = [entry.get("rateLimits", {}) for entry in result["rate_limits"]]
    if transport == "http" and enabled:
        checks["rate_limit_consumer"] = len(rates) == 2 and all(
            entry.get("limitId") == "codex" and entry.get("limitName") == "Fixture Pro quota" and
            # The official app-server protocol rounds API f64 percentages.
            entry.get("primary", {}).get("usedPercent") == 24 and
            entry.get("primary", {}).get("windowDurationMins") == 300 and
            entry.get("primary", {}).get("resetsAt") == 2000000000 and
            entry.get("secondary", {}).get("usedPercent") == 7.0 and
            entry.get("credits") == {"hasCredits": True, "unlimited": False, "balance": "19.25"}
            for entry in rates)
    else:
        checks["rate_limit_consumer"] = all(entry.get("primary") is None for entry in rates)
    if gateway:
        authenticated = [row for row in rows if row["headers"].get("authorization") and
                         (row["path"].split("?")[0].endswith("/responses") or row in model_gets)]
        checks["pool_pro_auth_isolation"] = bool(authenticated) and all(
            row["headers"].get("authorization") == "Bearer " + POOL_TOKEN and
            row["headers"].get("chatgpt-account-id") == POOL_ACCOUNT for row in authenticated)
    result["checks"] = checks
    result["passed"] = all(checks.values())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", type=Path, default=CLIENT)
    parser.add_argument("--gateway", type=Path, default=GATEWAY)
    parser.add_argument("--source-repo", type=Path, required=True,
                        help="Official Git checkout containing the pinned source commit; read-only")
    parser.add_argument("--direct-only", action="store_true", help="qualify the fixture without launching a gateway")
    parser.add_argument("--gateway-sha256", help="require the announced newly built gateway hash")
    parser.add_argument("--transport", choices=("http", "websocket", "both"), default="both")
    parser.add_argument("--diagnostics-only", action="store_true", help="run only the structured WS error controls")
    args = parser.parse_args()
    if sys.platform != "darwin" or not shutil.which("sandbox-exec"):
        raise RuntimeError("audit requires macOS loopback sandbox")
    os.umask(0o077)
    client, gateway_binary = args.client.resolve(), args.gateway.resolve()
    version = subprocess.check_output([str(client), "--version"], text=True).strip()
    if version != "codex-cli 0.160.0":
        raise RuntimeError("client version differs from pinned reference")
    gateway_hash = None if args.direct_only else sha(gateway_binary.read_bytes())
    if not args.direct_only and not args.gateway_sha256:
        parser.error("--gateway-sha256 is required so a stale binary cannot be accepted")
    if not args.direct_only and gateway_hash != args.gateway_sha256:
        raise RuntimeError("gateway differs from the announced new build")
    source_repo = args.source_repo.resolve(strict=True)
    if not source_repo.is_dir():
        parser.error("--source-repo must be an official Git checkout directory")
    source_evidence, catalog = verify_source(source_repo)
    helpers = load_wire_helpers()
    output_root = ROOT / "var/verification"
    output_root.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="native-control-header-", dir=output_root))
    output.chmod(0o700)
    gateway_source_path = gateway_binary
    if not args.direct_only:
        # Root may rebuild while the audit runs; all cases must use one build.
        frozen_gateway = output / "gateway-binary"
        shutil.copyfile(gateway_binary, frozen_gateway)
        frozen_gateway.chmod(0o700)
        if sha(frozen_gateway.read_bytes()) != gateway_hash:
            raise RuntimeError("gateway changed while the audit was freezing its build")
        gateway_binary = frozen_gateway
    work = output / "workspace"
    work.mkdir(mode=0o700)
    state = Fixture(catalog, helpers)
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), fixture_handler(state))
    upstream.daemon_threads = True
    server_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    server_thread.start()
    upstream_base = "http://127.0.0.1:%d" % upstream.server_address[1]
    report = {"source_commit": SOURCE_COMMIT, "source_files_sha256": source_evidence,
              "client_version": version, "client_sha256": sha(client.read_bytes()),
              "gateway_sha256": gateway_hash, "synthetic_pro_oauth_only": True,
              "gateway_source_path": str(gateway_source_path),
              "network_boundary": "macOS sandbox-exec loopback only for native driver and gateway",
              "real_oauth_authorization_proven": False, "cases": {}, "all_passed": False,
              "reference_semantics": {
                  "reasoning_header": "presence is true, including the literal value false",
                  "safety_header": "enabled=false still permits faster-model fallback; event supplies visibility",
                  "rpc_used_percent": "native RPC rounds the HTTP f64 value to i32",
                  "websocket_handshake_consumed": ["openai-model", "x-reasoning-included"],
                  "websocket_handshake_ignored": ["x-models-etag", "rate-limit header families",
                                                   "x-codex-safety-buffering-enabled",
                                                   "x-codex-safety-buffering-faster-model"],
                  "websocket_control_frames": "not covered by this handshake-only differential",
                  "turn_state": "identity-scoped header excluded from this consumer fixture",
                  "additional_rate_limit_families": "not covered by this default-family fixture",
              },
              "diagnostic_scope": "Structured WS error headers and error envelopes only; native 400 raw error and 403 retry diagnostics; source message remains unchanged and contains no identity sentinel",
              "scope": "Native model/rate/safety notifications, actual catalog refreshes, native context-token traces and structured WS diagnostic isolation; no real authorization or midstream control-header equivalence claim"}
    auth_hashes = {}
    gateway = None
    try:
        transports = ["http", "websocket"] if args.transport == "both" else [args.transport]
        scenarios = [] if args.diagnostics_only else [(transport, enabled, None)
            for transport in transports for enabled in (False, True)]
        scenarios.extend(("websocket", False, status) for status in (403, 400))
        for transport, enabled, diagnostic_status in scenarios:
            for route in (["direct"] if args.direct_only else ["direct", "gateway"]):
                suffix = "diagnostic-%d" % diagnostic_status if diagnostic_status else ("headers" if enabled else "baseline")
                phase = "%s-%s-%s" % (route, transport, suffix)
                case_dir = output / phase
                case_dir.mkdir(mode=0o700)
                home = case_dir / "client-home"
                home.mkdir(mode=0o700)
                synthetic_pro_auth(home / "auth.json", CLIENT_ACCOUNT, CLIENT_TOKEN)
                auth_hashes[str(home / "auth.json")] = sha((home / "auth.json").read_bytes())
                state.start_case(phase, transport, enabled, diagnostic_status)
                base = upstream_base + "/v1"
                if route == "gateway":
                    pool_auth = case_dir / "pool-auth.json"
                    synthetic_pro_auth(pool_auth, POOL_ACCOUNT, POOL_TOKEN)
                    auth_hashes[str(pool_auth)] = sha(pool_auth.read_bytes())
                    port = helpers.free_port()
                    config = case_dir / "gateway.json"
                    private_file(config, json.dumps({"listen": "127.0.0.1:%d" % port,
                        "state_dir": str(case_dir / "gateway-state"), "base_url": upstream_base + "/v1",
                        "chatgpt_base_url": upstream_base + "/backend-api", "oauth_issuer": upstream_base,
                        "allow_insecure_http": True, "telemetry": {"official_metrics_enabled": False},
                        "scheduling": {"max_sessions_by_account_age": [128] * 5, "startup_spacing_secs": 0},
                        "accounts": [{"id": "control-pool", "auth_path": str(pool_auth), "enabled": True}]
                        }, separators=(",", ":")).encode())
                    log = (case_dir / "gateway.log").open("xb")
                    gateway = subprocess.Popen(["sandbox-exec", "-p", SANDBOX, str(gateway_binary), str(config)],
                        cwd=work, env=isolated_env(home), stdout=log, stderr=subprocess.STDOUT)
                    log.close()
                    helpers.wait_gateway(gateway, port)
                    base = "http://127.0.0.1:%d/v1" % port
                result = run_native(client, home, work, base, upstream_base, case_dir)
                if gateway:
                    gateway.terminate()
                    try:
                        gateway.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        gateway.kill()
                        gateway.wait(timeout=5)
                    gateway = None
                rows = [row for row in state.rows if row["phase"] == phase]
                if diagnostic_status:
                    summarize_diagnostic(result, rows, diagnostic_status, route == "gateway")
                else:
                    summarize_case(result, rows, transport, enabled, route == "gateway")
                report["cases"][phase] = result
                print(json.dumps({"case": phase, "passed": result["passed"], "checks": result["checks"]}), flush=True)
        if not args.direct_only:
            report["differentials"] = {}
            for transport in ([] if args.diagnostics_only else transports):
                for enabled in (False, True):
                    suffix = "%s-%s" % (transport, "headers" if enabled else "baseline")
                    direct, via = report["cases"]["direct-" + suffix], report["cases"]["gateway-" + suffix]
                    keys = ("model_reroutes", "safety_buffering", "rate_limits", "post_sampling_token_usage", "model_catalog_refresh_gets")
                    report["differentials"][suffix] = {key: direct[key] == via[key] for key in keys}
            # Startup catalog traffic is recorded separately from response
            # controls; an extra startup query is not hidden by the comparison.
            report["startup_catalog_observations"] = {key: value["startup_model_catalog_gets"]
                for key, value in report["cases"].items() if "startup_model_catalog_gets" in value}
        report["all_passed"] = all(case["passed"] for case in report["cases"].values()) and all(
            all(case.values()) for case in report.get("differentials", {}).values())
    except Exception as error:
        report["stopped_reason"] = type(error).__name__ + ": " + str(error)
    finally:
        if gateway:
            gateway.terminate()
            try:
                gateway.wait(timeout=10)
            except subprocess.TimeoutExpired:
                gateway.kill()
                gateway.wait(timeout=5)
        upstream.shutdown()
        upstream.server_close()
        server_thread.join(timeout=5)
        report["synthetic_auth_unchanged"] = all(sha(Path(path).read_bytes()) == digest for path, digest in auth_hashes.items())
        report["all_passed"] = report["all_passed"] and report["synthetic_auth_unchanged"]
        captures = output / "raw-captures.json"
        private_file(captures, json.dumps(state.rows, indent=2).encode())
        report["raw_capture_sha256"] = sha(captures.read_bytes())
        report_path = output / "report.json"
        private_file(report_path, json.dumps(report, indent=2).encode())
        print(json.dumps({"report": str(report_path), "all_passed": report["all_passed"],
                          "direct_only": args.direct_only, "stopped_reason": report.get("stopped_reason")}))
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
