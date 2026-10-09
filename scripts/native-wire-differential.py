#!/usr/bin/env python3
"""Compare pinned native Codex direct and gateway HTTP sends on a loopback fixture.

Both client invocations and the gateway are confined by macOS sandbox-exec to
loopback outbound sockets. Credentials are synthetic; captures stay private.
This is a bounded reference differential, not real OAuth authorization proof.
"""

import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "var/verification/native-client-0.160.0/codex-aarch64-apple-darwin"
GATEWAY = ROOT / "target/debug/right-codex"
SOURCE_COMMIT = "a956835d020762cb2b570053af06f643a11c0ecc"
MAX_BODY = 16 * 1024 * 1024
SANDBOX = ('(version 1)(allow default)(deny network-outbound)'
           '(allow network-outbound (remote ip "localhost:*"))')
CLIENT_ACCOUNT = "fixture-client-account"
POOL_ACCOUNT = "fixture-pool-account"
CLIENT_TOKEN = "fixture-client-oauth-only"
POOL_TOKEN = "fixture-pool-oauth-only"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def private_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def jwt(account):
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=").decode()
    claims = {"email": "fixture@example.invalid", "exp": 3000000000,
              "https://api.openai.com/auth": {
                  "chatgpt_account_id": account, "chatgpt_user_id": "fixture-user",
                  "chatgpt_plan_type": "plus"}}
    return encode({"alg": "none"}) + "." + encode(claims) + ".fixture"


def auth(path, account, token):
    value = {"auth_mode": "chatgpt", "tokens": {
        "id_token": jwt(account), "access_token": token,
        "refresh_token": "fixture-refresh-" + account, "account_id": account},
        "last_refresh": "2026-10-10T00:00:00Z"}
    private_file(path, json.dumps(value, separators=(",", ":")).encode())


def zstd_library():
    candidates = [os.environ.get("CODEX_TEST_ZSTD_LIB"),
                  str(Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/native/poppler/poppler/lib/libzstd.dylib")]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return ctypes.CDLL(candidate)
    raise RuntimeError("local libzstd is required for raw zstd differential")


def zstd_decode(library, raw):
    library.ZSTD_decompress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
    library.ZSTD_decompress.restype = ctypes.c_size_t
    library.ZSTD_isError.argtypes = [ctypes.c_size_t]
    library.ZSTD_isError.restype = ctypes.c_uint
    source = ctypes.create_string_buffer(raw)
    target = ctypes.create_string_buffer(MAX_BODY)
    count = library.ZSTD_decompress(target, MAX_BODY, source, len(raw))
    if library.ZSTD_isError(count) or count > MAX_BODY:
        raise RuntimeError("captured zstd frame did not decode within limit")
    return target.raw[:count]


def sse_for(body, ordinal):
    response_id = "resp_fixture_%d" % ordinal
    items = body.get("input") if isinstance(body.get("input"), list) else []
    has_tool_output = any(isinstance(item, dict) and item.get("type") == "function_call_output"
                          for item in items)
    is_tool = has_tool_output or "WIRE_TOOL" in json.dumps(body, ensure_ascii=False)
    if is_tool and not has_tool_output:
        item = {"type": "function_call", "call_id": "call_fixture_shell",
                "name": "exec_command", "arguments": json.dumps({"cmd": "cat fixture.txt"})}
    else:
        message = "WIRE_TOOL_OK" if is_tool else "WIRE_ORDINARY_OK"
        item = {"type": "message", "role": "assistant", "id": "msg_fixture_%d" % ordinal,
                "content": [{"type": "output_text", "text": message, "annotations": []}]}
    events = [
        {"type": "response.created", "response": {"id": response_id, "status": "in_progress"}},
        {"type": "response.output_item.done", "item": item},
        {"type": "response.completed", "response": {
            "id": response_id, "status": "completed", "output": [item],
            "usage": {"input_tokens": 7, "output_tokens": 3, "total_tokens": 10}}},
    ]
    return "".join("event: %s\ndata: %s\n\n" %
                   (event["type"], json.dumps(event, separators=(",", ":")))
                   for event in events).encode()


class Captures:
    def __init__(self, catalog, zstd):
        self.catalog = catalog
        self.zstd = zstd
        self.rows = []
        self.lock = threading.Lock()
        self.phase = "setup"

    def record(self, method, path, headers, wire=b"", decoded=b"", body=None,
               status=None, response=b"", response_headers=None):
        with self.lock:
            phase = self.phase
            ordinal = 1 + sum(row["phase"] == phase and row["method"] == "POST" and
                              row["path"].split("?")[0].endswith("/responses")
                              for row in self.rows)
            row = {"phase": phase, "method": method, "path": path, "headers": dict(headers),
                   "wire_sha256": sha(wire), "wire_b64": base64.b64encode(wire).decode(),
                   "decoded_sha256": sha(decoded), "body": body, "status": status,
                   "response_offered_sha256": sha(response),
                   "response_offered_b64": base64.b64encode(response).decode(),
                   "response_headers": response_headers or {}}
            self.rows.append(row)
        return ordinal


def handler(state):
    class FixtureHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            return

        def answer(self, status, body, kind="application/json", more=None):
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            for key, value in (more or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if body:
                self.wfile.write(body)
            self.close_connection = True

        def do_GET(self):
            headers = {key.lower(): value for key, value in self.headers.items()}
            path = self.path.split("?", 1)[0]
            if path.endswith("/responses") and headers.get("upgrade", "").lower() == "websocket":
                state.record("GET", self.path, headers, status=426)
                self.answer(426, b'{"error":{"code":"ws_fixture_fallback"}}')
                return
            if path.endswith("/models"):
                state.record("GET", self.path, headers, status=200)
                self.answer(200, state.catalog)
                return
            if path.endswith("/wham/accounts/check"):
                account = (CLIENT_ACCOUNT if headers.get("authorization") == "Bearer " + CLIENT_TOKEN
                           else POOL_ACCOUNT)
                payload = {"accounts": [{"id": account,
                                        "workspace_backend_origin": "NO_CONSTRAINT",
                                        "account_routing_override": "NO_CONSTRAINT"}],
                           "default_account_id": account}
                state.record("GET", self.path, headers, status=200)
                self.answer(200, json.dumps(payload).encode())
                return
            if path.endswith("/wham/usage"):
                state.record("GET", self.path, headers, status=200)
                self.answer(200, b'{"rate_limit":{"allowed":true,"limit_reached":false}}')
                return
            state.record("GET", self.path, headers, status=404)
            self.answer(404, b'{"error":{"code":"fixture_path_unknown"}}')

        def do_POST(self):
            headers = {key.lower(): value for key, value in self.headers.items()}
            length = int(headers.get("content-length", "0"))
            if length > MAX_BODY:
                self.answer(413, b"")
                return
            wire = self.rfile.read(length)
            decoded = zstd_decode(state.zstd, wire) if headers.get("content-encoding") == "zstd" else wire
            try:
                body = json.loads(decoded)
            except (ValueError, UnicodeDecodeError):
                body = None
            if self.path.split("?", 1)[0].endswith("/responses") and isinstance(body, dict):
                ordinal = 1 + sum(row["phase"] == state.phase and row["method"] == "POST" and
                                  row["path"].split("?", 1)[0].endswith("/responses")
                                  for row in state.rows)
                response = sse_for(body, ordinal)
                state.record("POST", self.path, headers, wire, decoded, body, 200,
                             response=response,
                             response_headers={"content-type": "text/event-stream",
                                               "x-request-id": "fixture-request-%d" % ordinal})
                self.answer(200, response, "text/event-stream",
                            {"x-request-id": "fixture-request-%d" % ordinal})
                return
            state.record("POST", self.path, headers, wire, decoded, body, 404)
            self.answer(404, b'{"error":{"code":"fixture_path_unknown"}}')

    return FixtureHandler


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_gateway(process, port):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("gateway exited before readiness")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2) as sock:
                sock.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                if b"200" in sock.recv(100):
                    return
        except OSError:
            pass
        time.sleep(.1)
    raise RuntimeError("gateway readiness deadline")


def run_client(client, home, work, base, chatgpt_base, scenario, log):
    command = ["sandbox-exec", "-p", SANDBOX, str(client), "exec", "--ignore-user-config",
               # The outer policy already confines every descendant to loopback.
               # Avoid nesting the Codex macOS sandbox for the local cat command.
               "--skip-git-repo-check", "-C", str(work), "-s", "danger-full-access",
               "-m", "gpt-6.1-sol", "-c", 'openai_base_url="%s"' % base,
               "-c", 'chatgpt_base_url="%s"' % chatgpt_base,
               "-c", 'otel.metrics_exporter="none"',
               "--json", ("Reply exactly WIRE_ORDINARY_OK. Do not call tools." if scenario == "ordinary"
                          else "WIRE_TOOL: Read fixture.txt with exec_command, then reply WIRE_TOOL_OK.")]
    env = dict(os.environ, CODEX_HOME=str(home), NO_COLOR="1", NO_PROXY="localhost,127.0.0.1",
               no_proxy="localhost,127.0.0.1")
    for key in ("OPENAI_API_KEY", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN", "CHATGPT_SESSION_TOKEN"):
        env.pop(key, None)
    start = time.monotonic()
    with open(log, "xb") as output:
        os.chmod(log, 0o600)
        try:
            code = subprocess.run(command, cwd=work, env=env, stdout=output,
                                  stderr=subprocess.STDOUT, timeout=90, check=False).returncode
        except subprocess.TimeoutExpired:
            code = None
    events = []
    for line in log.read_text(errors="replace").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict):
            events.append(event)
    completed = any(event.get("type") == "turn.completed" for event in events)
    thread_ids = [event.get("thread_id") for event in events if event.get("type") == "thread.started"]
    actual_tool = any(event.get("type") == "item.completed" and
                      event.get("item", {}).get("type") == "command_execution" and
                      event.get("item", {}).get("exit_code") == 0 for event in events)
    return {"exit_code": code, "seconds": round(time.monotonic()-start, 3),
            "native_completed": completed, "native_tool_completed": actual_tool,
            "native_thread_id": thread_ids[0] if len(thread_ids) == 1 else None,
            "log_sha256": sha(log.read_bytes())}


def provider_rows(rows, phase):
    return [row for row in rows if row["phase"] == phase and row["method"] == "POST" and
            row["path"].split("?", 1)[0].endswith("/responses")]


def native_tool_result(rows, phase):
    """The next native HTTP request, not JSONL display, proves tool execution."""
    for row in provider_rows(rows, phase)[1:]:
        for item in row["body"].get("input", []):
            if not isinstance(item, dict) or item.get("type") != "function_call_output":
                continue
            output = item.get("output", "")
            if isinstance(output, str) and "Process exited with code 0" in output and \
                    "audit fixture value = 42" in output:
                return True
    return False


def normalize_fixture_tool_output(output):
    if not isinstance(output, str):
        return output
    if "Process exited with code 0" in output and "audit fixture value = 42" in output:
        return {"exit_code": 0, "final_output": "audit fixture value = 42"}
    return output


ID_PREFIXES = {"additional_tools": "at_", "message": "msg_", "reasoning": "rs_",
               "function_call": "fc_", "function_call_output": "fco_",
               "compaction": "cmp_"}


def identity_mapping_valid(direct_rows, gateway_rows):
    """Check typed item IDs have native prefixes and one consistent mapping."""
    mapping, inverse = {}, {}
    calls, reverse_calls = {}, {}
    for original, outbound in zip(direct_rows, gateway_rows):
        source_items = original["body"].get("input", [])
        target_items = outbound["body"].get("input", [])
        if len(source_items) != len(target_items):
            return False
        for source, target in zip(source_items, target_items):
            if not isinstance(source, dict) or not isinstance(target, dict):
                continue
            kind = source.get("type")
            if kind != target.get("type"):
                return False
            source_call, target_call = source.get("call_id"), target.get("call_id")
            if source_call is not None or target_call is not None:
                if not isinstance(source_call, str) or not isinstance(target_call, str):
                    return False
                if not source_call.startswith("call_") or not target_call.startswith("call_"):
                    return False
                if source_call in calls and calls[source_call] != target_call:
                    return False
                if target_call in reverse_calls and reverse_calls[target_call] != source_call:
                    return False
                calls[source_call], reverse_calls[target_call] = target_call, source_call
            original_id, mapped_id = source.get("id"), target.get("id")
            if original_id is None and mapped_id is None:
                continue
            prefix = ID_PREFIXES.get(kind)
            if not prefix or not isinstance(original_id, str) or not isinstance(mapped_id, str):
                return False
            if not original_id.startswith(prefix) or not mapped_id.startswith(prefix):
                return False
            label = (kind, original_id)
            if label in mapping and mapping[label] != mapped_id:
                return False
            if mapped_id in inverse and inverse[mapped_id] != label:
                return False
            mapping[label], inverse[mapped_id] = mapped_id, label
    return True


def client_metadata_shape(direct, gateway):
    """Keep client provenance omissions visible without treating it as model JSON."""
    original = direct.get("client_metadata", {})
    outbound = gateway.get("client_metadata", {})
    return {"direct_keys": sorted(original), "gateway_keys": sorted(outbound),
            "omitted_keys": sorted(set(original) - set(outbound)),
            "added_keys": sorted(set(outbound) - set(original)),
            "direct_model_matches_business": original.get("model", direct.get("model")) == direct.get("model"),
            "direct_effort_matches_business": original.get("reasoning_effort", direct.get("reasoning", {}).get("effort")) ==
            direct.get("reasoning", {}).get("effort")}


def scrub_structured(value):
    """Remove only typed identity fields from a copy; leave free JSON values intact."""
    if isinstance(value, list):
        return [scrub_structured(item) for item in value]
    if not isinstance(value, dict):
        return value
    kind = value.get("type")
    result = {}
    for key, item in value.items():
        if key == "client_metadata":
            continue
        if key == "internal_chat_message_metadata_passthrough" and isinstance(item, dict):
            retained = {name: scrub_structured(member) for name, member in item.items()
                        if name not in ("turn_id", "create_time")}
            if retained:
                result[key] = retained
            continue
        if key in ("id", "call_id", "response_id") and kind in (
                "additional_tools", "message", "reasoning", "function_call",
                "function_call_output", "compaction"):
            continue
        if kind == "function_call_output" and key == "output":
            result[key] = normalize_fixture_tool_output(item)
            continue
        result[key] = scrub_structured(item)
    return result


def business_difference(direct, gateway):
    """Return paths whose non-identity business value differs, never their content."""
    allowed_top = {"client_metadata", "prompt_cache_key", "conversation", "previous_response_id", "id"}
    left = {k: scrub_structured(v) for k, v in direct.items() if k not in allowed_top}
    right = {k: scrub_structured(v) for k, v in gateway.items() if k not in allowed_top}
    differences = []
    def walk(a, b, path):
        if type(a) is not type(b):
            differences.append(path)
        elif isinstance(a, dict):
            for key in sorted(a.keys() | b.keys()):
                if key not in a or key not in b:
                    missing = b[key] if key not in a else a[key]
                    if isinstance(missing, dict) and missing:
                        differences.extend(path + "/" + key + "/" + name for name in sorted(missing))
                    else:
                        differences.append(path + "/" + key)
                else:
                    walk(a[key], b[key], path + "/" + key)
        elif isinstance(a, list):
            if len(a) != len(b):
                differences.append(path + "/length")
            for index, (one, two) in enumerate(zip(a, b)):
                walk(one, two, path + "/" + str(index))
        elif a != b:
            differences.append(path)
    walk(left, right, "")
    return differences


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", type=Path, default=CLIENT)
    parser.add_argument("--gateway", type=Path, default=GATEWAY)
    parser.add_argument("--tools", action="store_true")
    args = parser.parse_args()
    if sys.platform != "darwin" or not shutil.which("sandbox-exec"):
        raise RuntimeError("this offline differential requires macOS sandbox-exec")
    client, gateway_binary = args.client.resolve(), args.gateway.resolve()
    if not client.is_file() or not gateway_binary.is_file():
        raise RuntimeError("pinned native client and built gateway binary are required")
    version = subprocess.check_output([str(client), "--version"], text=True).strip()
    if version != "codex-cli 0.160.0":
        raise RuntimeError("native client version differs from pinned reference")
    source_lock = json.loads((ROOT / "vendor/codex-source-lock.json").read_text())
    if source_lock.get("source_commit") != SOURCE_COMMIT or source_lock.get("workspace_version") != "0.160.0":
        raise RuntimeError("vendored source lock differs from the fixed native reference")
    root = ROOT / "var/verification"
    root.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="native-wire-differential-", dir=root))
    output.chmod(0o700)
    catalog = (ROOT / "vendor/codex/codex-rs/models-manager/models.json").read_bytes()
    state = Captures(catalog, zstd_library())
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), handler(state))
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    upstream_base = "http://127.0.0.1:%d" % upstream.server_address[1]
    work = output / "workspace"
    work.mkdir(mode=0o700)
    private_file(work / "fixture.txt", b"audit fixture value = 42\n")
    # The same original client profile must produce both requests. Each exec
    # starts a fresh native thread; a second home would change prompt text.
    client_home = output / "client-home"
    client_home.mkdir(mode=0o700)
    auth(client_home / "auth.json", CLIENT_ACCOUNT, CLIENT_TOKEN)
    gateway_home = client_home
    pool_auth = output / "pool-auth.json"
    auth(pool_auth, POOL_ACCOUNT, POOL_TOKEN)
    original_auth_hashes = {str(path): sha(path.read_bytes()) for path in
                            (client_home / "auth.json", gateway_home / "auth.json", pool_auth)}
    port = free_port()
    gateway_config = output / "gateway.json"
    private_file(gateway_config, json.dumps({
        "listen": "127.0.0.1:%d" % port,
        "state_dir": str(output / "gateway-state"),
        "base_url": upstream_base + "/v1",
        "chatgpt_base_url": upstream_base + "/backend-api",
        "oauth_issuer": upstream_base,
        "allow_insecure_http": True,
        "telemetry": {"official_metrics_enabled": False},
        "scheduling": {"max_sessions_by_account_age": [128]*5,
                       "startup_spacing_secs": 0},
        "accounts": [{"id": "pool", "auth_path": str(pool_auth), "enabled": True}]
    }, separators=(",", ":")).encode())
    report = {"source_commit": SOURCE_COMMIT, "client_version": version,
              "client_sha256": sha(client.read_bytes()), "gateway_sha256": sha(gateway_binary.read_bytes()),
              "synthetic_auth_only": True, "network_boundary": "sandbox-exec loopback outbound only",
              "pass_scope": "business JSON after explicit typed identity mapping, real native completion, and pool isolation; not byte-exact wire or Analytics equivalence",
              "websocket_scope": "Require exactly one controlled-upstream WS handshake (HTTP 426) per native turn; downstream HTTP 101 and later client fallback timing are recorded separately and not asserted equal",
              "cases": {}, "all_passed": False}
    gateway = None
    try:
        scenarios = ["ordinary"] + (["tools"] if args.tools else [])
        for scenario in scenarios:
            phase = "direct-" + scenario
            state.phase = phase
            result = run_client(client, client_home, work, upstream_base + "/v1",
                                upstream_base + "/backend-api", scenario, output / (phase + ".jsonl"))
            report["cases"][phase] = result
            if not result["native_completed"] or result["exit_code"] != 0:
                raise RuntimeError("native direct %s failed" % scenario)
        gateway_log = output / "gateway.log"
        with open(gateway_log, "xb") as log:
            os.chmod(gateway_log, 0o600)
            gateway = subprocess.Popen(["sandbox-exec", "-p", SANDBOX, str(gateway_binary), str(gateway_config)],
                                       cwd=work, env=dict(os.environ, NO_COLOR="1"),
                                       stdout=log, stderr=subprocess.STDOUT)
            wait_gateway(gateway, port)
            for scenario in scenarios:
                phase = "gateway-" + scenario
                state.phase = phase
                result = run_client(client, gateway_home, work, "http://127.0.0.1:%d/v1" % port,
                                    upstream_base + "/backend-api", scenario, output / (phase + ".jsonl"))
                report["cases"][phase] = result
                if not result["native_completed"] or result["exit_code"] != 0:
                    raise RuntimeError("native gateway %s failed" % scenario)
        for scenario in scenarios:
            direct = provider_rows(state.rows, "direct-" + scenario)
            via = provider_rows(state.rows, "gateway-" + scenario)
            if scenario == "tools":
                report["cases"]["direct-tools"]["native_tool_completed"] = native_tool_result(state.rows, "direct-tools")
                report["cases"]["gateway-tools"]["native_tool_completed"] = native_tool_result(state.rows, "gateway-tools")
            direct_ws = [row for row in state.rows if row["phase"] == "direct-" + scenario and
                         row["method"] == "GET" and row["status"] == 426]
            gateway_ws = [row for row in state.rows if row["phase"] == "gateway-" + scenario and
                          row["method"] == "GET" and row["status"] == 426]
            count = 2 if scenario == "tools" else 1
            comparisons = []
            mapped_ids = identity_mapping_valid(direct, via) if len(direct) == len(via) else False
            for one, two in zip(direct, via):
                differences = business_difference(one["body"], two["body"])
                comparisons.append({"non_identity_difference_paths": differences,
                                    "client_metadata_shape": client_metadata_shape(one["body"], two["body"]),
                                    "exact_request_wire_equal": one["wire_sha256"] == two["wire_sha256"],
                                    "same_method": one["method"] == two["method"],
                                    "same_path": one["path"] == two["path"],
                                    "same_content_encoding": one["headers"].get("content-encoding") == two["headers"].get("content-encoding"),
                                    "same_originator": one["headers"].get("originator") == two["headers"].get("originator"),
                                    "same_user_agent": one["headers"].get("user-agent") == two["headers"].get("user-agent"),
                                    "direct_zstd": one["headers"].get("content-encoding") == "zstd",
                                    "gateway_zstd": two["headers"].get("content-encoding") == "zstd",
                                    "gateway_pool_auth": two["headers"].get("authorization") == "Bearer " + POOL_TOKEN,
                                    "gateway_pool_account": two["headers"].get("chatgpt-account-id") == POOL_ACCOUNT,
                                    "gateway_no_client_token": CLIENT_TOKEN not in json.dumps(two),
                                    "gateway_no_client_account": CLIENT_ACCOUNT not in json.dumps(two),
                                    "gateway_no_client_thread_id": bool(report["cases"]["gateway-" + scenario]["native_thread_id"]) and
                                    report["cases"]["gateway-" + scenario]["native_thread_id"] not in json.dumps(two),
                                    "gateway_session_header_not_client_thread": two["headers"].get("session-id") !=
                                    report["cases"]["gateway-" + scenario]["native_thread_id"],
                                    "direct_client_auth": one["headers"].get("authorization") == "Bearer " + CLIENT_TOKEN,
                                    "gateway_session_disjoint_from_direct": one["headers"].get("session-id") != two["headers"].get("session-id")})
            required = {"same_method", "same_path", "same_content_encoding", "direct_zstd",
                        "gateway_zstd", "gateway_pool_auth", "gateway_pool_account",
                        "gateway_no_client_token", "gateway_no_client_account",
                        "gateway_no_client_thread_id", "gateway_session_header_not_client_thread",
                        "gateway_session_disjoint_from_direct", "direct_client_auth"}
            passed = mapped_ids and len(direct) == count and len(via) == count and len(direct_ws) == 1 and len(gateway_ws) == 1 and all(
                not item["non_identity_difference_paths"] and all(item[key] for key in required)
                for item in comparisons)
            if scenario == "tools":
                passed = passed and report["cases"]["direct-tools"]["native_tool_completed"] and report["cases"]["gateway-tools"]["native_tool_completed"]
            report["cases"][scenario + "-differential"] = {
                "passed": passed, "direct_response_posts": len(direct), "gateway_response_posts": len(via),
                "typed_item_id_mapping_consistent": mapped_ids,
                "direct_upstream_426_handshakes": len(direct_ws),
                "gateway_upstream_426_handshakes": len(gateway_ws),
                "comparisons": comparisons}
        report["all_passed"] = all(report["cases"][name + "-differential"]["passed"] for name in scenarios)
    except Exception as error:
        report["stopped_reason"] = type(error).__name__ + ":" + str(error)
    finally:
        if gateway is not None:
            gateway.terminate()
            try:
                gateway.wait(timeout=10)
            except subprocess.TimeoutExpired:
                gateway.kill()
                gateway.wait(timeout=5)
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)
        capture = output / "raw-captures.json"
        private_file(capture, json.dumps(state.rows, ensure_ascii=False, indent=2).encode())
        report["raw_capture_sha256"] = sha(capture.read_bytes())
        report["phase_wire_counts"] = {
            phase: {
                "response_posts": len(provider_rows(state.rows, phase)),
                "websocket_426": sum(row["phase"] == phase and row["method"] == "GET" and
                                     row["status"] == 426 for row in state.rows),
                "offered_sse": sum(row["phase"] == phase and row["method"] == "POST" and
                                   row["path"].split("?", 1)[0].endswith("/responses") and
                                   row["response_headers"].get("content-type") == "text/event-stream"
                                   for row in state.rows),
            } for phase in ("direct-ordinary", "gateway-ordinary", "direct-tools", "gateway-tools")}
        report["source_auth_unchanged"] = all(
            Path(path).is_file() and sha(Path(path).read_bytes()) == before
            for path, before in original_auth_hashes.items())
        report["all_passed"] = report["all_passed"] and report["source_auth_unchanged"]
        summary = output / "report.json"
        private_file(summary, json.dumps(report, ensure_ascii=False, indent=2).encode())
        print(json.dumps({"report": str(summary), "all_passed": report["all_passed"],
                          "stopped_reason": report.get("stopped_reason"),
                          "cases": {k: v.get("passed") for k, v in report["cases"].items()
                                    if k.endswith("-differential")}}, ensure_ascii=False))
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
