#!/usr/bin/env python3
"""Bounded synthetic OAuth HTTP audit, using only the Python standard library.

All listeners and the gateway process are owned by this invocation. No Codex
client, real credentials, external upstream, existing service or deployment is
used. The controlled backend records compressed wire hashes and authoritative
headers; it does not pretend to decode zstd with an unavailable decoder.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = 'x-codex-turn-metadata'


def digest(value):
    return hashlib.sha256(value).hexdigest()


def private_json(path, value):
    path.write_text(json.dumps(value, indent=2))
    path.chmod(0o600)


class Backend(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def __init__(self):
        super().__init__(('127.0.0.1', 0), Handler)
        self.lock = threading.Lock()
        self.requests = []
        self.errors = []
        self.gets = []


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def do_GET(self):
        # Account quota reads stay on the same controlled loopback service.
        if self.path == '/backend-api/wham/accounts/check':
            value = {'accounts': [{'id': 'synthetic-upstream-workspace'}],
                'default_account_id': 'synthetic-upstream-workspace'}
        else:
            value = {'rate_limit': {'allowed': True, 'limit_reached': False,
                'primary_window': {'used_percent': 0, 'limit_window_seconds': 18000,
                    'reset_after_seconds': 3600, 'reset_at': 1900000000}}}
        with self.server.lock:
            self.server.gets.append({'path': self.path, 'accounts_reply': 'accounts' in value})
        payload = json.dumps(value).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length <= 0 or length > 1024 * 1024:
                raise ValueError('bounded_wire_length')
            raw = self.rfile.read(length)
            metadata = json.loads(self.headers[CANONICAL])
            thread = self.headers['thread-id']
            session = self.headers['session-id']
            turn = metadata['turn_id']
            assert self.path == '/backend-api/codex/responses'
            assert metadata['thread_id'] == thread and metadata['session_id'] == session
            assert self.headers.get('Authorization') == 'Bearer SYNTHETIC_UPSTREAM_OAUTH'
            assert self.headers.get('chatgpt-account-id') == 'synthetic-upstream-workspace'
            assert not any('client-source-' in value for value in [thread, session, turn,
                self.headers.get('x-client-request-id', ''), self.headers[CANONICAL]])
            assert self.headers.get('Content-Encoding') in (None, 'zstd')
            with self.server.lock:
                ordinal = len(self.server.requests) + 1
                self.server.requests.append({'ordinal': ordinal, 'thread_id': thread,
                    'session_id': session, 'turn_id': turn, 'wire_sha256': digest(raw),
                    'wire_bytes': len(raw), 'content_encoding': self.headers.get('Content-Encoding')})
            marker = 'LOAD_OK_' + digest(thread.encode())[:16]
            response_id = 'resp_' + uuid.uuid4().hex
            item = {'type': 'message', 'id': 'msg_' + uuid.uuid4().hex, 'role': 'assistant',
                'content': [{'type': 'output_text', 'text': marker, 'annotations': []}]}
            events = [
                {'type': 'response.created', 'response': {'id': response_id, 'status': 'in_progress'}},
                {'type': 'response.output_item.done', 'response_id': response_id, 'item': item},
                {'type': 'response.completed', 'response': {'id': response_id, 'status': 'completed',
                    'output': [item], 'usage': {'input_tokens': 1, 'output_tokens': 1, 'total_tokens': 2}}}]
            chunks = [('event: ' + e['type'] + '\ndata: ' + json.dumps(e) + '\n\n').encode() for e in events]
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(sum(map(len, chunks))))
            self.send_header('x-request-id', 'request_' + str(ordinal))
            self.end_headers()
            self.wfile.write(chunks[0])
            self.wfile.flush()
            time.sleep(.03)  # A bounded cancellation window after actual response.created.
            for chunk in chunks[1:]:
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as error:
            with self.server.lock:
                self.server.errors.append(type(error).__name__)
            try:
                self.send_error(500)
            except OSError:
                pass


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def rss_kib(pid):
    value = subprocess.run(['ps', '-o', 'rss=', '-p', str(pid)], capture_output=True,
        text=True, timeout=2)
    return int(value.stdout.strip()) if value.returncode == 0 and value.stdout.strip() else None


def state_size(directory):
    rows = [p for p in directory.rglob('*') if p.is_file()] if directory.exists() else []
    return {'files': len(rows), 'bytes': sum(p.stat().st_size for p in rows)}


def start_gateway(binary, config, port, directory, generation):
    log = directory / ('gateway-' + str(generation) + '.log')
    output = log.open('wb')
    log.chmod(0o600)
    env = dict(os.environ, NO_COLOR='1')
    for name in ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']:
        env.pop(name, None)
    process = subprocess.Popen([str(binary), str(config)], stdout=output, stderr=subprocess.STDOUT, env=env)
    output.close()
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError('owned_gateway_start_failed')
            try:
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=.5)
                conn.request('GET', '/health')
                response = conn.getresponse()
                value = json.loads(response.read())
                conn.close()
                if response.status == 200 and value['runtime'] == 'direct_protocol':
                    return process
            except (OSError, ValueError):
                pass
            time.sleep(.05)
        raise RuntimeError('owned_gateway_ready_timeout')
    except BaseException:
        stop_gateway(process)
        raise


def stop_gateway(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    return process.returncode


def run_request(port, ordinal, sessions):
    scope = ordinal % sessions
    # A subset explicitly repeats a completed logical turn. No tool is executed.
    turn = ordinal // sessions
    repeated = turn > 0 and ordinal % 17 == 0
    if repeated:
        turn -= 1
    local_thread = 'client-source-thread-' + str(scope)
    metadata = {'request_kind': 'turn', 'thread_id': local_thread,
        'session_id': 'client-source-session-' + str(scope),
        'turn_id': 'client-source-turn-' + str(scope) + '-' + str(turn)}
    invalid = ordinal % 29 == 0
    cancelled = not invalid and ordinal % 31 == 0
    body = {'model': 'synthetic-model', 'stream': not invalid,
        'input': [{'type': 'message', 'id': 'msg_client-source-' + str(scope) + '-' + str(turn),
            'role': 'user', 'content': [{'type': 'input_text', 'text': 'bounded load fixture'}]}],
        'client_metadata': {CANONICAL: json.dumps(metadata)}}
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=9)
    row = {'ordinal': ordinal, 'scope': scope, 'logical_turn': turn,
        'repeated_turn_requested': repeated, 'cancel_requested': cancelled, 'invalid_requested': invalid}
    started = time.monotonic()
    try:
        conn.request('POST', '/v1/responses', body=json.dumps(body), headers={
            'Content-Type': 'application/json', 'Authorization': 'Bearer SYNTHETIC_CLIENT_OAUTH',
            'chatgpt-account-id': 'synthetic-client-workspace', 'thread-id': local_thread,
            CANONICAL: json.dumps(metadata), 'originator': 'codex_cli_rs',
            'User-Agent': 'codex_cli_rs/0.160.0 (controlled load fixture)'})
        response = conn.getresponse()
        row['http_status'] = response.status
        if cancelled and response.status == 200:
            observed = response.read(64)
            row.update(outcome='client_cancelled', bytes_received=len(observed))
        else:
            raw = response.read(1024 * 1024)
            row['wire_response_sha256'] = digest(raw)
            if response.status == 200:
                events = [json.loads(line[6:]) for line in raw.decode().splitlines() if line.startswith('data: ')]
                terminal = [e for e in events if e.get('type') == 'response.completed']
                if len(terminal) != 1:
                    row['outcome'] = 'unknown'
                else:
                    item = terminal[0]['response']['output'][0]
                    row.update(outcome='completed', response_alias=terminal[0]['response']['id'],
                        marker=item['content'][0]['text'])
            else:
                row['outcome'] = 'explicit_rejection'
                try:
                    row['error_code'] = json.loads(raw)['error']['code']
                except (ValueError, KeyError):
                    row['error_code'] = 'non_json_rejection'
    except Exception as error:
        row.update(outcome='transport_unknown', error_class=type(error).__name__)
    finally:
        conn.close()
    row['seconds'] = round(time.monotonic() - started, 4)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/debug/right-codex')
    parser.add_argument('--requests', type=int, default=400)
    parser.add_argument('--concurrency', type=int, default=16)
    parser.add_argument('--sessions', type=int, default=48)
    parser.add_argument('--max-seconds', type=int, default=110)
    args = parser.parse_args()
    if not (200 <= args.requests <= 2000 and 1 <= args.concurrency <= 64
            and 2 <= args.sessions <= 128 and 20 <= args.max_seconds <= 120):
        parser.error('bounded request/concurrency/session/time limits exceeded')
    binary = args.binary.resolve(strict=True)
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8]
    directory = ROOT / 'var/verification' / ('bounded-load-' + stamp)
    directory.mkdir(mode=0o700, parents=True)
    frozen_binary = directory / 'gateway-executable'
    binary_sha = digest(binary.read_bytes())
    frozen_binary.write_bytes(binary.read_bytes())
    frozen_binary.chmod(0o500)
    assert digest(frozen_binary.read_bytes()) == binary_sha == digest(binary.read_bytes())
    binary = frozen_binary
    config = directory / 'config.json'
    auth = directory / 'synthetic-auth.json'
    claims = {'email': 'synthetic@example.invalid', 'https://api.openai.com/auth':
        {'chatgpt_account_id': 'synthetic-upstream-workspace', 'chatgpt_plan_type': 'plus'}}
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode()
    synthetic_jwt = 'e30.' + encoded + '.synthetic-signature'
    private_json(auth, {'auth_mode': 'chatgpt', 'tokens': {'id_token': synthetic_jwt,
        'access_token': 'SYNTHETIC_UPSTREAM_OAUTH', 'refresh_token': 'synthetic-refresh',
        'account_id': 'synthetic-upstream-workspace'}, 'last_refresh': '2026-10-10T00:00:00Z'})
    backend = Backend()
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    port = free_port()
    state = directory / 'state'
    private_json(config, {'listen': '127.0.0.1:' + str(port), 'state_dir': str(state),
        'base_url': 'http://127.0.0.1:' + str(backend.server_port) + '/backend-api/codex',
        'chatgpt_base_url': 'http://127.0.0.1:' + str(backend.server_port) + '/backend-api',
        'oauth_issuer': 'http://127.0.0.1:' + str(backend.server_port), 'allow_insecure_http': True,
        'request_timeout_secs': 8, 'queue_timeout_secs': 8,
        'telemetry': {'official_metrics_enabled': False},
        'scheduling': {'max_sessions_by_account_age': [128] * 5, 'startup_spacing_secs': 0,
            'idle_timeout_secs': 300},
        'accounts': [{'id': 'synthetic-account', 'auth_path': str(auth), 'enabled': True}]})
    started = time.monotonic()
    process = None
    rows, samples, exits = [], [], []
    failure = None
    try:
        for generation, ordinals in enumerate([range(args.requests // 2), range(args.requests // 2, args.requests)]):
            process = start_gateway(binary, config, port, directory, generation)
            samples.append({'phase': 'started-' + str(generation), 'rss_kib': rss_kib(process.pid),
                'state': state_size(state)})
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency)
            futures = [pool.submit(run_request, port, ordinal, args.sessions) for ordinal in ordinals]
            try:
                remaining = args.max_seconds - (time.monotonic() - started)
                for future in concurrent.futures.as_completed(futures, timeout=max(1, remaining)):
                    rows.append(future.result())
            finally:
                pool.shutdown(wait=False, cancel_futures=True)
            samples.append({'phase': 'finished-' + str(generation), 'rss_kib': rss_kib(process.pid),
                'state': state_size(state)})
            exits.append(stop_gateway(process))
            process = None
        assert all(code == 0 for code in exits), 'owned_gateway_shutdown_failed'
    except Exception as error:
        failure = type(error).__name__
    finally:
        if process is not None:
            exits.append(stop_gateway(process))
        backend.shutdown()
        backend.server_close()
    rows.sort(key=lambda x: x['ordinal'])
    private_json(directory / 'requests.json', rows)
    with backend.lock:
        upstream = list(backend.requests)
        backend_errors = list(backend.errors)
    private_json(directory / 'upstream.json', upstream)
    counts = {name: sum(row.get('outcome') == name for row in rows) for name in
        ['completed', 'explicit_rejection', 'client_cancelled', 'unknown', 'transport_unknown']}
    markers, response_aliases, scope_identity = {}, {}, {}
    isolated = True
    for row in rows:
        if row.get('outcome') != 'completed':
            continue
        scope = row['scope']
        marker = row['marker']
        if scope in markers and markers[scope] != marker:
            isolated = False
        markers[scope] = marker
        prior = response_aliases.setdefault(row['response_alias'], scope)
        isolated &= prior == scope
    isolated &= len(set(markers.values())) == len(markers)
    for path in (state / 'sessions').glob('*.json'):
        snapshot = json.loads(path.read_text())['session']
        thread = snapshot['thread_id']
        identity = (snapshot['session_id'], snapshot['cache_key'], snapshot['window_id'])
        if thread in scope_identity and scope_identity[thread] != identity:
            isolated = False
        scope_identity[thread] = identity
    persistent_domains_distinct = all(len({identity[index] for identity in scope_identity.values()}) == len(scope_identity) for index in range(3))
    isolated &= persistent_domains_distinct and len(scope_identity) == args.sessions and len(markers) == args.sessions
    # Unknown counts come from persisted attempts, not from a cancelled socket's inferred outcome.
    states = {}
    for path in (state / 'sessions').glob('*.json'):
        for attempt in json.loads(path.read_text())['session']['attempts'].values():
            name = attempt['state']
            states[name] = states.get(name, 0) + 1
    invalid_correct = all(row.get('http_status') == 400 and row.get('error_code') == 'unsupported_business_request'
        for row in rows if row['invalid_requested'])
    report = {'scope': 'bounded_synthetic_http_load', 'binary_sha256': digest(binary.read_bytes()),
        'source_commit': 'a956835d020762cb2b570053af06f643a11c0ecc',
        'script_sha256': digest(Path(__file__).read_bytes()), 'binary_snapshot_immutable': True,
        'actual_oauth': False, 'cross_account_load_qualified': False,
        'host_auth_read': False, 'external_network': False, 'client_tool_execution': False,
        'official_metrics_delivery': False, 'upstream_body_zstd_decoded': False,
        'wire_hashes_and_actual_identity_headers_checked': True,
        'requests_planned': args.requests, 'requests_observed': len(rows), 'concurrency': args.concurrency,
        'logical_sessions': args.sessions, 'counts': counts, 'actual_upstream_requests': len(upstream),
        'upstream_errors': backend_errors, 'controlled_gets': backend.gets, 'request_identity_isolated': bool(isolated),
        'invalid_requests_rejected': invalid_correct, 'persisted_attempt_states': states,
        'persistent_session_cache_window_domains_distinct': persistent_domains_distinct,
        'repeated_turn_requests': sum(row['repeated_turn_requested'] for row in rows),
        'memory_and_storage_samples': samples, 'shutdown_exit_codes': exits,
        'owned_gateway_alive': process is not None and process.poll() is None,
        'seconds': round(time.monotonic() - started, 3), 'failure_class': failure,
        'long_duration_pressure_qualified': False, 'deployed': False,
        'passed': not failure and len(rows) == args.requests and counts['completed'] >= args.requests * .8
            and counts['unknown'] == 0 and counts['transport_unknown'] == 0 and invalid_correct
            and isolated and not backend_errors and all(code == 0 for code in exits)}
    private_json(directory / 'report.json', report)
    print(json.dumps({'report': str(directory / 'report.json'), 'passed': report['passed'],
        'counts': counts, 'upstream': len(upstream), 'seconds': report['seconds'], 'failure_class': failure}))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
