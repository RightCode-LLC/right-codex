#!/usr/bin/env python3
"""Isolated config + complete private-state backup and relocation audit.

Uses a copied executable, synthetic OAuth and owned loopback listeners only.
No host auth, real upstream, existing service, client home or Cargo is used.
"""
import argparse
import base64
import hashlib
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import shutil
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('bounded_audit', ROOT / 'scripts/bounded-load-audit.py')
BOUNDED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOUNDED)
CANONICAL = 'x-codex-turn-metadata'
ADMIN = 'SYNTHETIC_BACKUP_ADMIN'
CLIENT_THREAD = 'client-source-backup-thread'
CLIENT_SESSION = 'client-source-backup-session'
CLIENT_TURN = 'client-source-backup-turn-first'
PNG = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wl6S3EAAAAASUVORK5CYII='


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def manifest(directory):
    result = {}
    for path in sorted(directory.rglob('*')):
        assert not path.is_symlink(), 'private_backup_symlink'
        if path.is_file():
            result[str(path.relative_to(directory))] = {'sha256': sha(path.read_bytes()),
                'bytes': path.stat().st_size, 'mode': path.stat().st_mode & 0o777}
    return result


def fetch(port, path, value=None, method=None, headers=None):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
    try:
        merged = {'Content-Type': 'application/json', **(headers or {})}
        body = None if value is None else json.dumps(value)
        conn.request(method or ('GET' if value is None else 'POST'), path, body, merged)
        response = conn.getresponse()
        raw = response.read(4 * 1024 * 1024)
        assert len(raw) < 4 * 1024 * 1024, 'bounded_client_reply'
        if response.getheader('Content-Type', '').startswith('text/event-stream'):
            parsed = [json.loads(line[6:]) for line in raw.decode().splitlines()
                if line.startswith('data: ')]
        else:
            parsed = json.loads(raw)
        return response.status, parsed
    finally:
        conn.close()


def admin(port, path, value=None, method=None):
    status, response = fetch(port, path, value, method, {'Authorization': 'Bearer ' + ADMIN})
    assert status == 200, 'admin_http_' + str(status)
    return response


class Backend(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(('127.0.0.1', 0), Handler)
        self.lock = threading.Lock()
        self.requests = []
        self.errors = []
        self.metric_posts = 0


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def reply(self, status, value, content_type='application/json'):
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
        self.wfile.flush()

    def do_GET(self):
        if self.path.endswith('/wham/accounts/check'):
            self.reply(200, {'accounts': [{'id': 'synthetic-upstream-workspace'}],
                'default_account_id': 'synthetic-upstream-workspace'})
        else:
            self.reply(200, {'rate_limit': {'allowed': True, 'limit_reached': False,
                'primary_window': {'used_percent': 0, 'limit_window_seconds': 18000,
                    'reset_after_seconds': 3600, 'reset_at': 1900000000}}})

    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length', '0'))
            assert 0 < length < 4 * 1024 * 1024, 'bounded_upstream_request'
            raw = self.rfile.read(length)
            assert len(raw) == length, 'request_body_eof'
            if self.path == '/otlp/v1/metrics':
                with self.server.lock:
                    self.server.metric_posts += 1
                # Actual failed delivery, not a manufactured pending file.
                return self.reply(503, {'error': 'controlled_collector_unavailable'})
            assert self.headers.get('Authorization') == 'Bearer SYNTHETIC_UPSTREAM_OAUTH'
            assert self.headers.get('chatgpt-account-id') == 'synthetic-upstream-workspace'
            for name in ['thread-id', 'session-id', 'x-client-request-id',
                    CANONICAL, 'x-codex-image-turn-id']:
                assert 'client-source-' not in self.headers.get(name, ''), 'client_identity_leak'
            row = {'path': self.path, 'wire_sha256': sha(raw), 'wire_bytes': length,
                'content_encoding': self.headers.get('Content-Encoding')}
            if self.path.endswith('/responses'):
                metadata = json.loads(self.headers[CANONICAL])
                assert metadata['thread_id'] == self.headers['thread-id']
                assert metadata['session_id'] == self.headers['session-id']
                row.update(thread_id=self.headers['thread-id'], session_id=self.headers['session-id'],
                    turn_id=metadata['turn_id'], response_id='resp_' + uuid.uuid4().hex,
                    item_id='msg_' + uuid.uuid4().hex)
                item = {'type': 'message', 'id': row['item_id'], 'role': 'assistant',
                    'content': [{'type': 'output_text', 'text': 'BACKUP_RESTORE_OK', 'annotations': []}]}
                events = [{'type': 'response.created', 'response': {'id': row['response_id'], 'status': 'in_progress'}},
                    {'type': 'response.output_item.done', 'response_id': row['response_id'], 'item': item},
                    {'type': 'response.completed', 'response': {'id': row['response_id'],
                        'status': 'completed', 'output': [item],
                        'usage': {'input_tokens': 2, 'output_tokens': 2, 'total_tokens': 4}}}]
                payload = ''.join('event: ' + e['type'] + '\ndata: ' + json.dumps(e) + '\n\n' for e in events).encode()
                content_type = 'text/event-stream'
            elif self.path.endswith('/images/generations') or self.path.endswith('/images/edits'):
                assert self.headers.get('Content-Encoding') is None
                body = json.loads(raw)
                row['turn_id'] = self.headers['x-codex-image-turn-id']
                if self.path.endswith('/images/edits'):
                    assert body['images'][0] == {'image_url': 'data:image/png;base64,' + PNG}
                    row['restored_source_bytes_matched'] = True
                payload = {'created': 1, 'data': [{'b64_json': PNG, 'generation_id': 'upstream-image-id'}]}
                content_type = 'application/json'
            else:
                raise AssertionError('unexpected_upstream_endpoint')
            with self.server.lock:
                self.server.requests.append(row)
            self.reply(200, payload, content_type)
        except Exception as error:
            with self.server.lock:
                self.server.errors.append(type(error).__name__ + ':' + str(error))
            try:
                self.reply(500, {'error': 'controlled_backend_assertion'})
            except OSError:
                pass


def response_request(port, turn, previous=None):
    metadata = {'request_kind': 'turn', 'thread_id': CLIENT_THREAD,
        'session_id': CLIENT_SESSION, 'turn_id': turn}
    body = {'model': 'synthetic-model', 'stream': True,
        'input': [{'type': 'message', 'id': 'msg_' + uuid.uuid4().hex,
            'role': 'user', 'content': [{'type': 'input_text', 'text': 'controlled backup test'}]}],
        'client_metadata': {CANONICAL: json.dumps(metadata)}}
    if previous:
        body['previous_response_id'] = previous
    status, events = fetch(port, '/v1/responses', body, headers={
        'Authorization': 'Bearer SYNTHETIC_CLIENT_OAUTH', 'chatgpt-account-id': 'client-source-workspace',
        'thread-id': CLIENT_THREAD, 'session-id': CLIENT_SESSION, CANONICAL: json.dumps(metadata),
        'originator': 'codex_cli_rs', 'User-Agent': 'codex_cli_rs/0.160.0 (controlled backup fixture)'})
    assert status == 200, 'responses_http_' + str(status)
    completed = [event for event in events if event['type'] == 'response.completed']
    assert len(completed) == 1, 'actual_completed_terminal'
    return completed[0]['response']['id']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/debug/right-codex')
    args = parser.parse_args()
    source_binary = args.binary.resolve(strict=True)
    assert source_binary.is_file() and os.access(source_binary, os.X_OK)
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8]
    directory = ROOT / 'var/verification' / ('backup-restore-' + stamp)
    directory.mkdir(mode=0o700, parents=True)
    binary = directory / 'gateway-executable'
    binary.write_bytes(source_binary.read_bytes())
    binary.chmod(0o500)
    binary_sha = sha(binary.read_bytes())
    backend = Backend()
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    original = directory / 'original'
    original.mkdir(mode=0o700)
    original_state = original / 'state'
    original_state.mkdir(mode=0o700)
    claims = {'email': 'synthetic@example.invalid', 'exp': 3000000000,
        'https://api.openai.com/auth': {'chatgpt_account_id': 'synthetic-upstream-workspace',
            'chatgpt_plan_type': 'plus'}}
    token = 'e30.' + base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode() + '.fixture'
    auth = directory / 'synthetic-import-auth.json'
    BOUNDED.private_json(auth, {'auth_mode': 'chatgpt', 'tokens': {'id_token': token,
        'access_token': 'SYNTHETIC_UPSTREAM_OAUTH', 'refresh_token': 'synthetic-refresh',
        'account_id': 'synthetic-upstream-workspace'}, 'last_refresh': '2026-10-10T00:00:00Z'})
    port = BOUNDED.free_port()
    config_value = {'listen': '127.0.0.1:' + str(port), 'state_dir': 'state', 'admin_token': ADMIN,
        'base_url': 'http://127.0.0.1:' + str(backend.server_port) + '/backend-api/codex',
        'chatgpt_base_url': 'http://127.0.0.1:' + str(backend.server_port) + '/backend-api',
        'oauth_issuer': 'http://127.0.0.1:' + str(backend.server_port), 'allow_insecure_http': True,
        'request_timeout_secs': 10, 'queue_timeout_secs': 10,
        'telemetry': {'official_metrics_enabled': True, 'allow_loopback_http': True,
            'otlp_endpoint': 'http://127.0.0.1:' + str(backend.server_port) + '/otlp/v1/metrics'},
        'scheduling': {'startup_spacing_secs': 0},
        'accounts': [{'id': 'synthetic-account', 'auth_path': str(auth), 'enabled': True}]}
    config = original / 'config.json'
    BOUNDED.private_json(config, config_value)
    process = None
    exits = []
    checks = {}
    failure = None
    started = time.monotonic()
    try:
        process = BOUNDED.start_gateway(binary, config, port, directory, 0)
        first_alias = response_request(port, CLIENT_TURN)
        status, generated = fetch(port, '/v1/images/generations', {'model': 'gpt-image-1', 'prompt': 'controlled'},
            headers={'Authorization': 'Bearer SYNTHETIC_CLIENT_OAUTH', 'chatgpt-account-id': 'client-source-workspace',
                'x-codex-image-turn-id': CLIENT_TURN})
        assert status == 200, 'image_generation_http_' + str(status)
        image_alias = generated['data'][0]['generation_id']
        settings = {'max_sessions_by_account_age': [5, 7, 9, 11, 13], 'idle_timeout_secs': 123,
            'startup_spacing_secs': 0, 'rest_interval_minutes': 0, 'rest_percent': 0, 'rest_duration_minutes': 0}
        assert admin(port, '/admin/api/settings', settings, 'PATCH') == settings
        facts_before = admin(port, '/admin/api/facts')['facts']
        assert any(row['outcome'] == 'completed' for row in facts_before)
        exits.append(BOUNDED.stop_gateway(process))
        process = None
        assert exits[-1] == 0, 'first_sigterm_exit'
        before = manifest(original_state)
        assert any(path.endswith('.jsonl') for path in before), 'actual_persistent_network_facts'
        assert any(path.endswith('.attempted') for path in before), 'actual_metric_attempted_delivery'
        assert any(path.startswith('generated-images/') for path in before), 'actual_generated_resource'
        snapshot_paths = list((original_state / 'sessions').glob('*.json'))
        assert len(snapshot_paths) == 1
        original_snapshot = json.loads(snapshot_paths[0].read_text())['session']
        # The completed alias's persisted history still contains its actual source item.
        snapshot_text = json.dumps(original_snapshot)
        assert backend.requests[0]['item_id'] in snapshot_text
        restored = directory / 'relocated'
        restored.mkdir(mode=0o700)
        shutil.copytree(original_state, restored / 'state', copy_function=shutil.copy2)
        assert manifest(restored / 'state') == before, 'exact_complete_private_backup'
        restored_config = restored / 'config.json'
        BOUNDED.private_json(restored_config, config_value)
        auth.unlink()  # Startup must restore the private home without reopening the import source.
        original.rename(directory / 'original-retired')
        process = BOUNDED.start_gateway(binary, restored_config, port, directory, 1)
        assert admin(port, '/admin/api/settings') == settings, 'restored_schedule'
        assert admin(port, '/admin/api/facts')['facts'] == [], 'documented_process_local_http_fact_list'
        deliveries = admin(port, '/admin/api/telemetry/deliveries')['accounts'][0]['deliveries']
        assert deliveries and all(row['state'] == 'attempted' for row in deliveries)
        metric_before = backend.metric_posts
        second_alias = response_request(port, 'client-source-backup-turn-second', first_alias)
        assert second_alias != first_alias
        status, edited = fetch(port, '/v1/images/edits', {'model': 'gpt-image-1', 'prompt': 'controlled edit',
            'images': [{'file_id': image_alias}]}, headers={'Authorization': 'Bearer SYNTHETIC_CLIENT_OAUTH',
            'chatgpt-account-id': 'client-source-workspace', 'x-codex-image-turn-id': CLIENT_TURN})
        assert status == 200, 'restored_image_edit_http_' + str(status)
        assert edited['data'][0]['generation_id'] != image_alias
        exits.append(BOUNDED.stop_gateway(process))
        process = None
        assert exits[-1] == 0, 'restored_sigterm_exit'
        after = manifest(restored / 'state')
        for path, evidence in before.items():
            if path.startswith('facts/') or path.endswith('.attempted') or path.startswith('generated-images/'):
                assert after[path] == evidence, 'original_private_fact_or_resource_mutated'
        current_snapshot = json.loads((restored / 'state/sessions' / snapshot_paths[0].name).read_text())['session']
        for key in ['thread_id', 'session_id', 'installation_id', 'cache_key', 'window_id', 'context_window_id']:
            assert current_snapshot[key] == original_snapshot[key], 'restored_scope_identity_' + key
        responses = [row for row in backend.requests if row['path'].endswith('/responses')]
        assert len(responses) == 2 and responses[0]['thread_id'] == responses[1]['thread_id']
        assert responses[0]['session_id'] == responses[1]['session_id']
        assert not backend.errors
        checks = {'sigterm_zero_twice': True, 'complete_backup_manifest_identical': True,
            'restore_without_import_source': True, 'private_scope_and_actual_source_history_inherited': True,
            'previous_completed_alias_accepted_after_relocation': True, 'client_ids_not_in_outbound_identity': True,
            'generated_image_source_bytes_restored_for_edit': True, 'scheduling_restored': True,
            'persistent_network_fact_files_immutable': True, 'attempted_metric_delivery_state_preserved': True,
            'http_fact_list_is_process_local': True, 'new_metric_posts_after_restore': backend.metric_posts - metric_before}
        BOUNDED.private_json(directory / 'backup-manifest.json', before)
        BOUNDED.private_json(directory / 'restored-manifest.json', after)
    except Exception as error:
        failure = type(error).__name__ + ':' + str(error)
    finally:
        if process is not None:
            exits.append(BOUNDED.stop_gateway(process))
        backend.shutdown()
        backend.server_close()
    report = {'scope': 'synthetic_oauth_private_state_backup_relocation', 'passed': failure is None,
        'binary_sha256': binary_sha, 'script_sha256': sha(Path(__file__).read_bytes()),
        'helper_sha256': sha((ROOT / 'scripts/bounded-load-audit.py').read_bytes()),
        'source_commit': 'a956835d020762cb2b570053af06f643a11c0ecc', 'checks': checks,
        'failure': failure, 'shutdown_exit_codes': exits, 'controlled_upstream': backend.requests,
        'controlled_backend_errors': backend.errors, 'actual_metric_posts': backend.metric_posts,
        'host_auth_read': False, 'external_network': False, 'real_oauth': False, 'deployed': False,
        'outbound_compressed_responses_body_decoded': False,
        'limitations': ['Config accompanies the complete private state; endpoint and account slot identities remain unchanged.',
            'HTTP admin FactStore is process-local; JSONL network facts are persistent.',
            'Runtime capacity, rest, quota cooldown, live lease and OAuth job state are transient.',
            'This run tests a configured import account, not dynamic OAuth registry relocation.',
            '503 collector outcomes remain attempted/unknown; no remote point acceptance is inferred.',
            'Partial/corrupt backups and cross-version migrations are not qualified.'],
        'seconds': round(time.monotonic() - started, 3), 'owned_gateway_alive': process is not None and process.poll() is None}
    BOUNDED.private_json(directory / 'report.json', report)
    print(json.dumps({'report': str(directory / 'report.json'), 'passed': report['passed'],
        'failure': failure, 'seconds': report['seconds']}))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
