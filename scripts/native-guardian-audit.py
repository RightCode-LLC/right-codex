#!/usr/bin/env python3
"""One bounded real Guardian approval inside an isolated client home/workspace.

The official client owns approval and tool execution. This driver refuses
interactive approvals and never grants escalated permissions. The gateway
remains a pure protocol process. Raw RPC/rollout/logs stay in private var/.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_rpc', ROOT / 'scripts/native-rpc-audit.py')
RPC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RPC)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def private(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)


def save(path, value):
    path.write_text(json.dumps(value, indent=2))
    path.chmod(0o600)


class GuardianRpc(RPC.Rpc):
    def __init__(self, *args, **kwargs):
        self.deadline = time.monotonic() + 240
        super().__init__(*args, **kwargs)

    def wait(self, predicate, timeout=300):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('guardian_audit_total_budget')
        return super().wait(predicate, min(timeout, remaining))


def private_rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def evidence_recheck(output):
    """Read sealed originals, never start processes or read a credential file.

    Session snapshots retain client input history, not canonical/outbound
    headers. Source attribution is derived from actual native lineage, the
    domain-salted local scope key, and actual completed network facts.
    """
    state = output / 'server-state'
    rpc_path = output / 'rpc-private.jsonl'
    rpc = private_rows(rpc_path)
    thread = next(row['result']['thread']['id'] for row in rpc
        if isinstance(row.get('result'), dict) and isinstance(row['result'].get('thread'), dict))
    turns = [row['params']['turn']['id'] for row in rpc if row.get('method') == 'turn/completed']
    domain_path = state / 'domain.json'
    domain = json.loads(domain_path.read_text())['id']
    evidence = [{'file': str(rpc_path.relative_to(output)), 'sha256': sha(rpc_path.read_bytes())},
        {'file': str(domain_path.relative_to(output)), 'sha256': sha(domain_path.read_bytes())}]
    guardians, models, identities = [], set(), {'native_parent_thread': thread}
    identities.update({'native_parent_turn:' + str(index): turn for index, turn in enumerate(turns)})
    for path in (output / 'client-home/sessions').rglob('*.jsonl'):
        native = private_rows(path)
        meta = next((row['payload'] for row in native if row.get('type') == 'session_meta'), None)
        for row in native:
            if row.get('type') == 'turn_context' and isinstance(row.get('payload', {}).get('model'), str):
                models.add(row['payload']['model'])
        if not meta or meta.get('source') != {'subagent': {'other': 'guardian'}}:
            continue
        evidence.append({'file': str(path.relative_to(output)), 'sha256': sha(path.read_bytes())})
        if not isinstance(meta.get('creator_account_id'), str):
            continue
        namespace = sha(len(domain.encode()).to_bytes(8, 'big') + domain.encode()
            + meta['creator_account_id'].encode())
        child = meta['id']
        local_key = sha(len(namespace.encode()).to_bytes(8, 'big') + namespace.encode()
            + len(child.encode()).to_bytes(8, 'big') + child.encode())
        snapshot_path = state / 'sessions' / (local_key + '.json')
        if not snapshot_path.is_file():
            continue
        snapshot = json.loads(snapshot_path.read_text())['session']
        evidence.append({'file': str(snapshot_path.relative_to(output)), 'sha256': sha(snapshot_path.read_bytes())})
        network = []
        for path in (state / 'facts').rglob('*.jsonl'):
            facts = [row['fact'] for row in private_rows(path)]
            started = next((row for row in facts if row.get('kind') == 'started'), None)
            terminal = next((row for row in reversed(facts) if row.get('kind') == 'terminal'), None)
            if not started or started['identity']['thread_id'] != snapshot['thread_id']:
                continue
            evidence.append({'file': str(path.relative_to(output)), 'sha256': sha(path.read_bytes())})
            network.append({'endpoint': started['identity']['endpoint'],
                'request_sha256': started['request_sha256'], 'wire_sha256': started['wire_sha256'],
                'outcome': terminal.get('outcome') if terminal else None})
        guardians.append({'source': meta['source'], 'native_parent_matches': meta.get('parent_thread_id') == thread,
            'native_child_sha256': sha(child.encode()), 'local_scope_key': local_key,
            'gateway_thread_differs_from_native': snapshot['thread_id'] != child,
            'network_facts': network})
    # Include actual native response/tool/review identifiers without printing
    # their values. These are compared against text, not treated as references.
    def ids(value, path):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in ('call_id', 'callId', 'response_id', 'responseId', 'reviewId', 'targetItemId') \
                        and isinstance(child, str) and len(child) >= 16:
                    identities.setdefault('native_rpc:' + path + '/' + key, child)
                ids(child, path + '/' + key)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                ids(child, path + '/' + str(index))
    ids(rpc, '')
    body_matches = []
    for path in (state / 'sessions').glob('*.json'):
        snapshot = json.loads(path.read_text())['session']
        for index, item in enumerate(snapshot.get('plaintext_history', [])):
            for part_index, part in enumerate(item.get('content', [])):
                text = part.get('text') if isinstance(part, dict) else None
                if not isinstance(text, str):
                    continue
                matched = [{'kind': kind, 'identity_sha256': sha(value.encode()), 'count': text.count(value)}
                    for kind, value in identities.items() if value in text]
                if matched:
                    evidence.append({'file': str(path.relative_to(output)), 'sha256': sha(path.read_bytes())})
                    body_matches.append({'file': str(path.relative_to(output)),
                        'path': f'/session/plaintext_history/{index}/content/{part_index}/text',
                        'text_sha256': sha(text.encode()), 'matches': matched,
                        'contains_fixed_reviewed_session_marker': text.startswith('Reviewed Codex session id: ')})
    return {'guardian_sources': guardians, 'actual_native_models': sorted(models),
        'guardian_parent_and_scope_network_proven': any(row['native_parent_matches']
            and row['gateway_thread_differs_from_native'] and any(fact['endpoint'] == '/responses'
                and fact['outcome'] == 'completed' for fact in row['network_facts']) for row in guardians),
        'outbound_header_original_archived': False, 'outbound_canonical_original_archived': False,
        'body_identity_matches': body_matches,
        'body_evidence_source': 'native_input_history_before_gateway_projection',
        'history_is_not_outbound_body': True,
        'outbound_projection_not_measured': True,
        'projection_source': 'src/session.rs:491-505 and src/native_context.rs',
        'native_marker_source': 'vendor/codex/codex-rs/guardian-context/src/composition.rs:223-227',
        'identity_isolation_proven': False,
        'evidence': sorted({row['file']: row for row in evidence}.values(), key=lambda row: row['file'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', type=Path)
    parser.add_argument('--auth', type=Path)
    parser.add_argument('--recheck', type=Path, help='Read sealed private evidence only; no processes or credentials')
    parser.add_argument('--gateway-binary', type=Path, default=ROOT / 'target/debug/right-codex')
    parser.add_argument('--model', default='gpt-6.1-sol')
    parser.add_argument('--proxy')
    args = parser.parse_args()
    if args.recheck:
        output = args.recheck.resolve(strict=True)
        original = output / 'report.json'
        original_report = json.loads(original.read_text())
        details = evidence_recheck(output)
        save(output / 'evidence-recheck.json', {'original_report_sha256': sha(original.read_bytes()),
            'script_sha256': sha(Path(__file__).read_bytes()), 'no_network_or_process': True,
            'functional_passed': all(value for key, value in original_report['checks'].items()
                if key != 'outbound_guardian_source_observed'), **details})
        print(json.dumps({'report': str(output / 'evidence-recheck.json'),
            'guardian_parent_and_scope_network_proven': details['guardian_parent_and_scope_network_proven'],
            'body_identity_match_count': len(details['body_identity_matches']),
            'identity_isolation_proven': False}))
        return
    if not args.client or not args.auth:
        parser.error('--client and --auth are required for a new actual scene')
    client = args.client.resolve(strict=True)
    assert subprocess.check_output([str(client), '--version'], text=True).strip() == 'codex-cli 0.160.0'
    assert 'daybreak' not in args.model.lower()
    material = args.auth.read_bytes()
    source_sha = sha(material)
    output = ROOT / 'var/verification' / ('native-guardian-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8])
    private(output)
    home, work = output / 'client-home', output / 'workspace'
    private(home)
    private(work)
    (home / 'auth.json').write_bytes(material)
    (home / 'auth.json').chmod(0o600)
    # A prompt rule asks for approval without requesting a broader sandbox.
    # Fixed execpolicy rules are local to this newly created private home.
    private(home / 'rules')
    (home / 'rules/audit.rules').write_text('prefix_rule(pattern=["python3"], decision="prompt")\n')
    (home / 'rules/audit.rules').chmod(0o600)
    (home / 'config.toml').write_text('''approvals_reviewer = "auto_review"
approval_policy = "on-request"
sandbox_mode = "workspace-write"
[features]
guardian_approval = true
[features.guardianv2]
enabled = true
persist_scores = true
review_threshold = 0.0
[features.guardianv2.review_scope]
computer_use_only = false
sandboxed_exec_commands = true
''')
    (home / 'config.toml').chmod(0o600)
    config, state = output / 'gateway.json', output / 'server-state'
    save(config, {'listen': '127.0.0.1:0', 'admin_token': 'isolated-guardian-admin',
        'state_dir': str(state), 'scheduling': {'max_sessions_by_account_age': [32] * 5, 'startup_spacing_secs': 0},
        'accounts': [{'id': 'readonly-guardian-import', 'auth_path': str(args.auth.resolve()),
            'proxy': args.proxy, 'enabled': True}]})
    binary = output / 'gateway-executable'
    binary.write_bytes(args.gateway_binary.resolve(strict=True).read_bytes())
    binary.chmod(0o500)
    environment = dict(os.environ, NO_COLOR='1')
    for name in ['OPENAI_BASE_URL', 'CODEX_ACCESS_TOKEN', 'OPENAI_API_KEY', 'CODEX_API_KEY',
            'CODEX_HOME', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']:
        environment.pop(name, None)
    log = (output / 'gateway.log').open('w')
    (output / 'gateway.log').chmod(0o600)
    gateway = subprocess.Popen([str(binary), str(config)], stdout=log, stderr=subprocess.STDOUT, env=environment)
    rpc = None
    report = {'source_commit': 'a956835d020762cb2b570053af06f643a11c0ecc',
        'binary_sha256': sha(binary.read_bytes()), 'client_sha256': sha(client.read_bytes()),
        'script_sha256': sha(Path(__file__).read_bytes()), 'host_auth_readonly': True,
        'gateway_starts_native_client': False, 'escalated_permission_requested': False,
        'interactive_approval_granted': False, 'passed': False, 'checks': {},
        'functional_scope_only': True, 'outbound_projection_live_captured': False,
        'projection_reference_files': {str(path): sha((ROOT / path).read_bytes())
            for path in ['src/native_context.rs', 'src/session.rs', 'tests/native_context.rs']}}
    started_at = time.monotonic()
    try:
        for _ in range(100):
            if gateway.poll() is not None:
                raise RuntimeError('gateway_start_failed')
            match = re.search(r'127\.0\.0\.1:(\d+)', (output / 'gateway.log').read_text())
            if match:
                port = int(match[1])
                break
            time.sleep(.1)
        else:
            raise TimeoutError('gateway_ready')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        request = urllib.request.Request(f'http://127.0.0.1:{port}/v1/models?client_version=0.160.0',
            headers={'Authorization': 'Bearer isolated-client-native-oauth'})
        with opener.open(request, timeout=30) as response:
            catalog = json.load(response)
        save(output / 'catalog-private.json', catalog)
        models = {row.get('slug') or row.get('id'): row for row in catalog['models']}
        assert args.model in models, 'parent_model_not_in_actual_catalog'
        assert 'gpt-5.6-luna' in models, 'guardian_classifier_not_in_actual_catalog'
        override = models[args.model].get('auto_review_model_override')
        assert not override or ('daybreak' not in override.lower() and override in models), 'reviewer_override_not_admitted'
        report['model_selection'] = {'parent': args.model, 'classifier': 'gpt-5.6-luna',
            'parent_auto_review_override': override, 'catalog_contains_codex_auto_review': 'codex-auto-review' in models}
        # Rpc constructor reads os.environ, so pass the cleaned environment by
        # temporarily wrapping only this Popen call; do not mutate process env.
        class IsolatedRpc(GuardianRpc):
            def __init__(self):
                self.deadline = time.monotonic() + 240
                self.log = (output / 'rpc-private.jsonl').open('w')
                (output / 'rpc-private.jsonl').chmod(0o600)
                self.stderr = (output / 'rpc-stderr.log').open('w')
                (output / 'rpc-stderr.log').chmod(0o600)
                self.process = subprocess.Popen([str(client), 'app-server', '-c',
                    f'openai_base_url="http://127.0.0.1:{port}/v1"', '-c', f'model="{args.model}"'],
                    cwd=work, env=dict(environment, CODEX_HOME=str(home)), stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=self.stderr, text=True)
                self.queue = RPC.queue.Queue()
                self.pending, self.events, self.counter = [], [], 0
                self.reader = RPC.threading.Thread(target=self.read, daemon=True)
                self.reader.start()
        rpc = IsolatedRpc()
        rpc.call('initialize', {'clientInfo': {'name': 'codex_cli_rs', 'title': 'Isolated Guardian audit',
            'version': '0.160.0'}, 'capabilities': {'experimentalApi': True}})
        rpc.send({'method': 'initialized', 'params': {}})
        started = rpc.call('thread/start', {'cwd': str(work), 'model': args.model,
            'approvalPolicy': 'on-request', 'approvalsReviewer': 'auto_review', 'sandbox': 'workspace-write'})
        thread = started['thread']['id']
        command = 'python3 -c "from pathlib import Path; Path(\'guardian-proof.txt\').write_text(\'GUARDIAN_FILE_OK\\n\')"'
        prompt = ('In this isolated working directory execute exactly this harmless command with the native shell tool: '
            + command + '. Use the default workspace sandbox. Do not request any elevated/additional permissions. '
            'The local approval policy will review it automatically. Do not substitute another tool or command. '
            'After the command succeeds, reply exactly GUARDIAN_NORMAL_OK. Do not access any other path or network.')
        turn = rpc.call('turn/start', {'threadId': thread, 'input': [{'type': 'text', 'text': prompt, 'textElements': []}]})
        completed = rpc.completed_turn(thread, turn['turn']['id'])
        started_reviews = [row['params'] for row in rpc.events if row.get('method') == 'item/autoApprovalReview/started']
        completed_reviews = [row['params'] for row in rpc.events if row.get('method') == 'item/autoApprovalReview/completed']
        commands = [row['params']['item'] for row in rpc.events if row.get('method') == 'item/completed'
            and row.get('params', {}).get('item', {}).get('type') == 'commandExecution']
        messages = [row['params']['item'] for row in rpc.events if row.get('method') == 'item/completed'
            and row.get('params', {}).get('item', {}).get('type') == 'agentMessage']
        approved = [review for review in completed_reviews if review.get('review', {}).get('status') == 'approved'
            and review.get('threadId') == thread and review.get('turnId') == turn['turn']['id']]
        safe = all('require_escalated' not in json.dumps(row) and 'with_additional_permissions' not in json.dumps(row)
            for row in commands)
        marker = work / 'guardian-proof.txt'
        details = evidence_recheck(output)
        save(output / 'outbound-role-facts.json', details)
        report['actual_review_decisions'] = [{'review_id_sha256': sha(row['reviewId'].encode()),
            'status': row['review']['status'], 'risk_level': row['review'].get('riskLevel'),
            'decision_source': row.get('decisionSource'), 'same_native_parent': row.get('threadId') == thread
                and row.get('turnId') == turn['turn']['id']} for row in completed_reviews]
        report['checks'] = {'turn_completed': completed['status'] == 'completed',
            'actual_review_started': bool(started_reviews), 'actual_review_approved_same_parent': bool(approved),
            'native_command_completed': any(row.get('exitCode') == 0 for row in commands),
            'only_default_permission_command': safe,
            'workspace_marker_exact': marker.exists() and marker.read_text() == 'GUARDIAN_FILE_OK\n',
            'normal_business_resumed': any(row.get('text', '').strip() == 'GUARDIAN_NORMAL_OK' for row in messages),
            'outbound_guardian_source_observed': details['guardian_parent_and_scope_network_proven']}
        report['identity_isolation_proven'] = False
        report['outbound_original_headers_archived'] = False
        report['native_terminal_status'] = completed['status']
        report['functional_passed'] = all(report['checks'].values())
        # Client input is retained for continuation; its original marker does
        # not describe the outgoing projection or fail this functional scene.
        report['passed'] = report['functional_passed']
    except Exception as error:
        report['stopped_reason'] = type(error).__name__ + ':' + str(error)
    finally:
        if rpc is not None:
            rpc.close()
        gateway.send_signal(signal.SIGTERM)
        try:
            gateway.wait(timeout=15)
        except subprocess.TimeoutExpired:
            gateway.kill()
            gateway.wait(timeout=5)
        log.close()
        report['gateway_exit_code'] = gateway.returncode
        report['source_auth_unchanged'] = sha(args.auth.read_bytes()) == source_sha
        report['owned_native_alive'] = rpc is not None and rpc.process.poll() is None
        report['owned_gateway_alive'] = gateway.poll() is None
        report['seconds'] = round(time.monotonic() - started_at, 3)
        report['passed'] &= report['source_auth_unchanged'] and gateway.returncode == 0
        save(output / 'report.json', report)
    print(json.dumps({'report': str(output / 'report.json'), 'passed': report['passed'],
        'checks': report['checks'], 'stopped_reason': report.get('stopped_reason'),
        'seconds': report['seconds'], 'source_auth_unchanged': report['source_auth_unchanged']}))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
