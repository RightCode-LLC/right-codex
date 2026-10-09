#!/usr/bin/env python3
"""Isolated real-native audit; credentials/raw logs remain private in var/.
Never mutates source auth or an existing client home. It is a test driver, not
part of the pure protocol gateway runtime.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import signal
import subprocess
import time
from native_audit_evidence import evidence, rows, make_image, rollout, direct_history, attempt_ids, midpoint_projection

ROOT = pathlib.Path(__file__).resolve().parents[1]
CLI_CASES = {'ordinary', 'tools', 'websearch', 'subagent', 'image', 'file', 'resume', 'midway'}
RPC_CASES = {'rpc_initial', 'compact', 'after_compact', 'review', 'image_generate', 'image_edit'}


def private(path):
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def execute(command, environment, log):
    start = time.monotonic()
    timed_out = False
    with log.open('w') as stream:
        log.chmod(0o600)
        try:
            result = subprocess.run(command, env=environment, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=300)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code, timed_out = None, True
    return {'exit_code': code, 'seconds': round(time.monotonic() - start, 3),
            'timed_out': timed_out, 'private_log': str(log.relative_to(ROOT))}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--auth', required=True, type=pathlib.Path)
    parser.add_argument('--client', required=True, type=pathlib.Path)
    parser.add_argument('--gateway-binary', type=pathlib.Path, default=ROOT / 'target/debug/right-codex')
    parser.add_argument('--proxy')
    parser.add_argument('--model', default='gpt-6.1-sol')
    parser.add_argument('--ordinary-only', action='store_true')
    parser.add_argument('--rpc-only', action='store_true')
    parser.add_argument('--cases', help='Comma-separated scenarios; rpc expands rpc_initial,compact,after_compact,review,image_generate,image_edit')
    args = parser.parse_args()
    selected = CLI_CASES | RPC_CASES
    if args.cases:
        selected = {name.strip() for name in args.cases.split(',')}
        if 'rpc' in selected:
            selected.remove('rpc')
            selected |= RPC_CASES
        if not selected or selected - CLI_CASES - RPC_CASES:
            parser.error('Unknown or empty audit scenario')
        if args.ordinary_only or args.rpc_only:
            parser.error('--cases cannot be combined with the legacy single-mode flags')
    elif args.ordinary_only:
        selected = {'ordinary'}
    elif args.rpc_only:
        selected = RPC_CASES
    if 'resume' in selected:
        selected.add('ordinary')
    if 'image_edit' in selected:
        selected.add('image_generate')
    version = subprocess.check_output([str(args.client.resolve()), '--version'], text=True).strip()
    assert version == 'codex-cli 0.160.0', version
    material = args.auth.read_bytes()
    before = hashlib.sha256(material).hexdigest()
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + str(time.time_ns() % 1_000_000_000)
    output = ROOT / 'var' / 'verification' / ('real-oauth-' + stamp)
    if output.exists():
        raise RuntimeError('Audit output already exists; choose a new run time')
    private(output)
    home = output / 'client-home'
    private(home)
    (home / 'auth.json').write_bytes(material)
    (home / 'auth.json').chmod(0o600)
    work = output / 'workspace'
    private(work)
    (work / 'fixture.txt').write_text('audit fixture value = 42\n')
    (work / 'attachment.txt').write_text('isolated file marker = FILE_COBALT_42\n')
    make_image(work / 'red-blue.png')
    subprocess.run(['git', 'init', '-q', str(work)], check=True)
    subprocess.run(['git', '-C', str(work), 'add', 'fixture.txt', 'attachment.txt', 'red-blue.png'], check=True)
    subprocess.run(['git', '-C', str(work), '-c', 'user.name=Protocol Audit', '-c',
                    'user.email=audit@localhost', 'commit', '-qm', 'isolated fixture'], check=True)
    state = output / 'server-state'
    config = output / 'gateway.json'
    config.write_text(json.dumps({'listen': '127.0.0.1:0', 'admin_token': 'local-audit-only',
        'state_dir': str(state), 'scheduling': {'max_sessions_by_account_age': [128] * 5, 'startup_spacing_secs': 0},
        'accounts': [{'id': 'readonly-host-import', 'auth_path': str(args.auth.resolve()),
                      'proxy': args.proxy, 'enabled': True}]}))
    config.chmod(0o600)
    gateway_log = open(output / 'gateway.log', 'w+')
    os.chmod(output / 'gateway.log', 0o600)
    gateway_binary = args.gateway_binary.resolve()
    if not gateway_binary.is_file() or not os.access(gateway_binary, os.X_OK):
        raise RuntimeError('Gateway binary is not executable')
    gateway = subprocess.Popen([str(gateway_binary), str(config)],
        stdout=gateway_log, stderr=subprocess.STDOUT, env=dict(os.environ, NO_COLOR='1'))
    results = {'client_version': version, 'source_auth_sha256_before': before,
               'gateway_binary_sha256': hashlib.sha256(gateway_binary.read_bytes()).hexdigest(),
               'requested_cases': sorted(selected), 'scenarios': [], 'deployed': False}
    try:
        port = None
        for _ in range(100):
            if gateway.poll() is not None:
                raise RuntimeError('Gateway exited; inspect private log')
            gateway_log.flush()
            match = re.search(r'127\.0\.0\.1:(\d+)', (output / 'gateway.log').read_text())
            if match:
                port = int(match[1])
                break
            time.sleep(.1)
        if port is None:
            raise RuntimeError('No gateway readiness')
        base = f'http://127.0.0.1:{port}/v1'
        common = [str(args.client.resolve()), 'exec', '--ignore-user-config', '--skip-git-repo-check',
                  '-C', str(work), '-s', 'workspace-write', '-m', args.model,
                  '-c', f'openai_base_url="{base}"', '--json']
        environment = dict(os.environ, CODEX_HOME=str(home), NO_COLOR='1')
        session = None
        cases = [
            ('ordinary', 'Reply exactly HTTP_AUDIT_OK. Do not use tools.', [], 'HTTP_AUDIT_OK'),
            ('tools', 'Read fixture.txt using a shell tool, then report its value.', [], 'audit fixture value = 42'),
            ('websearch', 'Use the native web search tool to find the official OpenAI Codex GitHub repository. Return its URL. Do not use shell, curl or any local command for this task.', ['-c', 'web_search="live"'], None),
            ('subagent', 'Spawn one subagent to read fixture.txt with a shell tool. Wait for the subagent to finish and report its value.', [], 'audit fixture value = 42'),
            ('image', 'Describe the attached image. Reply only the left color followed by the right color in English. Do not use tools.', ['--image', str(work / 'red-blue.png'), '--'], None),
            ('file', 'Read the local attachment.txt using a shell tool and report its exact marker. This tests local file input via native client execution.', [], 'FILE_COBALT_42'),
        ]
        for name, prompt, extra, expected in cases:
            if name not in selected:
                continue
            log = output / (name + '.jsonl')
            result = execute(common + extra + [prompt], environment, log)
            result.update(evidence(rows(log), name, home, expected))
            result['passed'] = result['passed'] and result['exit_code'] == 0
            result['name'] = name
            if name == 'file':
                result['file_contract'] = 'client_local_file_read_and_model_tool_output; not native multipart Files upload'
            results['scenarios'].append(result)
            if name == 'ordinary':
                session = result['thread_id']
        if 'resume' in selected:
            log = output / 'resume.jsonl'
            if session:
                result = execute(common + ['resume', session, 'What marker did you reply in our first turn? Reply with that marker only. Do not use tools.'], environment, log)
                result.update(evidence(rows(log), 'resume', home, 'HTTP_AUDIT_OK', session))
                result['passed'] = result['passed'] and result['exit_code'] == 0
                results['scenarios'].append({'name': 'resume', **result})
            else:
                results['scenarios'].append({'name': 'resume', 'passed': False, 'reason': 'ordinary_thread_missing'})
        if selected & RPC_CASES:
            spec = importlib.util.spec_from_file_location('native_rpc_audit', ROOT / 'scripts/native-rpc-audit.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            results['scenarios'].extend(module.run(args.client.resolve(), home, work, base, output,
                                                  args.model, selected & RPC_CASES))
        if 'midway' in selected:
            direct_home = output / 'midway-client-home'
            private(direct_home)
            (direct_home / 'auth.json').write_bytes(material)
            (direct_home / 'auth.json').chmod(0o600)
            direct_environment = dict(environment, CODEX_HOME=str(direct_home))
            direct_command = [str(args.client.resolve()), 'exec', '--ignore-user-config', '--skip-git-repo-check',
                              '-C', str(work), '-s', 'read-only', '-m', args.model, '--json']
            direct_log = output / 'midway-direct.jsonl'
            result = execute(direct_command + ['Remember JADE-73. Reply exactly JADE-73. Do not use tools.'],
                             direct_environment, direct_log)
            result.update(evidence(rows(direct_log), 'midway_direct', direct_home, 'JADE-73'))
            result['passed'] = result['passed'] and result['exit_code'] == 0
            results['scenarios'].append({'name': 'midway_direct', **result})
            if result['passed']:
                direct_thread = result['thread_id']
                prior_rollout, _ = rollout(direct_home, direct_thread)
                prior_ids, prior_ciphers = direct_history(prior_rollout)
                prior_ids.add(direct_thread)
                previous_attempts = attempt_ids(state)
                log = output / 'midway-gateway-resume.jsonl'
                continued = execute(direct_command + ['-c', f'openai_base_url="{base}"', 'resume', direct_thread,
                    'What marker did I ask you to remember? Reply with that marker only. Do not use tools.'],
                    direct_environment, log)
                continued.update(evidence(rows(log), 'midway_resume', direct_home, 'JADE-73', direct_thread))
                projection = midpoint_projection(state, previous_attempts, prior_ids, prior_ciphers)
                continued['midway_isolation'] = projection
                continued['passed'] = continued['passed'] and continued['exit_code'] == 0 and projection['passed']
                results['scenarios'].append({'name': 'midway_gateway_resume', **continued})
            else:
                results['scenarios'].append({'name': 'midway_gateway_resume', 'passed': False,
                                             'reason': 'direct_oauth_prerequisite_failed'})
    except Exception as error:
        results['stopped_reason'] = type(error).__name__
    finally:
        gateway.send_signal(signal.SIGINT)
        try:
            gateway.wait(timeout=15)
        except subprocess.TimeoutExpired:
            gateway.kill()
            gateway.wait()
        gateway_log.close()
        from native_audit_evidence import completed_endpoints
        endpoints = completed_endpoints(state)
        for scenario in results['scenarios']:
            expected = {'image_generate': '/images/generations', 'image_edit': '/images/edits'}.get(scenario['name'])
            if expected:
                confirmed = endpoints.get(expected, 0) > 0
                scenario.setdefault('checks', {})['actual_auxiliary_endpoint_completed'] = confirmed
                scenario['passed'] = scenario.get('passed', False) and confirmed
        results['source_auth_unchanged'] = before == hashlib.sha256(args.auth.read_bytes()).hexdigest()
        results['all_passed'] = bool(results['scenarios']) and all(result.get('passed') for result in results['scenarios']) and not results.get('stopped_reason')
        report = output / 'report.json'
        report.write_text(json.dumps(results, ensure_ascii=False, indent=2))
        report.chmod(0o600)
        print(json.dumps({'report': str(report), 'source_auth_unchanged': results['source_auth_unchanged'],
                          'all_passed': results['all_passed'],
                          'scenarios': [{key: value for key, value in result.items() if key != 'thread_id'}
                                        for result in results['scenarios']],
                          'stopped_reason': results.get('stopped_reason')}, ensure_ascii=False, indent=2))
        assert results['source_auth_unchanged'], 'Source auth changed'
    return 0 if results['all_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
