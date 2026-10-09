#!/usr/bin/env python3
"""Isolated release-container OAuth smoke; source credentials remain read-only.

The official client is a test driver on the host. The gateway container never
runs it. Raw logs, copied account state and client home remain under private var/.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import time
import urllib.request
import uuid

from native_audit_evidence import evidence, rows

ROOT = Path(__file__).resolve().parents[1]


def docker(*args, **kwargs):
    return subprocess.run(['docker', *args], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--auth', required=True, type=Path)
    parser.add_argument('--client', required=True, type=Path)
    args = parser.parse_args()
    source = args.auth.read_bytes()
    before = hashlib.sha256(source).hexdigest()
    ident = uuid.uuid4().hex[:12]
    directory = ROOT / 'var/verification' / ('linux-release-' + ident)
    directory.mkdir(mode=0o700, parents=True)
    home = directory / 'client-home'
    home.mkdir(mode=0o700)
    (home / 'auth.json').write_bytes(source)
    (home / 'auth.json').chmod(0o600)
    work = directory / 'workspace'
    work.mkdir(mode=0o700)
    name = 'codex-http-oauth-audit-' + ident
    created = False
    report = {'image': args.image, 'platform': 'linux/arm64', 'deployed': False}
    try:
        inspect = json.loads(docker('image', 'inspect', args.image).stdout)[0]
        report['image_id'] = inspect['Id']
        docker('create', '--platform', 'linux/arm64', '--name', name,
               '-p', '127.0.0.1::18184', args.image, '/tmp/config.json')
        created = True
        config = {'listen': '0.0.0.0:18184', 'state_dir': '/tmp/audit-state',
                  'admin_token': 'private-release-audit', 'trusted_networks': ['0.0.0.0/0'],
                  'scheduling': {'max_sessions_by_account_age': [128] * 5,
                                 'startup_spacing_secs': 0},
                  'accounts': [{'id': 'readonly-import', 'auth_path': '/tmp/auth.json',
                                'enabled': True}]}
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w') as tar:
            for filename, content in [('config.json', json.dumps(config).encode()),
                                      ('auth.json', source)]:
                info = tarfile.TarInfo(filename)
                info.size = len(content)
                info.mode = 0o600
                info.uid = info.gid = 10001
                tar.addfile(info, io.BytesIO(content))
        docker('cp', '-a', '-', name + ':/tmp', input=archive.getvalue())
        docker('start', name)
        published = docker('port', name, '18184/tcp').stdout.decode().strip()
        assert re.fullmatch(r'127\.0\.0\.1:\d+', published)
        base = 'http://' + published
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(100):
            try:
                with opener.open(base + '/health', timeout=1) as response:
                    report['health'] = json.load(response)
                break
            except OSError:
                time.sleep(.1)
        assert report.get('health', {}).get('codex_version') == '0.160.0'
        log = directory / 'ordinary.jsonl'
        environment = dict(os.environ, CODEX_HOME=str(home), NO_COLOR='1')
        for variable in ['OPENAI_BASE_URL', 'OPENAI_API_KEY', 'CODEX_API_KEY', 'CODEX_ACCESS_TOKEN']:
            environment.pop(variable, None)
        with log.open('w') as output:
            log.chmod(0o600)
            result = subprocess.run([str(args.client.resolve()), 'exec', '--ignore-user-config',
                '--skip-git-repo-check', '-C', str(work), '-s', 'read-only', '-m', 'gpt-6.1-sol',
                '-c', f'openai_base_url="{base}/v1"', '--json',
                'Reply exactly RELEASE_AUDIT_OK. Do not use tools.'], env=environment,
                stdout=output, stderr=subprocess.STDOUT, timeout=180)
        report['native'] = evidence(rows(log), 'ordinary', home, 'RELEASE_AUDIT_OK')
        report['native'].pop('thread_id', None)
        report['native']['exit_code'] = result.returncode
        # Observe a real exporter acknowledgement, never infer it from an empty queue.
        for _ in range(8):
            logs = re.sub(r'\x1b\[[0-9;]*m', '', docker('logs', name).stdout.decode())
            if re.search(r'acknowledged_batches=[1-9]', logs):
                break
            time.sleep(5)
        report['official_metrics_http_acknowledged'] = bool(
            re.search(r'acknowledged_batches=[1-9]', logs))
        report['point_level_metric_acceptance_proven'] = False
        docker('stop', '--time', '15', name)
        status = json.loads(docker('inspect', name).stdout)[0]['State']
        report['shutdown_exit_code'] = status['ExitCode']
        report['runtime_user'] = inspect['Config']['User']
        report['passed'] = (report['native']['passed'] and result.returncode == 0
                            and report['official_metrics_http_acknowledged']
                            and report['shutdown_exit_code'] == 0)
    except Exception as error:
        report['stopped_reason'] = type(error).__name__
        report['passed'] = False
    finally:
        if created:
            captured = subprocess.run(['docker', 'logs', name], stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT).stdout
            (directory / 'gateway.log').write_bytes(captured)
            (directory / 'gateway.log').chmod(0o600)
            subprocess.run(['docker', 'stop', '--time', '5', name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['docker', 'cp', name + ':/tmp/audit-state', str(directory / 'state')],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            docker('rm', name)
        report['source_auth_unchanged'] = before == hashlib.sha256(args.auth.read_bytes()).hexdigest()
        report['passed'] = report.get('passed', False) and report['source_auth_unchanged']
        path = directory / 'report.json'
        path.write_text(json.dumps(report, indent=2))
        path.chmod(0o600)
        print(json.dumps({'report': str(path), **report}, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
