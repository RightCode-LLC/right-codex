#!/usr/bin/env python3
"""Bounded native 0.160.0 Memory startup probe against a private home copy.

The gateway remains a protocol proxy. Any Memory work is performed by the
separate official client launched only by this audit driver.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / 'var/verification/native-client-0.160.0/codex-aarch64-apple-darwin'
GATEWAY = ROOT / 'target/debug/right-codex'
MODEL = 'gpt-6.1-sol'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def files(root):
    return {str(p.relative_to(root)): sha(p) for p in root.rglob('*') if p.is_file()}


def rows(path):
    conn = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
    try:
        return conn.execute('select id,rollout_path,cwd,source,memory_mode,updated_at_ms from threads order by id').fetchall()
    finally:
        conn.close()


def jobs(path):
    try:
        conn = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
        conn.execute('select 1 from jobs limit 1')
    except sqlite3.OperationalError:
        # A stopped official client may leave a checkpointed WAL-mode database
        # without its -shm sidecar. Immutable reading never mutates that source.
        conn = sqlite3.connect(f'file:{path}?immutable=1', uri=True)
    try:
        return conn.execute('select kind,status,count(*) from jobs group by kind,status').fetchall()
    finally:
        conn.close()


def fact_counts(state):
    result = {}
    for path in (state / 'facts').glob('*/*.jsonl'):
        for line in path.read_text(errors='replace').splitlines():
            try:
                fact = json.loads(line).get('fact', {})
            except ValueError:
                continue
            kind = fact.get('kind', 'unknown')
            result[kind] = result.get(kind, 0) + 1
    return result


def native_result(path):
    events = []
    for line in path.read_text(errors='replace').splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict) and 'type' in item:
            events.append(item['type'])
    return {'turn_completed': 'turn.completed' in events,
            'turn_failed': 'turn.failed' in events,
            'error_events': events.count('error')}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True,
                        help='Existing private audit fixture directory; read-only source')
    parser.add_argument('--auth', type=Path, required=True,
                        help='Explicit OAuth auth.json source; read-only')
    parser.add_argument('--client', type=Path, default=CLIENT)
    parser.add_argument('--gateway', type=Path, default=GATEWAY)
    args = parser.parse_args()
    started = time.monotonic()
    source = args.source.resolve(strict=True)
    source_home = source / 'client-home'
    source_work = source / 'workspace'
    host_auth = args.auth.resolve(strict=True)
    if not source_home.is_dir() or not source_work.is_dir() or not host_auth.is_file():
        raise RuntimeError('complete source fixture and read-only host auth are required')
    if subprocess.check_output([str(args.client.resolve()), '--version'], text=True).strip() != 'codex-cli 0.160.0':
        raise RuntimeError('native version mismatch')
    account_before = json.loads((source_home / 'auth.json').read_bytes())['tokens']['account_id']
    host_material = host_auth.read_bytes()
    account_current = json.loads(host_material)['tokens']['account_id']
    if account_before != account_current:
        raise RuntimeError('host OAuth account differs from source account')
    src_rows = rows(source_home / 'state_5.sqlite')
    if not src_rows or jobs(source_home / 'memories_1.sqlite'):
        raise RuntimeError('source thread state absent or already has Memory jobs')
    now_ms = int(time.time() * 1000)
    # Match fixed codex_rollout::INTERACTIVE_SESSION_SOURCES exactly. `exec`
    # sessions can trigger global consolidation, but are not stage-one sources.
    eligible = [r for r in src_rows if r[3] in ('cli', 'vscode', 'atlas', 'chatgpt') and r[4] == 'enabled'
                and now_ms - 10*86400*1000 <= r[5] <= now_ms - 3600*1000]
    if not eligible:
        raise RuntimeError('no current-account source thread meets native one-hour gate')
    source_hashes = files(source_home)
    source_work_hashes = files(source_work)
    output = Path(tempfile.mkdtemp(prefix='native-memory-audit-', dir=ROOT / 'var/verification'))
    output.chmod(0o700)
    home, work = output / 'client-home', output / 'workspace'
    shutil.copytree(source_home, home, copy_function=shutil.copy2)
    shutil.copytree(source_work, work, copy_function=shutil.copy2)
    home.chmod(0o700)
    work.chmod(0o700)
    baseline = rows(home / 'state_5.sqlite')
    old_home, old_work = str(source_home), str(source_work)
    for row in baseline:
        if not row[1].startswith(old_home + os.sep) or row[2] != old_work:
            raise RuntimeError('source SQLite contains a foreign home or workspace path')
        original_file = Path(row[1])
        copied_file = home / original_file.relative_to(source_home)
        if not copied_file.is_file() or sha(original_file) != sha(copied_file):
            raise RuntimeError('rollout custody mismatch in complete home copy')
    db = sqlite3.connect(home / 'state_5.sqlite')
    try:
        db.execute('begin immediate')
        for row in baseline:
            relocated = str(home / Path(row[1]).relative_to(source_home))
            db.execute('update threads set rollout_path=?,cwd=? where id=?', (relocated, str(work), row[0]))
        db.commit()
    finally:
        db.close()
    relocated_rows = rows(home / 'state_5.sqlite')
    if len(relocated_rows) != len(baseline) or any(
            new[0] != old[0] or new[3:] != old[3:] or
            new[1] != str(home / Path(old[1]).relative_to(source_home)) or new[2] != str(work)
            for old, new in zip(baseline, relocated_rows)):
        raise RuntimeError('private path relocation changed source business facts')
    (home / 'auth.json').write_bytes(host_material)
    (home / 'auth.json').chmod(0o600)
    (home / 'config.toml').write_text((home / 'config.toml').read_text() +
                                     '\n[features]\nmemories = true\n[memories]\nmin_rollout_idle_hours = 1\n'
                                     f'extract_model = "{MODEL}"\nconsolidation_model = "{MODEL}"\n')
    report = {'source_fixture': str(source), 'source_home_files': len(source_hashes),
              'source_home_tree_sha256': hashlib.sha256(json.dumps(source_hashes,sort_keys=True).encode()).hexdigest(),
              'source_work_files': len(source_work_hashes), 'eligible_source_threads': len(eligible),
              'source_last_updated_at_ms': max(r[5] for r in eligible),
              'private_path_relocation_only': True, 'memory_version': 'official default V1',
              'memory_idle_hours': 1, 'model_override': MODEL,
              'host_auth_sha256_before': hashlib.sha256(host_material).hexdigest(),
              'source_auth_account_matches_host': True, 'native_started': False}
    state = output / 'gateway-state'
    config = output / 'gateway.json'
    config.write_text(json.dumps({'listen':'127.0.0.1:0','state_dir':str(state),
       'accounts':[{'id':'memory-audit','auth_path':str(home / 'auth.json'),'enabled':True}]}))
    config.chmod(0o600)
    gateway_log = output / 'gateway.log'
    native_log = output / 'native.jsonl'
    gateway = None
    try:
        with gateway_log.open('xb') as log:
            gateway_log.chmod(0o600)
            gateway = subprocess.Popen([str(args.gateway.resolve()), str(config)], stdout=log,
                                       stderr=subprocess.STDOUT, env=dict(os.environ,NO_COLOR='1'))
            port = None
            for _ in range(100):
                if gateway.poll() is not None:
                    raise RuntimeError('gateway exited before readiness')
                log.flush()
                match = re.search(r'127\.0\.0\.1:(\d+)',gateway_log.read_text(errors='replace'))
                if match:
                    port = int(match[1]);break
                time.sleep(.1)
            if port is None:
                raise RuntimeError('gateway readiness deadline')
            base = f'http://127.0.0.1:{port}/v1'
            command = [str(args.client.resolve()),'exec','--ignore-user-config','--skip-git-repo-check',
                       '-C',str(work),'-s','danger-full-access','-m',MODEL,
                       '-c',f'openai_base_url="{base}"','-c','features.memories=true',
                       '-c','memories.min_rollout_idle_hours=1',
                       '-c',f'memories.extract_model="{MODEL}"',
                       '-c',f'memories.consolidation_model="{MODEL}"','--json',
                       'Use exec_command to run sleep 45, then reply exactly MEMORY_AUDIT_DONE.']
            env = dict(os.environ,CODEX_HOME=str(home),NO_COLOR='1')
            for key in ('OPENAI_API_KEY','CODEX_API_KEY','CODEX_ACCESS_TOKEN','CHATGPT_SESSION_TOKEN'):
                env.pop(key,None)
            report['native_started'] = True
            with native_log.open('xb') as stream:
                native_log.chmod(0o600)
                try:
                    proc = subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT,
                                          env=env,cwd=work,timeout=min(100, max(1,420-(time.monotonic()-started))))
                    report['native_exit_code'] = proc.returncode
                except subprocess.TimeoutExpired:
                    report['native_exit_code'] = None
                    report['native_timeout'] = True
            report.update(native_result(native_log))
            report['memory_jobs'] = jobs(home / 'memories_1.sqlite')
            report['memory_artifacts'] = [str(p.relative_to(home)) for p in home.glob('memories/**/*') if p.is_file()][:20]
            report['gateway_fact_counts'] = fact_counts(state)
            report['memory_stage1_completed'] = any(k == 'memory_stage1' and status == 'done'
                                                    for k,status,_ in report['memory_jobs'])
    except Exception as error:
        report['stopped_reason'] = type(error).__name__ + ':' + str(error)
    finally:
        if gateway is not None:
            gateway.send_signal(signal.SIGINT)
            try: gateway.wait(timeout=10)
            except subprocess.TimeoutExpired:
                gateway.kill(); gateway.wait(timeout=5)
        report['source_home_unchanged'] = files(source_home) == source_hashes
        report['source_work_unchanged'] = files(source_work) == source_work_hashes
        report['host_auth_unchanged'] = sha(host_auth) == report['host_auth_sha256_before']
        report['elapsed_seconds'] = round(time.monotonic()-started,2)
        destination = output / 'report.json'
        destination.write_text(json.dumps(report,indent=2))
        destination.chmod(0o600)
        print(json.dumps({'report':str(destination),'eligible_source_threads':len(eligible),
                          'native_completed':report.get('turn_completed'),
                          'memory_jobs':report.get('memory_jobs'),
                          'memory_stage1_completed':report.get('memory_stage1_completed'),
                          'source_home_unchanged':report['source_home_unchanged'],
                          'host_auth_unchanged':report['host_auth_unchanged'],
                          'stopped_reason':report.get('stopped_reason')}))
    return 0 if report.get('memory_stage1_completed') and report.get('source_home_unchanged') else 1


if __name__ == '__main__':
    sys.exit(main())
