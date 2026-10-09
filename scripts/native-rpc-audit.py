#!/usr/bin/env python3
"""Real official client RPC audit, exclusively inside a supplied private home.

This is a verification driver, never a gateway runtime dependency. Raw RPC
notifications remain in the private audit directory and are not printed.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import time
from native_audit_evidence import rpc_evidence


class Rpc:
    def __init__(self, client, home, work, base, output, model):
        self.log = (output / 'rpc-private.jsonl').open('w')
        os.chmod(output / 'rpc-private.jsonl', 0o600)
        self.stderr = (output / 'rpc-stderr.log').open('w')
        os.chmod(output / 'rpc-stderr.log', 0o600)
        self.process = subprocess.Popen(
            [str(client), 'app-server', '-c', f'openai_base_url="{base}"', '-c', f'model="{model}"'],
            cwd=work, env=dict(os.environ, CODEX_HOME=str(home), NO_COLOR='1'),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr, text=True,
        )
        self.queue = queue.Queue()
        self.pending = []
        self.events = []
        self.counter = 0
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        for line in self.process.stdout:
            self.log.write(line)
            self.log.flush()
            try:
                value = json.loads(line)
                self.events.append(value)
                self.queue.put(value)
            except json.JSONDecodeError:
                pass
        self.queue.put({'audit_process_ended': True})

    def send(self, value):
        self.process.stdin.write(json.dumps(value) + '\n')
        self.process.stdin.flush()

    def wait(self, predicate, timeout=300):
        deadline = time.monotonic() + timeout
        while True:
            for index, row in enumerate(self.pending):
                if predicate(row):
                    return self.pending.pop(index)
            row = self.queue.get(timeout=max(.01, deadline-time.monotonic()))
            if row.get('audit_process_ended'):
                raise RuntimeError('Official client ended before audit completion')
            if 'id' in row and 'method' in row:
                # No approval is fabricated by the driver.
                self.send({'id': row['id'], 'error': {'code': -32601, 'message': 'Audit does not approve interactive operations'}})
            else:
                self.pending.append(row)

    def call(self, method, params):
        self.counter += 1
        ident = self.counter
        self.send({'id': ident, 'method': method, 'params': params})
        response = self.wait(lambda row: row.get('id') == ident)
        if 'error' in response:
            raise RuntimeError('RPC rejected: ' + method)
        return response['result']

    def completed_turn(self, thread, turn=None):
        row = self.wait(lambda row: row.get('method') == 'turn/completed'
            and row.get('params', {}).get('threadId') == thread
            and (turn is None or row.get('params', {}).get('turn', {}).get('id') == turn))
        return row['params']['turn']

    def complete(self, thread, turn=None):
        return self.completed_turn(thread, turn)['status']

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.reader.join(timeout=5)
        self.log.close()
        self.stderr.close()


def run(client, home, work, base, output, model, cases=None):
    selected = set(cases or ['rpc_initial', 'compact', 'after_compact', 'review'])
    rpc = Rpc(client, home, work, base, output, model)
    results = []
    try:
        rpc.call('initialize', {'clientInfo': {'name': 'codex_cli_rs', 'title': 'Isolated protocol audit', 'version': '0.160.0'}, 'capabilities': {'experimentalApi': True}})
        rpc.send({'method': 'initialized', 'params': {}})
        started = rpc.call('thread/start', {'cwd': str(work), 'model': model, 'approvalPolicy': 'never', 'sandbox': 'workspace-write'})
        thread = started['thread']['id']
        turn = rpc.call('turn/start', {'threadId': thread, 'input': [{'type': 'text', 'text': 'Remember the audit marker COBALT-42. Reply with the marker only. Do not use tools.', 'textElements': []}]})
        status = rpc.complete(thread, turn['turn']['id'])
        results.append({'name': 'rpc_initial', 'prerequisite': 'rpc_initial' not in selected,
                        **rpc_evidence(rpc.events, thread, turn['turn']['id'], 'rpc_initial', 'COBALT-42')})
        if status != 'completed':
            return results
        if selected & {'compact', 'after_compact'}:
            rpc.call('thread/compact/start', {'threadId': thread})
            completed = rpc.completed_turn(thread)
            results.append({'name': 'compact', 'prerequisite': 'compact' not in selected,
                            **rpc_evidence(rpc.events, thread, completed['id'], 'compact')})
        if 'after_compact' in selected:
            turn = rpc.call('turn/start', {'threadId': thread, 'input': [{'type': 'text', 'text': 'State only the audit marker from before compaction. Do not use tools.', 'textElements': []}]})
            rpc.complete(thread, turn['turn']['id'])
            results.append({'name': 'after_compact', **rpc_evidence(rpc.events, thread, turn['turn']['id'], 'after_compact', 'COBALT-42')})
        if 'review' in selected:
            (work / 'division.py').write_text('def ratio(total, count):\n    return total / count\n')
            subprocess.run(['git', '-C', str(work), 'add', 'division.py'], check=True)
            review = rpc.call('review/start', {'threadId': thread, 'target': {'type': 'uncommittedChanges'}, 'delivery': 'inline'})
            rpc.complete(thread, review['turn']['id'])
            results.append({'name': 'review', **rpc_evidence(rpc.events, thread, review['turn']['id'], 'review')})
        for scenario, prompt in [
            ('image_generate', 'Use the native image generation tool to generate a simple red square on a white background. Do not use shell, scripts, or external image tools. Generate exactly one image.'),
            ('image_edit', 'Use the native image tool to edit the image from the previous turn: change the red square to blue, keeping the background white. Do not use shell, scripts, or external image tools. Generate exactly one edited image.'),
        ]:
            if scenario not in selected:
                continue
            turn = rpc.call('turn/start', {'threadId': thread, 'input': [{'type': 'text', 'text': prompt, 'textElements': []}]})
            rpc.complete(thread, turn['turn']['id'])
            results.append({'name': scenario, **rpc_evidence(rpc.events, thread, turn['turn']['id'], scenario)})
            if not results[-1]['passed']:
                break
    except Exception as error:
        results.append({'name': 'rpc_stopped', 'passed': False, 'error_type': type(error).__name__})
    finally:
        rpc.close()
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ['client', 'home', 'work', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--base', required=True)
    parser.add_argument('--model', default='gpt-6.1-sol')
    parser.add_argument('--cases', help='Comma-separated RPC scenarios: rpc_initial,compact,after_compact,review')
    args = parser.parse_args()
    result = run(args.client.resolve(), args.home.resolve(), args.work.resolve(), args.base,
                 args.output.resolve(), args.model, args.cases.split(',') if args.cases else None)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result and all(item.get('passed') for item in result) else 1)
