#!/usr/bin/env python3
"""Body-free summaries of actual official CLI/RPC/rollout audit evidence.

Pinned contracts: codex 0.160.0 exec/src/exec_events.rs and protocol/src/items.rs.
These local verification observations do not become gateway telemetry/tool facts.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import zlib


def rows(path):
    result = []
    with Path(path).open() as source:
        for line in source:
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict):
                result.append(value)
    return result


def digest(value):
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def item_type(item):
    return re.sub(r'[_-]', '', item.get('type', '')).lower()


def completed_items(events):
    result = []
    for event in events:
        item = None
        if event.get('type') == 'item.completed':
            item = event.get('item')
        elif event.get('method') == 'item/completed':
            item = event.get('params', {}).get('item')
        elif event.get('type') == 'event_msg' and event.get('payload', {}).get('type') == 'item_completed':
            item = event['payload'].get('item')
        if isinstance(item, dict):
            result.append(item)
    return result


def agent_text(items):
    result = []
    for item in items:
        if item_type(item) != 'agentmessage':
            continue
        if isinstance(item.get('text'), str):
            result.append(item['text'])
        for content in item.get('content', []):
            if isinstance(content, dict) and isinstance(content.get('text'), str):
                result.append(content['text'])
    return '\n'.join(result)


def command_succeeded(item, expected):
    output = item.get('aggregated_output', item.get('aggregatedOutput', '')) or ''
    return (item_type(item) == 'commandexecution' and item.get('status') == 'completed'
            and item.get('exit_code', item.get('exitCode')) == 0 and expected in output)


def rollout(home, thread):
    if not thread:
        return [], None
    for path in (Path(home) / 'sessions').rglob('*.jsonl'):
        events = rows(path)
        if any(event.get('type') == 'session_meta' and event.get('payload', {}).get('id') == thread
               for event in events):
            return events, path
    return [], None


def evidence(events, scenario, home=None, expected=None, expected_thread=None):
    terminal = [event.get('type') for event in events
                if event.get('type') in ('turn.completed', 'turn.failed')]
    thread = next((event.get('thread_id') for event in events if event.get('type') == 'thread.started'), None)
    completed = bool(terminal and terminal[-1] == 'turn.completed')
    items = completed_items(events)
    persistent, path = rollout(home, thread) if home else ([], None)
    persisted_items = completed_items(persistent)
    all_items = items + persisted_items
    text = agent_text(items)
    checks = {'native_turn_completed': completed}
    if scenario in ('ordinary', 'resume', 'midway_direct', 'midway_resume'):
        checks['actual_marker_reply'] = bool(expected and text.strip() == expected)
    if expected_thread is not None:
        checks['same_native_thread'] = thread == expected_thread
    if scenario in ('tools', 'file'):
        checks['actual_command_completed_with_fixture_output'] = any(
            command_succeeded(item, expected or 'audit fixture value = 42') for item in all_items)
    if scenario == 'websearch':
        checks['actual_native_web_search_completed'] = any(item_type(item) == 'websearch' for item in all_items)
        checks['actual_repository_url_reply'] = 'github.com/openai/codex' in text.lower()
    if scenario == 'subagent':
        activities = [item for item in persisted_items if item_type(item) == 'subagentactivity']
        child_ids = {item.get('agent_thread_id') for item in activities if item.get('kind') == 'started'}
        collab = [item for item in all_items if item_type(item) == 'collabtoolcall' or item_type(item) == 'collabagenttoolcall']
        for item in collab:
            if item.get('tool', '').lower().replace('_', '') == 'spawnagent' and item.get('status') == 'completed':
                child_ids.update(item.get('receiver_thread_ids', item.get('receiverThreadIds', [])))
        child_ids.discard(None)
        child_ids.discard(thread)
        child_results = []
        for child in child_ids:
            child_events, _ = rollout(home, child) if home else ([], None)
            meta = next((event['payload'] for event in child_events if event.get('type') == 'session_meta'), {})
            done = any(event.get('type') == 'event_msg' and event.get('payload', {}).get('type') == 'task_complete'
                       and not event['payload'].get('error') for event in child_events)
            child_results.append(meta.get('parent_thread_id') == thread and done and any(
                command_succeeded(item, expected or 'audit fixture value = 42') for item in completed_items(child_events)))
        checks['actual_distinct_child_started'] = bool(child_ids)
        checks['child_parent_and_completed_file_execution'] = bool(child_results) and all(child_results)
        checks['parent_received_fixture_value'] = '42' in text
    if scenario == 'image':
        checks['actual_native_image_input'] = any(event.get('type') == 'response_item'
            and event.get('payload', {}).get('type') == 'message' and event['payload'].get('role') == 'user'
            and any(part.get('type') == 'input_image' for part in event['payload'].get('content', [])
                    if isinstance(part, dict)) for event in persistent)
        lower = text.lower()
        checks['left_right_colors_recognized'] = bool(re.search(r'red\W+blue', lower))
    return {'passed': all(checks.values()), 'checks': checks,
            'turn_completed': completed, 'errors': sum(event.get('type') in ('error', 'turn.failed') for event in events),
            'thread_id': thread, 'completed_item_count': len(items),
            'actual_evidence_source': 'official_cli_jsonl_and_private_rollout',
            'rollout_sha256': digest(path.read_bytes()) if path else None,
            'client_execution_exported_as_gateway_fact': False}


def rpc_evidence(events, thread, turn, scenario, expected=None):
    scoped = [event for event in events if event.get('params', {}).get('threadId') == thread
              and event['params'].get('turnId', event['params'].get('turn', {}).get('id')) == turn]
    finished = [event for event in scoped if event.get('method') == 'turn/completed']
    status = finished[-1]['params']['turn'].get('status') if finished else None
    items = completed_items(scoped)
    checks = {'same_native_turn_completed': status == 'completed'}
    text = agent_text(items)
    if scenario in ('rpc_initial', 'after_compact'):
        checks['actual_marker_reply'] = bool(expected and text.strip() == expected)
    if scenario == 'compact':
        checks['actual_context_compaction_item'] = any(item_type(item) == 'contextcompaction' for item in items)
    if scenario == 'review':
        checks['actual_entered_review_mode'] = any(item_type(item) == 'enteredreviewmode' for item in items)
        checks['actual_exited_review_mode'] = any(item_type(item) == 'exitedreviewmode' for item in items)
        checks['actual_review_command_execution'] = any(item_type(item) == 'commandexecution'
            and item.get('status') == 'completed' and item.get('exitCode') == 0 for item in items)
    if scenario in ('image_generate', 'image_edit'):
        checks['actual_native_image_completed'] = any(item_type(item) == 'imagegeneration'
            and item.get('status') == 'completed' and not item.get('failure')
            and (item.get('result') or item.get('savedPath')) for item in items)
    return {'passed': all(checks.values()), 'checks': checks, 'status': status,
            'completed_item_count': len(items), 'actual_evidence_source': 'official_rpc_notifications',
            'client_execution_exported_as_gateway_fact': False}


def make_image(path):
    """A simple red-left/blue-right PNG, generated locally without external images."""
    width, height = 64, 32
    image = b''.join(b'\x00' + b''.join(b'\xff\x00\x00' if x < width // 2 else b'\x00\x00\xff'
                                     for x in range(width)) for _ in range(height))
    def chunk(kind, body):
        return struct.pack('>I', len(body)) + kind + body + struct.pack('>I', zlib.crc32(kind + body) & 0xffffffff)
    Path(path).write_bytes(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
                          + chunk(b'IDAT', zlib.compress(image)) + chunk(b'IEND', b''))
    Path(path).chmod(0o600)


def direct_history(events):
    ids, ciphers = set(), set()
    for event in events:
        if event.get('type') != 'response_item':
            continue
        item = event.get('payload', {})
        for field in ('id', 'call_id'):
            if isinstance(item.get(field), str):
                ids.add(item[field])
        if isinstance(item.get('encrypted_content'), str):
            ciphers.add(item['encrypted_content'])
    return ids, ciphers


def attempt_ids(state):
    return {ident for path in (Path(state) / 'sessions').glob('*.json')
            for ident in json.loads(path.read_text()).get('session', {}).get('attempts', {})}


def completed_endpoints(state):
    """Only successful durable one-shot HTTP facts, never model text claims."""
    endpoints = {}
    for path in (Path(state) / 'facts').rglob('*.jsonl'):
        facts = [row.get('fact', {}) for row in rows(path)]
        start = next((fact for fact in facts if fact.get('kind') == 'started'), {})
        terminal = next((fact for fact in reversed(facts) if fact.get('kind') == 'terminal'), {})
        endpoint = start.get('identity', {}).get('endpoint')
        if endpoint and terminal.get('outcome') == 'http_completed' and any(
                fact.get('kind') == 'http_response' and 200 <= fact.get('status', 0) < 300 for fact in facts):
            endpoints[endpoint] = endpoints.get(endpoint, 0) + 1
    return endpoints


def midpoint_projection(state, previous_attempt_ids, client_ids, client_ciphers):
    inputs, count = [], 0
    gateway_ids = set()
    for path in (Path(state) / 'sessions').glob('*.json'):
        session = json.loads(path.read_text()).get('session', {})
        new = [attempt for ident, attempt in session.get('attempts', {}).items() if ident not in previous_attempt_ids]
        if not new:
            continue
        count += len(new)
        for key in ('thread_id', 'session_id', 'installation_id', 'window_id', 'context_window_id'):
            gateway_ids.add(session.get(key))
        for attempt in new:
            inputs.extend(attempt.get('input', []))
            gateway_ids.add(attempt.get('upstream_turn_id'))
    copied_ids = set()
    copied_ciphers = set()
    for item in inputs:
        for field in ('id', 'call_id', 'previous_response_id', 'response_id'):
            if isinstance(item.get(field), str) and item[field] in client_ids:
                copied_ids.add(item[field])
        if item.get('encrypted_content') in client_ciphers:
            copied_ciphers.add(item['encrypted_content'])
    checks = {'actual_new_gateway_attempt': count > 0, 'prior_direct_ids_not_in_committed_input': not copied_ids,
              'prior_direct_cipher_not_in_committed_input': not copied_ciphers,
              'gateway_generated_scope_disjoint': not (gateway_ids & client_ids)}
    return {'passed': all(checks.values()), 'checks': checks, 'new_gateway_attempt_count': count,
            'prior_direct_id_count': len(client_ids), 'prior_direct_cipher_count': len(client_ciphers),
            'projection_source': 'persisted_gateway_committed_attempt_input',
            'raw_outbound_network_body_retained': False,
            'actual_wire_isolation_independently_proven': False}


def self_test():
    import tempfile
    done = {'type': 'turn.completed', 'usage': {}}
    claim = {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': '42; github.com/openai/codex'}}
    assert not evidence([claim, done], 'tools')['passed']
    assert not evidence([claim, done], 'websearch')['passed']
    assert not evidence([claim, done], 'subagent')['passed']
    assert not evidence([claim, done], 'image')['passed']
    actual = {'type': 'item.completed', 'item': {'type': 'command_execution', 'status': 'completed',
                                              'exit_code': 0, 'aggregated_output': 'audit fixture value = 42'}}
    assert evidence([actual, done], 'tools')['passed']
    assert not evidence([actual, done, {'type': 'turn.failed'}], 'tools')['passed']
    assert not rpc_evidence([{'method': 'turn/completed', 'params': {'threadId': 'other', 'turn': {'id': 'turn', 'status': 'completed'}}}], 'thread', 'turn', 'compact')['passed']
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / 'image.png'; make_image(path)
        assert path.read_bytes().startswith(b'\x89PNG\r\n\x1a\n')
    print(json.dumps({'pure_evidence_checks': 8, 'passed': True, 'network_requests': 0, 'client_processes': 0}))


if __name__ == '__main__':
    self_test()
