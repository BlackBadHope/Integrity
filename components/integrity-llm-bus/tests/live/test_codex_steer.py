import uuid
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import agent_registry
import codex_steer
import codex_steer_hook
import relay

THREAD = 'a000000d-b00e-700e-a00e-c0000000000e'
MESSAGE = {'id': 'm1', 'from': 'claude', 'to': 'codex', 'body': 'secret body text', 'reply_to': None}


def run_hook(payload, root):
    out = io.StringIO()
    # The hook also auto-registers the thread under DEFAULT_STATE; keep that in the tempdir.
    with patch.object(agent_registry, 'DEFAULT_STATE', Path(root) / 'state'), \
            patch('sys.stdin', io.StringIO(json.dumps(payload))), patch('sys.stdout', out), \
            patch.object(codex_steer_hook, 'take_for_hook',
                         lambda t, turn: codex_steer.take_for_hook(t, turn, root)):
        codex_steer_hook.main()
    return out.getvalue()


class SteerTest(unittest.TestCase):
    def test_steer_goes_to_desktop_owner_not_queue(self):
        rid = str(uuid.uuid4())
        with patch('relay.wake_codex', return_value={'status': 'inProgress'}) as wake, \
                patch('relay.subprocess.run') as run:
            receipt = relay.send_codex([dict(MESSAGE, delivery='steer')], rid, THREAD)
        run.assert_not_called()
        self.assertEqual(wake.call_args.args[1:], (rid, THREAD))
        self.assertEqual(receipt['requested_delivery'], 'steer')

    def test_owner_wake_rejects_non_uuid_request_id(self):
        with self.assertRaises(ValueError):
            relay.wake_codex(['pointer'], 'op', THREAD)
    def test_hook_delivers_pointer_once_without_body(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            codex_steer.stage(THREAD, 'op', ['m1'], relay.codex_prompts([MESSAGE])[0], root)
            first = json.loads(run_hook({'hook_event_name': 'PostToolUse', 'session_id': THREAD, 'turn_id': 't1'}, root))
            context = first['hookSpecificOutput']['additionalContext']
            self.assertEqual(first['hookSpecificOutput']['hookEventName'], 'PostToolUse')
            self.assertIn('m1', context)
            self.assertNotIn('secret body text', context)
            self.assertEqual(run_hook({'hook_event_name': 'PostToolUse', 'session_id': THREAD}, root), '')
            self.assertEqual(codex_steer.entries(THREAD, root)[0]['turn_id'], 't1')

    def test_hook_ignores_other_threads_events_and_garbage(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            codex_steer.stage(THREAD, 'op', ['m1'], 'pointer', root)
            other = 'a000000e-b00f-700f-800f-c0000000000f'
            self.assertEqual(run_hook({'hook_event_name': 'PostToolUse', 'session_id': other}, root), '')
            self.assertEqual(run_hook({'hook_event_name': 'UserPromptSubmit', 'session_id': THREAD}, root), '')
            self.assertEqual(run_hook({'session_id': '../../x'}, root), '')
            self.assertEqual(codex_steer.entries(THREAD, root)[0]['state'], 'staged')

    def test_sweep_wakes_owner_once_and_hook_cannot_duplicate(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            key = str(uuid.uuid4())
            codex_steer.stage(THREAD, key, ['m1'], 'pointer', root)
            sent = []
            r = relay.Relay(root / 'state', THREAD, senders={})
            wake = lambda p, k, t: sent.append((p, k, t)) or {'status': 'inProgress'}
            self.assertEqual(r.sweep_codex_steer(root, wake, allowed_threads={'other'}), [])
            out = r.sweep_codex_steer(root, wake, allowed_threads={THREAD})
            self.assertEqual(out[0]['state'], 'owner_accepted')
            self.assertEqual(sent, [(['pointer'], key, THREAD)])
            self.assertEqual(run_hook({'hook_event_name': 'PostToolUse', 'session_id': THREAD}, root), '')
            self.assertEqual(r.sweep_codex_steer(root, wake, allowed_threads={THREAD}), [])
    def test_turn_active_reads_last_task_event(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'rollout.jsonl'
            started = '{"type":"event_msg","payload":{"type":"task_started"}}\n'
            complete = '{"type":"event_msg","payload":{"type":"task_complete"}}\n'
            path.write_text(started + complete)
            self.assertFalse(codex_steer.turn_active(path))
            path.write_text(started + complete + started + '{"type":"response_item"}\n')
            self.assertTrue(codex_steer.turn_active(path))
            path.write_text('{"type":"response_item"}\n')
            self.assertIsNone(codex_steer.turn_active(path))


if __name__ == '__main__':
    unittest.main()
