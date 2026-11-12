import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

import relay
from relay import NotSent

THREAD = 'a0000010-b011-7011-9011-c00000000013'
STALE_TURN = 'a0000010-b011-7011-9011-c00000000014'
NEW_TURN = 'a0000010-b011-7011-9011-c00000000015'
ACCEPTED = {'accepted': True, 'thread_id': THREAD, 'turn_id': NEW_TURN, 'status': 'inProgress',
            'delivery_mode': 'start_followup_turn', 'delivery_route': 'codex_desktop_owner'}


def wake(peer, hint=STALE_TURN, rid=None):
    rid = rid or str(uuid.uuid4())
    with patch('relay.verify_desktop_peer_route'), patch('relay.owner_turn_hint', return_value=hint), \
            patch('relay.peer_call', side_effect=peer) as call:
        try:
            return relay.wake_codex(['pointer'], rid, THREAD), call, rid
        except Exception as exc:
            exc.call, exc.rid = call, rid
            raise


class StaleTurnHintTest(unittest.TestCase):
    def test_crashed_turn_rejection_retries_once_without_hint(self):
        for code in relay.STALE_HINT_REJECTIONS:
            receipt, call, rid = wake([ValueError(code), dict(ACCEPTED)])
            self.assertEqual(call.call_count, 2)
            first, second = call.call_args_list
            self.assertEqual(first.args[1]['expected_turn_id'], STALE_TURN)
            self.assertEqual(first.args[2], rid)
            self.assertNotIn('expected_turn_id', second.args[1])
            self.assertEqual(second.args[1]['prompt'], 'pointer')
            self.assertEqual(second.args[2], relay.stale_hint_retry_id(rid))
            self.assertEqual(receipt['turn_id'], NEW_TURN)
            self.assertEqual(receipt['stale_turn_hint'], {'rejected': code, 'turn_id': STALE_TURN})

    def test_retry_id_is_deterministic_uuid_distinct_from_original(self):
        rid = str(uuid.uuid4())
        retry = relay.stale_hint_retry_id(rid)
        self.assertTrue(relay.THREAD_RE.fullmatch(retry))
        self.assertNotEqual(retry, rid)
        self.assertEqual(retry, relay.stale_hint_retry_id(rid))

    def test_rejection_without_hint_stays_unknown_and_is_not_retried(self):
        with self.assertRaises(OSError) as ctx:
            wake([ValueError('codex_expected_turn_not_active')], hint=None)
        self.assertNotIsInstance(ctx.exception, NotSent)
        self.assertEqual(ctx.exception.call.call_count, 1)

    def test_other_rejections_are_not_retried(self):
        for code in ('codex_task_not_idle', 'codex_desktop_owner_unavailable', 'native host identity mismatch'):
            with self.assertRaises(OSError) as ctx:
                wake([ValueError(code)])
            self.assertEqual(ctx.exception.call.call_count, 1)

    def test_ambiguous_first_outcome_is_never_retried(self):
        with self.assertRaises(OSError) as ctx:
            wake([TimeoutError()])
        self.assertNotIsInstance(ctx.exception, NotSent)
        self.assertEqual(ctx.exception.call.call_count, 1)

    def test_ambiguous_retry_stays_unknown_after_exactly_two_calls(self):
        with self.assertRaises(OSError) as ctx:
            wake([ValueError('codex_expected_turn_not_active'), TimeoutError()])
        self.assertNotIsInstance(ctx.exception, NotSent)
        self.assertEqual(ctx.exception.call.call_count, 2)

    def test_second_stale_rejection_does_not_loop(self):
        with self.assertRaises(OSError) as ctx:
            wake([ValueError('codex_expected_turn_not_active'), ValueError('codex_expected_turn_not_active')])
        self.assertEqual(ctx.exception.call.call_count, 2)

    def test_retry_not_sent_propagates_for_later_idempotent_replay(self):
        with self.assertRaises(NotSent):
            wake([ValueError('codex_expected_turn_mismatch'), NotSent('host_link_down')])

    def test_unverified_retry_receipt_is_rejected(self):
        bad = dict(ACCEPTED, delivery_route='existing_owner_proxy')
        with self.assertRaises(OSError) as ctx:
            wake([ValueError('codex_expected_turn_not_active'), bad])
        self.assertEqual(str(ctx.exception), 'desktop_owner_wake_receipt_unverified')

    def test_receipt_without_stale_hint_is_unchanged(self):
        receipt, call, _ = wake([dict(ACCEPTED)])
        self.assertEqual(call.call_count, 1)
        self.assertNotIn('stale_turn_hint', receipt)

    def test_hint_still_reports_turn_left_open_by_crash(self):
        # Regression context: the rollout of a killed turn has task_started and no terminal event.
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / f'rollout-x-{THREAD}.jsonl'
            lines = [{'type': 'session_meta', 'payload': {'id': THREAD}},
                     {'type': 'event_msg', 'payload': {'type': 'task_started', 'turn_id': STALE_TURN}},
                     {'type': 'response_item', 'payload': {'type': 'function_call', 'name': 'wait'}}]
            path.write_text('\n'.join(json.dumps(l) for l in lines) + '\n', encoding='utf-8')
            with patch('relay.find_transcript', return_value=path):
                self.assertEqual(relay.owner_turn_hint(THREAD), STALE_TURN)


if __name__ == '__main__':
    unittest.main()
