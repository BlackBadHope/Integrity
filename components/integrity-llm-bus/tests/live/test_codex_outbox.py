import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from codex_outbox import CodexOutbox, parse_frames
from local_cli import open_store


def frame(parent='incoming', reply='reply', body='received fresh text'):
    value={'id':reply,'from':'codex','to':'grok','body':body,'reply_to':parent}
    return 'LLM_BUS_REPLY_BEGIN\n'+json.dumps(value)+'\nLLM_BUS_REPLY_END'


def record(text, role='assistant', phase='final_answer'):
    return json.dumps({'type':'response_item','payload':{'type':'message','id':'native-item',
        'role':role,'phase':phase,'content':[{'type':'output_text','text':text}]}})+'\n'


class OutboxTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        self.state=root/'state'
        self.store=open_store(self.state)
        self.store.post({'id':'incoming','from':'grok','to':'codex','body':'new text','reply_to':None})
        self.transcript=root/'current.jsonl'
        self.transcript.write_text('',encoding='utf-8')
        self.outbox=CodexOutbox(self.state,self.transcript,self.store)

    def append(self,text):
        with self.transcript.open('a',encoding='utf-8',newline='') as f: f.write(text)

    def test_final_reply_has_source_receipt_and_performs_no_ack(self):
        self.append(record(frame(body='private body of ordinary message')))
        with patch.object(self.store,'ack',side_effect=AssertionError('ACK must never be called')):
            outcome=self.outbox.poll({'incoming'})
        self.assertEqual(outcome[0]['event'],'observed-text-reply')
        self.assertEqual(outcome[0]['source_message_id'],'native-item')
        self.assertFalse(outcome[0]['model_tool_execution'])
        self.assertFalse(outcome[0]['ack_performed'])
        with self.store._connection() as db:
            parent=db.execute('SELECT status,acked_at FROM messages WHERE id=?',('incoming',)).fetchone()
        self.assertEqual(parent['status'],'replied')
        self.assertIsNone(parent['acked_at'])
        self.assertNotIn('private body of ordinary message',(self.state/'codex-outbox-receipts.jsonl').read_text())

    def test_user_commentary_ordinary_text_and_ack_frames_cannot_mutate(self):
        self.append(record(frame(),role='user'))
        self.append(record(frame(),phase='commentary'))
        self.append(record('quoted example: '+frame()))
        self.append(record('LLM_BUS_ACK_BEGIN\n{"agent":"codex","ids":["incoming"]}\nLLM_BUS_ACK_END'))
        self.assertEqual(self.outbox.poll({'incoming'}),[])
        self.assertEqual(len(self.store.inbox('codex','pending',50)),1)

    def test_unnotified_parent_wrong_recipient_and_credentials_are_rejected(self):
        self.append(record(frame()))
        self.assertEqual(self.outbox.poll(set())[0]['action'],'rejected-frame')
        wrong=frame().replace('"to": "grok"','"to": "claude"')
        self.append(record(wrong))
        self.assertEqual(self.outbox.poll({'incoming'})[0]['action'],'rejected-frame')
        self.append(record(frame(body='Bearer '+'a'*40)))
        self.assertEqual(self.outbox.poll({'incoming'})[0]['action'],'rejected-frame')
        self.assertEqual(len(self.store.inbox('codex','pending',50)),1)

    def test_partial_append_restart_and_duplicate_are_safe(self):
        line=record(frame())
        self.append(line[:-1])
        self.assertEqual(self.outbox.poll({'incoming'}),[])
        self.append('\n')
        self.assertEqual(len(self.outbox.poll({'incoming'})),1)
        restarted=CodexOutbox(self.state,self.transcript,self.store)
        self.assertEqual(restarted.poll({'incoming'}),[])
        self.append(line)
        self.assertTrue(restarted.poll({'incoming'})[0]['duplicate'])
        with self.store._connection() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM messages WHERE id=?',('reply',)).fetchone()[0],1)


if __name__=='__main__': unittest.main()
