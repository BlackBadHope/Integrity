"""Targeted Grok wire/continuation contract and durable no-repeat tests; no real network/ACL."""
import json, os, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from io import BytesIO
BUS=Path(__file__).resolve().parents[2] / "src" / "integrity_llm_bus" / "resources"  # this copy of the package, never an installed bus
sys.path.insert(0,str(BUS))
import relay
from bus import MessageStore

def message(mid='one',delivery='steer'):
    return {'id':mid,'from':'codexint','to':'grok','body':'CLOSE55 status only','reply_to':None,'delivery':delivery}

class Response:
    status=200
    def __enter__(self): return self
    def __exit__(self,*_): pass
    def read(self, size): return json.dumps({'success':True,'runUuid':'mock-run'}).encode()

class GrokDelivery(unittest.TestCase):
    def worker(self,state,sender):
        r=relay.Relay.__new__(relay.Relay)
        r.state_dir=state;r.store=MessageStore(state/'bus.sqlite3',3600)
        r.path=state/'relay-journal.json';r.thread_id=None;r.threads={}
        r.senders={'grok':sender}
        r.journal=json.loads(r.path.read_text()) if r.path.exists() else {'version':1,'batches':{}}
        return r
    def wire(self,messages):
        with patch.dict(os.environ,{'INTEGRITY_LLM_BUS_CONFIG':os.environ['INTEGRITY_LLM_BUS_CONFIG'],'GROKBOT_WEBHOOK_URL':'https://webhook.example.invalid/hook/mock','GROKBOT_WEBHOOK_KEY':'fixture-only'},clear=True),patch('relay.urllib.request.urlopen',return_value=Response()) as opened:
            result=relay.send_grok(messages,'mock-request',None)
            return json.loads(opened.call_args.args[0].data),result
    def test_explicit_steer_reaches_wire_and_receipt(self):
        p,r=self.wire([message()])
        self.assertEqual(p['delivery'],'steer')
        self.assertEqual(p['messages'][0]['delivery'],'steer')
        self.assertEqual(r['requested_delivery'],'steer')
        self.assertFalse(r['application_verified'])
        self.assertFalse(r['execution_complete'])
        self.assertFalse(r['steer_receiver_verified'])
    def test_legacy_default_is_explicit_on_wire(self):
        p,_=self.wire([message(delivery=None)])
        self.assertEqual(p['messages'][0]['delivery'],'steer')
    def test_queue_rejected_before_HTTP_without_fallback(self):
        with patch('relay.urllib.request.urlopen') as opened:
            with self.assertRaisesRegex(ValueError,'unsupported_grok_queue'):
                relay.send_grok([message(delivery='queue')],'r',None)
            opened.assert_not_called()
    def test_invalid_mode_rejected_before_HTTP(self):
        with patch('relay.urllib.request.urlopen') as opened:
            with self.assertRaisesRegex(ValueError,'invalid_grok_delivery'):
                relay.send_grok([message(delivery='force')],'r',None)
            opened.assert_not_called()
    def test_mixed_modes_rejected_before_HTTP(self):
        with patch('relay.urllib.request.urlopen') as opened:
            with self.assertRaisesRegex(ValueError,'mixed_grok_delivery_batch'):
                relay.send_grok([message(),message('q','queue')],'r',None)
            opened.assert_not_called()
    def test_policy_is_continuation_not_new_owner_authority(self):
        p,_=self.wire([message()])
        self.assertIn('existing task',p['policy'])
        self.assertIn('duplicate',p['policy'])
        self.assertIn('no authority',p['policy'])
        self.assertFalse(p['delivery_contract']['active_turn_injection_claimed'])
    def test_journal_records_mode_without_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            r=self.worker(Path(td),lambda *_:{'http_status':200})
            r.store.post(message())
            out=r.once(['grok'],min_gap=0)[0]
            self.assertEqual(out['delivery'],'steer')
            self.assertNotIn('delivery_ignored',out)
    def test_mixed_modes_split_without_changing_order(self):
        with tempfile.TemporaryDirectory() as td:
            seen=[]
            r=self.worker(Path(td),lambda m,*_:(seen.append([x['id'] for x in m]) or {}))
            for mid,mode in [('s','steer'),('q','queue'),('s2','steer')]: r.store.post(message(mid,mode))
            for expected in ['steer','queue','steer']: self.assertEqual(r.once(['grok'],min_gap=0)[0]['delivery'],expected)
            self.assertEqual(seen,[['s'],['q'],['s2']])
    def test_unknown_stays_nonrepeatable_after_reopen(self):
        with tempfile.TemporaryDirectory() as td:
            calls=[]
            def lost(*_): calls.append(1);raise TimeoutError()
            r=self.worker(Path(td),lost);r.store.post(message())
            self.assertEqual(r.once(['grok'],min_gap=0)[0]['state'],'unknown')
            reopened=self.worker(Path(td),lost)
            self.assertEqual(reopened.once(['grok'],min_gap=0),[])
            self.assertEqual(calls,[1])
    def test_old_ignored_accepted_notice_is_not_reposted(self):
        with tempfile.TemporaryDirectory() as td:
            calls=[]
            r=self.worker(Path(td),lambda *_:calls.append(1))
            r.store.post(message())
            r.journal['batches']['old']={'state':'accepted','target':'grok','ids':['one'],'timestamp':1,'delivery_ignored':['one']}
            r.save()
            self.assertEqual(r.once(['grok'],min_gap=0),[])
            self.assertEqual(calls,[])
    def test_pre_dispatch_reservation_exists_for_sender(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)
            def sender(m,req,_):
                saved=json.loads((path/'relay-journal.json').read_text())
                self.assertEqual(saved['batches'][req]['state'],'sending')
                self.assertEqual(saved['batches'][req]['delivery'],'steer')
                return {}
            r=self.worker(path,sender);r.store.post(message())
            self.assertEqual(r.once(['grok'],min_gap=0)[0]['state'],'accepted')
    def test_HTTP200_does_not_claim_receiver_delivery(self):
        _,r=self.wire([message()])
        self.assertEqual(r['delivery_mode'],'webhook_trigger')
        self.assertEqual(r['delivery_route'],'grok_webhook')
        self.assertFalse(r['steer_receiver_verified'])

if __name__=='__main__':
    unittest.main(verbosity=2)

