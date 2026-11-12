import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest.mock import patch


def _state_value(module, state):
    """Point one resource module's configured state directory at a test folder."""
    original = module._integrity_value
    return patch.object(module, "_integrity_value",
                        lambda key: str(state) if key == "state_directory" else original(key))
import agent_registry as ar
import bus_claude_hook as hook
from bus import MessageStore
from local_cli import main as cli
from relay import Relay

LEAD='a000000a-b00b-400b-900b-c0000000000b'
NEXT='a000000b-b00c-400c-800c-c0000000000c'
CODEX='a000000c-b00d-700d-900d-c0000000000d'


class ClaudeSessions(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root=Path(self.folder.name);self.state=self.root/'state';self.state.mkdir()
        self.store=MessageStore(self.state/'bus.sqlite3',3600)
        ar.register('codextest',CODEX,state_dir=self.state)
        ar.register('claude-lead',LEAD,'claude',state_dir=self.state)
        ar.register('claude3llm',NEXT,'claude',state_dir=self.state)
        ar.set_claude_alias('claude-lead',state_dir=self.state)

    def send(self,mid,to='claude3llm',body='PRIVATE BODY MUST NOT BE PRINTED'):
        self.store.post({'id':mid,'from':'grok','to':to,'body':body,'reply_to':None})

    def run_hook(self,session,**extra):
        stream=types.SimpleNamespace(buffer=io.BytesIO(json.dumps({'session_id':session,**extra}).encode()))
        out=io.StringIO()
        with _state_value(hook,self.state),patch.object(hook.sys,'stdin',stream),contextlib.redirect_stdout(out):
            hook.main()
        return out.getvalue()

    def test_distinct_sessions_and_lead_alias(self):
        self.send('lead-direct','claude-lead');self.send('lead-legacy','claude');self.send('new-only')
        new=self.run_hook(NEXT);lead=self.run_hook(LEAD)
        self.assertIn('new-only',new);self.assertNotIn('lead-',new)
        self.assertIn('lead-direct',lead);self.assertIn('lead-legacy',lead);self.assertNotIn('new-only',lead)
        self.assertEqual(self.run_hook(NEXT),'');self.assertEqual(self.run_hook(LEAD),'')
        self.assertNotIn('PRIVATE BODY',new+lead)
        self.assertIn('+00:00',new)
        self.assertEqual(len(self.store.inbox('claude3llm','pending',50)),1)
        self.assertEqual(len(self.store.inbox('claude','pending',50)),1)

    def test_missing_foreign_conflicting_session_gets_nothing(self):
        self.send('private')
        before={p.name:p.read_bytes() for p in (self.state/'claude-hook-seen').glob('*.json')}
        for session in ('',None,CODEX,'../../escape'):
            self.assertEqual(self.run_hook(session),'')
        self.assertEqual(self.run_hook(NEXT,sessionId=LEAD),'')
        self.assertEqual(before,{p.name:p.read_bytes() for p in (self.state/'claude-hook-seen').glob('*.json')})

    def test_registration_and_alias_start_after_backlog_without_ack(self):
        new='abcdefab-1234-5678-9012-abcdefabcdef'
        self.send('old-direct','claude-new');self.send('old-alias','claude')
        ar.register('claude-new',new,'claude',state_dir=self.state)
        ar.set_claude_alias('claude-new','claude-lead',self.state)
        self.assertEqual(self.run_hook(new),'')
        self.send('fresh-direct','claude-new');self.send('fresh-alias','claude')
        ar.register('claude-new',new,'claude',state_dir=self.state)
        ar.set_claude_alias('claude-new','claude-new',self.state)
        notice=self.run_hook(new)
        self.assertIn('fresh-direct',notice);self.assertIn('fresh-alias',notice)
        self.assertNotIn('old-direct',notice);self.assertNotIn('old-alias',notice)
        self.assertEqual(len(self.store.inbox('claude-new','pending',50)),2)
        self.assertEqual(len(self.store.inbox('claude','pending',50)),2)

    def test_pending_paging_not_starved_by_old_notices(self):
        for i in range(35):self.send('page-'+str(i))
        first=self.run_hook(NEXT);second=self.run_hook(NEXT)
        self.assertEqual(first.count('; get --agent'),20)
        self.assertEqual(second.count('; get --agent'),15)
        self.assertEqual(self.run_hook(NEXT),'')
        self.assertEqual(len(self.store.inbox('claude3llm','pending',50)),35)

    def test_alias_cas_and_handoff_preserves_addresses(self):
        raw=(self.state/'agents-registry.json').read_bytes()
        with self.assertRaises(ValueError):ar.set_claude_alias('claude3llm',state_dir=self.state)
        self.assertEqual(raw,(self.state/'agents-registry.json').read_bytes())
        ar.set_claude_alias('claude3llm','claude-lead',self.state)
        self.assertEqual(ar.claude_mailboxes(LEAD,self.state),('claude-lead',))
        self.assertEqual(ar.claude_mailboxes(NEXT,self.state),('claude3llm','claude'))
        self.assertEqual(set(ar.load(self.state)),{'codextest','claude-lead','claude3llm'})

    def test_no_harness_or_foreign_address_overwrite(self):
        raw=(self.state/'agents-registry.json').read_bytes()
        for address,identity,harness in [('claude3llm',LEAD,'claude'),('claude3llm',NEXT,'codex'),('another',NEXT,'claude')]:
            with self.assertRaises(ValueError):ar.register(address,identity,harness,state_dir=self.state)
        self.assertEqual(raw,(self.state/'agents-registry.json').read_bytes())

    def test_writer_lock_rejects_concurrent_mutation(self):
        raw=(self.state/'agents-registry.json').read_bytes()
        with ar._writer(self.state):
            with self.assertRaises(ValueError):ar.register('blocked',NEXT,'claude',state_dir=self.state)
        self.assertEqual(raw,(self.state/'agents-registry.json').read_bytes())

    def test_corrupt_registry_not_replaced(self):
        path=self.state/'agents-registry.json';path.write_text('{broken',encoding='utf-8')
        with self.assertRaises(ValueError):ar.register('new',NEXT,'claude',state_dir=self.state)
        self.assertEqual(path.read_text(),'{broken')
        self.assertEqual(self.run_hook(NEXT),'')

    def test_relay_excludes_claude_from_codex_targets(self):
        relay=Relay(self.state,senders={'grok':lambda *_:{}})
        with patch('relay.send_codex',side_effect=AssertionError('Claude must not reach Codex')):
            targets=relay.refresh_registry()
            self.assertEqual(targets,['codextest'])
            self.send('claude-queue')
            self.assertEqual(relay.once(targets,0),[])
            self.assertFalse(relay.is_codex('claude3llm'))
            self.assertFalse(relay.is_codex('claude-lead'))
        self.assertEqual(ar.codex_threads(self.state),{'codextest':CODEX})

    def test_cli_requires_explicit_claude_session(self):
        args=['--state-dir',str(self.state),'register','--address','claude-new','--harness','claude']
        with patch.dict(os.environ,{'CODEX_THREAD_ID':CODEX}),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli(args),2)
            self.assertEqual(cli(args+['--thread',LEAD]),2)

    def test_cli_claude_registration_and_alias_listing(self):
        new='abcdefab-1234-5678-9012-abcdefabcdef'
        args=['--state-dir',str(self.state)]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli(args+['register','--address','claude-new','--harness','claude','--session',new]),0)
            self.assertEqual(cli(args+['claude-alias','--address','claude-new','--expected','claude-lead']),0)
        lead=next(row for row in ar.listing(self.state) if row['address']=='claude')
        self.assertEqual(lead['session_id'],new)
        self.assertNotIn('claude-new',ar.codex_threads(self.state))

    def test_expired_and_acked_are_not_announced(self):
        self.send('acked');self.store.ack('acked','claude3llm')
        self.send('expired')
        with self.store._connection() as db:db.execute('UPDATE messages SET expires_at=? WHERE id=?',(int(time.time())-1,'expired'))
        self.assertEqual(self.run_hook(NEXT),'')

    def test_missing_database_not_created(self):
        self.store.path.unlink()
        with self.assertRaises(Exception):hook.collect({'session_id':NEXT},self.state)
        self.assertFalse(self.store.path.exists())


if __name__=='__main__':unittest.main(verbosity=2)
