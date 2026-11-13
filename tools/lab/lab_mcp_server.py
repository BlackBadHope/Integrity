# SPDX-License-Identifier: BUSL-1.1
"""Full Integrity MCP with explicit Windows LAB source/witness adapters.

The upstream Guardian, Mind and Action Log code is unmodified. No HTTP server,
production endpoint, credential import, agent or model is started here.
"""
from __future__ import annotations
from pathlib import Path
import argparse
import importlib.util
import json
import os
import sqlite3
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).absolute().parent))
from runtime_common import ROOT,within
from integrity_guardian import memory_synapse_mcp as core
from integrity_guardian.memory_synapse_lts import MemorySynapseLtsService
from integrity_guardian.native_trust import NativeTrustStore
from integrity_guardian.medor_architecture import MedorArchitectureKeys,PersistentMedorArchitectureService,TENANT_ID,CUSTODY_LEDGER_ID
from integrity_guardian.turn_memory import namespace_fingerprint
from integrity_guardian.turn_memory_profiles import VersionedTurnMemoryService
from integrity_guardian.signing import public_key_fingerprint
from integrity_guardian.seed_catalog import SeedCatalog
from integrity_guardian._windows_files import create_private_directory_tree,assert_private_directory_acl
from integrity_guardian.windows_private_state import write_private_once


class WindowsLabWitness:
    """Fresh read-only observations of the actual private LAB Action Log DB."""
    def __init__(self,path):
        self.path=within(path)
        assert_private_directory_acl(self.path)
        st=self.path.stat();self.identity=(st.st_dev,st.st_ino)
    def observe(self,*,event_uid,request_sha256):
        p=within(self.path);assert_private_directory_acl(p)
        st=p.stat()
        if (st.st_dev,st.st_ino)!=self.identity:raise core.McpFacadeError('LAB witness source identity changed')
        with sqlite3.connect(p.as_uri()+'?mode=ro',uri=True) as db:
            db.execute('PRAGMA query_only=ON')
            rows=db.execute('SELECT id,event_uid,details FROM events WHERE event_uid=? LIMIT 2',(event_uid,)).fetchall()
        if not rows:return {'status':'absent','event_uid':event_uid,'event_id':0,'request_sha256':request_sha256,'observed_record_digest':core._sha256([])}
        if len(rows)!=1:raise core.McpFacadeError('duplicate LAB witness identity')
        eid,uid,raw=rows[0];actual=json.loads(raw).get(core.RESERVED_DETAILS_KEY,{}).get('request_sha256')
        return {'status':'exact' if actual==request_sha256 else 'collision','event_uid':uid,'event_id':eid,'request_sha256':request_sha256,'observed_record_digest':core._sha256({'event_id':eid,'event_uid':uid,'stored_request_sha256':actual})}
    def close(self):pass


class DisabledHome:
    def __getattr__(self,name):raise core.McpFacadeError('Integrity Home is not connected to LAB')


def source_module(backend_root):
    data=within(backend_root/'source');create_private_directory_tree(data)
    db=data/'action-log.sqlite3'
    if not db.exists():write_private_once(db,b'')
    os.environ['CODEX_LOG_DATA_DIR']=str(data)
    os.environ['CODEX_LOG_DB']=str(db)
    os.environ['CODEX_LOG_SEED_DIRTY_MARKER']=str(data/'seed-dirty')
    os.environ['CODEX_LOG_HOST']='127.0.0.1'
    os.environ['CODEX_LOG_PORT']='1' # No source HTTP listener is used or created.
    os.environ.pop('CODEX_LOG_TOKEN',None)
    sys.path.insert(0,str(within('vendor/action_log_source')))
    spec=importlib.util.spec_from_file_location('lab_actual_action_log',within('vendor/action_log_source/codex_action_log.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.ensure_db()
    if module.event_count()==0:
        module.insert_event({'event_uid':'lab:infrastructure:prepared','actor':'lab-provisioner','action':'seed_doctrine_declared','summary':'Synthetic LAB infrastructure marker; no agent or benchmark has run.','details':{'synthetic':True,'phase':'technical-preparation'},'tags':['LAB','synthetic']})
    return module,db


class LabActionLog(core.ActionLogClient):
    def __init__(self,source,catalog,namespace,identity):
        super().__init__('http://127.0.0.1:1',timeout=0.05)
        self.source=source;self.catalog=catalog;self.namespace=namespace;self.identity=identity
    def sync(self):
        events=self.source.query_all_events()
        self.catalog.import_events(events,source_namespace=self.namespace,source_identity=self.identity)
    def request(self,method,path,*,query=None,payload=None):
        if path=='/api/mind' and method in {'GET','POST'}:
            args={k:([str(v)] if not isinstance(v,list) else v) for k,v in (query or {}).items()}
            for k,v in (payload or {}).items():
                if k not in {'read_session'}:args[k]=v if isinstance(v,list) else [str(v).lower() if isinstance(v,bool) else str(v)]
            result=self.source.build_mind(args,read_session=(payload or {}).get('read_session'))
            return self.source.compact_mind(result) if args.get('compact')==['true'] else result
        if path=='/api/events' and method=='GET':
            return self.source.query_events_page({k:[str(v)] for k,v in (query or {}).items()})
        if path=='/api/events' and method=='POST':
            reply=self.source.insert_event(payload);self.sync();return reply
        raise core.McpFacadeError('No network fallback: unsupported LAB source request')


def build(backend,actor):
    if backend not in {'shared','session-a','session-b'} or actor not in {'LAB-A','LAB-B'}:raise ValueError('unknown LAB binding')
    root=within(Path('state/pilot-infra')/backend);create_private_directory_tree(root)
    source,db=source_module(root)
    catalog=SeedCatalog(root/'catalog/catalog.sqlite3')
    namespace='seed://project/integrity-lab-runtime-'+backend
    identity='lab-runtime-only:'+backend
    log=LabActionLog(source,catalog,namespace,identity);log.sync()
    lts=MemorySynapseLtsService(catalog.path)
    trust=NativeTrustStore(root/'trust',instance_id='instance:integrity-lab-'+backend)
    trust.bootstrap();device='device:integrity-lab-'+actor.lower();trust.ensure_local_transport_device(device_id=device)
    enrolled=trust.ensure_database(tenant_id=TENANT_ID,ledger_id=CUSTODY_LEDGER_ID)
    keys=MedorArchitectureKeys(source_signer=enrolled.source_signer,checkpoint_signer=enrolled.checkpoint_signer)
    architecture=PersistentMedorArchitectureService(root/'architecture'/actor,keys=keys,event_authority_key=trust.trusted_key('event-append-issuer'),native_database_enrollment=enrolled.enrollment,native_ledger_issuer_key=trust.trusted_key('ledger-issuer'))
    security=trust.security_admission(artifact_digest=lts.package_digest())
    turns=VersionedTurnMemoryService(architecture.root/'turn-memory/turn-memory.sqlite3',namespace=namespace_fingerprint(source_namespace=namespace,trust_fingerprint=public_key_fingerprint(keys.source_signer.public_key)),signer=keys.checkpoint_signer,initialize_native=True,modern_creation_enabled=True)
    snapshot=root/'snapshots'/actor;create_private_directory_tree(snapshot)
    server=core.MemorySynapseMcp(lts,action_log=log,home=DisabledHome(),architecture=architecture,action_witness=WindowsLabWitness(db),security_admission=security,snapshot_source=catalog.path,snapshot_root=snapshot,native_trust=trust,native_device_id=device,turn_memory=turns)
    return server


def main():
    raise RuntimeError('BLOCKED: unmodified Native custody/lifecycle kernel requires POSIX durability. Candidate is retained for diagnosis only; no fallback is permitted.')
    p=argparse.ArgumentParser();p.add_argument('--backend',choices=['shared','session-a','session-b'],required=True);p.add_argument('--actor',choices=['LAB-A','LAB-B'],required=True);p.add_argument('--bootstrap-only',action='store_true');a=p.parse_args()
    server=build(a.backend,a.actor)
    if a.bootstrap_only:
        print(json.dumps({'backend':a.backend,'actor':a.actor,'status':'BOOTSTRAPPED','turn_memory_complete':server.turn_memory.complete,'source_transport':'actual-source-functions-no-HTTP','agents':0,'benchmarks':0}));server.close();return 0
    # Retain the actual upstream stateful MCP protocol, validation and receipts.
    return core.serve(server)

if __name__=='__main__':raise SystemExit(main())
