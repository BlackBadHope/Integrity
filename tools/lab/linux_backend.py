# SPDX-License-Identifier: BUSL-1.1
"""Guest-only LAB composition of unmodified public Integrity components.

No HTTP listener, Home connector, agent or model launcher. The stdio process is
intended for a later SSH route over the VM-only network.
"""
from pathlib import Path
import argparse, importlib, json, os, sys

sys.path.insert(0, str(Path(__file__).absolute().parent))
import lab_config

ROOT = Path.home()/'backend'
INSTANCE = lab_config.setting('linux_guest.instance_id')
DEVICE = lab_config.setting('linux_guest.device_id')

def private(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077:
        raise PermissionError('LAB state directory custody rejected')
    return path

def build(*, initialize_turn_memory=False):
    if sys.platform != 'linux' or os.geteuid() == 0:
        raise RuntimeError('Requires the unprivileged Linux LAB account')
    os.umask(0o077)
    from integrity_guardian import memory_synapse_mcp as core
    from integrity_guardian.memory_synapse_lts import MemorySynapseLtsService
    from integrity_guardian.native_trust import NativeTrustStore
    from integrity_guardian.medor_architecture import MedorArchitectureKeys, PersistentMedorArchitectureService, TENANT_ID, CUSTODY_LEDGER_ID
    from integrity_guardian.turn_memory import namespace_fingerprint, TurnMemoryStore
    from integrity_guardian.turn_memory_profiles import VersionedTurnMemoryService
    from integrity_guardian.signing import public_key_fingerprint
    from integrity_guardian.seed_catalog import SeedCatalog
    import integrity_action_log
    private(ROOT)
    data = private(ROOT/'source')
    config = ROOT/'action-log-config.json'
    if not config.exists():
        config.write_text(json.dumps({'schema':'integrity/component-config/v1', 'component':'integrity-action-log',
            'configured':True, 'guardian_version':'6.1.0', 'memory_api_version':'2.11.0',
            'values':{'path_b8bbeaea89e4':str(ROOT/'workspace-id')}}))
    os.environ.update(INTEGRITY_ACTION_LOG_CONFIG=str(config), CODEX_LOG_DATA_DIR=str(data),
        CODEX_LOG_DB=str(data/'action-log.sqlite3'), CODEX_LOG_SEED_DIRTY_MARKER=str(data/'seed-dirty'),
        CODEX_LOG_HOST='127.0.0.1', CODEX_LOG_PORT='1')
    os.environ.pop('CODEX_LOG_TOKEN', None)
    resources = Path(integrity_action_log.__file__).parent/'resources'
    sys.path.insert(0,str(resources))
    source = importlib.import_module('integrity_action_log.resources.codex_action_log')
    source.ensure_db()
    if source.event_count() == 0:
        source.insert_event({'event_uid':'lab:infrastructure:prepared', 'actor':'lab-provisioner',
            'action':'seed_doctrine_declared', 'summary':'Synthetic LAB infrastructure marker; no model or benchmark run.',
            'details':{'synthetic':True,'phase':'technical-preparation'}, 'tags':['LAB','synthetic']})
    namespace = 'seed://project/integrity-lab-vm-preflight'
    catalog = SeedCatalog(private(ROOT/'catalog')/'catalog.sqlite3')
    class LabLog(core.ActionLogClient):
        def __init__(self):
            super().__init__('http://127.0.0.1:1',timeout=0.05)
        def sync(self):
            catalog.import_events(source.query_all_events(),source_namespace=namespace,source_identity='lab-linux-vm-only')
        def request(self,method,path,*,query=None,payload=None):
            if path == '/api/mind' and method in {'GET','POST'}:
                args={k:([str(v)] if not isinstance(v,list) else v) for k,v in (query or {}).items()}
                for k,v in (payload or {}).items():
                    if k != 'read_session': args[k] = v if isinstance(v,list) else [str(v).lower() if isinstance(v,bool) else str(v)]
                result=source.build_mind(args,read_session=(payload or {}).get('read_session'))
                return source.compact_mind(result) if args.get('compact') == ['true'] else result
            if path == '/api/events' and method == 'GET':
                return source.query_events_page({k:[str(v)] for k,v in (query or {}).items()})
            if path == '/api/events' and method == 'POST':
                result=source.insert_event(payload); self.sync(); return result
            raise core.McpFacadeError('No network fallback for this LAB route')
    class DisabledHome:
        def reset_context(self):
            pass
        def call(self,name,arguments):
            raise core.McpFacadeError('Home is not connected to LAB')
    log=LabLog(); log.sync()
    lts=MemorySynapseLtsService(catalog.path)
    trust=NativeTrustStore(private(ROOT/'trust'),instance_id=INSTANCE)
    trust.bootstrap(); trust.ensure_local_transport_device(device_id=DEVICE)
    enrolled=trust.ensure_database(tenant_id=TENANT_ID,ledger_id=CUSTODY_LEDGER_ID)
    keys=MedorArchitectureKeys(source_signer=enrolled.source_signer,checkpoint_signer=enrolled.checkpoint_signer)
    architecture=PersistentMedorArchitectureService(private(ROOT/'architecture'),keys=keys,
        event_authority_key=trust.trusted_key('event-append-issuer'),native_database_enrollment=enrolled.enrollment,
        native_ledger_issuer_key=trust.trusted_key('ledger-issuer'))
    security=trust.security_admission(artifact_digest=lts.package_digest())
    turn_path=private(architecture.root/'turn-memory')/'turn-memory.sqlite3'
    turn_namespace=namespace_fingerprint(source_namespace=namespace,trust_fingerprint=public_key_fingerprint(keys.source_signer.public_key))
    if initialize_turn_memory:
        # Explicit infrastructure bootstrap; never infer or invent a Native turn.
        # Existing lineage is validated rather than reset or silently migrated.
        TurnMemoryStore(turn_path,namespace=turn_namespace,signer=keys.checkpoint_signer,
                        create=not turn_path.exists())
    turns=VersionedTurnMemoryService(turn_path,namespace=turn_namespace,
        signer=keys.checkpoint_signer,initialize_native=initialize_turn_memory,modern_creation_enabled=True)
    return core.MemorySynapseMcp(lts,action_log=log,home=DisabledHome(),architecture=architecture,
        action_witness=core.SqliteActionLogWitness(data/'action-log.sqlite3'),security_admission=security,
        snapshot_source=catalog.path,snapshot_root=private(ROOT/'snapshots'),native_trust=trust,
        native_device_id=DEVICE,turn_memory=turns)

if __name__ == '__main__':
    parser=argparse.ArgumentParser();mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--stdio',action='store_true');mode.add_argument('--bootstrap-turn-memory',action='store_true');args=parser.parse_args()
    if args.bootstrap_turn_memory:
        server=build(initialize_turn_memory=True)
        coverage=server.turn_memory.coverage(limit=1)
        assert coverage['complete'] and coverage['modern_creation_enabled']
        assert coverage['counts']['registered']==coverage['counts']['terminal']==0
        print(json.dumps({'status':'BOOTSTRAPPED_EMPTY_NATIVE_AND_LEGACY_LEDGERS','namespace_fingerprint':coverage['namespace_fingerprint'],
            'coverage_complete':coverage['complete'],'counts':coverage['counts'],'modern_creation_enabled':True,'models':'NOT_RUN','agents':'NOT_RUN'}))
        server.close();raise SystemExit(0)
    from integrity_guardian.memory_synapse_mcp_protocol import serve
    server=build()
    raise SystemExit(serve(server,idle_release_seconds=0))
