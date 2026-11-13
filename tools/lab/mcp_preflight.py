# SPDX-License-Identifier: BUSL-1.1
"""Real stdio MCP checks through MXC, never through an agent or model."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).absolute().parent))
from runtime_common import ROOT,PYTHON,sandbox_command,within
from native_peer import JsonLines
import hashlib
import json


def tool(session,name,args):
    reply=session.call('tools/call',{'name':name,'arguments':args})
    if 'error' in reply:return reply
    result=reply['result']
    if result.get('isError'):return {'error':result}
    return json.loads(result['content'][0]['text'])


def main():
    rows=[];shared_snapshots=[]
    for backend,actor in [('shared','LAB-A'),('shared','LAB-B'),('session-a','LAB-A'),('session-b','LAB-B')]:
        root=ROOT/'runtime/mcp-snapshots'/backend/actor
        catalog=ROOT/'state/memory'/backend/'catalog.sqlite3'
        before=hashlib.sha256(catalog.read_bytes()).hexdigest()
        command=[PYTHON,'-I','-B',ROOT/'tools/readonly_mcp_host.py','--backend',backend,'--actor',actor]
        with JsonLines(command,cwd=root,log_name=f'MCP-{backend}-{actor}.log') as session:
            init=session.call('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'lab-technical-check','version':'1'}})
            assert 'error' not in init,init
            session.notify('notifications/initialized')
            listing=session.call('tools/list',{})
            names={x['name'] for x in listing['result']['tools']}
            assert names=={'integrity_memory_capabilities','integrity_seed_snapshot','integrity_seed_recall','integrity_seed_event_uid'},names
            capability=tool(session,'integrity_memory_capabilities',{})
            assert capability.get('read_plane')=='ready' and capability.get('native_admission') is False,capability
            snapshot=tool(session,'integrity_seed_snapshot',{})
            sid=snapshot['snapshot_id']
            if backend=='shared':shared_snapshots.append(sid)
            suffix=backend.replace('-','_') if backend!='shared' else backend
            uid='integrity-lab-'+suffix+'-prepared-1'
            exact=tool(session,'integrity_seed_event_uid',{'snapshot_id':sid,'event_uid':uid})
            assert exact.get('outcome')=='found' and exact.get('event',{}).get('id')==1,'exact UID lookup did not return the canonical event'
            missing=tool(session,'integrity_seed_event_uid',{'snapshot_id':sid,'event_uid':'lab:technical:missing'})
            assert missing.get('outcome')=='not-found','missing UID did not return not-found'
            recall=tool(session,'integrity_seed_recall',{'snapshot_id':sid,'query':'Synthetic preparation marker','limit':3})
            assert 'error' not in recall,recall
            invalid=tool(session,'integrity_seed_event_uid',{'snapshot_id':'sha256:'+'0'*64,'event_uid':uid})
            assert 'error' in invalid,'foreign snapshot accepted'
            append=tool(session,'integrity_append_event',{'kind':'thought','event_uid':'client:lab:must-not-append','summary':'This attempt must be refused'})
            assert 'error' in append,'append accepted by read-only profile'
            foreign_uid='integrity-lab-session_b-prepared-1' if backend!='session-b' else 'integrity-lab-session_a-prepared-1'
            foreign=tool(session,'integrity_seed_event_uid',{'snapshot_id':sid,'event_uid':foreign_uid})
            assert foreign.get('outcome')=='not-found','foreign catalog event leaked'
        assert hashlib.sha256(catalog.read_bytes()).hexdigest()==before,'source bytes changed'
        rows.append({'backend':backend,'actor':actor,'status':'PASS','tools':len(names),'snapshot_id':sid,'exact_found':True,'ranked_recall':'PASS','missing_uid':'NOT_FOUND','foreign_catalog_uid':'NOT_FOUND','foreign_snapshot':'DENIED','append':'DENIED','source_bytes_unchanged':True,'process_exited':session.process.poll() is not None})
    assert len(set(shared_snapshots))==1,'shared backend snapshots differ without source change'
    report={'status':'PASS','scope':'four-tool read-only MCP only; independent technical processes, no models','process_boundary':'process-local audit gate, not MXC','connections':rows,'same_shared_snapshot_across_processes':True,'native_lifecycle':'BLOCKED_POSIX_CUSTODY','agents':'NOT_RUN','benchmarks':'NOT_RUN'}
    within('evidence/MCP-PREFLIGHT.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':'PASS','connections':len(rows),'tools_per_connection':4,'source_bytes_unchanged':True,'native_lifecycle':'BLOCKED_POSIX_CUSTODY','agents':'NOT_RUN','benchmarks':'NOT_RUN'}))

if __name__=='__main__':main()
