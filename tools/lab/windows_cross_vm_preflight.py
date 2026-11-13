# SPDX-License-Identifier: BUSL-1.1
"""Technical Windows-to-Linux SSH/MCP gate; never creates a model intent."""
from pathlib import Path
import argparse, json, os, subprocess, sys
sys.path.insert(0,str(Path(__file__).absolute().parent))
import lab_config

ROOT=Path('C:/IntegrityLAB')
CONTROL=ROOT/'control/preflight-labadmin'
def main():
    if os.environ.get('COMPUTERNAME')!=lab_config.setting('vms.windows.hostname'):raise RuntimeError('Wrong guest')
    guest_ip=lab_config.setting('network.linux_guest_ip')
    nat_address=lab_config.setting('egress_network.nat_address')
    nat_route={'gateway':lab_config.setting('egress_network.nat_gateway'),'dev':'egress0'}
    parser=argparse.ArgumentParser();parser.add_argument('--readback-only',action='store_true');options=parser.parse_args()
    args=['C:/Windows/System32/OpenSSH/ssh.exe','-T','-i',str(CONTROL/'linux-management-key'),
        '-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(CONTROL/'linux-known-hosts'),
        '-o','BatchMode=yes','-o','ConnectTimeout=5','lab@'+guest_ip]
    identity="""import hashlib,json,os,socket,subprocess
from pathlib import Path
from datetime import datetime,timezone
from integrity_guardian.native_trust import NativeTrustStore
root=Path.home()/'backend'
genesis=NativeTrustStore(root/'trust',instance_id=@INSTANCE@).verify_genesis()
routes=json.loads(subprocess.check_output(['ip','-j','route']))
addresses=json.loads(subprocess.check_output(['ip','-j','address']))
nics=[x for x in addresses if x['ifname']!='lo']
print(json.dumps({'hostname':socket.gethostname(),'uid':os.geteuid(),
 'genesis_id':genesis['genesis_id'],'genesis_verified':True,
 'home_mode':oct(Path.home().stat().st_mode & 0o777),
 'backend_mode':oct(root.stat().st_mode & 0o777),
 'default_routes':sum(x.get('dst')=='default' for x in routes),
 'default_route_bindings':[{'gateway':x.get('gateway'),'dev':x.get('dev')} for x in routes if x.get('dst')=='default'],
 'IPv4_forwarding':Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()=='1',
 'NIC_count':len(nics),'IPv4':[a['local'] for n in nics for a in n['addr_info'] if a['family']=='inet'],
 'interfaces':{n['ifname']:{'state':n.get('operstate'),'MAC':n.get('address')} for n in nics},
 'backend_source_sha256':hashlib.sha256(Path('/opt/integrity-lab/tools/linux_backend.py').read_bytes()).hexdigest(),
 'utc':datetime.now(timezone.utc).isoformat()}))"""
    identity=lab_config.fill(identity,INSTANCE=lab_config.setting('linux_guest.instance_id'))
    p=subprocess.run([*args,"/opt/integrity-lab/venv/bin/python -c "+__import__('shlex').quote(identity)],capture_output=True,text=True,timeout=20)
    if p.returncode:raise RuntimeError('Pinned SSH route failed: '+p.stderr[-300:])
    bound=json.loads(p.stdout)
    assert bound['hostname']==lab_config.setting('vms.linux.hostname') and bound['uid']==1000
    assert bound['genesis_id']==lab_config.setting('linux_guest.genesis_id')
    assert bound['home_mode']=='0o700' and bound['backend_mode']=='0o700'
    assert not bound['IPv4_forwarding']
    if bound['NIC_count']==1:
        assert bound['default_routes']==0 and bound['IPv4']==[guest_ip]
    else:
        assert bound['NIC_count']==2 and set(bound['interfaces'])=={'lab0','egress0'}
        assert bound['interfaces']['egress0']['MAC']==lab_config.mac(lab_config.setting('vms.linux.egress_mac'))
        if bound['interfaces']['egress0']['state']=='DOWN':
            assert set(bound['IPv4']) in [{guest_ip},{guest_ip,nat_address}]
            assert bound['default_route_bindings'] in [[],[nat_route]]
        else:
            assert set(bound['IPv4'])=={guest_ip,nat_address}
            assert bound['default_routes']==1 and bound['default_route_bindings']==[nat_route]
    if options.readback_only:
        report={'schema':'integrity-lab.linux-fresh-readback.v1','status':'PASS','backend':bound,
            'SSH':'PINNED_HOST_KEY','intent_admissions':0,'models':'NOT_RUN','agents':'NOT_RUN','benchmarks':'NOT_RUN'}
        (ROOT/'evidence/linux-readback.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report));return
    frames=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'lab-cross-vm-preflight','version':'1'}}},
        {'jsonrpc':'2.0','method':'notifications/initialized'}, {'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}}]
    p=subprocess.run([*args,'/opt/integrity-lab/venv/bin/python /opt/integrity-lab/tools/linux_backend.py --stdio'],
        input=''.join(json.dumps(f)+'\n' for f in frames),capture_output=True,text=True,timeout=120)
    if p.returncode:raise RuntimeError('Cross-VM MCP child failed: '+p.stderr[-300:])
    responses=[json.loads(x) for x in p.stdout.splitlines() if x.strip()]
    assert 'result' in next(x for x in responses if x.get('id')==1)
    tools=next(x for x in responses if x.get('id')==2)['result']['tools']
    assert len(tools)==19 and 'integrity_turn_memory_close' in [x['name'] for x in tools]
    report={'schema':'integrity-lab.cross-vm-preflight.v1','status':'PASS','SSH':'PINNED_HOST_KEY','backend_identity':bound,
        'MCP_initialize':'PASS','native_tools_count':len(tools),'intent_admissions':0,'agents':'NOT_RUN','models':'NOT_RUN',
        'benchmarks':'NOT_RUN','Desktop_owner_binding':'NOT_RUN','sandbox_command_execution':'NOT_RUN'}
    (ROOT/'evidence/cross-vm.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
if __name__=='__main__':main()
