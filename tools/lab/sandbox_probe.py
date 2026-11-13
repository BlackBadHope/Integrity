# SPDX-License-Identifier: BUSL-1.1
"""Harmless real OS probes; no Python audit guard is installed here."""
from pathlib import Path
import argparse
import json
import socket

p=argparse.ArgumentParser();p.add_argument('--actor',choices=['LAB-A','LAB-B'],required=True);p.add_argument('--sentinel-port',type=int,required=True)
# The sandboxed probe may not read lab.json, so the caller passes the denied sentinels explicitly.
p.add_argument('--working-sentinel',type=Path,required=True);p.add_argument('--policy-sentinel',type=Path,required=True);a=p.parse_args()
r=Path(__file__).absolute().parent.parent;own=r/'runtime/probes'/a.actor;foreign=r/'runtime/probes'/('LAB-B' if a.actor=='LAB-A' else 'LAB-A')
checks=[]
def record(name,fn):
    try: fn();checks.append({'claim':name,'status':'PASS'})
    except Exception as e: checks.append({'claim':name,'status':'FAIL','reason':type(e).__name__+': '+str(e)[:160]})
def denied_open(path):
    try:
        with open(path,'rb'): pass  # No bytes are read, including on an isolation failure.
    except PermissionError:return
    except FileNotFoundError:raise AssertionError('missing file is not proof of denied access')
    raise AssertionError('outside file could be opened')
record('own_input_readable',lambda:(own/'readable.txt').read_text())
record('own_output_writable',lambda:(own/'probe-output.txt').write_text('Technical check only; no model.\n'))
record('foreign_participant_denied',lambda:denied_open(foreign/'readable.txt'))
record('controller_oracle_denied',lambda:denied_open(r/'controller/oracles/S02.json'))
record('working_source_denied',lambda:denied_open(a.working_sentinel))
record('owner_policy_denied',lambda:denied_open(a.policy_sentinel))
def network():
    try:
        with socket.create_connection(('127.0.0.1',a.sentinel_port),timeout=1): pass
    except PermissionError:return
    except OSError as e:
        if getattr(e,'winerror',None) in {10013,10051,10065}:return
        raise AssertionError('network failure not proven policy denial: '+str(getattr(e,'winerror',None)))
    raise AssertionError('host loopback reachable despite network=false')
record('host_loopback_sentinel_denied',network)
report={'actor':a.actor,'guard_installed':False,'checks':checks,'status':'PASS' if all(x['status']=='PASS' for x in checks) else 'FAIL'}
print(json.dumps(report));raise SystemExit(0 if report['status']=='PASS' else 1)
