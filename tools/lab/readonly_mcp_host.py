# SPDX-License-Identifier: BUSL-1.1
"""Pinned four-tool reader, with an explicit process-local read/network boundary.

This is NOT described as MXC isolation. Native Windows custody checks need
ancestor metadata unavailable in the strict MXC namespace. Shells retain MXC.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import runpy
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).absolute().parent.parent
sys.path.insert(0,str(Path(__file__).absolute().parent))
import lab_config
WORKING_SENTINEL=Path(lab_config.setting('host.denied_sentinels.working_source'))
p=argparse.ArgumentParser();p.add_argument('--backend',choices=['shared','session-a','session-b'],required=True);p.add_argument('--actor',choices=['LAB-A','LAB-B'],required=True);a=p.parse_args()
catalog=ROOT/'state/memory'/a.backend/'catalog.sqlite3'
snapshots=ROOT/'runtime/mcp-snapshots'/a.backend/a.actor
source=ROOT/'runtime/integrity-next-source/examples/local-memory/memory_server.py'
pin=json.loads((ROOT/'controller/reader-source-pin.json').read_text())
if hashlib.sha256(source.read_bytes()).hexdigest()!=pin['memory_server_sha256']:raise RuntimeError('reader source changed')
allowed_reads=[catalog,source,ROOT/'runtime/venv',Path(sys.base_prefix)]
def permitted(path,writing=False):
    p=Path(os.fsdecode(path)).absolute()
    if '..' in p.parts:raise PermissionError('parent traversal')
    if p==snapshots or p.is_relative_to(snapshots):return p
    if not writing and any(p==x or (x.is_dir() and p.is_relative_to(x)) for x in allowed_reads):return p
    raise PermissionError('outside this reader binding')
def audit(event,args):
    if event.startswith(('subprocess.','os.exec','os.spawn','socket.')) and event!='socket.gethostname':raise PermissionError('reader has no process or network capability')
    if event in {'os.system','os.startfile'}:raise PermissionError('reader process launch denied')
    if event=='open' and not isinstance(args[0],int):
        flags=args[2] if len(args)>2 else 0;mode=args[1] or ''
        write=any(x in mode for x in 'wax+') or bool(flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
        permitted(args[0],write)
    if event=='sqlite3.connect':
        raw=str(args[0])
        if raw==':memory:':return
        if raw.startswith('file:'):
            from urllib.parse import urlsplit,unquote
            raw=unquote(urlsplit(raw).path).lstrip('/')
        permitted(raw)
    if event in {'os.mkdir','os.remove','os.rmdir','os.chmod','os.utime'}:permitted(args[0],True)
    if event=='os.rename':permitted(args[0],True);permitted(args[1],True)
sys.addaudithook(audit)
# Technical startup checks make no outside read or network connection.
for path in [ROOT/'controller/oracles/S02.json',WORKING_SENTINEL,ROOT/'state/memory/negative-control/catalog.sqlite3']:
    try:
        with open(path,'rb'):pass
    except PermissionError:pass
    else:raise RuntimeError('reader boundary did not deny a forbidden open')
sys.argv=[str(source),'--catalog',str(catalog),'--snapshots',str(snapshots)]
runpy.run_path(str(source),run_name='__main__')
