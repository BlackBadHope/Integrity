# SPDX-License-Identifier: BUSL-1.1
"""Stream public installers into a DVD image; no large in-memory image copies."""
from pathlib import Path
import hashlib, io, json, sys
import pycdlib
sys.path.insert(0,str(Path(__file__).absolute().parent))
import lab_config

ROOT=Path(__file__).absolute().parent.parent
SOURCE=ROOT/'runtime/media/windows-runtimes'
OUT=ROOT/'runtime/media/windows-runtime-v1.iso'
def main():
    if OUT.exists():raise FileExistsError('Runtime media already exists')
    iso=pycdlib.PyCdlib();iso.new(interchange_level=3,joliet=3,vol_ident='LABRUNTIME')
    iso.add_directory(iso_path='/WHEELS',joliet_path='/wheels')
    files={p.relative_to(SOURCE).as_posix():p for p in SOURCE.rglob('*') if p.is_file()}
    files['SETUP.PS1']=ROOT/'tools/windows_setup_tools.ps1'
    files['BASEPF.PS1']=ROOT/'tools/windows_guest_preflight.ps1'
    # Both guest scripts read the lab configuration from the media root.
    files['lab.json']=lab_config.location()
    wrapper=b"& (Join-Path $PSScriptRoot 'SETUP.PS1')\r\n& (Join-Path $PSScriptRoot 'BASEPF.PS1')\r\n"
    iso.add_fp(io.BytesIO(wrapper),len(wrapper),iso_path='/WINPF.PS1;1',joliet_path='/WINPF.PS1')
    hashes={}
    for i,(name,path) in enumerate(sorted(files.items())):
        parent,_,leaf=name.rpartition('/')
        assert len(leaf)<=64 and parent in {'','wheels'}
        iso.add_file(str(path),iso_path=('/WHEELS' if parent else '')+'/F%06d.DAT;1'%i,joliet_path='/'+name)
        with path.open('rb') as stream:hashes[name]=hashlib.file_digest(stream,'sha256').hexdigest()
    iso.write(str(OUT));iso.close()
    with OUT.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    report={'schema':'integrity-lab.windows-runtime-media.v1','image':str(OUT),'bytes':OUT.stat().st_size,'sha256':digest,
        'files':hashes,'private_credentials_included':False,'host_installs':'NOT_RUN','agents':'NOT_RUN','models':'NOT_RUN'}
    (ROOT/'evidence/WINDOWS-RUNTIME-MEDIA.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'image':str(OUT),'bytes':report['bytes'],'sha256':digest,'files':len(files)+1}))
if __name__=='__main__':main()
