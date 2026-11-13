# SPDX-License-Identifier: BUSL-1.1
"""Create a non-bootable, public postinstall DVD for the Windows LAB guest."""
from pathlib import Path
import hashlib, json, sys
import pycdlib
sys.path.insert(0,str(Path(__file__).absolute().parent))
import lab_config

ROOT=Path(__file__).absolute().parent.parent
SOURCE=Path(lab_config.setting('host.guest_additions_iso'))
OUT=ROOT/'runtime/media/windows-postinstall-v2.iso'


def main():
    if OUT.exists():raise FileExistsError('Postinstall DVD exists; do not rewrite attached media')
    files=ROOT/'runtime/media/windows-postinstall-v2-files'
    if files.exists():raise FileExistsError('Extraction exists; inspect before repeating')
    files.mkdir()
    source=pycdlib.PyCdlib();source.open(str(SOURCE))
    names=['VBoxWindowsAdditions.exe','VBoxWindowsAdditions-amd64.exe','VBoxWindowsAdditions-x86.exe']
    for name in names:
        with (files/name).open('xb') as stream:
            source.get_file_from_iso_fp(stream,joliet_path='/'+name)
    source.close()
    iso=pycdlib.PyCdlib();iso.new(interchange_level=3,joliet=3,vol_ident='LABPOST')
    iso.add_directory(iso_path='/VBOXADD',joliet_path='/vboxadditions')
    hashes={}
    for i,name in enumerate(names):
        path=files/name
        iso.add_file(str(path),iso_path='/VBOXADD/F%d.EXE;1'%i,joliet_path='/vboxadditions/'+name)
        hashes[name]=hashlib.sha256(path.read_bytes()).hexdigest()
    script=ROOT/'runtime/vms/control/windows-install-v2/lab-postinstall-template.cmd'
    iso.add_file(str(script),iso_path='/VBOXPOST.CMD;1',joliet_path='/VBOXPOST.CMD')
    assert iso.eltorito_boot_catalog is None
    iso.write(str(OUT));iso.close()
    with OUT.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    report={'schema':'integrity-lab.windows-postinstall-media.v1','image':str(OUT),'bytes':OUT.stat().st_size,
        'sha256':digest,'bootable':False,'private_credentials_included':False,'GuestAdditions_files':hashes,
        'postinstall_script_sha256':hashlib.sha256(script.read_bytes()).hexdigest(),
        'purpose':'Replace bootable setup DVD only after OS image copying is complete; keep postinstall available.',
        'models':'NOT_RUN','agents':'NOT_RUN'}
    (ROOT/'evidence/WINDOWS-POSTINSTALL-MEDIA.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'image':str(OUT),'bootable':False,'bytes':report['bytes'],'sha256':digest}))


if __name__=='__main__':main()
