# SPDX-License-Identifier: BUSL-1.1
"""Reseal static LAB sources only, preserving the preceding manifest."""
from pathlib import Path
import hashlib, json, os, shutil
ROOT=Path(__file__).absolute().parent.parent
def main():
    files={}
    for directory,dirs,names in os.walk(ROOT):
        dirs[:]=[x for x in dirs if x not in {'runtime','state','evidence','.git','__pycache__'}]
        for name in sorted(names):
            if name in {'PACKAGE-MANIFEST.json','SHA256SUMS.txt'}:continue
            p=Path(directory)/name
            if p.is_symlink() or getattr(p.stat(),'st_nlink',1)>1:raise RuntimeError('Unexpected source link')
            with p.open('rb') as f:files[p.relative_to(ROOT).as_posix()]=hashlib.file_digest(f,'sha256').hexdigest()
    previous=ROOT/'PACKAGE-MANIFEST.json'
    if previous.exists():
        tag=hashlib.sha256(previous.read_bytes()).hexdigest()[:16]
        shutil.copy2(previous,ROOT/'evidence'/('PACKAGE-MANIFEST-before-VM-'+tag+'.json'))
    document={'schema':'integrity-lab.package.v1','files':dict(sorted(files.items()))}
    temporary=ROOT/'PACKAGE-MANIFEST.json.tmp'
    temporary.write_text(json.dumps(document,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    temporary.replace(previous)
    (ROOT/'SHA256SUMS.txt').write_text(''.join(v+'  '+k+'\n' for k,v in sorted(files.items())),encoding='utf-8')
    print(json.dumps({'files':len(files),'manifest_sha256':hashlib.sha256(previous.read_bytes()).hexdigest(),'runtime_state_evidence_excluded':True}))
if __name__=='__main__':main()
