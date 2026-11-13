# SPDX-License-Identifier: BUSL-1.1
"""LAB-only host/controller plumbing. This module never invokes a model."""
from __future__ import annotations
from pathlib import Path
import os
import subprocess
import sys

sys.path.insert(0,str(Path(__file__).absolute().parent))
import lab_config

ROOT=Path(__file__).absolute().parent.parent
CLI=Path(lab_config.setting('host.codex_cli'))
PYTHON=ROOT/'runtime/venv/Scripts/python.exe'
BASE_PYTHON=Path(lab_config.setting('host.base_python'))

def within(path):
    p=Path(path)
    if not p.is_absolute(): p=ROOT/p
    if '..' in p.parts or not p.is_relative_to(ROOT): raise PermissionError('outside LAB')
    for x in [p,*p.parents]:
        if x.exists() and getattr(x.lstat(),'st_file_attributes',0)&0x400: raise PermissionError('reparse point')
    return p

def environment(home=None,extra=None):
    names=['SystemRoot','SystemDrive','WINDIR','COMSPEC','PATHEXT','LOCALAPPDATA','USERPROFILE','PATH','APPDATA','ProgramFiles','ProgramFiles(x86)','ProgramData','PROCESSOR_ARCHITECTURE','NUMBER_OF_PROCESSORS']
    env={k:os.environ[k] for k in names if k in os.environ}
    env.update(CODEX_HOME=str(within(home or 'runtime/controller-home')),TEMP=str(ROOT/'runtime/tmp'),TMP=str(ROOT/'runtime/tmp'),PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
    if extra: env.update(extra)
    return env

def sandbox_command(profile,command,cwd=None):
    return [str(CLI),'sandbox','--include-managed-config','--permission-profile',profile,'-C',str(within(cwd or 'runtime/probes/shared')),'--',*map(str,command)]

def bounded(command,*,profile=None,cwd=None,home=None,timeout=45,extra=None):
    argv=sandbox_command(profile,command,cwd) if profile else list(map(str,command))
    return subprocess.run(argv,cwd=within(cwd or ROOT),env=environment(home,extra),capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
