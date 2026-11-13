# SPDX-License-Identifier: BUSL-1.1
"""Prepare one visible guest launcher; does not log in or approve UAC."""
import json
from windows_guest_control import powershell, ROOT
import lab_config

SOURCE = r'''
$ErrorActionPreference='Stop'
$labWindowsHost=@WINDOWS_HOSTNAME@
if($env:COMPUTERNAME -ne $labWindowsHost){throw 'Wrong guest'}
$desktop=Join-Path $env:USERPROFILE 'Desktop'
if(-not(Test-Path -LiteralPath $desktop)){throw 'LAB desktop absent'}
$launcher=@'
@echo off
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -Command "Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile -NoExit -ExecutionPolicy RemoteSigned -File C:\IntegrityLAB\control\preflight-labadmin\windows_elevated_sandbox_setup.ps1' -Verb RunAs -Wait"
'@
[IO.File]::WriteAllText((Join-Path $desktop 'START-LAB-ELEVATED-SETUP.cmd'),$launcher,[Text.Encoding]::ASCII)
@{status='PREPARED_NOT_RUN';launcher='Desktop\START-LAB-ELEVATED-SETUP.cmd';requires='Guest login and UAC';model_calls=0} | ConvertTo-Json -Compress
'''

if __name__ == '__main__':
    result = powershell(lab_config.fill(SOURCE, quote=lab_config.ps_quote, WINDOWS_HOSTNAME=lab_config.setting('vms.windows.hostname')), 45)
    if result.returncode:
        raise RuntimeError(result.stderr[-900:])
    report = json.loads(result.stdout)
    (ROOT/'evidence/WINDOWS-ELEVATED-HANDOFF.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))
