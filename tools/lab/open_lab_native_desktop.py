# SPDX-License-Identifier: BUSL-1.1
"""Open only the installed LAB Desktop shell, using an interactive limited token.

No prompt, task, authentication, model or agent is started. The trigger-free
activation task is removed after it exits; this never changes the Windows host.
"""
import argparse,json
from windows_guest_control import powershell,ROOT
from windows_vm_stage import require
import lab_config

COMMON=r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$labWindowsHost=@WINDOWS_HOSTNAME@
if($env:COMPUTERNAME -ne $labWindowsHost){throw 'Wrong guest'}
if((Get-CimInstance Win32_ComputerSystem).UserName -ne ($labWindowsHost+'\labadmin')){throw 'Interactive LAB user required'}
'''
START=COMMON+r'''
$p=Get-AppxPackage -Name OpenAI.Codex
if($p.PackageFamilyName -ne 'OpenAI.Codex_2p2nqsd0c76g0'){throw 'Wrong native package'}
$running=@(Get-Process -Name ChatGPT -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq (Join-Path $p.InstallLocation 'app\ChatGPT.exe')})
if($running.Count){@{status='ALREADY_RUNNING';model_turns=0} | ConvertTo-Json -Compress;exit}
$name='IntegrityLAB-Open-Native-Desktop'
if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Existing activation task; inspect first'}
$action=New-ScheduledTaskAction -Execute C:\Windows\explorer.exe -Argument 'shell:AppsFolder\OpenAI.Codex_2p2nqsd0c76g0!App'
$principal=New-ScheduledTaskPrincipal -UserId ($labWindowsHost+'\labadmin') -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings | Out-Null
Start-ScheduledTask -TaskName $name
@{status='DESKTOP_SHELL_ACTIVATION_REQUESTED';privilege='Limited';triggers=0;model_turns=0;agents='NOT_RUN'} | ConvertTo-Json -Compress
'''
STATUS=COMMON+r'''
$name='IntegrityLAB-Open-Native-Desktop'
$task=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
$removed=$false
if($task){$info=Get-ScheduledTaskInfo -TaskName $name;if($task.State -ne 'Running' -and $info.LastRunTime.Year -gt 2020){Unregister-ScheduledTask -TaskName $name -Confirm:$false;$removed=$true}}
$p=Get-AppxPackage -Name OpenAI.Codex
$running=@(Get-Process -Name ChatGPT -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq (Join-Path $p.InstallLocation 'app\ChatGPT.exe')})
@{native_desktop_process_count=$running.Count;activation_task_removed=$removed;activation_task_present=($null -ne (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue));model_turns=0;agents='NOT_RUN'} | ConvertTo-Json -Compress
'''


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['start','status']);args=p.parse_args()
    report=json.loads(require(powershell(lab_config.fill(START if args.action=='start' else STATUS, quote=lab_config.ps_quote, WINDOWS_HOSTNAME=lab_config.setting('vms.windows.hostname')),45)))
    (ROOT/'evidence'/('NATIVE-DESKTOP-'+args.action.upper()+'.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
