# SPDX-License-Identifier: BUSL-1.1
"""One-shot, least-privilege technical probes in the logged-in LAB guest.

GuestControl uses session 0. This comparison uses an interactive-token task;
it stores no password, grants no elevation, has no trigger, and is removed
after collecting its terminal result. No models or agent turns are started.
"""
import argparse
import json
from windows_guest_control import powershell, ROOT
from windows_vm_stage import collect, require
import lab_config

TASK = 'IntegrityLAB-Technical-Preflight'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['start', 'status'])
    parser.add_argument('--stage', choices=['metadata', 'sandbox'], required=True)
    args = parser.parse_args()
    script = 'windows_native_preflight.py' if args.stage == 'metadata' else 'windows_sandbox_preflight.py'
    binding = json.loads((ROOT/'evidence/WINDOWS-INDEPENDENT-READBACK.json').read_text())
    cli = binding['CLI_path']
    if binding['status'] != 'PASS' or not cli.startswith('C:\\Program Files\\WindowsApps\\') or not cli.endswith('\\codex.exe'):
        raise RuntimeError('Expected verified LAB native package')
    probe = 'C:\\IntegrityLAB\\control\\preflight-labadmin\\'+script
    arguments = '-I -B "'+probe+'" --cli "'+cli+'" '
    arguments += '--sandbox-smoke --sandbox-implementation elevated' if args.stage == 'metadata' else '--implementation elevated'
    # All interpolated values above are fixed local allowlist values, never credentials.
    common = r'''
$ErrorActionPreference='Stop'
$labWindowsHost=@WINDOWS_HOSTNAME@
if($env:COMPUTERNAME -ne $labWindowsHost){throw 'Wrong guest'}
if((Get-CimInstance Win32_ComputerSystem).UserName -ne ($labWindowsHost+'\labadmin')){throw 'LAB interactive user required'}
'''
    common = lab_config.fill(common, quote=lab_config.ps_quote, WINDOWS_HOSTNAME=lab_config.setting('vms.windows.hostname'))
    if args.action == 'start':
        source = common + r"""
if(Get-ScheduledTask -TaskName 'TASK_NAME' -ErrorAction SilentlyContinue){throw 'Existing LAB technical task; inspect rather than duplicate'}
$action=New-ScheduledTaskAction -Execute 'C:\IntegrityLAB\runtime\venv\Scripts\python.exe' -Argument 'PROBE_ARGS' -WorkingDirectory 'C:\IntegrityLAB'
$principal=New-ScheduledTaskPrincipal -UserId ($labWindowsHost+'\labadmin') -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'TASK_NAME' -Action $action -Principal $principal -Settings $settings -Description 'Authorized technical LAB preflight only; no triggers or models' | Out-Null
$task=Get-ScheduledTask -TaskName 'TASK_NAME'
if($task.Principal.RunLevel -ne 'Limited' -or $task.Principal.LogonType -ne 'Interactive' -or @($task.Triggers | Where-Object {$null -ne $_}).Count){Unregister-ScheduledTask -TaskName 'TASK_NAME' -Confirm:$false;throw 'Unexpected task privilege or trigger'}
Start-ScheduledTask -TaskName 'TASK_NAME'
@{status='STARTED';run_level='Limited';logon='Interactive';triggers=0;password_stored=$false;models='NOT_RUN'} | ConvertTo-Json -Compress
""".replace('TASK_NAME',TASK).replace('PROBE_ARGS',arguments)
        report = json.loads(require(powershell(source,45)))
    else:
        evidence_name = 'native-preflight.json' if args.stage == 'metadata' else 'sandbox-preflight.json'
        source = common + r"""
$task=Get-ScheduledTask -TaskName 'TASK_NAME'
$info=Get-ScheduledTaskInfo -TaskName 'TASK_NAME'
if($task.Actions.Execute -ne 'C:\IntegrityLAB\runtime\venv\Scripts\python.exe' -or $task.Actions.Arguments -ne 'PROBE_ARGS'){throw 'Task binding mismatch'}
$terminal=([string]$task.State -ne 'Running' -and $info.LastRunTime.Year -gt 2020)
$evidence=Get-Item -LiteralPath 'C:\IntegrityLAB\evidence\EVIDENCE_NAME' -ErrorAction SilentlyContinue
$fresh=($null -ne $evidence -and $evidence.LastWriteTimeUtc -ge $info.LastRunTime.ToUniversalTime())
@{state=[string]$task.State;terminal=$terminal;last_result=$info.LastTaskResult;run_level=[string]$task.Principal.RunLevel;evidence_fresh=$fresh} | ConvertTo-Json -Compress
if($terminal){Unregister-ScheduledTask -TaskName 'TASK_NAME' -Confirm:$false}
""".replace('TASK_NAME',TASK).replace('PROBE_ARGS',arguments).replace('EVIDENCE_NAME',evidence_name)
        report = json.loads(require(powershell(source,45)))
        if report['terminal'] and report['evidence_fresh']:
            name,target = ('native-preflight.json','WINDOWS-ELEVATED-NATIVE-PREFLIGHT.json') if args.stage=='metadata' else ('sandbox-preflight.json','WINDOWS-SANDBOX-PREFLIGHT.json')
            report['probe'] = collect(name,target)
    (ROOT/'evidence'/('WINDOWS-INTERACTIVE-'+args.stage.upper()+'.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
