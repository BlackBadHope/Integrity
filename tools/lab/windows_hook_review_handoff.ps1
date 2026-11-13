# SPDX-License-Identifier: BUSL-1.1
param([ValidateSet('prepare','start','status')][string]$Stage)
$ErrorActionPreference='Stop'
$labConfigPath=Join-Path $PSScriptRoot 'lab.json'
if(-not (Test-Path -LiteralPath $labConfigPath)){throw 'lab.json not found next to this script; fill it from lab.example.json'}
$labConfig=Get-Content -LiteralPath $labConfigPath -Raw | ConvertFrom-Json
$labWindowsHost=[string]$labConfig.vms.windows.hostname
if(-not $labWindowsHost){throw 'lab configuration key vms.windows.hostname is missing'}
if($env:COMPUTERNAME -ne $labWindowsHost){throw 'Wrong guest'}
$control='C:\IntegrityLAB\control\preflight-labadmin'
$taskName='IntegrityLAB-Hook-Review'
$cli='C:\Program Files\WindowsApps\OpenAI.Codex_26.1013.4894.0_x64__2p2nqsd0c76g0\app\resources\codex.exe'
$desktop=[Environment]::GetFolderPath('Desktop')
if(-not (Test-Path -LiteralPath $cli)){throw 'Expected installed CLI'}
if($Stage -eq 'prepare'){
 $items=@()
 foreach($actor in @('LAB-A','LAB-B')){
  $workspace='C:\IntegrityLAB\workspaces\'+$actor
  $batch='@echo off'+"`r`n"+'title IntegrityLAB - '+$actor+' - Hook Review'+"`r`n"+
   'echo LAB hook review only. Enter /hooks, review and trust the nine LAB hooks. Do not send a model prompt.'+"`r`n"+
   'set "CODEX_HOME='+(Join-Path $env:USERPROFILE '.codex')+'"'+"`r`n"+
   'cd /d "'+$workspace+'"'+"`r`n"+'"'+$cli+'" -C "'+$workspace+'"'+"`r`n"
  $path=Join-Path $desktop ('REVIEW-'+$actor+'-HOOKS.cmd')
  if(Test-Path -LiteralPath $path){
   if([IO.File]::ReadAllText($path) -ne $batch){throw 'Unexpected review helper preimage'}
  }else{[IO.File]::WriteAllText($path,$batch,[Text.Encoding]::ASCII)}
  $items+=@{actor=$actor;path=$path;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()}
 }
 $launch=@'
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne @WINDOWS_HOSTNAME@){throw 'Wrong guest'}
$path=Join-Path ([Environment]::GetFolderPath('Desktop')) 'REVIEW-LAB-A-HOOKS.cmd'
Start-Process -FilePath C:\Windows\System32\cmd.exe -ArgumentList @('/c',$path) -WindowStyle Normal
'@
 $launch=$launch.Replace('@WINDOWS_HOSTNAME@',"'"+$labWindowsHost.Replace("'","''")+"'")
 [IO.File]::WriteAllText((Join-Path $control 'SHOW-HOOK-REVIEW.ps1'),$launch,[Text.Encoding]::ASCII)
 @{status='LAB_HOOK_REVIEW_SHORTCUTS_READY';items=$items;prompts_sent=0;trust_bypassed=$false} | ConvertTo-Json -Depth 5 -Compress
}elseif($Stage -eq 'start'){
 if((Get-CimInstance Win32_ComputerSystem).UserName -ne ($labWindowsHost+'\labadmin')){throw 'Interactive LAB user required'}
 if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'Existing review launch task'}
 $action=New-ScheduledTaskAction -Execute C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Argument ('-NoLogo -NoProfile -ExecutionPolicy RemoteSigned -WindowStyle Hidden -File "'+(Join-Path $control 'SHOW-HOOK-REVIEW.ps1')+'"')
 $principal=New-ScheduledTaskPrincipal -UserId ($labWindowsHost+'\labadmin') -LogonType Interactive -RunLevel Limited
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
 Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
 Start-ScheduledTask -TaskName $taskName
 @{status='INTERACTIVE_LAB_A_REVIEW_LAUNCH_REQUESTED';prompts_sent=0;trust_bypassed=$false;task_triggers=0} | ConvertTo-Json -Compress
}else{
 $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
 if($task -and $task.State -ne 'Running'){
  $info=Get-ScheduledTaskInfo -TaskName $taskName
  if($info.LastRunTime.Year -gt 2020){Unregister-ScheduledTask -TaskName $taskName -Confirm:$false}
 }
 $processes=@(Get-Process -Name codex -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq $cli})
 @{status='REVIEW_LAUNCH_READBACK';CLI_processes=$processes.Count;visible_CLI_windows=@($processes | Where-Object {$_.MainWindowHandle -ne 0}).Count;task_present=($null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue));trust_bypassed=$false;prompts_sent=0} | ConvertTo-Json -Compress
}
