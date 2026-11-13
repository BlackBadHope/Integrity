# SPDX-License-Identifier: BUSL-1.1
param([ValidateSet('prepare','start','status')][string]$Stage)
$ErrorActionPreference='Stop'
$labConfigPath=Join-Path $PSScriptRoot 'lab.json'
if(-not (Test-Path -LiteralPath $labConfigPath)){throw 'lab.json not found next to this script; fill it from lab.example.json'}
$labConfig=Get-Content -LiteralPath $labConfigPath -Raw | ConvertFrom-Json
$labWindowsHost=[string]$labConfig.vms.windows.hostname
if(-not $labWindowsHost){throw 'lab configuration key vms.windows.hostname is missing'}
$labLinuxIp=[string]$labConfig.network.linux_guest_ip
$labProxyPort=[string]$labConfig.network.proxy_port
if(-not $labLinuxIp -or -not $labProxyPort){throw 'lab configuration keys network.linux_guest_ip and network.proxy_port are required'}
$labProxyHost=$labLinuxIp+':'+$labProxyPort
if($env:COMPUTERNAME -ne $labWindowsHost){throw 'Wrong guest'}
if((Get-CimInstance Win32_ComputerSystem).Manufacturer -notmatch 'Oracle|innotek'){throw 'Wrong hypervisor'}
$control='C:\IntegrityLAB\control\preflight-labadmin'
$proxy='http://'+$labProxyHost
$reg='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$ca='C:\IntegrityLAB\runtime\venv\Lib\site-packages\pip\_vendor\certifi\cacert.pem'
$taskName='IntegrityLAB-Native-Account-Setup'
$p=Get-AppxPackage -Name OpenAI.Codex
if($p.PackageFullName -ne 'OpenAI.Codex_26.1013.4894.0_x64__2p2nqsd0c76g0'){throw 'Unexpected guest package'}
$exe=Join-Path $p.InstallLocation 'app\ChatGPT.exe'

if($Stage -eq 'prepare'){
 if(@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue).Count){throw 'Windows must remain without default route'}
 if(-not (Test-Path -LiteralPath $ca)){throw 'Missing already-installed public CA bundle'}
 $old=Get-ItemProperty -LiteralPath $reg
 if($old.ProxyEnable -or $old.ProxyServer -or $old.AutoConfigURL){throw 'Inspect unexpected existing guest proxy first'}
 $vars=@{HTTP_PROXY=$proxy;HTTPS_PROXY=$proxy;NO_PROXY='localhost,127.0.0.1,::1,'+$labLinuxIp;SSL_CERT_FILE=$ca;NODE_EXTRA_CA_CERTS=$ca}
 foreach($key in $vars.Keys){if([Environment]::GetEnvironmentVariable($key,'User')){throw 'Inspect unexpected existing guest environment first'}}
 $before=[ordered]@{registry=[ordered]@{};environment=[ordered]@{}}
 foreach($key in @('ProxyEnable','ProxyServer','ProxyOverride','AutoDetect')){
  $before.registry[$key]=@{present=($old.PSObject.Properties.Name -contains $key);value=$old.$key}
 }
 foreach($key in $vars.Keys){$before.environment[$key]=@{present=$false}}
 $backup=Join-Path $control 'account-proxy-preimage.json'
 if(Test-Path -LiteralPath $backup){throw 'Existing guest proxy preimage; inspect before reapplying'}
 $before | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backup -Encoding UTF8
 New-ItemProperty -LiteralPath $reg -Name ProxyEnable -Value 1 -PropertyType DWord -Force | Out-Null
 New-ItemProperty -LiteralPath $reg -Name AutoDetect -Value 0 -PropertyType DWord -Force | Out-Null
 New-ItemProperty -LiteralPath $reg -Name ProxyServer -Value ('http='+$labProxyHost+';https='+$labProxyHost) -PropertyType String -Force | Out-Null
 New-ItemProperty -LiteralPath $reg -Name ProxyOverride -Value ('localhost;127.0.0.1;[::1];'+$labLinuxIp) -PropertyType String -Force | Out-Null
 foreach($key in $vars.Keys){[Environment]::SetEnvironmentVariable($key,$vars[$key],'User')}
 $launch=@'
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne @WINDOWS_HOSTNAME@){throw 'Wrong guest'}
foreach($key in @('HTTP_PROXY','HTTPS_PROXY','NO_PROXY','SSL_CERT_FILE','NODE_EXTRA_CA_CERTS')){
 $value=[Environment]::GetEnvironmentVariable($key,'User')
 if($value){[Environment]::SetEnvironmentVariable($key,$value,'Process')}
}
$env:CODEX_HOME=Join-Path $env:USERPROFILE '.codex'
$p=Get-AppxPackage -Name OpenAI.Codex
if($p.PackageFullName -ne 'OpenAI.Codex_26.1013.4894.0_x64__2p2nqsd0c76g0'){throw 'Wrong package'}
Start-Process -FilePath (Join-Path $p.InstallLocation 'app\ChatGPT.exe')
'@
 $launch=$launch.Replace('@WINDOWS_HOSTNAME@',"'"+$labWindowsHost.Replace("'","''")+"'")
 $launch | Set-Content -LiteralPath (Join-Path $control 'START-NATIVE-ACCOUNT.ps1') -Encoding UTF8
 $result=@{status='GUEST_PROXY_PREPARED';Windows_default_routes=0;proxy=$proxy;TLS_verification_disabled=$false;CA_source='Already installed pip Mozilla bundle';Windows_trust_store_modified=$false;host_settings_modified=$false;account_global_settings_modified=$false;models='NOT_RUN'}
 $result | ConvertTo-Json | Set-Content -LiteralPath C:\IntegrityLAB\evidence\account-proxy.json -Encoding UTF8
 $result | ConvertTo-Json -Compress
}elseif($Stage -eq 'start'){
 if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'Existing activation task; inspect before starting'}
 if(@(Get-Process -Name ChatGPT -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq $exe}).Count){throw 'Guest Desktop already running; inspect first'}
 $action=New-ScheduledTaskAction -Execute C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Argument ('-NoLogo -NoProfile -ExecutionPolicy RemoteSigned -WindowStyle Hidden -File "'+(Join-Path $control 'START-NATIVE-ACCOUNT.ps1')+'"')
 $principal=New-ScheduledTaskPrincipal -UserId ($labWindowsHost+'\labadmin') -LogonType Interactive -RunLevel Limited
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
 Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
 Start-ScheduledTask -TaskName $taskName
 @{status='NATIVE_GUEST_SHELL_STARTED_WITH_LOCAL_POLICY_AND_PROXY';task_triggers=0;models='NOT_RUN'} | ConvertTo-Json -Compress
}else{
 $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
 if($task -and $task.State -ne 'Running'){
  $taskInfo=Get-ScheduledTaskInfo -TaskName $taskName
  if($taskInfo.LastRunTime.Year -gt 2020){Unregister-ScheduledTask -TaskName $taskName -Confirm:$false}
 }
 $running=@(Get-Process -Name ChatGPT -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq $exe})
 $s=Get-ItemProperty -LiteralPath $reg
 $result=@{status='READBACK_ONLY';native_processes=$running.Count;activation_task_present=($null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue));proxy_enabled=($s.ProxyEnable -eq 1);proxy_matches=($s.ProxyServer -eq ('http='+$labProxyHost+';https='+$labProxyHost));Windows_default_routes=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue).Count;account_global_settings_modified=$false;models='NOT_RUN'}
 $result | ConvertTo-Json | Set-Content -LiteralPath C:\IntegrityLAB\evidence\account-proxy-readback.json -Encoding UTF8
 $result | ConvertTo-Json -Compress
}
