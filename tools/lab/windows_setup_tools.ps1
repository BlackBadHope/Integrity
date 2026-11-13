# SPDX-License-Identifier: BUSL-1.1
# Guest-only offline prerequisites. Never invoke from the Windows host.
$ErrorActionPreference='Stop'
$labConfigPath=Join-Path $PSScriptRoot 'lab.json'
if(-not (Test-Path -LiteralPath $labConfigPath)){throw 'lab.json not found next to this script; fill it from lab.example.json'}
$labConfig=Get-Content -LiteralPath $labConfigPath -Raw | ConvertFrom-Json
$labWindowsHost=[string]$labConfig.vms.windows.hostname
if(-not $labWindowsHost){throw 'lab configuration key vms.windows.hostname is missing'}
if($env:COMPUTERNAME -ne $labWindowsHost){throw 'Wrong guest hostname'}
if((Get-CimInstance Win32_ComputerSystem).Manufacturer -notmatch 'Oracle|innotek'){throw 'Expected VirtualBox guest'}
$labRuntime=[ordered]@{schema='integrity-lab.windows-runtime.v1';status='FAIL';models='NOT_RUN';agents='NOT_RUN';authentication='NOT_CONFIGURED';source='offline signed installers'}
try {
    $labPrincipal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if(-not $labPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Guest installation requires the elevated FirstLogonCommands context'}
    New-Item -ItemType Directory -Path C:\IntegrityLAB\runtime,C:\IntegrityLAB\evidence,C:\IntegrityLAB\control -Force | Out-Null
    $labMsi=Start-Process -FilePath msiexec.exe -ArgumentList @('/i',('"'+$PSScriptRoot+'\PowerShell-7.6.7-win-x64.msi"'),'/qn','/norestart','ADD_PATH=0','ENABLE_PSREMOTING=0','USE_MU=0','ENABLE_MU=0') -Wait -PassThru -WindowStyle Hidden
    if($labMsi.ExitCode -notin @(0,3010)){throw ('PowerShell MSI exit '+$labMsi.ExitCode)}
    $labPyInstall=Start-Process -FilePath (Join-Path $PSScriptRoot 'python-3.14.8-amd64.exe') -ArgumentList @('/quiet','InstallAllUsers=1','TargetDir=C:\IntegrityLAB\runtime\Python','PrependPath=0','Include_launcher=0','Include_test=0','Include_tcltk=0') -Wait -PassThru -WindowStyle Hidden
    if($labPyInstall.ExitCode -notin @(0,3010)){throw ('Python installer exit '+$labPyInstall.ExitCode)}
    $labPython='C:\IntegrityLAB\runtime\Python\python.exe'
    & $labPython -m venv C:\IntegrityLAB\runtime\venv
    if($LASTEXITCODE){throw 'Guest venv creation failed'}
    & C:\IntegrityLAB\runtime\venv\Scripts\python.exe -m pip install --quiet --no-index --find-links (Join-Path $PSScriptRoot 'wheels') 'integrity-client-memory[native]==1.9.0'
    if($LASTEXITCODE){throw 'Guest offline wheel installation failed'}
    & C:\IntegrityLAB\runtime\venv\Scripts\python.exe -m pip check
    if($LASTEXITCODE){throw 'Guest Python dependency check failed'}
    $labRuntime['Python']=(& $labPython --version 2>&1 | Out-String).Trim()
    $labRuntime['PowerShell']=(& 'C:\Program Files\PowerShell\7\pwsh.exe' -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' | Out-String).Trim()
    Add-AppxProvisionedPackage -Online -PackagePath (Join-Path $PSScriptRoot ChatGPT.msix) -LicensePath (Join-Path $PSScriptRoot ChatGPT-License.xml) -Regions all | Out-Null
    Add-AppxPackage -Path (Join-Path $PSScriptRoot ChatGPT.msix)
    $labPackage=Get-AppxPackage -Name OpenAI.Codex
    if(-not $labPackage){throw 'Native desktop package not registered for labadmin'}
    $labRuntime['desktop_package']=[string]$labPackage.Version
    $labRuntime['desktop_started']=$false
    $labCli=Join-Path $labPackage.InstallLocation 'app\resources\codex.exe'
    $labRuntime['CLI_version']=(& $labCli --version 2>&1 | Out-String).Trim()
    if($LASTEXITCODE){throw 'Installed package CLI version check failed'}
    foreach($labActor in @('LAB-A','LAB-B')){
        $labHome='C:\IntegrityLAB\clients\'+$labActor+'\.codex'
        New-Item -ItemType Directory -Path $labHome -Force | Out-Null
        @'
approval_policy = "on-request"
web_search = "disabled"
[windows]
sandbox = "mxc"
[features]
apps = false
plugins = false
memories = false
[agents]
enabled = false
'@ | Set-Content -LiteralPath (Join-Path $labHome config.toml) -Encoding UTF8
    }
    $labRuntime['client_homes']='TWO_FRESH_NO_AUTH_NO_MCP'
    $labRuntime['MCP_profile']='PENDING_VERIFIED_CROSS_VM_TRANSPORT'
    $labRuntime['sandbox']='CONFIGURED_MXC_NOT_YET_EXECUTION_VERIFIED'
    $labRuntime['status']='PASS'
} catch {
    $labRuntime['reason']=$_.Exception.Message
} finally {
    New-Item -ItemType Directory -Path C:\IntegrityLAB\evidence -Force | Out-Null
    $labRuntime | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath C:\IntegrityLAB\evidence\runtime.json -Encoding UTF8
}
