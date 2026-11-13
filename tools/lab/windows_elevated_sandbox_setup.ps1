# SPDX-License-Identifier: BUSL-1.1
# Prepared guest-only fallback. Run manually from an elevated Windows LAB session.
# Creates only the client's documented sandbox accounts/rules in this new guest.
$ErrorActionPreference='Stop'
$labConfigPath=Join-Path $PSScriptRoot 'lab.json'
if(-not (Test-Path -LiteralPath $labConfigPath)){throw 'lab.json not found next to this script; fill it from lab.example.json'}
$labConfig=Get-Content -LiteralPath $labConfigPath -Raw | ConvertFrom-Json
$labWindowsHost=[string]$labConfig.vms.windows.hostname
if(-not $labWindowsHost){throw 'lab configuration key vms.windows.hostname is missing'}
if($env:COMPUTERNAME -ne $labWindowsHost){throw 'Refusing to run outside the configured Windows LAB guest'}
if((Get-CimInstance Win32_ComputerSystem).Manufacturer -notmatch 'Oracle|innotek'){throw 'VirtualBox LAB guest required'}
$labPrincipal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $labPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'Open an administrator PowerShell inside the LAB guest; UAC must be confirmed by the operator'
}
if(@(Get-NetRoute | Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0')).Count){throw 'Unexpected guest egress route'}
if(Test-Path -LiteralPath (Join-Path $env:ProgramData 'OpenAI\Codex\IntegrityMemoryLTS')){throw 'Unexpected working Integrity installation'}
$labPackage=Get-AppxPackage -AllUsers -Name OpenAI.Codex | Select-Object -First 1
if($labPackage.PackageFamilyName -ne 'OpenAI.Codex_2p2nqsd0c76g0'){throw 'Expected installed signed native package'}
$labCli=Join-Path $labPackage.InstallLocation 'app\resources\codex.exe'
$labRows=@()
foreach($labActor in @('LAB-A','LAB-B')){
    $labHome='C:\IntegrityLAB\clients\'+$labActor+'\.codex'
    if(Test-Path -LiteralPath (Join-Path $labHome auth.json)){throw 'Unexpected authenticated profile'}
    & $labCli sandbox setup --elevated --user ($labWindowsHost+'\labadmin') --codex-home $labHome
    if($LASTEXITCODE){throw ('Sandbox setup failed for '+$labActor+', exit '+$LASTEXITCODE)}
    $labRows+=@{actor=$labActor;setup='COMPLETED_ACCEPTANCE_PENDING'}
}
@{schema='integrity-lab.windows-elevated-setup.v1';status='SETUP_ONLY_NOT_ACCEPTED';actors=$labRows;
  agents='NOT_RUN';models='NOT_RUN';benchmarks='NOT_RUN';
  required_next_gate='Run windows_vm_stage.py sandbox --sandbox-implementation elevated from the host'} |
  ConvertTo-Json -Depth 4 | Set-Content -LiteralPath C:\IntegrityLAB\evidence\elevated-setup.json -Encoding UTF8
