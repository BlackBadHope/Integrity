# SPDX-License-Identifier: BUSL-1.1
# Runs only inside the new Windows guest. No provider or model calls.
$ErrorActionPreference='Stop'
$labConfigPath=Join-Path $PSScriptRoot 'lab.json'
if(-not (Test-Path -LiteralPath $labConfigPath)){throw 'lab.json not found next to this script; fill it from lab.example.json'}
$labConfig=Get-Content -LiteralPath $labConfigPath -Raw | ConvertFrom-Json
$labWindowsHost=[string]$labConfig.vms.windows.hostname
if(-not $labWindowsHost){throw 'lab configuration key vms.windows.hostname is missing'}
$labWindowsIp=[string]$labConfig.network.windows_guest_ip
$labPrefix=[int]$labConfig.network.prefix_length
if(-not $labWindowsIp -or -not $labPrefix){throw 'lab configuration keys network.windows_guest_ip and network.prefix_length are required'}
if($env:COMPUTERNAME -ne $labWindowsHost){throw 'Refusing to run outside the named LAB guest'}
if((Get-CimInstance Win32_ComputerSystem).Manufacturer -notmatch 'Oracle|innotek'){throw 'Expected VirtualBox guest'}
$labReport=[ordered]@{schema='integrity-lab.windows-guest-preflight.v1';status='FAIL';agents='NOT_RUN';models='NOT_RUN';benchmarks='NOT_RUN';native_clients='NOT_INSTALLED';full_native_owner_lifecycle='NOT_RUN'}
try {
    New-Item -ItemType Directory -Path C:\IntegrityLAB\evidence -Force | Out-Null
    $labNic=@(Get-NetAdapter | Where-Object HardwareInterface)
    if($labNic.Count -ne 1){throw 'Expected exactly one internal-network NIC'}
    Set-NetIPInterface -InterfaceIndex $labNic[0].ifIndex -AddressFamily IPv4 -Dhcp Disabled
    if(-not(Get-NetIPAddress -InterfaceIndex $labNic[0].ifIndex -AddressFamily IPv4 | Where-Object IPAddress -eq $labWindowsIp)){
        New-NetIPAddress -InterfaceIndex $labNic[0].ifIndex -IPAddress $labWindowsIp -PrefixLength $labPrefix | Out-Null
    }
    Set-DnsClientServerAddress -InterfaceIndex $labNic[0].ifIndex -ResetServerAddresses
    $labDefault=@(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0'))
    if($labDefault.Count){throw 'Unexpected default route'}
    $labDns=@((Get-DnsClientServerAddress -InterfaceIndex $labNic[0].ifIndex -AddressFamily IPv4).ServerAddresses)
    if($labDns.Count){throw 'Unexpected DNS resolver'}
    if(Test-Path -LiteralPath (Join-Path $env:ProgramData 'OpenAI\Codex\IntegrityMemoryLTS')){throw 'Unexpected production hook directory'}
    if(@(Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -eq 4).Count){throw 'Unexpected mapped network drive'}
    $labReport['os']=(Get-CimInstance Win32_OperatingSystem).Caption
    $labReport['build']=[Environment]::OSVersion.Version.ToString()
    $labReport['hostname']=$env:COMPUTERNAME
    $labReport['ip']=$labWindowsIp+'/'+$labPrefix
    $labReport['default_route']=$false
    $labReport['production_hooks_present']=$false
    $labReport['secure_boot']=Confirm-SecureBootUEFI
    $labReport['TPM_present']=(Get-Tpm).TpmPresent
    if(-not $labReport['secure_boot'] -or -not $labReport['TPM_present']){throw 'Guest Secure Boot or TPM missing'}
    $labReport['guest_additions_installed']=Test-Path -LiteralPath 'C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxService.exe'
    $labReport['activation']='NO_KEY_NOT_REQUESTED'
    if(Test-Path -LiteralPath C:\IntegrityLAB\evidence\runtime.json){
        $labRuntimeResult=Get-Content -LiteralPath C:\IntegrityLAB\evidence\runtime.json -Raw | ConvertFrom-Json
        $labReport['runtime']=$labRuntimeResult
        if($labRuntimeResult.status -ne 'PASS'){throw ('Guest runtime setup failed: '+$labRuntimeResult.reason)}
        $labReport['native_clients']='INSTALLED_NOT_STARTED'
    }
    $labReport['status']='PASS'
} catch {
    $labReport['reason']=$_.Exception.Message
} finally {
    # End the installer-only automatic login and remove its cached password.
    $labWinlogon='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-ItemProperty -LiteralPath $labWinlogon -Name AutoAdminLogon -Value '0' -ErrorAction SilentlyContinue
    Remove-ItemProperty -LiteralPath $labWinlogon -Name DefaultPassword -ErrorAction SilentlyContinue
    $labJson=$labReport | ConvertTo-Json -Depth 6 -Compress
    if(Test-Path -LiteralPath C:\IntegrityLAB\evidence){$labJson | Set-Content -LiteralPath C:\IntegrityLAB\evidence\preflight.json -Encoding UTF8}
    try {$labSerial=[System.IO.Ports.SerialPort]::new('COM1',115200,'None',8,'One');$labSerial.Open();$labSerial.WriteLine('INTEGRITY_LAB_PREFLIGHT_JSON='+$labJson);$labSerial.Close()} catch {}
    shutdown.exe /s /t 5
}
