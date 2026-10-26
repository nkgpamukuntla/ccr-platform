<#
.SYNOPSIS
    Court Connection Readiness - offline evidence collector (Windows).

.DESCRIPTION
    Reads this PC's security configuration and writes ONE encrypted bundle (.ccre) for the
    court office named in office.json. Upload the bundle in the CCR portal (Onboarding step 5
    or the Devices page), from this PC or from any other PC after copying it by USB.

    Reads: hostname, serial, MAC, make/model, OS build, installed updates, BitLocker,
    Secure Boot, TPM, security agents and their service state, Microsoft Defender state,
    firewall profiles, local Administrators members, password and screen-lock policy,
    domain / Entra join state.

    Never reads: files, documents, email, browser data, credentials, user content, or
    anything from Gavel. Installs nothing, changes nothing, leaves nothing running. The only
    file it writes is the bundle.

    Run as administrator for complete results (BitLocker, TPM and Secure Boot need it).
    Windows PowerShell 5.1 or later; no modules or internet access needed.

.PARAMETER ConfigPath
    office.json from the portal download. Default: next to this script.

.PARAMETER OutputPath
    Folder for the bundle. Default: next to this script (Desktop if that is read-only).

.PARAMETER Preview
    Show what would be collected, in plain text, and write nothing.

.EXAMPLE
    powershell.exe -ExecutionPolicy RemoteSigned -File .\Collect-CCREvidence.ps1
.EXAMPLE
    .\Collect-CCREvidence.ps1 -Preview
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = '',
    [string]$OutputPath = '',
    [switch]$Preview
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$CollectorVersion = '1.0.0'
# Windows PowerShell 5.1 leaves $PSScriptRoot empty in parameter defaults, so resolve here.
$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
if (-not $ConfigPath) { $ConfigPath = Join-Path $here 'office.json' }
if (-not $OutputPath) { $OutputPath = $here }
$script:Errors = New-Object System.Collections.Generic.List[string]

function Get-Safely([string]$What, [scriptblock]$Block) {
    try { & $Block } catch { $script:Errors.Add("$What ($($_.Exception.Message))"); $null }
}

function Iso([object]$Date) {
    if ($null -eq $Date) { return $null }
    try { return ([datetime]$Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } catch { return $null }
}

function Get-RegValue([string]$Path, [string]$Name) {
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

# Known EDR / MDR agents, by Windows service name.
$EdrCatalogue = @(
    @{ Service = 'CSFalconService';  Product = 'CrowdStrike Falcon' },
    @{ Service = 'Sense';            Product = 'Microsoft Defender for Endpoint' },
    @{ Service = 'SentinelAgent';    Product = 'SentinelOne' },
    @{ Service = 'SEDService';       Product = 'Sophos Intercept X' },
    @{ Service = 'CbDefense';        Product = 'VMware Carbon Black Cloud' },
    @{ Service = 'cyserver';         Product = 'Palo Alto Cortex XDR' },
    @{ Service = 'EndpointBasecamp'; Product = 'Trend Micro Vision One' },
    @{ Service = 'HuntressAgent';    Product = 'Huntress' },
    @{ Service = 'CylanceSvc';       Product = 'Cylance' }
)

$started = Get-Date
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------- device ----------
$cs   = Get-Safely 'computer system' { Get-CimInstance Win32_ComputerSystem }
$bios = Get-Safely 'BIOS' { Get-CimInstance Win32_BIOS }
$os   = Get-Safely 'operating system' { Get-CimInstance Win32_OperatingSystem }
$cv   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$macs = Get-Safely 'network adapters' {
    @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE' | Where-Object { $_.MACAddress } | ForEach-Object { $_.MACAddress })
}
$ubr = Get-RegValue $cv 'UBR'
$build = if ($os) { if ($ubr) { "$($os.Version).$ubr" } else { $os.Version } } else { $null }

$device = [ordered]@{
    hostname     = $env:COMPUTERNAME
    serial       = if ($bios) { $bios.SerialNumber } else { $null }
    manufacturer = if ($cs) { $cs.Manufacturer } else { $null }
    model        = if ($cs) { $cs.Model } else { $null }
    os           = if ($os) { $os.Caption } else { $null }
    os_version   = Get-RegValue $cv 'DisplayVersion'
    os_build     = $build
    last_boot    = if ($os) { Iso $os.LastBootUpTime } else { $null }
    macs         = @($macs)
}

# ---------- updates ----------
$updates = Get-Safely 'installed updates' {
    $hf = @(Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
    [ordered]@{
        count          = $hf.Count
        latest_kb      = if ($hf.Count) { $hf[0].HotFixID } else { $null }
        latest_install = if ($hf.Count) { Iso $hf[0].InstalledOn } else { $null }
        recent         = @($hf | Select-Object -First 10 | ForEach-Object { [ordered]@{ kb = $_.HotFixID; installed = (Iso $_.InstalledOn) } })
    }
}

# ---------- disk encryption, Secure Boot, TPM ----------
$bitlocker = Get-Safely 'BitLocker' {
    $sys = $env:SystemDrive
    if ($elevated) {
        $v = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter = '$sys'"
        [ordered]@{ drive = $sys; protection_on = ($v.ProtectionStatus -eq 1); source = 'Win32_EncryptableVolume' }
    } else {
        # Without admin: the shell's view of the volume (1 = on, 3 = on/encrypting, 2 = off).
        $p = (New-Object -ComObject Shell.Application).NameSpace("$sys\").Self.ExtendedProperty('System.Volume.BitLockerProtection')
        [ordered]@{ drive = $sys; protection_on = ($p -eq 1 -or $p -eq 3 -or $p -eq 5); source = 'shell (not elevated)' }
    }
}
$sbState = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
$secureBoot = [ordered]@{ enabled = if ($null -eq $sbState) { $null } else { [bool]$sbState }; source = 'registry' }
$tpm = Get-Safely 'TPM' {
    if ($elevated) {
        $t = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName Win32_Tpm
        if ($t) { [ordered]@{ present = $true; enabled = [bool]$t.IsEnabled_InitialValue; version = ($t.SpecVersion -split ',')[0].Trim() } }
        else { [ordered]@{ present = $false } }
    } else {
        $d = @(Get-CimInstance Win32_PnPEntity -Filter "Name LIKE '%Trusted Platform Module%'")
        [ordered]@{ present = ($d.Count -gt 0); enabled = $null; version = if ($d.Count) { ($d[0].Name -replace '.*Module\s*', '') } else { $null } }
    }
}

# ---------- security agents ----------
$agents = @(foreach ($e in $EdrCatalogue) {
    $svc = Get-Service -Name $e.Service -ErrorAction SilentlyContinue
    if ($svc) {
        $running = ($svc.Status -eq 'Running')
        if ($e.Service -eq 'Sense') {
            $onb = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' 'OnboardingState'
            $running = $running -and ($onb -eq 1)
        }
        [ordered]@{ product = $e.Product; service = $e.Service; state = [string]$svc.Status; start_type = [string]$svc.StartType; running = $running }
    }
})
$defender = Get-Safely 'Microsoft Defender' {
    $m = Get-MpComputerStatus
    [ordered]@{
        service    = [bool]$m.AMServiceEnabled
        realtime   = [bool]$m.RealTimeProtectionEnabled
        mode       = [string]$m.AMRunningMode
        signatures = Iso $m.AntivirusSignatureLastUpdated
    }
}
$avProducts = Get-Safely 'Security Center' {
    @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct | ForEach-Object { [ordered]@{ name = $_.displayName; state = ('0x{0:X6}' -f [int]$_.productState) } })
}
$firewall = Get-Safely 'firewall' {
    @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ profile = [string]$_.Name; enabled = ([string]$_.Enabled -eq 'True') } })
}

# ---------- accounts and policy ----------
$admins = Get-Safely 'local Administrators' {
    $name = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
    $group = [ADSI]"WinNT://$env:COMPUTERNAME/$name,group"
    @($group.psbase.Invoke('Members') | ForEach-Object {
        $path = $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null)
        ($path -replace '^WinNT://', '') -replace '/', '\'
    })
}
$password = Get-Safely 'password policy' {
    $p = [ordered]@{}
    foreach ($line in (& net.exe accounts)) {
        if ($line -match '^\s*(Minimum password length|Maximum password age \(days\)|Lockout threshold|Password history length)\s*:?\s+(.+)$') {
            $p[($Matches[1] -replace '[^A-Za-z]+', '_').Trim('_').ToLower()] = $Matches[2].Trim()
        }
    }
    $p
}
$screenLock = [ordered]@{
    machine_inactivity_seconds = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'
    policy_timeout_seconds     = Get-RegValue 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop' 'ScreenSaveTimeOut'
    policy_secure              = Get-RegValue 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop' 'ScreenSaverIsSecure'
    user_timeout_seconds       = Get-RegValue 'HKCU:\Control Panel\Desktop' 'ScreenSaveTimeOut'
    user_secure                = Get-RegValue 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure'
}

# ---------- domain / Entra join ----------
$join = Get-Safely 'join state' {
    $j = [ordered]@{ domain_joined = $null; domain = $null; entra_joined = $null; entra_tenant_id = $null; entra_device_id = $null; workplace_joined = $null }
    if ($cs) { $j.domain_joined = [bool]$cs.PartOfDomain; if ($cs.PartOfDomain) { $j.domain = $cs.Domain } }
    $map = @{ AzureAdJoined = 'entra_joined'; WorkplaceJoined = 'workplace_joined'; TenantId = 'entra_tenant_id'; DeviceId = 'entra_device_id' }
    foreach ($line in (& dsregcmd.exe /status)) {
        if ($line -match '^\s*(\w+)\s*:\s*(.+?)\s*$' -and $map.ContainsKey($Matches[1])) {
            $v = $Matches[2]
            $j[$map[$Matches[1]]] = if ($v -eq 'YES') { $true } elseif ($v -eq 'NO') { $false } else { $v }
        }
    }
    $j
}

$finished = Get-Date
$facts = [ordered]@{
    collector = [ordered]@{
        version  = $CollectorVersion
        token    = $null
        started  = Iso $started
        finished = Iso $finished
        elevated = $elevated
        run_by   = $identity.Name
    }
    device   = $device
    updates  = $updates
    disk     = [ordered]@{ bitlocker = $bitlocker; secure_boot = $secureBoot; tpm = $tpm }
    security = [ordered]@{ edr_agents = $agents; defender = $defender; antivirus = $avProducts; firewall = $firewall }
    accounts = [ordered]@{ local_admins = $admins; password_policy = $password; screen_lock = $screenLock }
    join     = $join
    errors   = @($script:Errors)
}

if ($Preview) {
    Write-Host "CCR collector $CollectorVersion - preview only, nothing written." -ForegroundColor Cyan
    $facts | ConvertTo-Json -Depth 8
    return
}

# ---------- seal for the office (see backend/app/collector/bundle.py for the format) ----------
if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "office.json not found at $ConfigPath. Download the collector for your office from the CCR portal." }
$cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
if ($cfg.format -ne 'ccr-collector-config/1') { throw 'office.json is not a CCR collector configuration.' }
$facts.collector.token = $cfg.token

function Join-Bytes([byte[][]]$Parts) {
    $ms = New-Object IO.MemoryStream
    foreach ($p in $Parts) { $ms.Write($p, 0, $p.Length) }
    , $ms.ToArray()
}

$plain = [Text.Encoding]::UTF8.GetBytes(($facts | ConvertTo-Json -Depth 8 -Compress))
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$key = New-Object byte[] 64; $rng.GetBytes($key)
$iv = New-Object byte[] 16; $rng.GetBytes($iv)
$macKey = [byte[]]$key[0..31]; $encKey = [byte[]]$key[32..63]

$rsa = New-Object Security.Cryptography.RSACng
$rp = New-Object Security.Cryptography.RSAParameters
$rp.Modulus = [Convert]::FromBase64String($cfg.public_key.n)
$rp.Exponent = [Convert]::FromBase64String($cfg.public_key.e)
$rsa.ImportParameters($rp)
$ek = $rsa.Encrypt($key, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)

$aes = [Security.Cryptography.Aes]::Create()
$aes.Mode = [Security.Cryptography.CipherMode]::CBC
$aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
$aes.Key = $encKey; $aes.IV = $iv
$ct = $aes.CreateEncryptor().TransformFinalBlock($plain, 0, $plain.Length)

$aad = [Text.Encoding]::UTF8.GetBytes("ccr-bundle/1|$($cfg.office_id)|$($cfg.key_arn)")
$al = [BitConverter]::GetBytes([UInt64]($aad.Length * 8)); if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($al) }
$hmac = New-Object Security.Cryptography.HMACSHA512 -ArgumentList (, $macKey)
$tag = [byte[]]($hmac.ComputeHash((Join-Bytes @($aad, $iv, $ct, $al))))[0..31]

$envelope = [ordered]@{
    format    = 'ccr-bundle/1'
    enc       = 'RSA-OAEP-256/A256CBC-HS512'
    office_id = $cfg.office_id
    key_arn   = $cfg.key_arn
    ek        = [Convert]::ToBase64String($ek)
    iv        = [Convert]::ToBase64String($iv)
    ct        = [Convert]::ToBase64String($ct)
    tag       = [Convert]::ToBase64String($tag)
}
[Array]::Clear($key, 0, $key.Length); [Array]::Clear($plain, 0, $plain.Length)

$name = '{0}_{1}.ccre' -f $env:COMPUTERNAME, $finished.ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$target = Join-Path $OutputPath $name
try {
    [IO.File]::WriteAllText($target, ($envelope | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))
} catch {
    $target = Join-Path ([Environment]::GetFolderPath('Desktop')) $name
    [IO.File]::WriteAllText($target, ($envelope | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))
}

$edrText = if ($agents.Count) { ($agents | ForEach-Object { "$($_.product) ($($_.state))" }) -join ', ' } else { 'none found' }
Write-Host ''
Write-Host "CCR collector $CollectorVersion for $($cfg.office_name)" -ForegroundColor Cyan
Write-Host "  Device         : $($device.hostname)  serial $($device.serial)"
Write-Host "  Security agent : $edrText"
Write-Host "  Administrator  : $elevated$(if (-not $elevated) { '  (run as administrator for BitLocker, TPM and Secure Boot)' })"
if ($script:Errors.Count) { Write-Host "  Not readable   : $($script:Errors.Count) item(s), listed inside the bundle" -ForegroundColor Yellow }
Write-Host "  Bundle written : $target" -ForegroundColor Green
Write-Host '  Upload it in the CCR portal: Devices > Upload collector bundles.'
