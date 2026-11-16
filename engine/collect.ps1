<#
  System Scanner - collection engine (READ-ONLY).
  Collects services, startup entries, scheduled tasks, hijack points, WMI
  persistence, AV status and remote-access session history, then writes JSON.
  It never changes, stops, deletes or uploads anything.

  Usage: powershell -NoProfile -ExecutionPolicy Bypass -File collect.ps1 -OutFile result.json
  Progress is printed to stdout as lines starting with "PROGRESS|".
#>
param([Parameter(Mandatory = $true)][string]$OutFile)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

function Say([string]$msg) { [Console]::Out.WriteLine("PROGRESS|$msg"); [Console]::Out.Flush() }

# ---------- helpers ----------
function Get-ExePath([string]$cmd) {
    if (-not $cmd) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
    $c = $c -replace '^"+', '"'                       # ""C:\x.exe"" -> "C:\x.exe"
    if ($c -match '^"([^"]+)"') { $p = $matches[1] }
    elseif ($c -match '^(.+?\.(exe|dll|sys|com|bat|cmd|ps1|vbs|js|scr|cpl|msc))(\s|$|,|")') { $p = $matches[1] }
    else { $p = ($c -split '\s+')[0] }
    $p = $p.Trim('"')
    $p = $p -replace '^\\\?\?\\', ''
    $p = $p -replace '^\\SystemRoot\\', "$env:windir\"
    $p = $p -replace '^(?i)system32\\', "$env:windir\system32\"
    if ($p -and -not (Test-Path -LiteralPath $p)) {
        if ($p -notmatch '\.\w{2,4}$' -and (Test-Path -LiteralPath "$p.exe")) { $p = "$p.exe" }
        elseif ($p -notmatch '\\') {
            $w = Get-Command $p -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($w) { $p = $w.Source }
        }
    }
    return $p
}

$fileCache = @{}
function Get-FileFacts([string]$path) {
    $empty = @{ Exists = $false; Sig = ''; Signer = ''; SHA256 = ''; Created = ''; Company = ''; Product = '' }
    if (-not $path) { return $empty }
    if ($fileCache.ContainsKey($path)) { return $fileCache[$path] }
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $s = Get-AuthenticodeSignature -LiteralPath $path
        $signer = ''
        if ($s.SignerCertificate) {
            $subj = $s.SignerCertificate.Subject
            if ($subj -match 'CN="([^"]+)"') { $signer = $matches[1] }
            elseif ($subj -match 'CN=([^,]+)') { $signer = $matches[1] }
        }
        $item = Get-Item -LiteralPath $path
        $r = @{
            Exists  = $true
            Sig     = [string]$s.Status
            Signer  = $signer
            SHA256  = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            Created = $item.CreationTime.ToString('yyyy-MM-dd HH:mm')
            Company = [string]$item.VersionInfo.CompanyName
            Product = [string]$item.VersionInfo.ProductName
        }
    } else {
        $r = $empty.Clone(); $r.Sig = 'Missing'
    }
    $fileCache[$path] = $r
    return $r
}

$items = New-Object System.Collections.Generic.List[object]
function Add-Entry([string]$category, [string]$name, [string]$command, [hashtable]$details, [string]$pathOverride) {
    $p = if ($PSBoundParameters.ContainsKey('pathOverride')) { $pathOverride } else { Get-ExePath $command }
    $f = Get-FileFacts $p
    $items.Add([ordered]@{
        Category = $category; Name = $name; Command = $command; Path = $p
        Exists = $f.Exists; Sig = $f.Sig; Signer = $f.Signer; SHA256 = $f.SHA256
        Created = $f.Created; Company = $f.Company; Product = $f.Product
        Details = $details
    })
}

# ---------- meta ----------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$os = Get-CimInstance Win32_OperatingSystem
$meta = [ordered]@{
    Computer = $env:COMPUTERNAME; User = "$env:USERDOMAIN\$env:USERNAME"; Admin = $isAdmin
    OS = "$($os.Caption) $($os.Version)"; ScanTime = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
}

# ---------- services ----------
Say 'Services'
$svcs = @(Get-CimInstance Win32_Service)
$i = 0
foreach ($s in $svcs) {
    $i++; if ($i % 40 -eq 0) { Say "Services ($i of $($svcs.Count))" }
    $det = @{ StartMode = $s.StartMode; State = $s.State; Account = $s.StartName; ServiceName = $s.Name }
    $cmd = [string]$s.PathName
    if ($cmd -match '(?i)\\svchost\.exe') {
        # Shared-host service: the code that actually runs is its ServiceDll.
        $base = "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)"
        $dll = (Get-ItemProperty "$base\Parameters").ServiceDll
        if (-not $dll) { $dll = (Get-ItemProperty $base).ServiceDll }
        if ($dll) {
            $det.HostCommand = $cmd
            Add-Entry 'Service' "$($s.Name) [$($s.DisplayName)]" $cmd $det ([Environment]::ExpandEnvironmentVariables([string]$dll))
            continue
        }
    }
    if (-not $cmd) {
        $det.Note = 'Path not readable without Administrator'
        Add-Entry 'Service' "$($s.Name) [$($s.DisplayName)]" '' $det ''
        continue
    }
    Add-Entry 'Service' "$($s.Name) [$($s.DisplayName)]" $cmd $det
}

# ---------- drivers (non-Microsoft only, to keep it short) ----------
Say 'Drivers'
foreach ($d in Get-CimInstance Win32_SystemDriver) {
    $p = Get-ExePath ([string]$d.PathName)
    $f = Get-FileFacts $p
    if ($f.Signer -match 'Microsoft' -and $f.Sig -eq 'Valid') { continue }
    Add-Entry 'Driver' "$($d.Name) [$($d.DisplayName)]" ([string]$d.PathName) @{
        StartMode = $d.StartMode; State = $d.State
    }
}

# ---------- registry Run keys ----------
Say 'Registry startup keys'
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce'
)
foreach ($k in $runKeys) {
    $props = Get-ItemProperty -Path $k
    if (-not $props) { continue }
    foreach ($pr in $props.PSObject.Properties) {
        if ($pr.Name -like 'PS*') { continue }
        Add-Entry 'RunKey' "$($pr.Name)" ([string]$pr.Value) @{ Key = $k }
    }
}
# Legacy HKCU ...\Windows Load/Run
$legacy = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
foreach ($n in 'Load', 'Run') {
    $v = $legacy.$n
    if ($v) { Add-Entry 'RunKey' "Legacy $n" ([string]$v) @{ Key = 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' } }
}

# ---------- Winlogon / AppInit / IFEO / other hijack points ----------
Say 'Hijack points (Winlogon, AppInit, IFEO)'
$hijack = [ordered]@{}
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$wlu = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$hijack.WinlogonShell = [string]$wl.Shell
$hijack.WinlogonUserinit = [string]$wl.Userinit
$hijack.WinlogonTaskman = [string]$wl.Taskman
$hijack.UserWinlogonShell = [string]$wlu.Shell
$appinit = @()
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
    $a = Get-ItemProperty $k
    $dlls = [string]$a.AppInit_DLLs
    if ($dlls) {
        $full = ($dlls -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object { $x = Get-Item -LiteralPath $_; if ($x) { $x.FullName } else { $_ } }) -join '; '
        $appinit += [ordered]@{ Key = $k; Dlls = $full; Enabled = ([int]$a.LoadAppInit_DLLs -eq 1) }
    }
}
$hijack.AppInit = $appinit

foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
    foreach ($sub in Get-ChildItem $root) {
        $dbg = (Get-ItemProperty $sub.PSPath).Debugger
        if ($dbg) { Add-Entry 'IFEO' $sub.PSChildName ([string]$dbg) @{ Key = $sub.Name } }
    }
}
# Silent process exit monitors (another IFEO-style persistence)
foreach ($sub in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit') {
    $mp = (Get-ItemProperty $sub.PSPath).MonitorProcess
    if ($mp) { Add-Entry 'IFEO' "SilentProcessExit: $($sub.PSChildName)" ([string]$mp) @{ Key = $sub.Name } }
}
# Winlogon notify / LSA packages / print monitors are noisy; AppCertDlls is rare and suspicious
$acd = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
if ($acd) {
    foreach ($pr in $acd.PSObject.Properties) {
        if ($pr.Name -like 'PS*') { continue }
        Add-Entry 'AppCertDll' $pr.Name ([string]$pr.Value) @{}
    }
}

# ---------- startup folders ----------
Say 'Startup folders'
$shell = New-Object -ComObject WScript.Shell
foreach ($f in "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
               "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") {
    foreach ($fi in Get-ChildItem -LiteralPath $f -Force) {
        if ($fi.Name -eq 'desktop.ini') { continue }
        if ($fi.Extension -eq '.lnk') {
            $sc = $shell.CreateShortcut($fi.FullName)
            Add-Entry 'StartupFolder' $fi.Name ("`"$($sc.TargetPath)`" $($sc.Arguments)".Trim()) @{ Shortcut = $fi.FullName }
        } else {
            Add-Entry 'StartupFolder' $fi.Name "`"$($fi.FullName)`"" @{ Shortcut = $fi.FullName }
        }
    }
}

# ---------- scheduled tasks ----------
Say 'Scheduled tasks'
$tasks = @(Get-ScheduledTask)
$i = 0
foreach ($t in $tasks) {
    $i++; if ($i % 40 -eq 0) { Say "Scheduled tasks ($i of $($tasks.Count))" }
    $info = $null
    foreach ($a in $t.Actions) {
        $exe = if ($a.Execute) { ([string]$a.Execute).Trim().Trim('"') } else { '' }
        if ($exe) {
            $cmd = ("`"$exe`" " + [string]$a.Arguments).Trim()
            $path = Get-ExePath "`"$exe`""
        } elseif ($a.ClassId) {
            $cmd = "COM handler $($a.ClassId) $($a.Data)"
            $path = $null
            $clsid = Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\CLSID\$($a.ClassId)\InprocServer32"
            if ($clsid) { $path = [Environment]::ExpandEnvironmentVariables([string]$clsid.'(default)') }
        } else { continue }
        Add-Entry 'Task' "$($t.TaskPath)$($t.TaskName)" $cmd @{
            State = [string]$t.State; Author = [string]$t.Author; RunAs = [string]$t.Principal.UserId
            RunLevel = [string]$t.Principal.RunLevel; Hidden = [bool]$t.Settings.Hidden
            Registered = [string]$t.Date; WorkingDir = [string]$a.WorkingDirectory
        } $path
    }
}

# ---------- WMI event subscriptions ----------
Say 'WMI subscriptions'
$wmi = @()
foreach ($c in Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer) {
    $wmi += [ordered]@{ Type = 'CommandLineConsumer'; Name = $c.Name; Payload = "$($c.ExecutablePath) $($c.CommandLineTemplate)".Trim() }
}
foreach ($c in Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer) {
    $wmi += [ordered]@{ Type = 'ActiveScriptConsumer'; Name = $c.Name; Payload = "$($c.ScriptFileName) $($c.ScriptText)".Trim() }
}
foreach ($c in Get-CimInstance -Namespace root\subscription -ClassName __EventFilter) {
    $wmi += [ordered]@{ Type = 'EventFilter'; Name = $c.Name; Payload = [string]$c.Query }
}
foreach ($c in Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding) {
    $wmi += [ordered]@{ Type = 'Binding'; Name = [string]$c.Filter; Payload = [string]$c.Consumer }
}

# ---------- security products ----------
Say 'Antivirus status'
$av = @()
foreach ($p in Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct) {
    $st = [int]$p.productState
    $av += [ordered]@{
        Name = $p.displayName
        Enabled = ((($st -shr 8) -band 0x10) -ne 0)
        UpToDate = (($st -band 0xFF) -eq 0)
        State = ('0x{0:X}' -f $st)
    }
}
$mp = Get-MpComputerStatus
$defender = if ($mp) {
    [ordered]@{ Available = $true; Running = [string]$mp.AMRunningMode; RealTime = [bool]$mp.RealTimeProtectionEnabled
                Tamper = [bool]$mp.IsTamperProtected; SigAgeDays = [int]$mp.AntivirusSignatureAge }
} else { [ordered]@{ Available = $false } }

# ---------- remote access tools & session history ----------
Say 'Remote access history'
function Read-TextAnyEncoding([string]$path) {
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes.Length -ge 2 -and (($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) -or ($bytes.Length -gt 3 -and $bytes[1] -eq 0))) {
        return [Text.Encoding]::Unicode.GetString($bytes)
    }
    return [Text.Encoding]::UTF8.GetString($bytes)
}
$sessions = @()
foreach ($trace in "$env:ProgramData\AnyDesk\connection_trace.txt", "$env:APPDATA\AnyDesk\connection_trace.txt") {
    if (-not (Test-Path -LiteralPath $trace)) { continue }
    foreach ($line in (Read-TextAnyEncoding $trace) -split "`r?`n") {
        $l = ($line -replace "`0", '' -replace '\s+', ' ').Trim()
        if ($l -match '^(Incoming|Outgoing)\s+(\d{4}-\d{2}-\d{2}),?\s+(\d{2}:\d{2})\s+(\S+)\s+(\d+)') {
            $sessions += [ordered]@{ Tool = 'AnyDesk'; Direction = $matches[1]; When = "$($matches[2]) $($matches[3])"
                                     Method = $matches[4]; RemoteId = $matches[5]; RemoteName = ''; Source = $trace }
        }
    }
}
foreach ($tv in "${env:ProgramFiles}\TeamViewer\Connections_incoming.txt", "${env:ProgramFiles(x86)}\TeamViewer\Connections_incoming.txt") {
    if (-not (Test-Path -LiteralPath $tv)) { continue }
    foreach ($line in Get-Content -LiteralPath $tv) {
        $f = $line -split "`t"
        if ($f.Count -ge 4) {
            $when = $f[2]
            try { $when = [datetime]::ParseExact($f[2], 'dd-MM-yyyy HH:mm:ss', $null).ToString('yyyy-MM-dd HH:mm') } catch {}
            $sessions += [ordered]@{ Tool = 'TeamViewer'; Direction = 'Incoming'; When = $when; Method = 'RemoteControl'
                                     RemoteId = $f[0]; RemoteName = $f[1]; Source = $tv }
        }
    }
}
$anydeskUnattended = $false
$sysconf = "$env:ProgramData\AnyDesk\system.conf"
if (Test-Path -LiteralPath $sysconf) {
    $anydeskUnattended = [bool](Select-String -LiteralPath $sysconf -Pattern '_unattended_access\.pwd=' -Quiet)
}

# ---------- write ----------
Say 'Writing results'
$result = [ordered]@{
    Meta = $meta; Items = $items; Hijack = $hijack; Wmi = $wmi
    Antivirus = $av; Defender = $defender
    RemoteSessions = $sessions; AnyDeskUnattended = $anydeskUnattended
}
$json = $result | ConvertTo-Json -Depth 6 -Compress
[IO.File]::WriteAllText($OutFile, $json, (New-Object Text.UTF8Encoding($false)))
Say "Done: $($items.Count) entries"
