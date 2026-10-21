<#
.SYNOPSIS
  CP-DFIR evidence collector for Windows (read-only). No installation needed.

.DESCRIPTION
  Collects, in order of volatility (RFC 3227): host identity, network connections, processes (with executable
  SHA-256), local accounts, persistence (Run keys, startup folders, scheduled tasks, services), recently written
  executables/scripts in temp and download folders, and exports of the Security, System, PowerShell and Sysmon
  event logs. Nothing on the computer is changed. Every output file is hashed (SHA-256) into
  cpdfir_manifest.json, and everything is packed into one zip.

  Upload the zip on the Evidence page of a case in the CP-DFIR console. The console re-hashes every file and
  compares it with the manifest, so any change between collection and upload is reported.

.EXAMPLE
  Right-click PowerShell > Run as Administrator, then:
    Set-ExecutionPolicy -Scope Process Bypass
    .\cpdfir-collect-windows.ps1                 # last 7 days, writes the zip to the current folder
    .\cpdfir-collect-windows.ps1 -Days 30 -OutDir D:\evidence
#>
param(
    [int]$Days = 7,
    [string]$OutDir = (Get-Location).Path,
    [switch]$NoLogs
)

$ErrorActionPreference = "Continue"
$Version = "1.2"
$Start = Get-Date
function Iso($d) { if ($null -eq $d) { return $null }; return ([datetime]$d).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
function Hash($p, [int64]$cap = 104857600) {
    try { if ((Get-Item -LiteralPath $p -ErrorAction Stop).Length -gt $cap) { return $null }
          return (Get-FileHash -Algorithm SHA256 -LiteralPath $p -ErrorAction Stop).Hash.ToLower() } catch { return $null } }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$hostName = $env:COMPUTERNAME
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$work = Join-Path ([IO.Path]::GetTempPath()) ("cpdfir_" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$hostDir = Join-Path $work "host"
New-Item -ItemType Directory -Path $hostDir -Force | Out-Null
$errors = New-Object System.Collections.ArrayList
$limited = @{}
if (-not $isAdmin) { $limited["not_admin"] = "Not run as Administrator: the Security log, other users' processes and some sockets are missing." }

$Utf8 = New-Object System.Text.UTF8Encoding $false          # UTF-8 without BOM (Windows PowerShell 5.1 adds one otherwise)
function WriteJson($path, $obj, $depth = 6) { [IO.File]::WriteAllText($path, ($obj | ConvertTo-Json -Depth $depth), $Utf8) }
function Save($name, $obj) {
    $p = Join-Path $hostDir $name
    WriteJson $p $obj
    Write-Host ("  {0}" -f $name)
}

Write-Host "CP-DFIR collector $Version - collecting from $hostName (admin=$isAdmin, last $Days days)"

# 1. system -------------------------------------------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
$tz = [TimeZoneInfo]::Local.GetUtcOffset((Get-Date))
$off = "{0}{1:00}:{2:00}" -f ($(if ($tz.TotalMinutes -ge 0) { "+" } else { "-" })), [math]::Abs($tz.Hours), [math]::Abs($tz.Minutes)
$logged = @()
try { $logged = @(quser 2>$null | Select-Object -Skip 1 | ForEach-Object { @{ name = (($_ -replace '^\s*>?', '') -split '\s+')[0]; terminal = $null; host = $null; started = $null } }) } catch {}
Save "system.json" ([ordered]@{
    collected_at = Iso (Get-Date); hostname = $hostName; fqdn = ([Net.Dns]::GetHostEntry($hostName)).HostName
    os = "Windows"; release = [string]$os.Version; version = [string]$os.Caption; machine = $env:PROCESSOR_ARCHITECTURE
    boot_time = Iso $os.LastBootUpTime; uptime_s = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
    timezone_offset = $off; is_admin = $isAdmin; collector_version = "ps-$Version"; run_as = "$env:USERDOMAIN\$env:USERNAME"
    logged_in = $logged
})

# 2. network connections (most volatile) ---------------------------------------------------------------
$conns = @()
try {
    $conns += Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
        $st = switch ($_.State) { "Listen" { "LISTEN" } "Established" { "ESTABLISHED" } "TimeWait" { "TIME_WAIT" } "CloseWait" { "CLOSE_WAIT" } default { ([string]$_.State).ToUpper() } }
        [ordered]@{ proto = $(if ($_.LocalAddress -like "*:*") { "tcp6" } else { "tcp" }); local_ip = $_.LocalAddress; local_port = $_.LocalPort
                    remote_ip = $(if ($_.RemoteAddress -in @("0.0.0.0", "::")) { $null } else { $_.RemoteAddress }); remote_port = $(if ($_.RemotePort) { $_.RemotePort } else { $null })
                    status = $st; pid = $_.OwningProcess }
    }
    $conns += Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{ proto = $(if ($_.LocalAddress -like "*:*") { "udp6" } else { "udp" }); local_ip = $_.LocalAddress; local_port = $_.LocalPort
                    remote_ip = $null; remote_port = $null; status = "NONE"; pid = $_.OwningProcess }
    }
} catch { [void]$errors.Add("connections: $_") }
Save "connections.json" ([ordered]@{ collected_at = Iso (Get-Date); items = $conns })

# 3. processes ---------------------------------------------------------------------------------------
Write-Host "  processes (owners and executable hashes) ..."
$hashCache = @{}
$procs = New-Object System.Collections.ArrayList
# owners in one call (needs Administrator); per-process WMI GetOwner is far too slow on a real machine
$owners = @{}
try { Get-Process -IncludeUserName -ErrorAction Stop | ForEach-Object { if ($_.UserName) { $owners[[int]$_.Id] = $_.UserName } } } catch { [void]$errors.Add("process owners: $_") }
foreach ($p in (Get-CimInstance Win32_Process)) {
    $u = $owners[[int]$p.ProcessId]
    $exe = $p.ExecutablePath
    $h = $null
    if ($exe) { if (-not $hashCache.ContainsKey($exe) -and $hashCache.Count -lt 400) { $hashCache[$exe] = Hash $exe }; $h = $hashCache[$exe] }
    $cmd = @()
    if ($p.CommandLine) { $cmd = @($p.CommandLine) }
    [void]$procs.Add([ordered]@{ pid = [int]$p.ProcessId; ppid = [int]$p.ParentProcessId; name = $p.Name; exe = $exe; cmdline = $cmd; username = $u
                          create_time_utc = Iso $p.CreationDate; status = "running"; cwd = $null; exe_deleted = $false; exe_sha256 = $h })
}
Save "processes.json" ([ordered]@{ collected_at = Iso (Get-Date); items = $procs })

# 4. accounts ----------------------------------------------------------------------------------------
$acc = @()
try { $acc = @(Get-LocalUser -ErrorAction Stop | ForEach-Object { [ordered]@{ name = $_.Name; kind = "local_user"; enabled = $_.Enabled; last_logon = Iso $_.LastLogon } }) } catch { [void]$errors.Add("accounts: $_") }
$admins = @()
try { $admins = @(Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop | ForEach-Object { [string]$_.Name }) } catch { [void]$errors.Add("administrators group: $_") }
Save "accounts.json" ([ordered]@{ collected_at = Iso (Get-Date); items = $acc; administrators = $admins })

# 5. persistence -------------------------------------------------------------------------------------
Write-Host "  persistence (Run keys, startup, scheduled tasks, services) ..."
$pers = @()
foreach ($k in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                 "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                 "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")) {
    try {
        $item = Get-ItemProperty -LiteralPath $k -ErrorAction Stop
        foreach ($prop in $item.PSObject.Properties) {
            if ($prop.Name -notlike "PS*") { $pers += [ordered]@{ kind = "run_key"; name = ($k -replace ':', '') + "\" + $prop.Name; value = [string]$prop.Value; mtime = $null } }
        }
    } catch {}
}
foreach ($d in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")) {
    Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue | ForEach-Object { $pers += [ordered]@{ kind = "startup_folder"; name = $_.FullName; value = $_.Name; mtime = Iso $_.LastWriteTime } }
}
try {
    Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
        $a = ($_.Actions | ForEach-Object { ("{0} {1}" -f $_.Execute, $_.Arguments).Trim() }) -join " ; "
        $pers += [ordered]@{ kind = "schtask"; name = $_.TaskPath + $_.TaskName; value = $a; mtime = $null; run_as = $_.Principal.UserId; status = [string]$_.State }
    }
} catch { [void]$errors.Add("scheduled tasks: $_") }
try {
    Get-CimInstance Win32_Service -ErrorAction Stop | ForEach-Object {
        $pers += [ordered]@{ kind = "service"; name = $_.Name; value = $_.PathName; mtime = $null; start_type = $_.StartMode; run_as = $_.StartName; status = $_.State }
    }
} catch { [void]$errors.Add("services: $_") }
Save "persistence.json" ([ordered]@{ collected_at = Iso (Get-Date); items = $pers })

# 6. recently written executables / scripts in temp and download folders --------------------------------
$cut = (Get-Date).AddDays(-$Days)
$dirs = @($env:TEMP, "$env:SystemRoot\Temp", "C:\Users\Public") + (Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName "Downloads" })
Write-Host "  recent executables and scripts in temp / Downloads ..."
$files = @(); $scanned = 0
foreach ($d in ($dirs | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique)) {
    Get-ChildItem -LiteralPath $d -File -Recurse -Depth 3 -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $scanned++
        if ($scanned -gt 20000) { return }
        $newest = @($_.LastWriteTime, $_.CreationTime) | Sort-Object -Descending | Select-Object -First 1
        if ($newest -lt $cut) { return }
        $magic = $null
        try { $fs = [IO.File]::OpenRead($_.FullName); $b = New-Object byte[] 4; [void]$fs.Read($b, 0, 4); $fs.Close()
              if ($b[0] -eq 0x4D -and $b[1] -eq 0x5A) { $magic = "PE" } elseif ($b[0] -eq 0x23 -and $b[1] -eq 0x21) { $magic = "script" } } catch {}
        if (-not $magic -and $_.Extension -in @(".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta")) { $magic = "script" }
        $files += [ordered]@{ path = $_.FullName; size = $_.Length; mtime = Iso $_.LastWriteTime; changed = Iso $_.CreationTime; magic = $magic
                              sha256 = $(if ($magic) { Hash $_.FullName } else { $null }); timestomped = ($_.CreationTime -gt $_.LastWriteTime.AddHours(1)) }
    }
}
$files = @($files | Sort-Object @{ e = { $null -eq $_.magic } }, @{ e = { $_.changed }; Descending = $true } | Select-Object -First 1000)
Save "files.json" ([ordered]@{ collected_at = Iso (Get-Date); window_days = $Days; scanned = $scanned; total_recent = $files.Count; items = $files })

# 7. event logs (last N days) --------------------------------------------------------------------------
$logFiles = @()
if (-not $NoLogs) {
    $ms = [int64]$Days * 86400000
    $q = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"
    $chans = [ordered]@{ "Security" = "Security.evtx"; "System" = "System.evtx"; "Microsoft-Windows-PowerShell/Operational" = "PowerShell.evtx" }
    if ((wevtutil el) -contains "Microsoft-Windows-Sysmon/Operational") { $chans["Microsoft-Windows-Sysmon/Operational"] = "Sysmon.evtx" }
    foreach ($c in $chans.Keys) {
        $dst = Join-Path $work $chans[$c]
        wevtutil epl $c $dst "/q:$q" 2>$null
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $dst)) { $logFiles += $chans[$c]; Write-Host ("  {0}" -f $chans[$c]) }
        elseif ($c -eq "Security") { $limited["security_log"] = "Security log could not be exported (run as Administrator)." }
        else { [void]$errors.Add("wevtutil export of $c failed") }
    }
}

# manifest with SHA-256 of every file, then one zip --------------------------------------------------
$art = @()
Get-ChildItem -LiteralPath $work -File -Recurse | ForEach-Object {
    $rel = $_.FullName.Substring($work.Length + 1) -replace '\\', '/'
    $art += [ordered]@{ path = $rel; sha256 = Hash $_.FullName; size = $_.Length }
}
$manifest = [ordered]@{ tool = "CP-DFIR collector"; collector_version = "ps-$Version"; platform = "Windows"; hostname = $hostName
                        run_as = "$env:USERDOMAIN\$env:USERNAME"; is_admin = $isAdmin; started_utc = Iso $Start; finished_utc = Iso (Get-Date)
                        window_days = $Days; files = $art; errors = $errors; limited = $limited }
WriteJson (Join-Path $work "cpdfir_manifest.json") $manifest
# host manifest kept for the framework's host parser
WriteJson (Join-Path $hostDir "manifest.json") ([ordered]@{ collector_version = "ps-$Version"; host = @{ hostname = $hostName; os = "Windows"; is_admin = $isAdmin }; errors = $errors; limited = $limited })

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$zip = Join-Path $OutDir ("CPDFIR_{0}_{1}.zip" -f $hostName, $stamp)
Compress-Archive -Path (Join-Path $work "*") -DestinationPath $zip -Force
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
$zh = Hash $zip
Write-Host ""
Write-Host "Done in $([int]((Get-Date) - $Start).TotalSeconds) s"
Write-Host "Evidence package : $zip"
Write-Host "SHA-256          : $zh"
Write-Host "Note this hash in your case notes, then upload the zip on the case's Evidence page."
if ($limited.Count) { Write-Host ""; $limited.Values | ForEach-Object { Write-Warning $_ } }
