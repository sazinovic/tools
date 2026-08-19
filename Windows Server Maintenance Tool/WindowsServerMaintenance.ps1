#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Server Maintenance Tool - safe, auditable, report-first maintenance sweep.

.DESCRIPTION
    Performs a configurable set of read-only health checks and (optionally) safe,
    scoped cleanup operations on a Windows Server host:

      - OS / uptime information
      - Disk free-space checks against configurable thresholds
      - User + system TEMP folder cleanup (age-based, best-effort, non-locking)
      - Recycle Bin cleanup (age-based, per-drive)
      - Old maintenance-log cleanup (this tool's own logs, age/count-based)
      - Windows Update status (pending updates, last install date; optional search)
      - Key Windows service checks (status + auto-start services not running)
      - Event Log checks (recent Error/Critical entries in System/Application)
      - Structured, timestamped maintenance logging (text + optional CSV/JSON)
      - Configurable retention periods and disk thresholds via parameters
      - -WhatIf / dry-run support on every destructive action (SupportsShouldProcess)
      - Robust try/catch error handling around every check, so one failure never
        aborts the whole run
      - A clear PASS/WARN/FAIL health summary at the end, with a matching exit code

    The script is intentionally conservative: it never deletes anything outside
    TEMP paths, the Recycle Bin, and its own log directory, and everything
    destructive respects -WhatIf and a minimum age threshold before it will
    touch a file.

.PARAMETER TempFileAgeDays
    Minimum age (in days) a file in TEMP must have (based on LastWriteTime)
    before it is eligible for cleanup. Default: 7.

.PARAMETER RecycleBinAgeDays
    Minimum age (in days) an item in the Recycle Bin must have before it is
    eligible for cleanup. Default: 30.

.PARAMETER LogRetentionDays
    Number of days to keep this tool's own maintenance logs before they are
    eligible for cleanup. Default: 90.

.PARAMETER DiskWarningPercent
    Free-space percentage below which a fixed disk is reported as WARNING.
    Default: 15.

.PARAMETER DiskCriticalPercent
    Free-space percentage below which a fixed disk is reported as CRITICAL.
    Default: 5.

.PARAMETER EventLogHours
    How many hours back to scan the System and Application event logs for
    Error/Critical entries. Default: 24.

.PARAMETER EventLogMaxErrors
    Number of Error/Critical events beyond which the Event Log check is
    flagged as WARNING. Default: 20.

.PARAMETER ServicesToCheck
    Explicit list of service names to check in addition to the automatic
    "Automatic start-up but not running" scan. Default: a short list of
    common infrastructure services (Spooler, W32Time, WinRM, EventLog, etc.),
    each checked only if present on the host.

.PARAMETER LogPath
    Directory where this run's maintenance log (and optional CSV/JSON summary)
    is written. Default: "$env:ProgramData\WindowsServerMaintenance\Logs".

.PARAMETER SkipCleanup
    Switch. When set, the script performs checks/reporting only and skips all
    cleanup actions (TEMP, Recycle Bin, old logs), regardless of -WhatIf.

.PARAMETER CheckWindowsUpdateOnline
    Switch. When set, additionally attempts an online Windows Update search
    (via the ComObject Update Session) to list pending updates. This can take
    several minutes and requires network access to the update source. When
    not set, only locally available Windows Update status (via the Windows
    Update Agent's history / PSWindowsUpdate module, if present) is reported.

.PARAMETER AsJson
    Switch. Also emit a machine-readable JSON summary alongside the text log.

.PARAMETER AsCsv
    Switch. Also append a one-row-per-run CSV summary (useful for trending
    across scheduled runs) alongside the text log.

.EXAMPLE
    .\WindowsServerMaintenance.ps1 -WhatIf

    Dry run: reports everything and shows exactly what cleanup *would* delete,
    without deleting anything. Recommended for the first run on any server.

.EXAMPLE
    .\WindowsServerMaintenance.ps1

    Full run with default thresholds: checks + safe cleanup of TEMP files
    older than 7 days, Recycle Bin items older than 30 days, and this tool's
    own logs older than 90 days.

.EXAMPLE
    .\WindowsServerMaintenance.ps1 -SkipCleanup -CheckWindowsUpdateOnline -AsJson

    Reporting-only run (no deletions) that also performs an online Windows
    Update search and writes a JSON summary next to the text log.

.EXAMPLE
    .\WindowsServerMaintenance.ps1 -TempFileAgeDays 14 -DiskWarningPercent 20 -DiskCriticalPercent 10 -Confirm:$false

    Custom thresholds: only touch TEMP files older than 14 days, warn at 20%
    free disk space, critical at 10%, and suppress the per-item confirmation
    prompts that -Confirm/high-impact ShouldProcess actions would otherwise show.

.EXAMPLE
    schtasks /Create /TN "WindowsServerMaintenance" /SC WEEKLY /D SUN /ST 03:00 `
        /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Tools\windows-server-maintenance\WindowsServerMaintenance.ps1 -AsJson -AsCsv"

    Example of registering the script as a weekly scheduled task (run this
    line in an elevated PowerShell/cmd prompt, not inside the script itself).

.OUTPUTS
    Writes a structured log file (and optionally CSV/JSON) to -LogPath, and
    prints a colour-coded PASS/WARN/FAIL summary to the host console.

.NOTES
    Exit codes:
        0  = All checks passed (HEALTHY)
        1  = One or more checks reported WARNING (DEGRADED) - review recommended
        2  = One or more checks reported CRITICAL/FAIL, or the script could not
             complete a required check due to an unrecoverable error
        10 = Bad parameters / precondition failure (e.g. not run on Windows)

    Requires:
        - Windows PowerShell 5.1 or PowerShell 7+ on Windows
        - Windows Server 2016+ (developed/tested against Windows Server 2022)
        - Local Administrator rights for full functionality (disk/service/event
          log/Windows Update checks and TEMP/Recycle Bin cleanup). The script
          will still run without elevation, but will report reduced-permission
          skips for checks it cannot complete, rather than failing outright.
        - Optional: PSWindowsUpdate module for richer Windows Update reporting
          (https://www.powershellgallery.com/packages/PSWindowsUpdate). The
          script degrades gracefully if it is not installed.

    Safety design:
        - All destructive operations are wrapped in functions with
          [CmdletBinding(SupportsShouldProcess)] and call Remove-Item / delete
          APIs via ShouldProcess, so -WhatIf and -Confirm work everywhere.
        - Deletions are scoped strictly to: the current user's TEMP folder,
          $env:SystemRoot\Temp, the Recycle Bin, and this tool's own log
          directory. Nothing else on the filesystem is ever touched.
        - Files are only deleted if they are older than the configured
          threshold AND not currently locked/in-use (locked files are skipped
          and reported, never forced).
        - Every check and every cleanup step is individually wrapped in
          try/catch; a failure in one section is logged and reflected in the
          summary, but never stops the rest of the run.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateRange(0, 3650)]
    [int]$TempFileAgeDays = 7,

    [ValidateRange(0, 3650)]
    [int]$RecycleBinAgeDays = 30,

    [ValidateRange(0, 3650)]
    [int]$LogRetentionDays = 90,

    [ValidateRange(1, 99)]
    [int]$DiskWarningPercent = 15,

    [ValidateRange(1, 99)]
    [int]$DiskCriticalPercent = 5,

    [ValidateRange(1, 8760)]
    [int]$EventLogHours = 24,

    [ValidateRange(1, 100000)]
    [int]$EventLogMaxErrors = 20,

    [string[]]$ServicesToCheck = @('Spooler', 'W32Time', 'WinRM', 'EventLog', 'Dnscache', 'LanmanServer', 'LanmanWorkstation', 'Schedule'),

    [string]$LogPath = (Join-Path $env:ProgramData 'WindowsServerMaintenance\Logs'),

    [switch]$SkipCleanup,

    [switch]$CheckWindowsUpdateOnline,

    [switch]$AsJson,

    [switch]$AsCsv
)

#region --- Setup & guard rails -------------------------------------------------

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($DiskCriticalPercent -ge $DiskWarningPercent) {
    Write-Error "DiskCriticalPercent ($DiskCriticalPercent) must be lower than DiskWarningPercent ($DiskWarningPercent)."
    exit 10
}

if (-not $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) {
    Write-Error "This script targets Windows Server and must be run on Windows."
    exit 10
}

$script:RunStart   = Get-Date
$script:RunStamp   = $script:RunStart.ToString('yyyyMMdd_HHmmss')
$script:HostName   = $env:COMPUTERNAME
$script:IsElevated = $false
try {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal        = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $script:IsElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $script:IsElevated = $false
}

# Results collection: one object per check/section, Status is one of PASS/WARN/FAIL/SKIP
$script:Results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][ValidateSet('PASS', 'WARN', 'FAIL', 'SKIP', 'INFO')][string]$Status,
        [Parameter(Mandatory)][string]$Message,
        [object]$Data = $null
    )
    $script:Results.Add([pscustomobject]@{
        Timestamp = Get-Date
        Section   = $Section
        Status    = $Status
        Message   = $Message
        Data      = $Data
    })
}

try {
    if (-not (Test-Path -LiteralPath $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }
} catch {
    Write-Warning "Could not create/access LogPath '$LogPath': $($_.Exception.Message). Falling back to TEMP."
    $LogPath = Join-Path $env:TEMP 'WindowsServerMaintenance\Logs'
    New-Item -ItemType Directory -Path $LogPath -Force -ErrorAction SilentlyContinue | Out-Null
}

$script:LogFile = Join-Path $LogPath "Maintenance_$($script:RunStamp).log"

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')][string]$Level = 'INFO'
    )
    $line = "[{0:yyyy-MM-dd HH:mm:ss}] [{1,-5}] {2}" -f (Get-Date), $Level, $Message
    Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'DEBUG' { Write-Verbose $line }
        default { Write-Host $line }
    }
}

Write-Log "==== Windows Server Maintenance run starting on $script:HostName ===="
Write-Log "PowerShell $($PSVersionTable.PSVersion), Elevated=$script:IsElevated, WhatIf=$($WhatIfPreference), SkipCleanup=$($SkipCleanup.IsPresent)"

if (-not $script:IsElevated) {
    Write-Log "Not running elevated. Some checks/cleanups may be skipped or limited." -Level WARN
    Add-Result -Section 'Preflight' -Status 'WARN' -Message 'Script is not running with Administrator privileges; some checks/cleanup will be limited.'
} else {
    Add-Result -Section 'Preflight' -Status 'PASS' -Message 'Script is running with Administrator privileges.'
}

#endregion

#region --- Helper: safe wrapper -------------------------------------------------

function Invoke-CheckSafely {
    <#
        Runs a scriptblock representing one check/section. Any exception is
        caught, logged, and turned into a FAIL result rather than aborting
        the whole run.
    #>
    param(
        [Parameter(Mandatory)][string]$SectionName,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    Write-Log "---- Starting section: $SectionName ----"
    try {
        & $Action
    } catch {
        $msg = "Unhandled error in section '$SectionName': $($_.Exception.Message)"
        Write-Log $msg -Level ERROR
        Add-Result -Section $SectionName -Status 'FAIL' -Message $msg
    }
    Write-Log "---- Finished section: $SectionName ----"
}

#endregion

#region --- OS / Uptime information ----------------------------------------------

Invoke-CheckSafely -SectionName 'OS Info' -Action {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $bootTime   = $os.LastBootUpTime
    $uptime     = (Get-Date) - $bootTime
    $uptimeText = "{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes

    $info = [pscustomobject]@{
        ComputerName   = $script:HostName
        OSName         = $os.Caption
        OSVersion      = $os.Version
        OSBuild        = $os.BuildNumber
        Architecture   = $os.OSArchitecture
        Manufacturer   = $cs.Manufacturer
        Model          = $cs.Model
        TotalMemoryGB  = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        LastBootTime   = $bootTime
        Uptime         = $uptimeText
    }

    Write-Log ("OS: {0} (Build {1}, {2}) | Uptime: {3} | Last boot: {4}" -f `
        $info.OSName, $info.OSBuild, $info.Architecture, $info.Uptime, $info.LastBootTime)

    $status = 'PASS'
    $msg    = "OS $($info.OSName) build $($info.OSBuild), uptime $($info.Uptime)."
    if ($uptime.TotalDays -gt 365) {
        $status = 'WARN'
        $msg    = "$msg Uptime exceeds 365 days - consider planning a reboot/patch window."
    }
    Add-Result -Section 'OS Info' -Status $status -Message $msg -Data $info
}

#endregion

#region --- Disk free-space checks -----------------------------------------------

Invoke-CheckSafely -SectionName 'Disk Space' -Action {
    $volumes = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
    if (-not $volumes) {
        Add-Result -Section 'Disk Space' -Status 'WARN' -Message 'No fixed disks (DriveType=3) were found.'
        return
    }

    foreach ($vol in $volumes) {
        if (-not $vol.Size -or $vol.Size -eq 0) {
            Add-Result -Section 'Disk Space' -Status 'SKIP' -Message "Drive $($vol.DeviceID) reported size 0; skipping."
            continue
        }
        $freePct = [math]::Round(($vol.FreeSpace / $vol.Size) * 100, 1)
        $freeGB  = [math]::Round($vol.FreeSpace / 1GB, 2)
        $sizeGB  = [math]::Round($vol.Size / 1GB, 2)

        $status = 'PASS'
        if ($freePct -lt $DiskCriticalPercent) {
            $status = 'FAIL'
        } elseif ($freePct -lt $DiskWarningPercent) {
            $status = 'WARN'
        }

        $msg = "Drive $($vol.DeviceID) - $freeGB GB free of $sizeGB GB ($freePct% free)."
        $logLevel = if ($status -eq 'PASS') { 'INFO' } else { 'WARN' }
        Write-Log $msg -Level $logLevel
        Add-Result -Section 'Disk Space' -Status $status -Message $msg -Data @{
            Drive = $vol.DeviceID; FreeGB = $freeGB; SizeGB = $sizeGB; FreePercent = $freePct
        }
    }
}

#endregion

#region --- Cleanup helpers (shared by TEMP / Recycle Bin / old logs) -----------

function Remove-OldFilesSafely {
    <#
        Deletes files under a root path older than $AgeDays, skipping locked
        files and anything that fails to delete. Fully respects -WhatIf via
        ShouldProcess. Returns a summary object.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [Parameter(Mandatory)][int]$AgeDays,
        [string]$Label = $RootPath
    )

    $summary = [pscustomobject]@{
        Path          = $RootPath
        Eligible      = 0
        Deleted       = 0
        SkippedLocked = 0
        FailedOther   = 0
        FreedBytes    = 0L
    }

    if (-not (Test-Path -LiteralPath $RootPath)) {
        Write-Log "Path not found, skipping cleanup: $RootPath" -Level WARN
        return $summary
    }

    $cutoff = (Get-Date).AddDays(-$AgeDays)
    $items = Get-ChildItem -LiteralPath $RootPath -Force -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff }

    foreach ($item in $items) {
        $summary.Eligible++
        if ($PSCmdlet.ShouldProcess($item.FullName, "Delete file older than $AgeDays days ($Label)")) {
            try {
                $size = $item.Length
                Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
                $summary.Deleted++
                $summary.FreedBytes += $size
            } catch [System.IO.IOException] {
                $summary.SkippedLocked++
                Write-Log "Skipped locked/in-use file: $($item.FullName)" -Level WARN
            } catch {
                $summary.FailedOther++
                Write-Log "Failed to delete '$($item.FullName)': $($_.Exception.Message)" -Level WARN
            }
        }
    }
    return $summary
}

#endregion

#region --- TEMP cleanup ----------------------------------------------------------

Invoke-CheckSafely -SectionName 'TEMP Cleanup' -Action {
    if ($SkipCleanup) {
        Add-Result -Section 'TEMP Cleanup' -Status 'SKIP' -Message 'Skipped: -SkipCleanup was specified.'
        return
    }

    $targets = @(
        @{ Path = $env:TEMP;                              Label = 'User TEMP' }
        @{ Path = Join-Path $env:SystemRoot 'Temp';        Label = 'System TEMP' }
    ) | Where-Object { $_.Path } | Select-Object -Unique -Property Path, Label

    $totalDeleted = 0
    $totalFreed   = 0L
    $anyLocked    = $false

    foreach ($t in $targets) {
        $result = Remove-OldFilesSafely -RootPath $t.Path -AgeDays $TempFileAgeDays -Label $t.Label -WhatIf:$WhatIfPreference -Confirm:$false
        $totalDeleted += $result.Deleted
        $totalFreed   += $result.FreedBytes
        if ($result.SkippedLocked -gt 0) { $anyLocked = $true }
        Write-Log ("{0}: eligible={1} deleted={2} lockedSkipped={3} otherFailed={4} freed={5:N1} MB" -f `
            $t.Label, $result.Eligible, $result.Deleted, $result.SkippedLocked, $result.FailedOther, ($result.FreedBytes / 1MB))
    }

    $freedMB = [math]::Round($totalFreed / 1MB, 1)
    $status  = 'PASS'
    $msg     = "Deleted $totalDeleted TEMP file(s) older than $TempFileAgeDays day(s), freeing ~$freedMB MB."
    if ($anyLocked) {
        $status = 'WARN'
        $msg    = "$msg Some files were skipped because they were in use (normal on a live server)."
    }
    if ($WhatIfPreference) { $msg = "[WhatIf] $msg (no files were actually deleted)" }
    Add-Result -Section 'TEMP Cleanup' -Status $status -Message $msg
}

#endregion

#region --- Recycle Bin cleanup ---------------------------------------------------

Invoke-CheckSafely -SectionName 'Recycle Bin Cleanup' -Action {
    if ($SkipCleanup) {
        Add-Result -Section 'Recycle Bin Cleanup' -Status 'SKIP' -Message 'Skipped: -SkipCleanup was specified.'
        return
    }

    if (-not (Get-Command Clear-RecycleBin -ErrorAction SilentlyContinue)) {
        Add-Result -Section 'Recycle Bin Cleanup' -Status 'SKIP' -Message 'Clear-RecycleBin cmdlet not available on this system (requires PS 5.1+ Storage module).'
        return
    }

    # Enumerate Recycle Bin contents via the Shell COM object so we can honour
    # an age threshold; Clear-RecycleBin itself has no age filter.
    $shell = New-Object -ComObject Shell.Application
    $bin   = $shell.Namespace(0xA)
    $cutoff = (Get-Date).AddDays(-$RecycleBinAgeDays)

    $eligible = 0
    $deleted  = 0
    $freed    = 0L

    if ($bin) {
        foreach ($item in @($bin.Items())) {
            try {
                $deleteDateRaw = $bin.GetDetailsOf($item, 2)  # "Date Deleted" column
                $deleteDate = $null
                if ($deleteDateRaw) {
                    [void][datetime]::TryParse(($deleteDateRaw -replace '[^\x20-\x7E]', ' '), [ref]$deleteDate)
                }
                if ($deleteDate -and $deleteDate -lt $cutoff) {
                    $eligible++
                    $size = 0L
                    try { $size = [long]$item.ExtendedProperty('Size') } catch { $size = 0L }
                    if ($PSCmdlet.ShouldProcess($item.Name, "Permanently delete from Recycle Bin (deleted $deleteDate)")) {
                        $item.InvokeVerb('delete')
                        $deleted++
                        $freed += $size
                    }
                }
            } catch {
                Write-Log "Could not evaluate Recycle Bin item: $($_.Exception.Message)" -Level WARN
            }
        }
        [void][System.Runtime.Interopservices.Marshal]::ReleaseComObject($bin)
        [void][System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell)
    }

    $freedMB = [math]::Round($freed / 1MB, 1)
    $msg = "Recycle Bin: $eligible item(s) older than $RecycleBinAgeDays day(s) found, $deleted removed (~$freedMB MB)."
    if ($WhatIfPreference) { $msg = "[WhatIf] $msg (no items were actually deleted)" }
    Add-Result -Section 'Recycle Bin Cleanup' -Status 'PASS' -Message $msg
}

#endregion

#region --- Old maintenance-log cleanup -------------------------------------------

Invoke-CheckSafely -SectionName 'Log Retention Cleanup' -Action {
    if ($SkipCleanup) {
        Add-Result -Section 'Log Retention Cleanup' -Status 'SKIP' -Message 'Skipped: -SkipCleanup was specified.'
        return
    }

    $result = Remove-OldFilesSafely -RootPath $LogPath -AgeDays $LogRetentionDays -Label 'Maintenance logs' -WhatIf:$WhatIfPreference -Confirm:$false
    $freedMB = [math]::Round($result.FreedBytes / 1MB, 2)
    $msg = "Removed $($result.Deleted) of $($result.Eligible) log file(s) older than $LogRetentionDays day(s) from '$LogPath' (~$freedMB MB freed)."
    if ($WhatIfPreference) { $msg = "[WhatIf] $msg (no files were actually deleted)" }
    Add-Result -Section 'Log Retention Cleanup' -Status 'PASS' -Message $msg
}

#endregion

#region --- Windows Update status -------------------------------------------------

Invoke-CheckSafely -SectionName 'Windows Update' -Action {
    $lastInstalled = $null
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $historyCount = $searcher.GetTotalHistoryCount()
        if ($historyCount -gt 0) {
            $history = $searcher.QueryHistory(0, [Math]::Min(1, $historyCount))
            if ($history -and $history.Count -gt 0) {
                $lastInstalled = $history.Item(0).Date
            }
        }
    } catch {
        Write-Log "Could not query update history via COM: $($_.Exception.Message)" -Level WARN
    }

    if ($lastInstalled) {
        $daysSince = [math]::Round(((Get-Date) - $lastInstalled).TotalDays, 0)
        Write-Log "Last Windows Update installed: $lastInstalled ($daysSince days ago)."
        $status = if ($daysSince -gt 60) { 'WARN' } else { 'PASS' }
        $msg = "Last update installed $daysSince day(s) ago ($lastInstalled)."
        if ($daysSince -gt 60) { $msg = "$msg No updates installed in over 60 days - review patch compliance." }
    } else {
        $status = 'WARN'
        $msg = 'Could not determine last installed update date (history unavailable or empty).'
    }
    Add-Result -Section 'Windows Update' -Status $status -Message $msg

    if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
        try {
            Import-Module PSWindowsUpdate -ErrorAction Stop
            $pending = Get-WindowsUpdate -ErrorAction Stop
            $count = @($pending).Count
            $pStatus = if ($count -gt 0) { 'WARN' } else { 'PASS' }
            Add-Result -Section 'Windows Update' -Status $pStatus -Message "$count pending update(s) reported by PSWindowsUpdate." -Data $pending
        } catch {
            Add-Result -Section 'Windows Update' -Status 'WARN' -Message "PSWindowsUpdate module present but query failed: $($_.Exception.Message)"
        }
    } elseif ($CheckWindowsUpdateOnline) {
        try {
            Write-Log "Performing online Windows Update search (this can take a while)..."
            $searchResult = $searcher.Search("IsInstalled=0 and Type='Software'")
            $count = $searchResult.Updates.Count
            $pStatus = if ($count -gt 0) { 'WARN' } else { 'PASS' }
            Add-Result -Section 'Windows Update' -Status $pStatus -Message "$count pending software update(s) found via online search."
        } catch {
            Add-Result -Section 'Windows Update' -Status 'WARN' -Message "Online update search failed: $($_.Exception.Message)"
        }
    } else {
        Add-Result -Section 'Windows Update' -Status 'INFO' -Message 'Pending-update count not checked. Install PSWindowsUpdate or pass -CheckWindowsUpdateOnline for full pending-update detail.'
    }
}

#endregion

#region --- Key service checks -----------------------------------------------------

Invoke-CheckSafely -SectionName 'Services' -Action {
    foreach ($svcName in $ServicesToCheck) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if (-not $svc) {
            Add-Result -Section 'Services' -Status 'SKIP' -Message "Service '$svcName' not present on this host."
            continue
        }
        if ($svc.Status -ne 'Running') {
            Add-Result -Section 'Services' -Status 'WARN' -Message "Service '$($svc.DisplayName)' ($svcName) is $($svc.Status), not Running."
        } else {
            Add-Result -Section 'Services' -Status 'PASS' -Message "Service '$($svc.DisplayName)' ($svcName) is Running."
        }
    }

    # Broader sweep: any Automatic-start service that isn't running (WMI gives StartMode directly).
    $autoNotRunning = Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto' AND State!='Running'" -ErrorAction SilentlyContinue
    if ($autoNotRunning) {
        foreach ($svc in $autoNotRunning) {
            Add-Result -Section 'Services' -Status 'WARN' -Message "Auto-start service '$($svc.DisplayName)' ($($svc.Name)) is $($svc.State) (expected Running)."
        }
    } else {
        Add-Result -Section 'Services' -Status 'PASS' -Message 'No Automatic-start services found in a stopped state.'
    }
}

#endregion

#region --- Event Log checks --------------------------------------------------------

Invoke-CheckSafely -SectionName 'Event Log' -Action {
    $since = (Get-Date).AddHours(-$EventLogHours)
    foreach ($logName in @('System', 'Application')) {
        try {
            $events = Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = 1, 2; StartTime = $since } -ErrorAction Stop
        } catch [Exception] {
            if ($_.Exception.Message -match 'No events were found') {
                Add-Result -Section 'Event Log' -Status 'PASS' -Message "No Error/Critical events in '$logName' log in the last $EventLogHours hour(s)."
                continue
            }
            Add-Result -Section 'Event Log' -Status 'WARN' -Message "Could not query '$logName' log: $($_.Exception.Message)"
            continue
        }

        $count = @($events).Count
        $status = if ($count -gt $EventLogMaxErrors) { 'WARN' } else { 'PASS' }
        $msg = "$count Error/Critical event(s) in '$logName' log in the last $EventLogHours hour(s) (threshold: $EventLogMaxErrors)."
        Add-Result -Section 'Event Log' -Status $status -Message $msg

        if ($count -gt 0) {
            $topSources = $events | Group-Object -Property ProviderName | Sort-Object Count -Descending | Select-Object -First 5
            foreach ($src in $topSources) {
                Write-Log ("  {0}: {1} event(s) - {2}" -f $logName, $src.Count, $src.Name)
            }
        }
    }
}

#endregion

#region --- Final summary -----------------------------------------------------------

$runEnd = Get-Date
$duration = $runEnd - $script:RunStart

$failCount = @($script:Results | Where-Object Status -eq 'FAIL').Count
$warnCount = @($script:Results | Where-Object Status -eq 'WARN').Count
$passCount = @($script:Results | Where-Object Status -eq 'PASS').Count

if ($failCount -gt 0) {
    $overall = 'CRITICAL'
    $exitCode = 2
} elseif ($warnCount -gt 0) {
    $overall = 'DEGRADED'
    $exitCode = 1
} else {
    $overall = 'HEALTHY'
    $exitCode = 0
}

Write-Host ""
Write-Host "================ Windows Server Maintenance Summary ================" -ForegroundColor Cyan
Write-Host ("Host:      {0}" -f $script:HostName)
Write-Host ("Started:   {0}" -f $script:RunStart)
Write-Host ("Finished:  {0}" -f $runEnd)
Write-Host ("Duration:  {0:hh\:mm\:ss}" -f $duration)
Write-Host ("Overall:   {0}" -f $overall) -ForegroundColor (@{HEALTHY='Green'; DEGRADED='Yellow'; CRITICAL='Red'}[$overall])
Write-Host ("Checks:    {0} PASS / {1} WARN / {2} FAIL" -f $passCount, $warnCount, $failCount)
Write-Host "----------------------------------------------------------------------"

foreach ($group in $script:Results | Group-Object Section) {
    Write-Host ("[{0}]" -f $group.Name) -ForegroundColor Cyan
    foreach ($r in $group.Group) {
        $color = switch ($r.Status) {
            'PASS' { 'Green' }
            'WARN' { 'Yellow' }
            'FAIL' { 'Red' }
            'SKIP' { 'DarkGray' }
            default { 'White' }
        }
        Write-Host ("  [{0,-4}] {1}" -f $r.Status, $r.Message) -ForegroundColor $color
    }
}
Write-Host "========================================================================" -ForegroundColor Cyan

Write-Log "==== Run complete: Overall=$overall PASS=$passCount WARN=$warnCount FAIL=$failCount Duration=$duration ===="

if ($AsJson) {
    try {
        $jsonPath = Join-Path $LogPath "Maintenance_$($script:RunStamp).json"
        [pscustomobject]@{
            Host      = $script:HostName
            Started   = $script:RunStart
            Finished  = $runEnd
            Overall   = $overall
            ExitCode  = $exitCode
            Results   = $script:Results
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        Write-Log "JSON summary written to $jsonPath"
    } catch {
        Write-Log "Failed to write JSON summary: $($_.Exception.Message)" -Level WARN
    }
}

if ($AsCsv) {
    try {
        $csvPath = Join-Path $LogPath 'MaintenanceHistory.csv'
        $row = [pscustomobject]@{
            Timestamp = $runEnd
            Host      = $script:HostName
            Overall   = $overall
            Pass      = $passCount
            Warn      = $warnCount
            Fail      = $failCount
            DurationSeconds = [math]::Round($duration.TotalSeconds, 1)
        }
        $writeHeader = -not (Test-Path -LiteralPath $csvPath)
        $row | Export-Csv -LiteralPath $csvPath -Append -NoTypeInformation -Encoding UTF8
        Write-Log "CSV trend row appended to $csvPath (new file: $writeHeader)"
    } catch {
        Write-Log "Failed to append CSV summary: $($_.Exception.Message)" -Level WARN
    }
}

Write-Host "Log file: $script:LogFile"

exit $exitCode

#endregion
