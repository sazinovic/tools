# Windows Server Maintenance Tool

A single-file, production-quality PowerShell script for routine Windows Server
health checks and safe, scoped cleanup. Built for Windows Server 2016+ and
tested against **Windows Server 2022** with **PowerShell 5.1** and
**PowerShell 7+**.

It is deliberately conservative: report-first, `-WhatIf`-friendly, and it only
ever deletes files in three well-known, low-risk locations (TEMP folders, the
Recycle Bin, and its own log directory).

## What it does

On every run the script:

1. **OS & uptime** — OS name/build/architecture, manufacturer/model, total RAM,
   last boot time, uptime. Flags `WARN` if uptime exceeds 365 days.
2. **Disk free-space checks** — every fixed drive (`DriveType=3`), with
   configurable `WARN`/`CRITICAL` free-space percentage thresholds.
3. **TEMP cleanup** — deletes files older than a configurable age from the
   current user's `%TEMP%` and `%SystemRoot%\Temp`. Locked/in-use files are
   skipped and reported, never forced.
4. **Recycle Bin cleanup** — permanently removes Recycle Bin items older than
   a configurable age (enumerated via the Shell COM object so age can be
   honoured; plain `Clear-RecycleBin` has no age filter).
5. **Maintenance-log cleanup** — prunes the script's own log files (from
   previous runs) older than a configurable retention period, so the log
   folder doesn't grow forever.
6. **Windows Update status** — last installed update date/age from update
   history; pending-update count via the
   [`PSWindowsUpdate`](https://www.powershellgallery.com/packages/PSWindowsUpdate)
   module if installed, or an optional live online search with
   `-CheckWindowsUpdateOnline`.
7. **Key service checks** — status of an explicit service list (spooler, time
   sync, WinRM, DNS client, server/workstation, task scheduler, etc.), plus an
   automatic sweep for **any** `Automatic`-start service that isn't running.
8. **Event Log checks** — counts `Error`/`Critical` entries in the `System`
   and `Application` logs over a configurable look-back window, flags `WARN`
   above a configurable threshold, and logs the top noisy sources.
9. **Structured logging** — every run writes a timestamped, leveled text log;
   `-AsJson` also writes a full JSON summary, and `-AsCsv` appends a one-row
   trend line to a running CSV (handy for graphing multiple runs over time).
10. **Final health summary** — a colour-coded `PASS`/`WARN`/`FAIL`/`SKIP`
    console report per check, an overall `HEALTHY`/`DEGRADED`/`CRITICAL`
    verdict, and a matching process exit code for automation/monitoring.

## Safety model

- Every destructive action goes through a `[CmdletBinding(SupportsShouldProcess)]`
  function and `$PSCmdlet.ShouldProcess(...)`, so **`-WhatIf` and `-Confirm`
  work correctly everywhere**, including inside the shared cleanup helper used
  by TEMP, Recycle Bin, and log cleanup.
- Deletion is **scoped to exactly four locations**: the current user's TEMP
  folder, `%SystemRoot%\Temp`, the Recycle Bin, and the script's own log
  directory. Nothing else is ever touched.
- Files are only deleted if they are **older than the configured threshold**.
  There is no "delete everything" mode.
- Locked/in-use files are caught (`IOException`) and **skipped, not forced**
  — the script will never call anything like `taskkill` or forcibly close
  handles.
- Every section (OS info, disk, TEMP, Recycle Bin, logs, Windows Update,
  services, event log) runs inside its own `try/catch`. **A failure in one
  section is logged and reflected as `FAIL` in the summary, but never aborts
  the rest of the run.**
- The script checks for Administrator rights up front and **degrades
  gracefully** (reports `WARN`/`SKIP` for limited checks) rather than
  crashing when run unelevated.

## Prerequisites

- Windows Server 2016 or later (developed/tested against **Windows Server
  2022**). Should also run fine on Windows 10/11 for testing purposes.
- **Windows PowerShell 5.1** or **PowerShell 7+**.
- **Local Administrator** rights recommended for full functionality (disk,
  service, event log, Windows Update, and TEMP/Recycle Bin cleanup checks).
  The script still runs without elevation but reports reduced-permission
  skips instead of failing.
- Optional: the [`PSWindowsUpdate`](https://www.powershellgallery.com/packages/PSWindowsUpdate)
  module for richer, faster pending-update reporting:
  ```powershell
  Install-Module -Name PSWindowsUpdate -Scope AllUsers
  ```
  If it isn't installed, the script still reports the last-installed-update
  date from local history, and can optionally do a live online search with
  `-CheckWindowsUpdateOnline`.

## Usage

Always do a dry run first on any server you haven't run this against before:

```powershell
.\WindowsServerMaintenance.ps1 -WhatIf
```

This reports everything and shows exactly what cleanup *would* delete,
without deleting anything.

Once you're happy with the plan, run it for real:

```powershell
.\WindowsServerMaintenance.ps1
```

Reporting-only run (no deletions at all, regardless of `-WhatIf`), plus an
online Windows Update search and a JSON summary:

```powershell
.\WindowsServerMaintenance.ps1 -SkipCleanup -CheckWindowsUpdateOnline -AsJson
```

Custom thresholds, and suppress the interactive confirmation prompt on
destructive steps:

```powershell
.\WindowsServerMaintenance.ps1 -TempFileAgeDays 14 -DiskWarningPercent 20 -DiskCriticalPercent 10 -Confirm:$false
```

> If your execution policy blocks local scripts, run it with:
> `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\WindowsServerMaintenance.ps1`

See [`examples/`](./examples) for a scheduled-task registration example and a
sample console/log output.

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-TempFileAgeDays` | int | `7` | Minimum age (days) a TEMP file must have before it's eligible for deletion. |
| `-RecycleBinAgeDays` | int | `30` | Minimum age (days) a Recycle Bin item must have before it's eligible for deletion. |
| `-LogRetentionDays` | int | `90` | How long to keep this tool's own logs before they're eligible for deletion. |
| `-DiskWarningPercent` | int | `15` | Free-space % below which a drive is reported `WARN`. |
| `-DiskCriticalPercent` | int | `5` | Free-space % below which a drive is reported `FAIL`. Must be lower than `-DiskWarningPercent`. |
| `-EventLogHours` | int | `24` | How many hours back to scan System/Application logs for Error/Critical entries. |
| `-EventLogMaxErrors` | int | `20` | Error/Critical event count above which the Event Log check is `WARN`. |
| `-ServicesToCheck` | string[] | `Spooler, W32Time, WinRM, EventLog, Dnscache, LanmanServer, LanmanWorkstation, Schedule` | Explicit services to check, in addition to the automatic scan for stopped Automatic-start services. Missing services are reported `SKIP`, not `FAIL`. |
| `-LogPath` | string | `%ProgramData%\WindowsServerMaintenance\Logs` | Directory for this run's log file (and optional CSV/JSON). |
| `-SkipCleanup` | switch | off | Report/check only — skip all cleanup actions regardless of `-WhatIf`. |
| `-CheckWindowsUpdateOnline` | switch | off | Also perform a live online Windows Update search (can take several minutes; needs network access). |
| `-AsJson` | switch | off | Also write a full JSON summary next to the text log. |
| `-AsCsv` | switch | off | Also append a one-row trend line to `MaintenanceHistory.csv` in `-LogPath`. |

Standard PowerShell common parameters also apply: `-WhatIf`, `-Confirm`,
`-Verbose`, `-ErrorAction`, etc. (the script declares
`[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]`).

## What the script does **not** do

- It does not touch user documents, application data, databases, IIS logs, or
  anything outside TEMP / Recycle Bin / its own log folder.
- It does not install updates, restart services, or reboot the server —
  it only **reports** on Windows Update and service state.
- It does not force-close applications or kill processes to free locked
  files.
- It does not modify firewall, registry, or security settings.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed — **HEALTHY** |
| `1` | One or more checks reported `WARN` — **DEGRADED**, review recommended |
| `2` | One or more checks reported `FAIL`, or an unrecoverable error occurred — **CRITICAL** |
| `10` | Bad parameters or precondition failure (e.g. `DiskCriticalPercent >= DiskWarningPercent`, or not running on Windows) |

These map cleanly onto Task Scheduler "last run result" checks or any
monitoring system that watches process exit codes (Nagios/Zabbix/PRTG style:
`0` = OK, `1` = WARNING, `2` = CRITICAL).

## Scheduling

Register as a weekly scheduled task (run from an elevated prompt):

```powershell
schtasks /Create /TN "WindowsServerMaintenance" /SC WEEKLY /D SUN /ST 03:00 `
    /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Tools\windows-server-maintenance\WindowsServerMaintenance.ps1 -AsJson -AsCsv" `
    /RU SYSTEM /RL HIGHEST
```

See [`examples/schedule-task.ps1`](./examples/schedule-task.ps1) for a
scripted version of task registration.

## Versioning / changelog

**v1.0.0** — initial release: OS/uptime, disk space, TEMP cleanup, Recycle
Bin cleanup, log retention cleanup, Windows Update status, service checks,
event log checks, structured logging, `-WhatIf` support throughout, PASS/WARN/FAIL
summary with exit codes.
