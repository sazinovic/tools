<#
.SYNOPSIS
    Example: registers WindowsServerMaintenance.ps1 as a weekly scheduled task.

.DESCRIPTION
    Run this from an elevated PowerShell prompt on the target server, after
    copying the windows-server-maintenance folder to the path referenced
    below (adjust $ScriptPath as needed).

    This is a helper/example only — it is not called by
    WindowsServerMaintenance.ps1 itself.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ScriptPath = 'C:\Tools\windows-server-maintenance\WindowsServerMaintenance.ps1',
    [string]$TaskName   = 'WindowsServerMaintenance',
    [string]$RunTime    = '03:00',
    [ValidateSet('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')]
    [string]$DayOfWeek  = 'Sunday'
)

if (-not (Test-Path -LiteralPath $ScriptPath)) {
    throw "Script not found at '$ScriptPath'. Copy the windows-server-maintenance folder there first, or pass -ScriptPath."
}

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -AsJson -AsCsv"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $DayOfWeek -At $RunTime

$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1)

if ($PSCmdlet.ShouldProcess($TaskName, "Register scheduled task")) {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Description 'Weekly Windows Server maintenance sweep (health checks + safe TEMP/Recycle Bin/log cleanup).' `
        -Force
    Write-Host "Scheduled task '$TaskName' registered: every $DayOfWeek at $RunTime, running as SYSTEM."
}
