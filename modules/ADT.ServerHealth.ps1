# ADT.ServerHealth.ps1 - general server health: CPU, memory, disk, stability, patching.
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.

#region Private helpers

function Get-ADTHealthWmiList {
    <#
        .SYNOPSIS
            Fetch every instance of a WMI/CIM class, falling back to Get-WmiObject. Never throws.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClassName
    )

    try {
        return @(Get-CimInstance -ClassName $ClassName -ErrorAction Stop)
    }
    catch {
        try {
            return @(Get-WmiObject -Class $ClassName -ErrorAction Stop)
        }
        catch {
            return @()
        }
    }
}

function ConvertTo-ADTHealthDateTime {
    <#
        .SYNOPSIS
            Normalise a WMI date value to [DateTime]. Never throws.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime]) { return $Value }

    try {
        return [Management.ManagementDateTimeConverter]::ToDateTime([string]$Value)
    }
    catch {
        return $null
    }
}

function Format-ADTHealthBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [double]$Bytes
    )

    if ($Bytes -ge 1073741824) { return ('{0:N1} GB' -f ($Bytes / 1073741824)) }
    if ($Bytes -ge 1048576)    { return ('{0:N1} MB' -f ($Bytes / 1048576)) }
    if ($Bytes -ge 1024)       { return ('{0:N0} KB' -f ($Bytes / 1024)) }
    return ('{0:N0} B' -f $Bytes)
}

function Get-ADTHealthCounterSamples {
    <#
        .SYNOPSIS
            Wrapper around Get-Counter that never throws; returns $null on any failure
            (including the known localisation pitfall - performance counter names are
            localised on non-English Windows, so English counter paths like
            \Processor(_Total)\% Processor Time will not resolve there; Microsoft Learn's
            Get-Counter documentation confirms this and recommends Get-Counter -ListSet to
            find the localised names on that system).
        .OUTPUTS
            Flattened array of PerformanceCounterSample objects (Path/InstanceName/CookedValue)
            across every sample set collected, or $null on failure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Counter,

        [int]$SampleInterval = 1,

        [int]$MaxSamples = 3
    )

    try {
        $sampleSets = @(Get-Counter -Counter $Counter -SampleInterval $SampleInterval -MaxSamples $MaxSamples -ErrorAction Stop)
        $allSamples = @()
        foreach ($set in $sampleSets) {
            $allSamples += @($set.CounterSamples)
        }
        return $allSamples
    }
    catch {
        return $null
    }
}

function Get-ADTHealthPendingRebootState {
    <#
        .SYNOPSIS
            Check the three standard pending-reboot registry indicators.
        .DESCRIPTION
            Private duplicate of the same three-indicator logic used in ADT.Discovery.ps1
            (Get-ADTDiscoveryPendingReboot). Kept as an independent copy under its own name
            rather than shared through Common, per module-isolation rules - each module file
            must be self-contained and independently loadable.
            Verified on Microsoft Learn ("List of prerequisite checks for Configuration
            Manager", section "Pending system restart on the remote SQL Server"):
              HKLM:Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending
              HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired
              HKLM:SYSTEM\CurrentControlSet\Control\Session Manager, PendingFileRenameOperations
        .OUTPUTS
            PSCustomObject with IsPending (bool) and Reasons (string[]).
    #>
    [CmdletBinding()]
    param()

    $reasons = @()

    try {
        $cbsPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        if (Test-Path -LiteralPath $cbsPath) { $reasons += 'Component Based Servicing\RebootPending key present' }
    }
    catch {
        $null = $_
    }

    try {
        $wuPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        if (Test-Path -LiteralPath $wuPath) { $reasons += 'WindowsUpdate\Auto Update\RebootRequired key present' }
    }
    catch {
        $null = $_
    }

    try {
        $smPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $pfro = Get-ItemProperty -LiteralPath $smPath -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
        if ($null -ne $pfro -and $null -ne $pfro.PendingFileRenameOperations -and @($pfro.PendingFileRenameOperations).Count -gt 0) {
            $reasons += 'Session Manager\PendingFileRenameOperations value present'
        }
    }
    catch {
        $null = $_
    }

    return [PSCustomObject]@{
        IsPending = ($reasons.Count -gt 0)
        Reasons   = @($reasons)
    }
}

#endregion

#region Section functions

function Invoke-ADTHealthCpu {
    [CmdletBinding()]
    param()

    try {
        $samples = Get-ADTHealthCounterSamples -Counter @('\Processor(_Total)\% Processor Time') -SampleInterval 1 -MaxSamples 3

        if ($null -eq $samples -or $samples.Count -eq 0) {
            $cpuWhy = 'Get-Counter returned no samples for \Processor(_Total)\% Processor Time. Performance counter names are localised (Microsoft Learn); on a non-English Windows install the English counter path will not resolve there. Access control on counter sets, or a non-elevated session, can also block this.'
            Write-ADTResult -Check 'CPU load' -Status ERROR -Detail 'Could not sample the CPU counter.' -Why $cpuWhy
            return
        }

        $sum = 0.0
        foreach ($sample in $samples) { $sum = $sum + $sample.CookedValue }
        $avg = $sum / $samples.Count
        $avgText = '{0:N1}' -f $avg
        $countText = [string]$samples.Count

        if ($avg -gt 95) {
            $why = 'Average processor load over ' + $countText + ' sample(s) was ' + $avgText + '%, above the 95% fail threshold. Sustained saturation this high causes request queuing and timeouts.'
            $fix = @('Identify the top CPU consumer: Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, Id, CPU')
            Write-ADTResult -Check 'CPU load' -Status FAIL -Detail ($avgText + '% average over ' + $countText + ' sample(s).') -Why $why -Fix $fix
        }
        elseif ($avg -gt 85) {
            $why = 'Average processor load over ' + $countText + ' sample(s) was ' + $avgText + '%, above the 85% warn threshold.'
            $fix = @('Identify the top CPU consumer: Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, Id, CPU')
            Write-ADTResult -Check 'CPU load' -Status WARN -Detail ($avgText + '% average over ' + $countText + ' sample(s).') -Why $why -Fix $fix
        }
        else {
            Write-ADTResult -Check 'CPU load' -Status PASS -Detail ($avgText + '% average over ' + $countText + ' sample(s).')
        }
    }
    catch {
        Write-ADTResult -Check 'CPU load' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTHealthMemory {
    [CmdletBinding()]
    param()

    try {
        $os = @(Get-ADTHealthWmiList -ClassName 'Win32_OperatingSystem')
        if ($os.Count -eq 0) {
            Write-ADTResult -Check 'Memory free' -Status ERROR -Detail 'Win32_OperatingSystem returned no data.'
            return
        }

        $osInst = $os[0]
        $totalKb = 0.0
        $freeKb = 0.0
        if ($null -ne $osInst.TotalVisibleMemorySize) { $totalKb = [double]$osInst.TotalVisibleMemorySize }
        if ($null -ne $osInst.FreePhysicalMemory) { $freeKb = [double]$osInst.FreePhysicalMemory }

        if ($totalKb -le 0) {
            Write-ADTResult -Check 'Memory free' -Status ERROR -Detail 'TotalVisibleMemorySize was zero or unavailable.'
            return
        }

        $pctFree = ($freeKb / $totalKb) * 100
        $pctText = '{0:N1}' -f $pctFree
        $totalGbText = '{0:N1}' -f ($totalKb / 1048576)
        $freeGbText = '{0:N1}' -f ($freeKb / 1048576)
        $detail = $pctText + '% free (' + $freeGbText + ' GB free of ' + $totalGbText + ' GB total).'

        if ($pctFree -le 5) {
            $why = 'Free physical memory is ' + $pctText + '%, at or below the 5% fail threshold (Win32_OperatingSystem.FreePhysicalMemory / TotalVisibleMemorySize, Microsoft Learn). High risk of heavy paging or memory-pressure failures.'
            $fix = @('Identify the top memory consumer: Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 5 Name, Id, @{N="WorkingSetMB";E={[math]::Round($_.WorkingSet64/1MB,1)}}')
            Write-ADTResult -Check 'Memory free' -Status FAIL -Detail $detail -Why $why -Fix $fix
        }
        elseif ($pctFree -le 10) {
            $why = 'Free physical memory is ' + $pctText + '%, at or below the 10% warn threshold.'
            $fix = @('Identify the top memory consumer: Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 5 Name, Id, @{N="WorkingSetMB";E={[math]::Round($_.WorkingSet64/1MB,1)}}')
            Write-ADTResult -Check 'Memory free' -Status WARN -Detail $detail -Why $why -Fix $fix
        }
        else {
            Write-ADTResult -Check 'Memory free' -Status PASS -Detail $detail
        }
    }
    catch {
        Write-ADTResult -Check 'Memory free' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTHealthDiskLatency {
    [CmdletBinding()]
    param()

    try {
        # THRESHOLD JUDGEMENT: 0.025s / 0.050s (25 ms / 50 ms) average disk latency are commonly
        # used field thresholds (roughly: under 10 ms good, 10-25 ms acceptable, 25-50 ms poor,
        # over 50 ms bad), drawn from long-standing SQL Server / Exchange storage sizing
        # guidance. This is not one official blanket Microsoft number for every workload - it is
        # treated here as a judgement call, not a verified fact, per contract rule 6.
        $counters = @('\LogicalDisk(*)\Avg. Disk sec/Read', '\LogicalDisk(*)\Avg. Disk sec/Write')
        $samples = Get-ADTHealthCounterSamples -Counter $counters -SampleInterval 1 -MaxSamples 2

        if ($null -eq $samples -or $samples.Count -eq 0) {
            $whyNo = 'Get-Counter returned no samples for the LogicalDisk Avg. Disk sec/Read and sec/Write counters. Performance counter names are localised (Microsoft Learn); this fails on a non-English Windows install unless the localised names are used.'
            Write-ADTResult -Check 'Disk latency' -Status ERROR -Detail 'Could not sample disk latency counters.' -Why $whyNo
            return
        }

        $readSamples = @($samples | Where-Object { $_.Path -like '*sec/read' -and $_.InstanceName -ne '_total' })
        $writeSamples = @($samples | Where-Object { $_.Path -like '*sec/write' -and $_.InstanceName -ne '_total' })

        $instances = @()
        $instances += @($readSamples | ForEach-Object { $_.InstanceName })
        $instances += @($writeSamples | ForEach-Object { $_.InstanceName })
        $instances = @($instances | Sort-Object -Unique)

        if ($instances.Count -eq 0) {
            Write-ADTResult -Check 'Disk latency' -Status INFO -Detail 'No per-disk LogicalDisk instances returned.'
            return
        }

        foreach ($inst in $instances) {
            $rArr = @($readSamples | Where-Object { $_.InstanceName -eq $inst })
            $wArr = @($writeSamples | Where-Object { $_.InstanceName -eq $inst })

            $rAvg = $null
            if ($rArr.Count -gt 0) {
                $rSum = 0.0
                foreach ($s in $rArr) { $rSum = $rSum + $s.CookedValue }
                $rAvg = $rSum / $rArr.Count
            }

            $wAvg = $null
            if ($wArr.Count -gt 0) {
                $wSum = 0.0
                foreach ($s in $wArr) { $wSum = $wSum + $s.CookedValue }
                $wAvg = $wSum / $wArr.Count
            }

            $worst = 0.0
            if ($null -ne $rAvg -and $rAvg -gt $worst) { $worst = $rAvg }
            if ($null -ne $wAvg -and $wAvg -gt $worst) { $worst = $wAvg }

            $rMsText = 'n/a'
            if ($null -ne $rAvg) { $rMsText = ('{0:N1}' -f ($rAvg * 1000)) + ' ms' }
            $wMsText = 'n/a'
            if ($null -ne $wAvg) { $wMsText = ('{0:N1}' -f ($wAvg * 1000)) + ' ms' }

            $detail = 'read ' + $rMsText + ', write ' + $wMsText

            if ($worst -gt 0.050) {
                $worstMsText = '{0:N1}' -f ($worst * 1000)
                $why = 'Worst average latency on this disk was ' + $worstMsText + ' ms, above the 50 ms judgement-call fail threshold. Applications will visibly stall on I/O at this level.'
                Write-ADTResult -Check ('Disk latency: ' + $inst) -Status FAIL -Detail $detail -Why $why
            }
            elseif ($worst -gt 0.025) {
                $worstMsText = '{0:N1}' -f ($worst * 1000)
                $why = 'Worst average latency on this disk was ' + $worstMsText + ' ms, above the 25 ms judgement-call warn threshold.'
                Write-ADTResult -Check ('Disk latency: ' + $inst) -Status WARN -Detail $detail -Why $why
            }
            else {
                Write-ADTResult -Check ('Disk latency: ' + $inst) -Status PASS -Detail $detail
            }
        }
    }
    catch {
        Write-ADTResult -Check 'Disk latency' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTHealthVolumes {
    [CmdletBinding()]
    param()

    try {
        $disks = @(Get-ADTHealthWmiList -ClassName 'Win32_LogicalDisk' | Where-Object { $null -ne $_.DriveType -and [int]$_.DriveType -eq 3 })

        if ($disks.Count -eq 0) {
            Write-ADTResult -Check 'Volume free space' -Status INFO -Detail 'No fixed volumes found.'
            return
        }

        foreach ($disk in ($disks | Sort-Object -Property DeviceID)) {
            $deviceText = [string]$disk.DeviceID
            $sizeBytes = 0.0
            $freeBytes = 0.0
            if ($null -ne $disk.Size) { $sizeBytes = [double]$disk.Size }
            if ($null -ne $disk.FreeSpace) { $freeBytes = [double]$disk.FreeSpace }

            if ($sizeBytes -le 0) {
                Write-ADTResult -Check ('Volume ' + $deviceText) -Status INFO -Detail 'Size not reported.'
                continue
            }

            $pctFree = ($freeBytes / $sizeBytes) * 100
            $pctText = '{0:N1}' -f $pctFree
            $freeText = Format-ADTHealthBytes -Bytes $freeBytes
            $sizeText = Format-ADTHealthBytes -Bytes $sizeBytes
            $detail = $pctText + '% free (' + $freeText + ' free of ' + $sizeText + ').'

            if ($pctFree -lt 5) {
                $why = $deviceText + ' has ' + $pctText + '% free, below the 5% fail threshold. A volume that fills completely can stop services, block log writes and corrupt in-progress operations.'
                $fix = @(('Find the largest folders: Get-ChildItem ' + $deviceText + '\ -Recurse -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 20 FullName, Length'))
                Write-ADTResult -Check ('Volume ' + $deviceText) -Status FAIL -Detail $detail -Why $why -Fix $fix
            }
            elseif ($pctFree -lt 10) {
                $why = $deviceText + ' has ' + $pctText + '% free, below the 10% warn threshold.'
                $fix = @(('Find the largest folders: Get-ChildItem ' + $deviceText + '\ -Recurse -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 20 FullName, Length'))
                Write-ADTResult -Check ('Volume ' + $deviceText) -Status WARN -Detail $detail -Why $why -Fix $fix
            }
            else {
                Write-ADTResult -Check ('Volume ' + $deviceText) -Status PASS -Detail $detail
            }
        }
    }
    catch {
        Write-ADTResult -Check 'Volume free space' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTHealthTopProcesses {
    [CmdletBinding()]
    param()

    try {
        $allProcs = @(Get-Process -ErrorAction SilentlyContinue)

        $byCpu = @($allProcs | Where-Object { $null -ne $_.CPU } | Sort-Object -Property CPU -Descending | Select-Object -First 5)
        if ($byCpu.Count -eq 0) {
            Write-ADTResult -Check 'Top processes by CPU' -Status INFO -Detail 'No process CPU data available.'
        }
        else {
            foreach ($proc in $byCpu) {
                $cpuText = '{0:N1}' -f $proc.CPU
                Write-ADTNote -Text ($proc.ProcessName + ' (PID ' + [string]$proc.Id + ')  CPU time ' + $cpuText + 's')
            }
            $cpuDetail = 'Top ' + [string]$byCpu.Count + ' by cumulative processor time shown above (seconds since process start, not a percentage).'
            Write-ADTResult -Check 'Top processes by CPU' -Status INFO -Detail $cpuDetail -Data $byCpu
        }

        $byWs = @($allProcs | Where-Object { $null -ne $_.WorkingSet64 } | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 5)
        if ($byWs.Count -eq 0) {
            Write-ADTResult -Check 'Top processes by working set' -Status INFO -Detail 'No process working-set data available.'
        }
        else {
            foreach ($proc in $byWs) {
                $wsText = '{0:N1}' -f ($proc.WorkingSet64 / 1MB)
                Write-ADTNote -Text ($proc.ProcessName + ' (PID ' + [string]$proc.Id + ')  working set ' + $wsText + ' MB')
            }
            $wsDetail = 'Top ' + [string]$byWs.Count + ' by working set shown above.'
            Write-ADTResult -Check 'Top processes by working set' -Status INFO -Detail $wsDetail -Data $byWs
        }
    }
    catch {
        Write-ADTResult -Check 'Top processes' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTHealthEventLog {
    [CmdletBinding()]
    param()

    try {
        $startTime = (Get-Date).AddDays(-7)

        # Get-WinEvent raises an error when a FilterHashtable matches zero events (a documented,
        # commonly-hit quirk of the cmdlet); the catch below treats both "no matches" and any
        # other query failure as "nothing found" rather than surfacing an ERROR, since neither
        # should block the rest of the health check.
        try {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 6008, 7031, 7034; StartTime = $startTime } -ErrorAction Stop)
        }
        catch {
            $events = @()
        }

        $shutdownEvents = @($events | Where-Object { $_.Id -eq 6008 })
        $crashEvents = @($events | Where-Object { $_.Id -eq 7031 -or $_.Id -eq 7034 })

        if ($shutdownEvents.Count -eq 0) {
            Write-ADTResult -Check 'Unexpected shutdowns (7 days)' -Status PASS -Detail 'No event ID 6008 (unexpected shutdown) in the last 7 days.'
        }
        else {
            foreach ($evt in ($shutdownEvents | Select-Object -First 10)) {
                Write-ADTNote -Text ($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm') + '  event 6008')
            }
            $shutdownCountText = [string]$shutdownEvents.Count
            $why = $shutdownCountText + ' unexpected shutdown(s) (event ID 6008, Microsoft Learn) logged in the last 7 days. Each one means the machine did not shut down cleanly - crash, power loss, or a hard hang.'
            $fix = @('Correlate with Kernel-Power event 41 and check for a saved dump: Get-WinEvent -FilterHashtable @{LogName="System";Id=41;StartTime=(Get-Date).AddDays(-7)}')
            Write-ADTResult -Check 'Unexpected shutdowns (7 days)' -Status WARN -Detail ($shutdownCountText + ' unexpected shutdown(s) in the last 7 days.') -Why $why -Fix $fix -Data $shutdownEvents
        }

        if ($crashEvents.Count -eq 0) {
            Write-ADTResult -Check 'Service crashes (7 days)' -Status PASS -Detail 'No event ID 7031/7034 (service terminated unexpectedly) in the last 7 days.'
        }
        else {
            foreach ($evt in ($crashEvents | Select-Object -First 10)) {
                $svcName = 'unknown service'
                if ($evt.Message) {
                    $msgMatch = [regex]::Match($evt.Message, '^The (.+?) service')
                    if ($msgMatch.Success) { $svcName = $msgMatch.Groups[1].Value }
                }
                Write-ADTNote -Text ($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm') + '  event ' + [string]$evt.Id + '  ' + $svcName)
            }
            $crashCountText = [string]$crashEvents.Count
            $why = $crashCountText + ' service crash event(s) (event ID 7031/7034, Service Control Manager source, Microsoft Learn) logged in the last 7 days.'
            $fix = @('Review the Application and System logs around each timestamp for the crashing service to find the root cause before restarting it repeatedly.')
            Write-ADTResult -Check 'Service crashes (7 days)' -Status WARN -Detail ($crashCountText + ' service crash event(s) in the last 7 days.') -Why $why -Fix $fix -Data $crashEvents
        }
    }
    catch {
        Write-ADTResult -Check 'Stability (last 7 days)' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTHealthPendingReboot {
    [CmdletBinding()]
    param()

    try {
        $result = Get-ADTHealthPendingRebootState
        if ($result.IsPending) {
            $why = 'One or more standard Windows pending-reboot indicators is set: ' + ($result.Reasons -join '; ') + '.'
            Write-ADTResult -Check 'Pending reboot' -Status WARN -Detail 'A reboot is pending.' -Why $why -Fix @('[SERVICE-AFFECTING] Restart-Computer -Force   (schedule during a maintenance window)')
        }
        else {
            Write-ADTResult -Check 'Pending reboot' -Status PASS -Detail 'No pending-reboot indicators found.'
        }
    }
    catch {
        Write-ADTResult -Check 'Pending reboot' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTHealthHotfixAge {
    [CmdletBinding()]
    param()

    try {
        $hotfixes = @(Get-HotFix -ErrorAction Stop)

        $dated = @()
        foreach ($fix in $hotfixes) {
            if ($null -ne $fix.InstalledOn) {
                $parsedDate = $null
                try { $parsedDate = [DateTime]$fix.InstalledOn } catch { $parsedDate = $null }
                if ($null -ne $parsedDate) {
                    $dated += [PSCustomObject]@{ HotFixID = $fix.HotFixID; InstalledOn = $parsedDate }
                }
            }
        }

        if ($dated.Count -eq 0) {
            $why = 'Get-HotFix / Win32_QuickFixEngineering (Microsoft Learn) only covers CBS-supplied updates, not everything delivered through Windows Update - no dated entries here does not prove the box is unpatched, only that this API has nothing to report.'
            Write-ADTResult -Check 'Days since last hotfix' -Status INFO -Detail 'No dated hotfix entries found.' -Why $why
            return
        }

        $sortedDated = @($dated | Sort-Object -Property InstalledOn -Descending)
        $mostRecent = $sortedDated[0]
        $days = [int]((Get-Date) - $mostRecent.InstalledOn).TotalDays
        $daysText = [string]$days
        $detail = $daysText + ' day(s) since ' + $mostRecent.HotFixID + ' (' + $mostRecent.InstalledOn.ToString('yyyy-MM-dd') + ').'

        if ($days -gt 60) {
            $why = 'The most recent CBS-supplied hotfix is ' + $daysText + ' day(s) old, above the 60-day warn threshold. This box may be missing several months of security updates.'
            $fix = @('Install the PSWindowsUpdate module and check for updates: Install-Module PSWindowsUpdate -Scope CurrentUser -Force; Get-WindowsUpdate -Install -AcceptAll -AutoReboot:$false', 'If WSUS-managed, confirm the client is checking in and approve any pending updates in the WSUS console.')
            Write-ADTResult -Check 'Days since last hotfix' -Status WARN -Detail $detail -Why $why -Fix $fix
        }
        else {
            Write-ADTResult -Check 'Days since last hotfix' -Status PASS -Detail $detail
        }
    }
    catch {
        Write-ADTResult -Check 'Days since last hotfix' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTHealthUptime {
    [CmdletBinding()]
    param()

    try {
        $os = @(Get-ADTHealthWmiList -ClassName 'Win32_OperatingSystem')
        if ($os.Count -eq 0) {
            Write-ADTResult -Check 'Uptime' -Status ERROR -Detail 'Win32_OperatingSystem returned no data.'
            return
        }

        $lastBoot = ConvertTo-ADTHealthDateTime -Value $os[0].LastBootUpTime
        if ($null -eq $lastBoot) {
            Write-ADTResult -Check 'Uptime' -Status INFO -Detail 'Last boot time not available.'
            return
        }

        $span = (Get-Date) - $lastBoot
        $days = [int]$span.Days
        $daysText = [string]$days
        $detail = $daysText + ' day(s) (last boot ' + $lastBoot.ToString('yyyy-MM-dd HH:mm') + ').'

        if ($days -gt 45) {
            $why = 'Uptime is ' + $daysText + ' day(s), above the 45-day watch threshold. A box that never reboots is also a box that never finishes applying pending updates that need a restart - patch risk accumulates quietly.'
            $fix = @('[SERVICE-AFFECTING] Schedule a maintenance-window reboot: Restart-Computer -Force')
            Write-ADTResult -Check 'Uptime' -Status WARN -Detail $detail -Why $why -Fix $fix
        }
        else {
            Write-ADTResult -Check 'Uptime' -Status INFO -Detail $detail
        }
    }
    catch {
        Write-ADTResult -Check 'Uptime' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTHealthPageFile {
    [CmdletBinding()]
    param()

    try {
        # Verified on Microsoft Learn: Win32_ComputerSystem.AutomaticManagedPagefile (boolean,
        # read/write) - "If True, the system manages the page file."
        $cs = @(Get-ADTHealthWmiList -ClassName 'Win32_ComputerSystem')
        $autoManaged = $null
        if ($cs.Count -gt 0 -and $null -ne $cs[0].AutomaticManagedPagefile) { $autoManaged = [bool]$cs[0].AutomaticManagedPagefile }

        $modeText = 'mode unknown'
        if ($null -ne $autoManaged -and $autoManaged) { $modeText = 'system-managed (automatic)' }
        elseif ($null -ne $autoManaged) { $modeText = 'manually configured (fixed/custom size)' }

        # Verified on Microsoft Learn: Win32_PageFileUsage.Name / AllocatedBaseSize (MB) /
        # CurrentUsage (MB) document the live page file(s); Win32_PageFileUsage.Name follows the
        # same "C:\PAGEFILE.SYS" format documented for Win32_PageFileSetting.Name.
        $usages = @(Get-ADTHealthWmiList -ClassName 'Win32_PageFileUsage')
        $systemDrive = $env:SystemDrive

        if ($usages.Count -eq 0) {
            if ($null -ne $autoManaged -and $autoManaged) {
                $autoDetail = 'No active page file instance found, but Windows is set to manage the page file automatically (' + $modeText + '); one is created on demand.'
                Write-ADTResult -Check 'Page file' -Status INFO -Detail $autoDetail
            }
            else {
                $why = 'AutomaticManagedPagefile is not set and no active Win32_PageFileUsage instance was found - this machine may be running with no page file at all, which risks stop errors under memory pressure with no diagnostic dump.'
                $fix = @('Review System Properties > Advanced > Performance > Settings > Advanced > Virtual memory, or check remotely: (Get-CimInstance Win32_ComputerSystem).AutomaticManagedPagefile')
                Write-ADTResult -Check 'Page file' -Status WARN -Detail ('No active page file found (' + $modeText + ').') -Why $why -Fix $fix
            }
            return
        }

        foreach ($pf in $usages) {
            $nameText = 'unknown'
            if ($pf.Name) { $nameText = [string]$pf.Name }

            $allocText = 'unknown'
            if ($null -ne $pf.AllocatedBaseSize) { $allocText = [string]$pf.AllocatedBaseSize + ' MB' }

            $curText = 'unknown'
            if ($null -ne $pf.CurrentUsage) { $curText = [string]$pf.CurrentUsage + ' MB' }

            $onSystemDrive = $false
            if ($nameText.Length -ge 2 -and $systemDrive) {
                if ($nameText.Substring(0, 2).ToUpperInvariant() -eq $systemDrive.ToUpperInvariant()) { $onSystemDrive = $true }
            }
            $driveText = 'not on system drive (' + $systemDrive + ')'
            if ($onSystemDrive) { $driveText = 'on system drive (' + $systemDrive + ')' }

            $detail = $nameText + '  allocated ' + $allocText + ', current use ' + $curText + '  ' + $driveText + '  ' + $modeText
            Write-ADTResult -Check 'Page file' -Status INFO -Detail $detail
        }
    }
    catch {
        Write-ADTResult -Check 'Page file' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

function Invoke-ADTServerHealth {
    <#
        .SYNOPSIS
            General server health - CPU, memory, disk latency, volume free space, top
            processes, recent stability, pending reboot, patch age, uptime and page file
            configuration, all judged PASS/WARN/FAIL against stated thresholds.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'CPU'
        Invoke-ADTHealthCpu

        Write-ADTSection -Title 'Memory'
        Invoke-ADTHealthMemory

        Write-ADTSection -Title 'Disk latency'
        Invoke-ADTHealthDiskLatency

        Write-ADTSection -Title 'Volume free space'
        Invoke-ADTHealthVolumes

        Write-ADTSection -Title 'Top processes'
        Invoke-ADTHealthTopProcesses

        Write-ADTSection -Title 'Stability (last 7 days)'
        Invoke-ADTHealthEventLog

        Write-ADTSection -Title 'Pending reboot'
        Invoke-ADTHealthPendingReboot

        Write-ADTSection -Title 'Patching'
        Invoke-ADTHealthHotfixAge

        Write-ADTSection -Title 'Uptime'
        Invoke-ADTHealthUptime

        Write-ADTSection -Title 'Page file'
        Invoke-ADTHealthPageFile
    }
    catch {
        Write-ADTResult -Check 'General server health' -Status ERROR -Detail $_.Exception.Message
    }
}

Register-ADTModule -Name 'Server health' -Group 'ON-PREM' -Items @(
    @{ Label = 'General server health'; Function = 'Invoke-ADTServerHealth'; Requires = @(); Snapshot = $true }
)
