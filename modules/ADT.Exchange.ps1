# ADT.Exchange.ps1 - Exchange on-premises: server health, mail flow smoke test, hybrid and Entra Connect.
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.

#region Private helpers

function Connect-ADTExShell {
    <#
        .SYNOPSIS
            Make the Exchange Management Shell cmdlets available in this session. Never throws.
        .DESCRIPTION
            Returns $true when Get-ExchangeServer is callable, $false otherwise. Every menu
            entry in this file calls this first and emits SKIP when it returns $false.

            Snap-in names are confirmed on Microsoft Learn (they are the same two names
            ADT.Common uses to set the HasExchangeShell capability):
              Microsoft.Exchange.Management.PowerShell.SnapIn  - Exchange 2013 and later
              Microsoft.Exchange.Management.PowerShell.E2010   - Exchange 2010
            Loading a snap-in changes only this PowerShell session, never the server.
    #>
    [CmdletBinding()]
    param()

    if ($script:ADTExShellLoaded) { return $true }

    try {
        if (Get-Command -Name 'Get-ExchangeServer' -ErrorAction SilentlyContinue) {
            $script:ADTExShellLoaded = $true
            return $true
        }

        # Add-PSSnapin does not exist on PowerShell 6+, which is why this is probed rather
        # than called blind. Windows PowerShell 5.1 is the contract floor, so it is normally
        # present; a PS7 session on an Exchange box lands here and reports SKIP honestly.
        $addSnapinCmd = Get-Command -Name 'Add-PSSnapin' -ErrorAction SilentlyContinue
        if ($null -eq $addSnapinCmd) { return $false }

        foreach ($snapinName in @('Microsoft.Exchange.Management.PowerShell.SnapIn',
                                  'Microsoft.Exchange.Management.PowerShell.E2010')) {
            try {
                if (-not (Test-ADTSnapinRegistered -Name $snapinName)) { continue }
                Add-PSSnapin -Name $snapinName -ErrorAction Stop
                if (Get-Command -Name 'Get-ExchangeServer' -ErrorAction SilentlyContinue) {
                    $script:ADTExShellLoaded = $true
                    return $true
                }
            }
            catch {
                $null = $_
            }
        }

        return $false
    }
    catch {
        return $false
    }
}

function Write-ADTExShellSkip {
    <#
        .SYNOPSIS
            One consistent SKIP result for "the Exchange shell would not load".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Check
    )

    $why = 'The Exchange management snap-in is registered (HasExchangeShell is true) but could not be loaded into this session, so no Exchange cmdlet can run. The usual causes are a non-elevated session, an account with no Exchange RBAC role assignment, or PowerShell 7 (which has no Add-PSSnapin).'
    $fix = @(
        'Run ADT from an elevated Windows PowerShell 5.1 session on the Exchange server, or launch the Exchange Management Shell from the Start menu and dot-source ADT there.',
        'Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn',
        'Add-PSSnapin does not exist on PowerShell 7 - if $PSVersionTable.PSVersion.Major is 7 or higher, re-run under Windows PowerShell 5.1.',
        'If the snap-in loads but every cmdlet says the term is not recognised, the signed-in account has no Exchange RBAC role assignment; see https://learn.microsoft.com/powershell/exchange/find-exchange-cmdlet-permissions'
    )
    Write-ADTResult -Check $Check -Status 'SKIP' -Detail 'Could not load the Exchange Management Shell in this session.' -Why $why -Fix $fix
}

function Get-ADTExProp {
    <#
        .SYNOPSIS
            Read one property off an object without throwing when it does not exist.
        .DESCRIPTION
            Exchange objects change shape between 2010, 2013, 2016, 2019 and SE, and several
            of the output types used in this file are not documented on Microsoft Learn at
            all. Every property read in this module goes through here so a shape mismatch
            produces a missing value rather than a terminating error or a false PASS.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) { return $null }

    try {
        $property = $InputObject.PSObject.Properties[$Name]
        if ($null -eq $property) { return $null }
        return $property.Value
    }
    catch {
        return $null
    }
}

function ConvertTo-ADTExText {
    <#
        .SYNOPSIS
            Flatten any Exchange property value (including MultiValuedProperty) to a string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return '' }

    try {
        if ($Value -is [string]) { return $Value }

        if ($Value -is [System.Collections.IEnumerable]) {
            $parts = @()
            foreach ($item in $Value) {
                if ($null -eq $item) { continue }
                $text = [string]$item
                if ([string]::IsNullOrWhiteSpace($text)) { continue }
                $parts += $text
            }
            return ($parts -join ', ')
        }

        return [string]$Value
    }
    catch {
        return ''
    }
}

function Format-ADTExBytes {
    <#
        .SYNOPSIS
            Human-readable byte size. Local copy so this file stays self-contained.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [double]$Bytes
    )

    $units = @('B', 'KB', 'MB', 'GB', 'TB', 'PB')
    $value = $Bytes
    $unitIndex = 0
    while ($value -ge 1024 -and $unitIndex -lt ($units.Count - 1)) {
        $value = $value / 1024
        $unitIndex++
    }
    return ($value.ToString('N2') + ' ' + $units[$unitIndex])
}

function Get-ADTExVolumeUsage {
    <#
        .SYNOPSIS
            Resolve the volume that hosts a path and return its size/free space. Never throws.
        .DESCRIPTION
            Drive-letter paths resolve through Win32_LogicalDisk (DriveType is not filtered
            here because an Exchange database can legitimately sit on any fixed volume).
            Paths with no drive letter - a mount point under an AutoReseed volume root, for
            instance - fall back to a longest-prefix match against Win32_Volume, which is the
            only class that describes mounted-folder volumes. UNC paths return $null; Exchange
            does not support databases on UNC paths, so there is nothing to measure.
        .OUTPUTS
            PSCustomObject with VolumeId, SizeBytes, FreeBytes, PercentFree - or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    try {
        $root = $null
        try { $root = [System.IO.Path]::GetPathRoot($Path) } catch { $root = $null }
        if ([string]::IsNullOrWhiteSpace($root)) { return $null }
        if ($root.StartsWith('\\')) { return $null }

        # --- Drive-letter path -------------------------------------------------------
        if ($root -match '^([A-Za-z]):') {
            $deviceId = $Matches[1].ToUpperInvariant() + ':'
            $filterText = "DeviceID='" + $deviceId + "'"
            $disk = $null
            try {
                $disk = Get-CimInstance -ClassName 'Win32_LogicalDisk' -Filter $filterText -ErrorAction Stop
            }
            catch {
                try {
                    $disk = Get-WmiObject -Class 'Win32_LogicalDisk' -Filter $filterText -ErrorAction Stop
                }
                catch {
                    $disk = $null
                }
            }

            if ($disk -is [System.Array]) {
                if ($disk.Count -gt 0) { $disk = $disk[0] } else { $disk = $null }
            }

            if ($null -ne $disk) {
                $sizeBytes = 0
                $freeBytes = 0
                $rawSize = Get-ADTExProp -InputObject $disk -Name 'Size'
                $rawFree = Get-ADTExProp -InputObject $disk -Name 'FreeSpace'
                if ($null -ne $rawSize) { $sizeBytes = [double]$rawSize }
                if ($null -ne $rawFree) { $freeBytes = [double]$rawFree }
                if ($sizeBytes -gt 0) {
                    return [PSCustomObject]@{
                        VolumeId    = $deviceId
                        SizeBytes   = $sizeBytes
                        FreeBytes   = $freeBytes
                        PercentFree = [math]::Round((($freeBytes / $sizeBytes) * 100), 1)
                    }
                }
            }
        }

        # --- Mounted-folder volume: longest Name prefix wins ---------------------------
        $volumes = @()
        try {
            $volumes = @(Get-CimInstance -ClassName 'Win32_Volume' -ErrorAction Stop)
        }
        catch {
            try {
                $volumes = @(Get-WmiObject -Class 'Win32_Volume' -ErrorAction Stop)
            }
            catch {
                $volumes = @()
            }
        }

        $bestVolume = $null
        $bestLength = -1
        $comparePath = $Path.ToUpperInvariant()

        foreach ($volume in $volumes) {
            $volumeName = [string](Get-ADTExProp -InputObject $volume -Name 'Name')
            if ([string]::IsNullOrWhiteSpace($volumeName)) { continue }
            $compareName = $volumeName.ToUpperInvariant()
            if ($comparePath.StartsWith($compareName) -and $compareName.Length -gt $bestLength) {
                $bestVolume = $volume
                $bestLength = $compareName.Length
            }
        }

        if ($null -eq $bestVolume) { return $null }

        $volSize = 0
        $volFree = 0
        $rawCapacity = Get-ADTExProp -InputObject $bestVolume -Name 'Capacity'
        $rawFreeSpace = Get-ADTExProp -InputObject $bestVolume -Name 'FreeSpace'
        if ($null -ne $rawCapacity) { $volSize = [double]$rawCapacity }
        if ($null -ne $rawFreeSpace) { $volFree = [double]$rawFreeSpace }
        if ($volSize -le 0) { return $null }

        return [PSCustomObject]@{
            VolumeId    = [string](Get-ADTExProp -InputObject $bestVolume -Name 'Name')
            SizeBytes   = $volSize
            FreeBytes   = $volFree
            PercentFree = [math]::Round((($volFree / $volSize) * 100), 1)
        }
    }
    catch {
        return $null
    }
}

function Get-ADTExEventSummary {
    <#
        .SYNOPSIS
            Defensive Get-WinEvent -FilterHashtable wrapper. Never throws.
        .OUTPUTS
            PSCustomObject: Success (bool), LogMissing (bool), Events (array), ErrorMessage.
            "No events were found" is a success with an empty set, not a failure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [int[]]$Id,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ProviderName,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $false)]
        [int]$MaxEvents = 200
    )

    $outcome = @{ Success = $false; LogMissing = $false; Events = @(); ErrorMessage = '' }

    try {
        $filter = @{ LogName = $LogName; StartTime = $StartTime }
        if ($null -ne $Id -and $Id.Count -gt 0) { $filter['Id'] = $Id }
        if (-not [string]::IsNullOrEmpty($ProviderName)) { $filter['ProviderName'] = $ProviderName }

        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
        $outcome.Success = $true
        $outcome.Events = $events
    }
    catch {
        $message = $_.Exception.Message
        $outcome.ErrorMessage = $message
        if ($message -match '(?i)no events were found' -or $message -match '(?i)there is not an event log') {
            $outcome.Success = $true
            $outcome.Events = @()
            if ($message -match '(?i)there is not an event log') { $outcome.LogMissing = $true }
        }
    }

    return [PSCustomObject]$outcome
}

function Test-ADTExHostResolves {
    <#
        .SYNOPSIS
            Can this box resolve a host name to an address? Never throws.
        .DESCRIPTION
            Uses System.Net.Dns rather than Resolve-DnsName so it also works on Server 2012 R2
            without the DnsClient module loaded, and so no extra module import is needed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$HostName
    )

    if ([string]::IsNullOrWhiteSpace($HostName)) { return $false }

    try {
        $addresses = [System.Net.Dns]::GetHostAddresses($HostName)
        if ($null -ne $addresses -and @($addresses).Count -gt 0) { return $true }
        return $false
    }
    catch {
        return $false
    }
}

function Get-ADTExInactiveRequester {
    <#
        .SYNOPSIS
            Name the requester that last drove a server component Inactive, if it can be read.
        .DESCRIPTION
            Microsoft Learn (KB2958835) documents reading
            "(Get-ServerComponentState -Identity <server> -Component <name>).LocalStates" and
            reading the requester off the result - that is the whole point of the KB, because
            Set-ServerComponentState only works when the Requester matches the one that set
            the state. The property names on the LocalState entries (Requester, State) are
            read defensively here; the article shows the values but not a typed schema.
        .OUTPUTS
            The requester name as a string, or $null when it cannot be determined.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Component
    )

    try {
        $localStates = Get-ADTExProp -InputObject $Component -Name 'LocalStates'
        if ($null -eq $localStates) { return $null }

        foreach ($localState in @($localStates)) {
            $stateText = [string](Get-ADTExProp -InputObject $localState -Name 'State')
            $requesterText = [string](Get-ADTExProp -InputObject $localState -Name 'Requester')
            if ([string]::IsNullOrWhiteSpace($requesterText)) { continue }
            if ($stateText -match '(?i)^inactive$' -or $stateText -match '(?i)^draining$') {
                return $requesterText
            }
        }
        return $null
    }
    catch {
        return $null
    }
}

function Test-ADTExHybridEndpoint {
    <#
        .SYNOPSIS
            Does this text look like a Microsoft 365 / Exchange Online endpoint?
        .DESCRIPTION
            Patterns come from Microsoft Learn: the hybrid smart host format
            "<domain>-com.mail.protection.outlook.com", the EWS endpoint
            "outlook.office365.com", and the "contoso.mail.onmicrosoft.com" coexistence
            address space used on the HCW-created Send connector (KB3087172).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    if ($Text -match '(?i)protection\.outlook\.com') { return $true }
    if ($Text -match '(?i)office365') { return $true }
    if ($Text -match '(?i)onmicrosoft\.com') { return $true }
    if ($Text -match '(?i)outlook\.com') { return $true }
    return $false
}

#endregion

#region Menu entries

function Invoke-ADTExchangeHealth {
    <#
        .SYNOPSIS
            Item 1: Exchange server health - services, component states, databases, DAG copies,
            transport queues, back pressure, certificates, database disk space and build.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Exchange server health'

        if (-not (Connect-ADTExShell)) {
            Write-ADTExShellSkip -Check 'Exchange server health'
            return
        }

        $serverName = $env:COMPUTERNAME

        # ------------------------------------------------------------------------------
        # Critical services (Test-ServiceHealth)
        # ------------------------------------------------------------------------------
        # Test-ServiceHealth is confirmed on Microsoft Learn: it "returns an error for any
        # service required by a configured role when the service is set to start
        # automatically and isn't currently running", and its syntax is
        # Test-ServiceHealth [[-Server] <ServerIdParameter>].
        # UNVERIFIED: the output property names (Role, RequiredServicesRunning,
        # ServicesRunning, ServicesNotRunning) are NOT published on Learn - the cmdlet's
        # Output Types section is empty. They are read through Get-ADTExProp so a shape
        # mismatch degrades to an honest ERROR instead of a false PASS.
        try {
            $healthResults = @(Test-ServiceHealth -Server $serverName -ErrorAction Stop)

            if ($healthResults.Count -eq 0) {
                Write-ADTResult -Check 'Exchange critical services' -Status 'ERROR' `
                    -Detail 'Test-ServiceHealth returned no role rows for this server.' `
                    -Why 'Learn notes that Test-ServiceHealth is not supported on Exchange 2013 Client Access servers and returns unexpected output there. An empty result on any other role is worth investigating directly.' `
                    -Fix @(('Get-Service -DisplayName "Microsoft Exchange*" | Format-Table Name,DisplayName,Status,StartType -AutoSize'))
            }
            else {
                $anyRoleParsed = $false

                foreach ($roleResult in $healthResults) {
                    $roleName = [string](Get-ADTExProp -InputObject $roleResult -Name 'Role')
                    if ([string]::IsNullOrWhiteSpace($roleName)) { $roleName = 'Exchange role' }

                    $notRunningRaw = Get-ADTExProp -InputObject $roleResult -Name 'ServicesNotRunning'
                    $runningRaw = Get-ADTExProp -InputObject $roleResult -Name 'ServicesRunning'
                    $requiredOkRaw = Get-ADTExProp -InputObject $roleResult -Name 'RequiredServicesRunning'

                    $notRunning = @()
                    if ($null -ne $notRunningRaw) {
                        foreach ($serviceName in @($notRunningRaw)) {
                            if ($null -eq $serviceName) { continue }
                            $serviceText = [string]$serviceName
                            if ([string]::IsNullOrWhiteSpace($serviceText)) { continue }
                            $notRunning += $serviceText
                        }
                    }

                    $runningCount = 0
                    if ($null -ne $runningRaw) { $runningCount = @($runningRaw).Count }

                    if ($null -eq $notRunningRaw -and $null -eq $runningRaw -and $null -eq $requiredOkRaw) {
                        continue
                    }
                    $anyRoleParsed = $true

                    if ($notRunning.Count -eq 0) {
                        Write-ADTResult -Check ('Services for role: ' + $roleName) -Status 'PASS' `
                            -Detail ($runningCount.ToString() + ' required service(s) running, none stopped.')
                    }
                    else {
                        foreach ($stoppedService in $notRunning) {
                            $stoppedWhy = 'Test-ServiceHealth reports this service is required by the ' + $roleName + ' role on ' + $serverName + ', is set to start automatically, and is not running. Exchange functionality that depends on it is down right now, not degraded.'
                            $stoppedFix = @(
                                ('[SERVICE-AFFECTING] Start-Service -Name ' + $stoppedService),
                                ('Get-Service -Name ' + $stoppedService + ' | Format-List Name,DisplayName,Status,StartType'),
                                ('Get-WinEvent -LogName System -MaxEvents 50 | Where-Object { $_.ProviderName -eq "Service Control Manager" -and $_.Message -like "*' + $stoppedService + '*" } | Format-List TimeCreated,Id,Message'),
                                ('Re-check once it is up: Test-ServiceHealth -Server ' + $serverName)
                            )
                            Write-ADTResult -Check ('Service stopped: ' + $stoppedService) -Status 'FAIL' `
                                -Detail ('Required by role ' + $roleName + ' on ' + $serverName + ' but not running.') `
                                -Why $stoppedWhy -Fix $stoppedFix
                        }
                    }
                }

                if (-not $anyRoleParsed) {
                    Write-ADTResult -Check 'Exchange critical services' -Status 'ERROR' `
                        -Detail 'Test-ServiceHealth returned rows, but none of the expected properties (Role/ServicesRunning/ServicesNotRunning) could be read from them.' `
                        -Why 'The output shape of Test-ServiceHealth is not documented on Microsoft Learn, so ADT reads it defensively and refuses to guess a result from an unrecognised shape.' `
                        -Fix @('Test-ServiceHealth | Format-List *')
                }
            }
        }
        catch {
            Write-ADTResult -Check 'Exchange critical services' -Status 'ERROR' `
                -Detail ('Test-ServiceHealth failed: ' + $_.Exception.Message) `
                -Fix @(('Test-ServiceHealth -Server ' + $serverName), 'Get-Service -DisplayName "Microsoft Exchange*" | Format-Table Name,Status,StartType -AutoSize')
        }

        # ------------------------------------------------------------------------------
        # Server component states
        # ------------------------------------------------------------------------------
        # Verified on Microsoft Learn: Get-ServerComponentState -Identity <server> returns
        # Component/State/LocalStates rows; Set-ServerComponentState -Identity <server>
        # -Component <name> -State Active -Requester <Maintenance|Functional|HealthAPI|
        # Sidelined|Deployment> is the documented way back. Learn's DAG maintenance article
        # explicitly calls out that a failed Exchange update "can leave some server components
        # in an inactive state" - that is the post-patch trap this check exists for.
        try {
            $components = @(Get-ServerComponentState -Identity $serverName -ErrorAction Stop)

            if ($components.Count -eq 0) {
                Write-ADTResult -Check 'Server component states' -Status 'ERROR' `
                    -Detail ('Get-ServerComponentState returned nothing for ' + $serverName + '.') `
                    -Fix @(('Get-ServerComponentState -Identity ' + $serverName + ' | Format-Table Component,State -AutoSize'))
            }
            else {
                # UNVERIFIED: 'FrontendTransport' as an exact Component string is not
                # enumerated on Microsoft Learn (the Component parameter is typed String with
                # no published value list). ServerWideOffline and HubTransport ARE both shown
                # verbatim in Learn examples. If the real component name differs, that
                # component simply falls into the WARN bucket below rather than FAIL - a safe
                # failure mode, never a missed-but-silent one.
                $criticalComponents = @('ServerWideOffline', 'HubTransport', 'FrontendTransport')
                $inactiveCount = 0

                foreach ($component in $components) {
                    $componentName = [string](Get-ADTExProp -InputObject $component -Name 'Component')
                    $componentState = [string](Get-ADTExProp -InputObject $component -Name 'State')
                    if ([string]::IsNullOrWhiteSpace($componentName)) { continue }
                    if ($componentState -match '(?i)^active$') { continue }

                    $inactiveCount++
                    $requester = Get-ADTExInactiveRequester -Component $component
                    $requesterForFix = 'Maintenance'
                    $requesterNote = 'The requester that last set this state could not be read.'
                    if (-not [string]::IsNullOrWhiteSpace($requester)) {
                        $requesterForFix = $requester
                        $requesterNote = 'The requester that last set this state is "' + $requester + '"; Set-ServerComponentState only takes effect when the Requester value matches it (Microsoft KB2958835).'
                    }
                    if ($requesterForFix -match '(?i)^maintenance$') {
                        $requesterNote = $requesterNote + ' A Maintenance requester means someone (or a DAG maintenance script) put this server into maintenance mode and it was never taken back out.'
                    }

                    $componentFix = @(
                        ('Confirm who set it first: (Get-ServerComponentState -Identity ' + $serverName + ' -Component ' + $componentName + ').LocalStates'),
                        ('Guidance only - ADT does not run this: Set-ServerComponentState -Identity ' + $serverName + ' -Component ' + $componentName + ' -State Active -Requester ' + $requesterForFix),
                        ('If the state does not change, repeat with -Requester Functional: Set-ServerComponentState -Identity ' + $serverName + ' -Component ' + $componentName + ' -State Active -Requester Functional'),
                        ('[SERVICE-AFFECTING] After reactivating a transport component, transport must be restarted to resume queue processing: Restart-Service MSExchangeTransport')
                    )

                    if ($criticalComponents -contains $componentName) {
                        $criticalWhy = 'Component ' + $componentName + ' is ' + $componentState + ' on ' + $serverName + '. This is the classic "server is up but not working" state - Windows, the services and the ping all look healthy while Exchange refuses connections. With HubTransport inactive, SMTP answers and then rejects with 412 4.3.2 Server not active (Microsoft KB2866822); with ServerWideOffline inactive, every component except Monitoring and RecoveryActionsEnabled is inactive. ' + $requesterNote
                        Write-ADTResult -Check ('Server component: ' + $componentName) -Status 'FAIL' `
                            -Detail ('State=' + $componentState) -Why $criticalWhy -Fix $componentFix -Data $component
                    }
                    else {
                        $otherWhy = 'Component ' + $componentName + ' is ' + $componentState + '. This is not one of the components that stops mail flow outright, but a non-Active component is still a feature that is switched off on this server. ' + $requesterNote
                        Write-ADTResult -Check ('Server component: ' + $componentName) -Status 'WARN' `
                            -Detail ('State=' + $componentState) -Why $otherWhy -Fix $componentFix -Data $component
                    }
                }

                if ($inactiveCount -eq 0) {
                    Write-ADTResult -Check 'Server component states' -Status 'PASS' `
                        -Detail ('All ' + $components.Count.ToString() + ' component(s) on ' + $serverName + ' are Active.')
                }
                else {
                    Write-ADTNote -Text ($inactiveCount.ToString() + ' of ' + $components.Count.ToString() + ' server components on ' + $serverName + ' are not Active.')
                }
            }
        }
        catch {
            Write-ADTResult -Check 'Server component states' -Status 'ERROR' `
                -Detail ('Get-ServerComponentState failed: ' + $_.Exception.Message) `
                -Fix @(('Get-ServerComponentState -Identity ' + $serverName + ' | Format-Table Component,State -AutoSize'))
        }

        # ------------------------------------------------------------------------------
        # Mailbox databases: mounted state, and the paths used later for disk space
        # ------------------------------------------------------------------------------
        # Verified on Learn: Get-MailboxDatabase -Identity <db> -Status returns the detailed
        # view, and "if you use the Get-MailboxDatabase cmdlet with the Server parameter, it
        # retrieves information about all mailbox databases on the server that you specify".
        # EdbFilePath and LogFolderPath are the documented path parameters/properties
        # (New-MailboxDatabase, Move-DatabasePath). Mount-Database -Identity <db> is the
        # documented way to mount one.
        $databases = @()
        try {
            $databases = @(Get-MailboxDatabase -Server $serverName -Status -ErrorAction Stop)
        }
        catch {
            $databases = @()
            Write-ADTResult -Check 'Mailbox databases' -Status 'ERROR' `
                -Detail ('Get-MailboxDatabase -Server ' + $serverName + ' -Status failed: ' + $_.Exception.Message) `
                -Why 'This is expected on an Edge Transport server, which holds no mailbox databases. On a Mailbox server it points at an AD read problem or missing RBAC rights.' `
                -Fix @(('Get-MailboxDatabase -Server ' + $serverName + ' -Status | Format-List Name,Mounted,MountedOnServer,EdbFilePath,LogFolderPath'))
        }

        if ($databases.Count -eq 0) {
            Write-ADTResult -Check 'Mailbox databases' -Status 'INFO' `
                -Detail ('No mailbox databases are hosted on ' + $serverName + '.')
        }
        else {
            foreach ($database in $databases) {
                $dbName = [string](Get-ADTExProp -InputObject $database -Name 'Name')
                if ([string]::IsNullOrWhiteSpace($dbName)) { continue }

                $mountedRaw = Get-ADTExProp -InputObject $database -Name 'Mounted'
                $mountedOn = [string](Get-ADTExProp -InputObject $database -Name 'MountedOnServer')
                $mountedText = 'unknown'
                if ($null -ne $mountedRaw) { $mountedText = [string]$mountedRaw }

                if ($null -eq $mountedRaw) {
                    Write-ADTResult -Check ('Database: ' + $dbName) -Status 'ERROR' `
                        -Detail 'The Mounted property could not be read, so mount state is unknown.' `
                        -Why 'Get-MailboxDatabase was called with -Status, which is what populates Mounted. An empty value here means the store could not be queried rather than that the database is dismounted - ADT will not guess either way.' `
                        -Fix @(('Get-MailboxDatabase -Identity "' + $dbName + '" -Status | Format-List Name,Mounted,MountedOnServer,Server'))
                    continue
                }

                if ([bool]$mountedRaw) {
                    $mountedDetail = 'Mounted'
                    if (-not [string]::IsNullOrWhiteSpace($mountedOn)) {
                        $mountedDetail = 'Mounted on ' + $mountedOn
                    }
                    Write-ADTResult -Check ('Database: ' + $dbName) -Status 'PASS' -Detail $mountedDetail
                }
                else {
                    $dismountWhy = 'Database ' + $dbName + ' is dismounted, so every mailbox it holds is offline right now. On a standalone server this is a hard outage for those users; in a DAG it may mean the copy failed over (check the copy status results below) or that the store could not mount after a restart.'
                    # Mount-Database -Identity <db> is verified on Microsoft Learn, as is its
                    # note that the database mounts only while the Information Store and
                    # Replication services are running (hence the service check below).
                    # UNVERIFIED: "eseutil /mh" was not re-confirmed against Learn in this
                    # session. It is included because it is read-only (a database header
                    # dump) and is the standard first look at a database that will not mount.
                    $dismountFix = @(
                        ('Check why before mounting - a dismount after a crash usually has an ESE error behind it: Get-WinEvent -LogName Application -MaxEvents 50 | Where-Object { $_.ProviderName -like "MSExchange*" -or $_.ProviderName -like "ESE*" } | Format-List TimeCreated,ProviderName,Id,Message'),
                        ('Confirm the store services are up first - Mount-Database needs both: Get-Service MSExchangeIS,MSExchangeRepl | Format-Table Name,Status -AutoSize'),
                        ('[SERVICE-AFFECTING] Guidance only - ADT does not run this: Mount-Database -Identity "' + $dbName + '"'),
                        ('If it will not mount, dump the header (read-only) before anything destructive: eseutil /mh "' + [string](Get-ADTExProp -InputObject $database -Name 'EdbFilePath') + '"')
                    )
                    Write-ADTResult -Check ('Database: ' + $dbName) -Status 'FAIL' `
                        -Detail ('Dismounted (Mounted=' + $mountedText + ')') -Why $dismountWhy -Fix $dismountFix -Data $database
                }
            }
        }

        # ------------------------------------------------------------------------------
        # DAG membership and local database copy status
        # ------------------------------------------------------------------------------
        # Verified on Learn: Get-DatabaseAvailabilityGroup [[-Identity]] [-Status], and
        # Get-MailboxDatabaseCopyStatus -Local returns "the status for all database copies on
        # the local Mailbox server". Copy status values (Healthy, Failed, Suspended,
        # FailedAndSuspended, Seeding, Initializing, Resynchronizing, ServiceDown,
        # DisconnectedAndHealthy, DisconnectedAndResynchronizing, Mounted, Dismounted,
        # Mounting, Dismounting, SeedingSource, SinglePageRestore) are the documented set.
        $isDagMember = $false
        $dagName = $null
        try {
            $dags = @(Get-DatabaseAvailabilityGroup -ErrorAction Stop)
            foreach ($dag in $dags) {
                # UNVERIFIED: the exact member-list property name on the DAG object. Learn
                # states the cmdlet is used "in addition to obtaining a list of DAG members"
                # but names only the -Status properties (OperationalServers,
                # PrimaryActiveManager, ReplicationPort, NetworkNames, WitnessShareInUse).
                # Both candidate names are checked so a rename cannot produce a false negative.
                $memberList = Get-ADTExProp -InputObject $dag -Name 'Servers'
                if ($null -eq $memberList) { $memberList = Get-ADTExProp -InputObject $dag -Name 'OperationalServers' }
                if ($null -eq $memberList) { continue }

                foreach ($member in @($memberList)) {
                    $memberText = [string]$member
                    if ([string]::IsNullOrWhiteSpace($memberText)) { continue }
                    $memberShort = ($memberText -split '\.')[0]
                    $memberShort = ($memberShort -split ',')[0]
                    if ($memberShort -match ('(?i)^' + [regex]::Escape($serverName) + '$')) {
                        $isDagMember = $true
                        $dagName = [string](Get-ADTExProp -InputObject $dag -Name 'Name')
                    }
                }
            }
        }
        catch {
            $isDagMember = $false
        }

        if (-not $isDagMember) {
            Write-ADTResult -Check 'DAG membership' -Status 'INFO' `
                -Detail ($serverName + ' is not a member of a database availability group (or no DAG could be read); database copy checks skipped.')
        }
        else {
            Write-ADTResult -Check 'DAG membership' -Status 'INFO' -Detail ($serverName + ' is a member of DAG ' + [string]$dagName + '.')

            try {
                $copies = @(Get-MailboxDatabaseCopyStatus -Local -ErrorAction Stop)

                if ($copies.Count -eq 0) {
                    Write-ADTResult -Check 'Database copy status' -Status 'INFO' `
                        -Detail ('No local database copies were returned on ' + $serverName + '.')
                }
                else {
                    foreach ($copy in $copies) {
                        $copyName = [string](Get-ADTExProp -InputObject $copy -Name 'Name')
                        if ([string]::IsNullOrWhiteSpace($copyName)) {
                            $copyName = [string](Get-ADTExProp -InputObject $copy -Name 'Identity')
                        }
                        if ([string]::IsNullOrWhiteSpace($copyName)) { continue }

                        $copyStatus = [string](Get-ADTExProp -InputObject $copy -Name 'Status')
                        $copyErrorText = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $copy -Name 'ErrorMessage')
                        $contentIndex = [string](Get-ADTExProp -InputObject $copy -Name 'ContentIndexState')

                        # UNVERIFIED as exact property names: CopyQueueLength and
                        # ReplayQueueLength. Learn documents the concepts verbatim ("Copy queue
                        # length: indicates the number of log files waiting to be copied to the
                        # selected database copy", "Replay queue length: ... waiting to be
                        # replayed") on the mailbox database copy properties page, and the
                        # switchover checks describe them, but no typed property list is
                        # published. Read defensively: unreadable means "not evaluated", never
                        # "zero".
                        $copyQueue = $null
                        $replayQueue = $null
                        $rawCopyQueue = Get-ADTExProp -InputObject $copy -Name 'CopyQueueLength'
                        $rawReplayQueue = Get-ADTExProp -InputObject $copy -Name 'ReplayQueueLength'
                        if ($null -ne $rawCopyQueue) { try { $copyQueue = [int64]$rawCopyQueue } catch { $copyQueue = $null } }
                        if ($null -ne $rawReplayQueue) { try { $replayQueue = [int64]$rawReplayQueue } catch { $replayQueue = $null } }

                        $queueText = 'CopyQueue=' + $(if ($null -eq $copyQueue) { 'n/a' } else { $copyQueue.ToString() })
                        $queueText = $queueText + ' ReplayQueue=' + $(if ($null -eq $replayQueue) { 'n/a' } else { $replayQueue.ToString() })

                        $copyDetail = 'Status=' + $copyStatus + ' ' + $queueText
                        if (-not [string]::IsNullOrWhiteSpace($contentIndex)) {
                            $copyDetail = $copyDetail + ' ContentIndex=' + $contentIndex
                        }

                        # Test-ReplicationHealth -Identity <server> and
                        # Resume-MailboxDatabaseCopy -Identity <DB\Server> are both documented
                        # on Microsoft Learn. Learn also documents the HighAvailability and
                        # MailboxDatabaseFailureItems "crimson channels" under Applications and
                        # Services Logs > Microsoft > Exchange, but does NOT publish their
                        # provider log-name strings - so the guidance below names the Event
                        # Viewer path rather than a Get-WinEvent -LogName value that might be
                        # wrong on the engineer's build.
                        $copyFix = @(
                            ('Get-MailboxDatabaseCopyStatus -Identity "' + $copyName + '" | Format-List Name,Status,CopyQueueLength,ReplayQueueLength,ContentIndexState,ErrorMessage'),
                            ('Test-ReplicationHealth -Identity ' + $serverName),
                            ('Guidance only - ADT does not run this: Resume-MailboxDatabaseCopy -Identity "' + $copyName + '"'),
                            'Event Viewer > Applications and Services Logs > Microsoft > Exchange > HighAvailability (and MailboxDatabaseFailureItems) carries the underlying replication failure. List the exact channel names with: Get-WinEvent -ListLog *Exchange* | Format-Table LogName,RecordCount -AutoSize'
                        )

                        if ($copyStatus -match '(?i)failed' -or $copyStatus -match '(?i)suspended') {
                            $copyWhy = 'Copy ' + $copyName + ' is in state ' + $copyStatus + '. A Failed copy is not copying or replaying log files, so it is not a usable failover target - the database has less redundancy than the design assumes. A Suspended copy was suspended by an administrator or by the system; FailedAndSuspended specifically will NOT self-recover and needs manual intervention.'
                            if (-not [string]::IsNullOrWhiteSpace($copyErrorText)) {
                                $copyWhy = $copyWhy + ' Reported error: ' + $copyErrorText
                            }
                            Write-ADTResult -Check ('Database copy: ' + $copyName) -Status 'FAIL' `
                                -Detail $copyDetail -Why $copyWhy -Fix $copyFix -Data $copy
                            continue
                        }

                        $queueBreach = $false
                        $queueWhich = @()
                        if ($null -ne $copyQueue -and $copyQueue -gt 100) {
                            $queueBreach = $true
                            $queueWhich += ('copy queue ' + $copyQueue.ToString())
                        }
                        if ($null -ne $replayQueue -and $replayQueue -gt 100) {
                            $queueBreach = $true
                            $queueWhich += ('replay queue ' + $replayQueue.ToString())
                        }

                        if ($queueBreach) {
                            $queueWhy = 'Copy ' + $copyName + ' has a deep queue (' + ($queueWhich -join ', ') + ' logs). The 100-log threshold is ADT judgement, not a Microsoft-published limit - read it as "look at this", not "this is broken". For context, Microsoft''s own Data Guarantee API treats a passive copy as healthy only when its copy queue is under 10 logs, and a lagged copy is expected to sit deep by design. A non-lagged copy that is climbing means log shipping or replay cannot keep up with the active copy.'
                            Write-ADTResult -Check ('Database copy: ' + $copyName) -Status 'WARN' `
                                -Detail $copyDetail -Why $queueWhy -Fix $copyFix -Data $copy
                            continue
                        }

                        if ($copyStatus -match '(?i)^(healthy|mounted)$') {
                            Write-ADTResult -Check ('Database copy: ' + $copyName) -Status 'PASS' -Detail $copyDetail
                        }
                        else {
                            Write-ADTResult -Check ('Database copy: ' + $copyName) -Status 'INFO' -Detail $copyDetail
                        }
                    }
                }
            }
            catch {
                Write-ADTResult -Check 'Database copy status' -Status 'ERROR' `
                    -Detail ('Get-MailboxDatabaseCopyStatus -Local failed: ' + $_.Exception.Message) `
                    -Fix @('Get-MailboxDatabaseCopyStatus -Local | Format-List Name,Status,CopyQueueLength,ReplayQueueLength,ErrorMessage', ('Test-ReplicationHealth -Identity ' + $serverName))
            }
        }

        # ------------------------------------------------------------------------------
        # Transport queues
        # ------------------------------------------------------------------------------
        # Verified on Learn: Get-Queue [-Server <ServerIdParameter>]; queue properties
        # Identity, Status (Active, Connecting, Suspended, Ready, Retry), MessageCount,
        # LastError, NextHopDomain, DeliveryType, LastRetryTime. The poison message queue
        # has DeliveryType Undefined and NextHopDomain "Poison Message", and does not appear
        # in Get-Queue results at all when it is empty. Retry-Queue -Resubmit $true is the
        # documented resubmit path.
        try {
            $queues = @(Get-Queue -Server $serverName -ErrorAction Stop)

            $totalMessages = 0
            foreach ($queue in $queues) {
                $countRaw = Get-ADTExProp -InputObject $queue -Name 'MessageCount'
                if ($null -ne $countRaw) {
                    try { $totalMessages = $totalMessages + [int64]$countRaw } catch { $null = $_ }
                }
            }
            Write-ADTResult -Check 'Transport queues' -Status 'INFO' `
                -Detail ($queues.Count.ToString() + ' queue(s) on ' + $serverName + ', ' + $totalMessages.ToString() + ' message(s) in total.')

            $problemQueues = 0

            foreach ($queue in $queues) {
                $queueIdentity = [string](Get-ADTExProp -InputObject $queue -Name 'Identity')
                if ([string]::IsNullOrWhiteSpace($queueIdentity)) { continue }

                $queueStatus = [string](Get-ADTExProp -InputObject $queue -Name 'Status')
                $nextHop = [string](Get-ADTExProp -InputObject $queue -Name 'NextHopDomain')
                $deliveryType = [string](Get-ADTExProp -InputObject $queue -Name 'DeliveryType')
                $lastError = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $queue -Name 'LastError')
                $lastRetry = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $queue -Name 'LastRetryTime')

                $messageCount = 0
                $rawCount = Get-ADTExProp -InputObject $queue -Name 'MessageCount'
                if ($null -ne $rawCount) {
                    try { $messageCount = [int64]$rawCount } catch { $messageCount = 0 }
                }

                $isPoison = ($queueIdentity -match '(?i)\\Poison$') -or ($nextHop -match '(?i)^Poison Message$')

                if ($isPoison) {
                    if ($messageCount -gt 0) {
                        $problemQueues++
                        $poisonWhy = 'The poison message queue holds ' + $messageCount.ToString() + ' message(s). Exchange only puts a message here after it crashed transport or a transport agent while being processed, and Learn is explicit that these messages are never automatically resumed or expired - they sit there until an administrator deals with them. A non-empty poison queue is also a strong hint that a transport agent (often third-party AV or a signature/disclaimer product) is faulting.'
                        # Get-Message -Queue and Export-Message -Identity are documented on
                        # Microsoft Learn ("Use the Exchange Management Shell to manage
                        # queues"). Resume-Message takes -Identity <Server\Queue\MessageId>
                        # or -Filter - it has NO -Queue parameter, which is why the guidance
                        # below spells out the full message identity form.
                        # UNVERIFIED: Get-TransportAgent was not re-confirmed against Learn
                        # in this session; it is listed as an investigative pointer only and
                        # nothing in ADT depends on it.
                        $poisonFix = @(
                            ('Get-Message -Queue "' + $queueIdentity + '" | Format-List Identity,Subject,FromAddress,Status,LastError'),
                            'Get-TransportAgent | Format-Table Identity,Enabled,Priority -AutoSize',
                            ('Export a message for offline inspection before touching it: Export-Message -Identity "' + $queueIdentity + '\<MessageId>"'),
                            ('Guidance only - ADT does not run this. Resume one message by its full Server\Queue\MessageId identity: Resume-Message -Identity "' + $queueIdentity + '\<MessageId>"')
                        )
                        Write-ADTResult -Check ('Poison queue: ' + $queueIdentity) -Status 'WARN' `
                            -Detail ($messageCount.ToString() + ' message(s) quarantined.') -Why $poisonWhy -Fix $poisonFix -Data $queue
                    }
                    continue
                }

                if (-not ($queueStatus -match '(?i)^(retry|suspended)$')) { continue }

                $problemQueues++
                $queueDetail = 'Status=' + $queueStatus + ' MessageCount=' + $messageCount.ToString() + ' NextHop=' + $nextHop + ' DeliveryType=' + $deliveryType
                if (-not [string]::IsNullOrWhiteSpace($lastRetry)) {
                    $queueDetail = $queueDetail + ' LastRetry=' + $lastRetry
                }

                $queueFix = @(
                    ('Get-Queue -Identity "' + $queueIdentity + '" | Format-List Identity,Status,MessageCount,LastError,NextHopDomain,LastRetryTime,NextRetryTime'),
                    ('Get-Message -Queue "' + $queueIdentity + '" -ResultSize 10 | Format-List Identity,Subject,FromAddress,Status,LastError'),
                    ('Guidance only - ADT does not run this: Retry-Queue -Identity "' + $queueIdentity + '" -Resubmit $true'),
                    ('Prove the next hop is reachable before resubmitting: Test-NetConnection ' + $nextHop + ' -Port 25')
                )

                $errorNote = 'No LastError text was recorded on the queue.'
                if (-not [string]::IsNullOrWhiteSpace($lastError)) {
                    $errorNote = 'LastError: ' + $lastError
                }

                if ($messageCount -gt 250) {
                    $failWhy = 'Queue ' + $queueIdentity + ' is in ' + $queueStatus + ' with ' + $messageCount.ToString() + ' messages backed up to ' + $nextHop + '. The 250-message line is ADT judgement, not a Microsoft-published limit, but a Retry queue this deep means the next hop has been refusing or unreachable long enough that users are noticing missing mail, and it will keep growing until the destination is fixed or the messages expire. ' + $errorNote
                    Write-ADTResult -Check ('Transport queue: ' + $queueIdentity) -Status 'FAIL' `
                        -Detail $queueDetail -Why $failWhy -Fix $queueFix -Data $queue
                }
                elseif ($messageCount -gt 50) {
                    $warnWhy = 'Queue ' + $queueIdentity + ' is in ' + $queueStatus + ' with ' + $messageCount.ToString() + ' messages for ' + $nextHop + '. The 50-message line is ADT judgement, not a Microsoft-published limit - a short Retry burst is normal when a remote host is briefly busy. Re-run this check in a few minutes: draining is fine, growing is not. ' + $errorNote
                    Write-ADTResult -Check ('Transport queue: ' + $queueIdentity) -Status 'WARN' `
                        -Detail $queueDetail -Why $warnWhy -Fix $queueFix -Data $queue
                }
                else {
                    Write-ADTResult -Check ('Transport queue: ' + $queueIdentity) -Status 'INFO' `
                        -Detail ($queueDetail + ' - below the WARN threshold of 50 messages.') -Data $queue
                }
            }

            if ($problemQueues -eq 0 -and $queues.Count -gt 0) {
                Write-ADTResult -Check 'Transport queue health' -Status 'PASS' `
                    -Detail 'No queues in Retry or Suspended, and no messages in the poison queue.'
            }
        }
        catch {
            Write-ADTResult -Check 'Transport queues' -Status 'ERROR' `
                -Detail ('Get-Queue failed: ' + $_.Exception.Message) `
                -Why 'Get-Queue talks to the Transport service on this server. A failure here usually means the Microsoft Exchange Transport service is stopped (see the service results above) rather than that the queues are empty.' `
                -Fix @(('Get-Queue -Server ' + $serverName + ' | Format-List Identity,Status,MessageCount,LastError'), 'Get-Service MSExchangeTransport | Format-List Name,Status,StartType')
        }

        # ------------------------------------------------------------------------------
        # Back pressure
        # ------------------------------------------------------------------------------
        # Event IDs verified verbatim on Microsoft Learn ("Understanding back pressure",
        # Back pressure logging information), Event Source MSExchangeTransport, category
        # Resource Manager:
        #   15004 Error       - Resource pressure increased from <x> to <y>
        #   15005 Information - Resource pressure decreased from <x> to <y>
        #   15006 Error       - rejecting messages, available disk space below threshold
        #   15007 Error       - rejecting submissions, memory above threshold
        # UNVERIFIED: Learn names the source and IDs but does not state the event log these
        # land in. Application is the long-standing location and is queried first; if that
        # query returns nothing usable the same IDs are retried without a provider filter
        # before any conclusion is drawn.
        try {
            $pressureStart = (Get-Date).AddHours(-24)
            $pressureIds = @(15004, 15005, 15006, 15007)
            $pressure = Get-ADTExEventSummary -LogName 'Application' -ProviderName 'MSExchangeTransport' -Id $pressureIds -StartTime $pressureStart -MaxEvents 200
            if (-not $pressure.Success) {
                $pressure = Get-ADTExEventSummary -LogName 'Application' -Id $pressureIds -StartTime $pressureStart -MaxEvents 200
            }

            if (-not $pressure.Success) {
                Write-ADTResult -Check 'Transport back pressure (24h)' -Status 'ERROR' `
                    -Detail ('Could not read the Application log: ' + $pressure.ErrorMessage) `
                    -Fix @('Get-WinEvent -FilterHashtable @{LogName="Application"; ProviderName="MSExchangeTransport"; Id=15004,15005,15006,15007} -MaxEvents 50 | Format-List TimeCreated,Id,Message')
            }
            else {
                $criticalPressure = @($pressure.Events | Where-Object { $_.Id -eq 15006 -or $_.Id -eq 15007 })
                $increasePressure = @($pressure.Events | Where-Object { $_.Id -eq 15004 })
                $decreasePressure = @($pressure.Events | Where-Object { $_.Id -eq 15005 })

                # Array-literal precedence rule: every element that uses + is wrapped in its
                # own parentheses. Without that, the comma binds tighter than + and the
                # element fragments.
                $pressureFix = @(
                    'View the live resource meters: [xml]$bp = Get-ExchangeDiagnosticInfo -Process EdgeTransport -Component ResourceThrottling; $bp.Diagnostics.Components.ResourceThrottling.ResourceTracker.ResourceMeter',
                    'Free space on the queue database volume (default %ExchangeInstallPath%TransportRoles\data\Queue) - back pressure needs the volume to stay above the computed high threshold, which reserves a 500 MB fixed constant.',
                    'Get-WinEvent -FilterHashtable @{LogName="Application"; ProviderName="MSExchangeTransport"; Id=15004,15005,15006,15007} -MaxEvents 50 | Format-List TimeCreated,Id,Message',
                    ('Confirm which resource is under pressure before acting - disk and memory need different fixes. If the queue database has outgrown its volume, moving it is a planned change on ' + $serverName + ', not a live fix; check the current paths first with Get-TransportService -Identity ' + $serverName + ' | Format-List QueueDatabasePath,QueueDatabaseLoggingPath')
                )

                if ($criticalPressure.Count -gt 0) {
                    $newestCritical = $criticalPressure | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1
                    $criticalWhy = 'Event ' + $newestCritical.Id.ToString() + ' means the Transport service is actively REJECTING mail because a monitored resource crossed its high threshold - 15006 is disk space on the queue database volume, 15007 is EdgeTransport.exe memory. This is not a warning about the future; senders are being refused at MAIL FROM right now, or were within the last 24 hours.'
                    Write-ADTResult -Check 'Transport back pressure (24h)' -Status 'FAIL' `
                        -Detail ($criticalPressure.Count.ToString() + ' critical back-pressure event(s), most recent ' + $newestCritical.TimeCreated.ToString('yyyy-MM-dd HH:mm') + ' (ID ' + $newestCritical.Id.ToString() + ')') `
                        -Why $criticalWhy -Fix $pressureFix -Data $criticalPressure
                }
                elseif ($increasePressure.Count -gt 0) {
                    $newestIncrease = $increasePressure | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1
                    $recoveryNote = ' No corresponding 15005 (pressure decreased) event was logged afterwards, so the elevated level may still be in force.'
                    if ($decreasePressure.Count -gt 0) {
                        $newestDecrease = $decreasePressure | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1
                        if ($newestDecrease.TimeCreated -gt $newestIncrease.TimeCreated) {
                            $recoveryNote = ' A 15005 (pressure decreased) event followed at ' + $newestDecrease.TimeCreated.ToString('yyyy-MM-dd HH:mm') + ', so the server recovered on its own - but the underlying resource is running close enough to its threshold to trip again.'
                        }
                    }
                    $increaseWhy = 'Event 15004 means resource utilisation on this transport server rose to Medium or High. At Medium, Exchange starts tarpitting and rejecting mail from non-Exchange senders; at High it stops accepting new mail entirely.' + $recoveryNote
                    Write-ADTResult -Check 'Transport back pressure (24h)' -Status 'WARN' `
                        -Detail ($increasePressure.Count.ToString() + ' pressure-increase event(s), most recent ' + $newestIncrease.TimeCreated.ToString('yyyy-MM-dd HH:mm')) `
                        -Why $increaseWhy -Fix $pressureFix -Data $increasePressure
                }
                elseif ($decreasePressure.Count -gt 0) {
                    Write-ADTResult -Check 'Transport back pressure (24h)' -Status 'INFO' `
                        -Detail ($decreasePressure.Count.ToString() + ' pressure-decrease event(s) (ID 15005) with no matching increase in the window - the increase probably fell just outside the last 24 hours.')
                }
                else {
                    Write-ADTResult -Check 'Transport back pressure (24h)' -Status 'PASS' `
                        -Detail 'No MSExchangeTransport back-pressure events (15004/15005/15006/15007) in the last 24 hours.'
                }
            }
        }
        catch {
            Write-ADTResult -Check 'Transport back pressure (24h)' -Status 'ERROR' -Detail ('Back-pressure check failed: ' + $_.Exception.Message)
        }

        # ------------------------------------------------------------------------------
        # Certificates
        # ------------------------------------------------------------------------------
        # Verified on Learn (Get-ExchangeCertificate): -Server <ServerIdParameter>, and the
        # documented properties Thumbprint, Services (None, Federation, IIS, IMAP, POP, SMTP,
        # UM, UMCallRouter), Subject, NotAfter, NotBefore, IsSelfSigned, Issuer,
        # CertificateDomains and Status (DateInvalid, Invalid, PendingRequest,
        # RevocationCheckFailure, Revoked, Unknown, Untrusted, Valid).
        try {
            $certificates = @(Get-ExchangeCertificate -Server $serverName -ErrorAction Stop)

            if ($certificates.Count -eq 0) {
                Write-ADTResult -Check 'Exchange certificates' -Status 'ERROR' `
                    -Detail ('Get-ExchangeCertificate returned nothing for ' + $serverName + '.') `
                    -Fix @(('Get-ExchangeCertificate -Server ' + $serverName + ' | Format-List Thumbprint,Services,Subject,NotAfter,IsSelfSigned,Status'))
            }
            else {
                $now = Get-Date
                $boundCount = 0
                $unboundExpired = 0

                foreach ($certificate in $certificates) {
                    $thumbprint = [string](Get-ADTExProp -InputObject $certificate -Name 'Thumbprint')
                    $subject = [string](Get-ADTExProp -InputObject $certificate -Name 'Subject')
                    $servicesText = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $certificate -Name 'Services')
                    $statusText = [string](Get-ADTExProp -InputObject $certificate -Name 'Status')
                    $notAfterRaw = Get-ADTExProp -InputObject $certificate -Name 'NotAfter'
                    $isSelfSignedRaw = Get-ADTExProp -InputObject $certificate -Name 'IsSelfSigned'
                    $domainsText = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $certificate -Name 'CertificateDomains')

                    if ([string]::IsNullOrWhiteSpace($thumbprint)) { continue }
                    if ($statusText -match '(?i)PendingRequest') {
                        Write-ADTResult -Check ('Certificate request: ' + $thumbprint) -Status 'INFO' `
                            -Detail ('Pending certificate request (CSR) for ' + $subject + ' - not an installed certificate.')
                        continue
                    }

                    $isBound = (-not [string]::IsNullOrWhiteSpace($servicesText)) -and ($servicesText -notmatch '(?i)^none$')
                    $shortLabel = $thumbprint
                    if ($thumbprint.Length -ge 8) { $shortLabel = $thumbprint.Substring(0, 8) }
                    $certLabel = 'Certificate ' + $shortLabel + ' (' + $subject + ')'

                    if ($null -eq $notAfterRaw) {
                        Write-ADTResult -Check $certLabel -Status 'ERROR' `
                            -Detail 'The NotAfter property could not be read, so expiry cannot be evaluated.' `
                            -Fix @(('Get-ExchangeCertificate -Thumbprint ' + $thumbprint + ' | Format-List Thumbprint,Subject,NotAfter,Services,Status'))
                        continue
                    }

                    $notAfter = [datetime]$notAfterRaw
                    $daysLeft = [int]($notAfter - $now).TotalDays
                    $certDetail = 'Services=' + $servicesText + ' Expires=' + $notAfter.ToString('yyyy-MM-dd') + ' (' + $daysLeft.ToString() + ' day(s)) Status=' + $statusText

                    if (-not $isBound) {
                        if ($notAfter -lt $now) { $unboundExpired++ }
                        continue
                    }

                    $boundCount++

                    # Enable-ExchangeCertificate is named on Microsoft Learn as the cmdlet
                    # that assigns services to a certificate (Get-ExchangeCertificate's
                    # Services property description says so verbatim), and the Services value
                    # list is the documented one. The certificate REQUEST syntax is
                    # deliberately not spelled out here - it varies by CA and by whether the
                    # renewal is a rekey, and a wrong -RequestFile/-GenerateRequest line would
                    # be worse than a pointer to the EAC wizard.
                    $certFix = @(
                        ('Get-ExchangeCertificate -Thumbprint ' + $thumbprint + ' | Format-List Thumbprint,Subject,CertificateDomains,Services,NotAfter,Issuer,IsSelfSigned'),
                        'Renew through the EAC (Servers > Certificates > Renew) or your CA''s normal process, keeping every name currently in CertificateDomains on the new certificate.',
                        ('[SERVICE-AFFECTING] After importing the renewed certificate, bind the services it must carry: Enable-ExchangeCertificate -Thumbprint <NEW-THUMBPRINT> -Services ' + ($servicesText -replace '\s', '')),
                        'If this server is hybrid, re-run the Hybrid Configuration wizard (or its Update Secure Mail Certificate for connectors option) so the connectors pick up the new certificate.'
                    )

                    if ($notAfter -lt $now) {
                        $expiredWhy = 'This certificate expired on ' + $notAfter.ToString('yyyy-MM-dd') + ' and is still bound to ' + $servicesText + ' on ' + $serverName + '. Clients hitting those services get a certificate error (Outlook prompts, ActiveSync failures) and TLS-authenticated SMTP partners - including the Exchange Online hybrid connectors - will refuse the session outright.'
                        Write-ADTResult -Check $certLabel -Status 'FAIL' -Detail $certDetail -Why $expiredWhy -Fix $certFix -Data $certificate
                    }
                    elseif ($daysLeft -lt 30) {
                        $soonWhy = 'This certificate expires in ' + $daysLeft.ToString() + ' day(s) and is bound to ' + $servicesText + '. Public CA issuance plus validation plus the change window rarely fits inside 30 days, and the failure mode when it lapses is immediate and total for every service listed.'
                        Write-ADTResult -Check $certLabel -Status 'WARN' -Detail $certDetail -Why $soonWhy -Fix $certFix -Data $certificate
                    }
                    else {
                        Write-ADTResult -Check $certLabel -Status 'PASS' -Detail $certDetail
                    }

                    if (($null -ne $isSelfSignedRaw) -and ([bool]$isSelfSignedRaw) -and ($servicesText -match '(?i)IIS')) {
                        $selfSignedFix = @(
                            ('Get-ExchangeCertificate -Thumbprint ' + $thumbprint + ' | Format-List Subject,CertificateDomains,Issuer,IsSelfSigned,Services'),
                            'Confirm which certificate clients actually receive from outside: check the published name against the certificate served on TCP 443.',
                            'If this is the certificate serving OWA/EWS/ActiveSync, replace it with one from a public CA covering the published names.'
                        )
                        Write-ADTResult -Check ('Self-signed certificate on IIS: ' + $shortLabel) -Status 'INFO' `
                            -Detail ('Self-signed certificate bound to IIS. Domains: ' + $domainsText) `
                            -Why 'Exchange installs a self-signed certificate and binds it to IIS by default, so this is often just the untouched default sitting behind a real certificate rather than a fault. It only matters if this is the certificate clients are actually presented with - a self-signed certificate is not trusted by any client that has not been told to trust it.'
                    }
                }

                Write-ADTNote -Text ($boundCount.ToString() + ' of ' + $certificates.Count.ToString() + ' certificate(s) on ' + $serverName + ' are bound to an Exchange service and were evaluated for expiry.')
                if ($unboundExpired -gt 0) {
                    Write-ADTResult -Check 'Expired unbound certificates' -Status 'INFO' `
                        -Detail ($unboundExpired.ToString() + ' expired certificate(s) present with no Exchange service bound (Services=None).') `
                        -Why 'These are not evaluated as failures because nothing in Exchange presents them - typically the WMSvc IIS management certificate or an old certificate left in the store after a renewal. Worth tidying, not worth an alert.'
                }
            }
        }
        catch {
            Write-ADTResult -Check 'Exchange certificates' -Status 'ERROR' `
                -Detail ('Get-ExchangeCertificate failed: ' + $_.Exception.Message) `
                -Fix @(('Get-ExchangeCertificate -Server ' + $serverName + ' | Format-List Thumbprint,Services,Subject,NotAfter,Status'))
        }

        # ------------------------------------------------------------------------------
        # Free space on the volumes hosting database and log paths
        # ------------------------------------------------------------------------------
        if ($databases.Count -gt 0) {
            $checkedVolumes = @{}

            foreach ($database in $databases) {
                $dbName = [string](Get-ADTExProp -InputObject $database -Name 'Name')
                $edbPath = [string](Get-ADTExProp -InputObject $database -Name 'EdbFilePath')
                $logPath = [string](Get-ADTExProp -InputObject $database -Name 'LogFolderPath')

                $pathPairs = @()
                if (-not [string]::IsNullOrWhiteSpace($edbPath)) { $pathPairs += ([PSCustomObject]@{ Kind = 'database'; Path = $edbPath }) }
                if (-not [string]::IsNullOrWhiteSpace($logPath)) { $pathPairs += ([PSCustomObject]@{ Kind = 'log'; Path = $logPath }) }

                foreach ($pathPair in $pathPairs) {
                    $usage = Get-ADTExVolumeUsage -Path $pathPair.Path
                    if ($null -eq $usage) {
                        Write-ADTResult -Check ('Volume for ' + $dbName + ' ' + $pathPair.Kind + ' path') -Status 'INFO' `
                            -Detail ('Could not resolve a local volume for ' + $pathPair.Path + ' - it is a UNC path, or the volume is not visible to WMI from this session.')
                        continue
                    }

                    $volumeKey = [string]$usage.VolumeId
                    if ($checkedVolumes.ContainsKey($volumeKey)) {
                        $checkedVolumes[$volumeKey] = $checkedVolumes[$volumeKey] + ', ' + $dbName + ' (' + $pathPair.Kind + ')'
                        continue
                    }
                    $checkedVolumes[$volumeKey] = $dbName + ' (' + $pathPair.Kind + ')'

                    $percentFree = [double]$usage.PercentFree
                    $volumeDetail = $volumeKey + ' - ' + (Format-ADTExBytes -Bytes $usage.FreeBytes) + ' free of ' + (Format-ADTExBytes -Bytes $usage.SizeBytes) + ' (' + $percentFree.ToString('N1') + '% free), hosting ' + $dbName + ' ' + $pathPair.Kind + ' files'

                    $volumeFix = @(
                        ('Get-MailboxDatabase -Server ' + $serverName + ' -Status | Format-Table Name,EdbFilePath,LogFolderPath,DatabaseSize -AutoSize'),
                        'Confirm backups are running and truncating logs - an unbacked-up database with circular logging off fills its log volume by design: Get-MailboxDatabase -Status | Format-List Name,LastFullBackup,LastIncrementalBackup,CircularLoggingEnabled',
                        ('Check for a stuck or suspended copy holding logs open: Get-MailboxDatabaseCopyStatus -Local | Format-Table Name,Status,CopyQueueLength,ReplayQueueLength -AutoSize'),
                        ('[SERVICE-AFFECTING] If the database really has to move, plan it as a change - Learn notes a mounted database is dismounted and remounted by this cmdlet, and it cannot be run against a replicated database at all: Move-DatabasePath -Identity "' + $dbName + '" -EdbFilePath <newpath> -LogFolderPath <newpath>')
                    )

                    if ($percentFree -lt 8) {
                        $volumeWhy = 'Volume ' + $volumeKey + ' is at ' + $percentFree.ToString('N1') + '% free and holds ' + $pathPair.Kind + ' files for ' + $dbName + '. The 8% line is ADT judgement, not a Microsoft-published limit. What is not judgement: when an Exchange volume fills, the store dismounts the database and transport back pressure starts rejecting mail - both are outages, and both happen without warning at the moment the last block is consumed. For reference, Managed Availability''s own low-space monitor defaults to alerting at 180 GB free regardless of percentage.'
                        Write-ADTResult -Check ('Volume free space: ' + $volumeKey) -Status 'FAIL' -Detail $volumeDetail -Why $volumeWhy -Fix $volumeFix
                    }
                    elseif ($percentFree -lt 15) {
                        $volumeWhy = 'Volume ' + $volumeKey + ' is at ' + $percentFree.ToString('N1') + '% free and holds ' + $pathPair.Kind + ' files for ' + $dbName + '. The 15% line is ADT judgement, not a Microsoft-published limit - treat it as "find out what is consuming it before it becomes urgent". A log volume that has been slowly filling almost always means backups have stopped truncating logs.'
                        Write-ADTResult -Check ('Volume free space: ' + $volumeKey) -Status 'WARN' -Detail $volumeDetail -Why $volumeWhy -Fix $volumeFix
                    }
                    else {
                        Write-ADTResult -Check ('Volume free space: ' + $volumeKey) -Status 'PASS' -Detail $volumeDetail
                    }
                }
            }
        }

        # ------------------------------------------------------------------------------
        # Build / patch level
        # ------------------------------------------------------------------------------
        # Verified on Learn ("Exchange Server build numbers and release dates"): option 2 is
        # "Get-Command Exsetup.exe | ForEach-Object {$_.FileVersionInfo}" which shows SU/HU
        # level, and option 3 is "Get-ExchangeServer | Format-List Name,Edition,
        # AdminDisplayVersion" which shows the CU only and explicitly does NOT show installed
        # security updates. Both are reported here for that reason. No build table is
        # hardcoded - it would be stale within a month.
        try {
            $exchangeServer = Get-ExchangeServer -Identity $serverName -ErrorAction Stop
            $adminVersion = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $exchangeServer -Name 'AdminDisplayVersion')
            $edition = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $exchangeServer -Name 'Edition')
            $serverRole = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $exchangeServer -Name 'ServerRole')

            $exSetupVersion = 'not read'
            try {
                $exchangeRoot = $env:ExchangeInstallPath
                if (-not [string]::IsNullOrEmpty($exchangeRoot)) {
                    $exSetupPath = Join-Path -Path $exchangeRoot -ChildPath 'bin\ExSetup.exe'
                    if (Test-Path -LiteralPath $exSetupPath) {
                        $versionInfo = (Get-Item -LiteralPath $exSetupPath -ErrorAction Stop).VersionInfo
                        if ($null -ne $versionInfo -and $versionInfo.FileVersion) {
                            $exSetupVersion = [string]$versionInfo.FileVersion
                        }
                    }
                }
            }
            catch {
                $exSetupVersion = 'not read'
            }

            $buildDetail = 'AdminDisplayVersion=' + $adminVersion + ' | ExSetup.exe FileVersion=' + $exSetupVersion + ' | Edition=' + $edition + ' | Role=' + $serverRole
            $buildFix = @(
                'Get-Command ExSetup.exe | ForEach-Object { $_.FileVersionInfo }',
                ('Get-ExchangeServer -Identity ' + $serverName + ' | Format-List Name,Edition,ServerRole,AdminDisplayVersion'),
                'Compare against the current build table: https://learn.microsoft.com/exchange/new-features/build-numbers-and-release-dates',
                'For a full patch and configuration assessment, run the Microsoft HealthChecker script: https://aka.ms/exchangehealthchecker'
            )
            Write-ADTResult -Check 'Exchange build' -Status 'INFO' -Detail $buildDetail `
                -Why 'ADT deliberately does not carry a build table - one goes stale within a month of shipping, and a wrong "you are current" is worse than no answer. AdminDisplayVersion shows the CU only and hides installed security updates; the ExSetup.exe file version is the value that reflects SU and HU level. Compare the ExSetup value against the Microsoft build reference below. Exchange security updates are frequently the fix for an actively exploited vulnerability, so an out-of-date build here is a security finding, not just a hygiene one.' `
                -Fix $buildFix -Data $exchangeServer
        }
        catch {
            Write-ADTResult -Check 'Exchange build' -Status 'ERROR' `
                -Detail ('Get-ExchangeServer failed: ' + $_.Exception.Message) `
                -Fix @('Get-Command ExSetup.exe | ForEach-Object { $_.FileVersionInfo }')
        }
    }
    catch {
        Write-ADTResult -Check 'Exchange server health' -Status 'ERROR' -Detail ('Unhandled exception: ' + $_.Exception.Message)
    }
}

function Invoke-ADTExchangeMailFlow {
    <#
        .SYNOPSIS
            Item 2: Mail flow smoke test. Sends a Test-Mailflow probe message, so it is
            deliberately excluded from the unattended snapshot and is confirm-gated.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Mail flow smoke test'

        if (-not (Connect-ADTExShell)) {
            Write-ADTExShellSkip -Check 'Mail flow smoke test'
            return
        }

        $serverName = $env:COMPUTERNAME

        # Verified on Learn (Test-Mailflow): the SourceServer parameter set is
        # "Test-Mailflow [[-Identity] <ServerIdParameter>] [-ExecutionTimeout <Int32>] ...",
        # which "verifies that each Mailbox server can successfully send itself a message".
        # Documented result values: TestMailflowResult is "typically Success or *FAILURE*",
        # and MessageLatencyTime uses hh:mm:ss.ffff. Default ExecutionTimeout in the shell is
        # 240 seconds; 120 is used here so a menu item cannot hang a field session for four
        # minutes.
        $prompt = 'Test-Mailflow sends a real system probe message from ' + $serverName + ' to its own system mailbox. Send it now?'
        if (-not (Confirm-ADTAction -Prompt $prompt)) {
            Write-ADTResult -Check 'Mail flow smoke test' -Status 'SKIP' `
                -Detail 'Not confirmed; no test message was sent.' `
                -Why 'Every other ADT check is read-only. This one injects a message into the transport pipeline, so it asks first and always declines itself in a non-interactive run.' `
                -Fix @(('Test-Mailflow -Identity ' + $serverName + ' | Format-List TestMailflowResult,MessageLatencyTime,Identity'))
            return
        }

        Write-ADTNote -Text ('Sending a Test-Mailflow probe message on ' + $serverName + '. This can take up to two minutes.')

        try {
            $mailflowResults = @(Test-Mailflow -Identity $serverName -ExecutionTimeout 120 -ErrorAction Stop)

            if ($mailflowResults.Count -eq 0) {
                Write-ADTResult -Check 'Mail flow smoke test' -Status 'ERROR' `
                    -Detail 'Test-Mailflow returned no result object.' `
                    -Fix @(('Test-Mailflow -Identity ' + $serverName + ' | Format-List *'))
                return
            }

            foreach ($mailflowResult in $mailflowResults) {
                $resultText = [string](Get-ADTExProp -InputObject $mailflowResult -Name 'TestMailflowResult')
                $latencyText = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $mailflowResult -Name 'MessageLatencyTime')
                $identityText = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $mailflowResult -Name 'Identity')

                if ([string]::IsNullOrWhiteSpace($resultText)) {
                    Write-ADTResult -Check 'Mail flow smoke test' -Status 'ERROR' `
                        -Detail 'The TestMailflowResult property could not be read from the result.' `
                        -Why 'ADT will not infer pass or fail from an output shape it does not recognise.' `
                        -Fix @(('Test-Mailflow -Identity ' + $serverName + ' | Format-List *'))
                    continue
                }

                $detailText = 'TestMailflowResult=' + $resultText
                if (-not [string]::IsNullOrWhiteSpace($latencyText)) { $detailText = $detailText + ' Latency=' + $latencyText }
                if (-not [string]::IsNullOrWhiteSpace($identityText)) { $detailText = $detailText + ' Target=' + $identityText }

                if ($resultText -match '(?i)success') {
                    Write-ADTResult -Check 'Mail flow smoke test' -Status 'PASS' -Detail $detailText -Data $mailflowResult
                }
                else {
                    $flowWhy = 'Test-Mailflow could not get a probe message submitted, transported and delivered on ' + $serverName + ' within the timeout. This exercises the whole local pipeline - submission, categoriser, transport, store delivery - so a failure here means real user mail is affected on this server too, not just the probe. The usual causes, in the order worth checking: a stopped transport or store service, an inactive HubTransport server component, a dismounted database holding the system mailbox, or a transport queue that is not draining.'
                    $flowFix = @(
                        ('Test-ServiceHealth -Server ' + $serverName),
                        ('Get-ServerComponentState -Identity ' + $serverName + ' | Format-Table Component,State -AutoSize'),
                        ('Get-Queue -Server ' + $serverName + ' | Format-List Identity,Status,MessageCount,LastError,NextHopDomain'),
                        ('Look at the Submission queue specifically - a probe that never leaves it points at the categoriser: Get-Queue -Identity ' + $serverName + '\Submission | Format-List'),
                        ('Confirm the system mailbox database is mounted - Test-Mailflow needs a system mailbox on the server: Get-MailboxDatabase -Server ' + $serverName + ' -Status | Format-Table Name,Mounted,MountedOnServer -AutoSize'),
                        ('Prove the server is answering SMTP on every receive connector binding: Test-SmtpConnectivity -Identity ' + $serverName),
                        'Open Queue Viewer from the Exchange Toolbox on this server for the live queue view.'
                    )
                    Write-ADTResult -Check 'Mail flow smoke test' -Status 'FAIL' -Detail $detailText -Why $flowWhy -Fix $flowFix -Data $mailflowResult
                }
            }
        }
        catch {
            Write-ADTResult -Check 'Mail flow smoke test' -Status 'ERROR' `
                -Detail ('Test-Mailflow failed: ' + $_.Exception.Message) `
                -Why 'The cmdlet itself did not complete. A missing system mailbox on the server, an RBAC gap, or a stopped transport service all surface here rather than as a clean FAILURE result.' `
                -Fix @(('Test-Mailflow -Identity ' + $serverName + ' | Format-List *'), ('Test-ServiceHealth -Server ' + $serverName), ('Test-SmtpConnectivity -Identity ' + $serverName), ('Get-MailboxDatabase -Server ' + $serverName + ' -Status | Format-Table Name,Mounted -AutoSize'))
        }
    }
    catch {
        Write-ADTResult -Check 'Mail flow smoke test' -Status 'ERROR' -Detail ('Unhandled exception: ' + $_.Exception.Message)
    }
}

function Invoke-ADTExchangeHybrid {
    <#
        .SYNOPSIS
            Item 3: Hybrid configuration, Office 365 connectors, Autodiscover, OAuth guidance
            and Entra Connect (ADSync) state on this box.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Hybrid and Entra Connect'

        if (-not (Connect-ADTExShell)) {
            Write-ADTExShellSkip -Check 'Hybrid and Entra Connect'
            return
        }

        $serverName = $env:COMPUTERNAME

        # ------------------------------------------------------------------------------
        # Hybrid configuration object
        # ------------------------------------------------------------------------------
        # Verified on Learn: Get-HybridConfiguration takes no parameters beyond
        # -DomainController. The property names read below are the parameter names published
        # for New-HybridConfiguration / Set-HybridConfiguration (Domains, Features,
        # SendingTransportServers, ReceivingTransportServers, OnPremisesSmartHost,
        # TlsCertificateName, ExternalIPAddresses, ServiceInstance); the object's own property
        # schema is not published, so each is read defensively.
        $hybridConfig = $null
        try {
            $hybridConfig = Get-HybridConfiguration -ErrorAction Stop
        }
        catch {
            $hybridConfig = $null
        }

        if ($null -eq $hybridConfig) {
            Write-ADTResult -Check 'Hybrid configuration object' -Status 'INFO' `
                -Detail 'No hybrid configuration object exists in this organization.' `
                -Why 'This organization has never had the Hybrid Configuration wizard run against it (or the object was removed). That is entirely normal for an Exchange organization with no Microsoft 365 tenant behind it - the connector checks below are reported for information only rather than measured against a hybrid expectation.'
        }
        else {
            $hybridDomains = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $hybridConfig -Name 'Domains')
            $hybridFeatures = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $hybridConfig -Name 'Features')
            $hybridSmartHost = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $hybridConfig -Name 'OnPremisesSmartHost')
            $hybridTlsCert = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $hybridConfig -Name 'TlsCertificateName')
            $hybridSending = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $hybridConfig -Name 'SendingTransportServers')
            $hybridReceiving = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $hybridConfig -Name 'ReceivingTransportServers')

            $hybridDetail = 'Domains: ' + $hybridDomains + ' | Features: ' + $hybridFeatures
            Write-ADTResult -Check 'Hybrid configuration object' -Status 'INFO' -Detail $hybridDetail -Data $hybridConfig
            Write-ADTNote -Text ('OnPremisesSmartHost: ' + $hybridSmartHost)
            Write-ADTNote -Text ('TlsCertificateName: ' + $hybridTlsCert)
            Write-ADTNote -Text ('SendingTransportServers: ' + $hybridSending)
            Write-ADTNote -Text ('ReceivingTransportServers: ' + $hybridReceiving)
        }

        # ------------------------------------------------------------------------------
        # Send connectors
        # ------------------------------------------------------------------------------
        # Verified on Learn: the HCW-created on-premises Send connector is named
        # "Outbound to Microsoft 365" (KB3087172) or "Outbound to Office 365 - <guid>"
        # (Choose Exchange Hybrid Configuration), its AddressSpaces should be "*" or
        # "contoso.mail.onmicrosoft.com;1", and the documented hybrid-style Send connector
        # carries -RequireTLS $true -TlsAuthLevel CertificateValidation with a smart host of
        # the form "<domain>-com.mail.protection.outlook.com".
        $hybridSendConnectorFound = $false
        try {
            $sendConnectors = @(Get-SendConnector -ErrorAction Stop)

            if ($sendConnectors.Count -eq 0) {
                Write-ADTResult -Check 'Send connectors' -Status 'WARN' `
                    -Detail 'No Send connectors exist in this organization.' `
                    -Why 'With no Send connector at all, this Exchange organization cannot deliver mail to any external domain - everything addressed outside the organization lands in the Unreachable queue with "A matching connector cannot be found to route the external recipient".' `
                    -Fix @('Get-SendConnector | Format-List Name,AddressSpaces,SmartHosts,Enabled,RequireTLS,TlsAuthLevel')
            }
            else {
                foreach ($sendConnector in $sendConnectors) {
                    $connectorName = [string](Get-ADTExProp -InputObject $sendConnector -Name 'Name')
                    if ([string]::IsNullOrWhiteSpace($connectorName)) { continue }

                    $addressSpaces = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $sendConnector -Name 'AddressSpaces')
                    $smartHosts = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $sendConnector -Name 'SmartHosts')
                    $requireTlsRaw = Get-ADTExProp -InputObject $sendConnector -Name 'RequireTLS'
                    $tlsAuthLevel = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $sendConnector -Name 'TlsAuthLevel')
                    $tlsCertName = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $sendConnector -Name 'TlsCertificateName')
                    $cloudServicesRaw = Get-ADTExProp -InputObject $sendConnector -Name 'CloudServicesMailEnabled'
                    $enabledRaw = Get-ADTExProp -InputObject $sendConnector -Name 'Enabled'

                    $looksHybrid = (Test-ADTExHybridEndpoint -Text $smartHosts) -or `
                                   (Test-ADTExHybridEndpoint -Text $addressSpaces) -or `
                                   ($connectorName -match '(?i)Outbound to (Office 365|Microsoft 365)')

                    $connectorDetail = 'AddressSpaces=' + $addressSpaces + ' SmartHosts=' + $smartHosts + ' Enabled=' + (ConvertTo-ADTExText -Value $enabledRaw) + ' RequireTLS=' + (ConvertTo-ADTExText -Value $requireTlsRaw) + ' TlsAuthLevel=' + $tlsAuthLevel

                    if (-not $looksHybrid) {
                        Write-ADTResult -Check ('Send connector: ' + $connectorName) -Status 'INFO' -Detail $connectorDetail
                        continue
                    }

                    $hybridSendConnectorFound = $true
                    $tlsFix = @(
                        ('Get-SendConnector -Identity "' + $connectorName + '" | Format-List Name,AddressSpaces,SmartHosts,Enabled,RequireTLS,TlsAuthLevel,TlsCertificateName,CloudServicesMailEnabled,Fqdn'),
                        ('Guidance only - ADT does not run this. The documented hybrid shape is: Set-SendConnector -Identity "' + $connectorName + '" -RequireTLS $true -TlsAuthLevel CertificateValidation -CloudServicesMailEnabled $true'),
                        'Safest route: re-run the Hybrid Configuration wizard and let it rewrite the connector rather than hand-editing it.'
                    )

                    $tlsProblem = @()
                    if ($null -eq $requireTlsRaw -or -not [bool]$requireTlsRaw) { $tlsProblem += 'RequireTLS is not $true' }
                    if ([string]::IsNullOrWhiteSpace($tlsAuthLevel) -or $tlsAuthLevel -match '(?i)^null$') { $tlsProblem += 'TlsAuthLevel is not set' }
                    if ($null -eq $cloudServicesRaw -or -not [bool]$cloudServicesRaw) { $tlsProblem += 'CloudServicesMailEnabled is not $true' }
                    if ($null -ne $enabledRaw -and -not [bool]$enabledRaw) { $tlsProblem += 'the connector is disabled' }

                    if ($tlsProblem.Count -gt 0) {
                        $tlsWhy = 'Send connector "' + $connectorName + '" routes mail to Exchange Online but ' + ($tlsProblem -join ', ') + '. Two consequences follow. Without RequireTLS and TlsAuthLevel, mail to the tenant can fall back to an unauthenticated or plaintext session. Without CloudServicesMailEnabled, Exchange strips the internal organization headers on the way out, so messages from on-premises users arrive in Exchange Online looking external - which is what drives the "internal mail is being marked as external / hitting spam" reports.'
                        Write-ADTResult -Check ('Hybrid Send connector: ' + $connectorName) -Status 'WARN' `
                            -Detail $connectorDetail -Why $tlsWhy -Fix $tlsFix -Data $sendConnector
                    }
                    else {
                        Write-ADTResult -Check ('Hybrid Send connector: ' + $connectorName) -Status 'PASS' `
                            -Detail ($connectorDetail + ' TlsCertificateName=' + $tlsCertName) -Data $sendConnector
                    }
                }
            }
        }
        catch {
            Write-ADTResult -Check 'Send connectors' -Status 'ERROR' `
                -Detail ('Get-SendConnector failed: ' + $_.Exception.Message) `
                -Fix @('Get-SendConnector | Format-List Name,AddressSpaces,SmartHosts,Enabled,RequireTLS,TlsAuthLevel')
        }

        # ------------------------------------------------------------------------------
        # Receive connectors
        # ------------------------------------------------------------------------------
        # Verified on Learn: the HCW targets the receive connector named
        # '<ServerName>\Default Frontend <ServerName>' and sets -TLSCertificateName on it.
        $hybridReceiveConnectorFound = $false
        try {
            $receiveConnectors = @(Get-ReceiveConnector -Server $serverName -ErrorAction Stop)

            $defaultFrontend = @($receiveConnectors | Where-Object { [string]$_.Name -like 'Default Frontend*' })

            if ($defaultFrontend.Count -eq 0) {
                Write-ADTResult -Check 'Default Frontend receive connector' -Status 'WARN' `
                    -Detail ('No receive connector named "Default Frontend*" exists on ' + $serverName + '.') `
                    -Why 'Default Frontend <ServerName> is the connector Exchange creates on TCP 25 to accept anonymous internet mail, and it is the connector the Hybrid Configuration wizard configures for inbound mail from Exchange Online. Its absence means either the connector was deleted (this server cannot receive internet or hybrid mail) or the connectors were renamed - worth confirming which before treating it as a fault.' `
                    -Fix @(('Get-ReceiveConnector -Server ' + $serverName + ' | Format-Table Identity,Bindings,Enabled,AuthMechanism,PermissionGroups -AutoSize'), ('Test-SmtpConnectivity -Identity ' + $serverName))
            }
            else {
                foreach ($frontendConnector in $defaultFrontend) {
                    $fcName = [string](Get-ADTExProp -InputObject $frontendConnector -Name 'Identity')
                    $fcEnabledRaw = Get-ADTExProp -InputObject $frontendConnector -Name 'Enabled'
                    $fcBindings = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $frontendConnector -Name 'Bindings')
                    $fcAuth = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $frontendConnector -Name 'AuthMechanism')
                    $fcTlsCert = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $frontendConnector -Name 'TlsCertificateName')
                    $fcDetail = 'Bindings=' + $fcBindings + ' Enabled=' + (ConvertTo-ADTExText -Value $fcEnabledRaw) + ' AuthMechanism=' + $fcAuth

                    if ($null -ne $fcEnabledRaw -and -not [bool]$fcEnabledRaw) {
                        Write-ADTResult -Check ('Receive connector: ' + $fcName) -Status 'FAIL' -Detail ($fcDetail + ' - DISABLED') `
                            -Why 'The Default Frontend receive connector is disabled, so this server is not listening for inbound SMTP on it. Inbound internet mail and inbound hybrid mail to this server both stop dead.' `
                            -Fix @(('[SERVICE-AFFECTING] Guidance only - ADT does not run this: Set-ReceiveConnector -Identity "' + $fcName + '" -Enabled $true'), ('Test-SmtpConnectivity -Identity ' + $serverName), ('Test-NetConnection ' + $serverName + ' -Port 25'))
                    }
                    else {
                        $fcResultDetail = $fcDetail
                        if (-not [string]::IsNullOrWhiteSpace($fcTlsCert)) { $fcResultDetail = $fcResultDetail + ' TlsCertificateName is set' }
                        Write-ADTResult -Check ('Receive connector: ' + $fcName) -Status 'PASS' -Detail $fcResultDetail
                    }
                }
            }

            foreach ($receiveConnector in $receiveConnectors) {
                $rcName = [string](Get-ADTExProp -InputObject $receiveConnector -Name 'Name')
                if ([string]::IsNullOrWhiteSpace($rcName)) { continue }
                if ($rcName -like 'Default Frontend*') { continue }

                $rcTlsDomains = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $receiveConnector -Name 'TlsDomainCapabilities')
                $looksHybridInbound = ($rcName -match '(?i)Inbound from (Office 365|Microsoft 365)') -or (Test-ADTExHybridEndpoint -Text $rcTlsDomains)

                if (-not $looksHybridInbound) { continue }

                $hybridReceiveConnectorFound = $true
                $rcIdentity = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $receiveConnector -Name 'Identity')
                $rcBindings = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $receiveConnector -Name 'Bindings')
                $rcEnabled = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $receiveConnector -Name 'Enabled')
                Write-ADTResult -Check ('Hybrid inbound receive connector: ' + $rcIdentity) -Status 'INFO' `
                    -Detail ('Bindings=' + $rcBindings + ' Enabled=' + $rcEnabled + ' TlsDomainCapabilities=' + $rcTlsDomains) -Data $receiveConnector
            }
        }
        catch {
            Write-ADTResult -Check 'Receive connectors' -Status 'ERROR' `
                -Detail ('Get-ReceiveConnector failed: ' + $_.Exception.Message) `
                -Fix @(('Get-ReceiveConnector -Server ' + $serverName + ' | Format-Table Identity,Bindings,Enabled,AuthMechanism -AutoSize'))
        }

        # ------------------------------------------------------------------------------
        # Hybrid object present but connectors missing
        # ------------------------------------------------------------------------------
        if ($null -ne $hybridConfig -and -not $hybridSendConnectorFound) {
            $missingWhy = 'A HybridConfiguration object exists, so the Hybrid Configuration wizard has been run against this organization - but ADT found no Send connector routing to Exchange Online (nothing with an office365 / protection.outlook.com / onmicrosoft.com smart host or address space, and nothing named "Outbound to Office 365"). If that connector really is gone, outbound mail from on-premises mailboxes to migrated mailboxes has no hybrid path and will route as ordinary internet mail - losing the internal headers and the mutual TLS the tenant expects.'
            $missingFix = @(
                'Get-SendConnector | Format-List Name,AddressSpaces,SmartHosts,Enabled,RequireTLS,TlsAuthLevel,CloudServicesMailEnabled',
                'Get-HybridConfiguration | Format-List',
                'Re-run the Hybrid Configuration wizard to recreate the connectors: https://learn.microsoft.com/exchange/hybrid-configuration-wizard',
                'Cross-check the tenant side too - the matching Inbound/Outbound connectors live in Exchange Online: Get-OutboundConnector; Get-InboundConnector'
            )
            Write-ADTResult -Check 'Hybrid connector presence' -Status 'WARN' `
                -Detail 'HybridConfiguration exists but no Office 365 Send connector was found on-premises.' -Why $missingWhy -Fix $missingFix
        }
        elseif ($null -ne $hybridConfig -and -not $hybridReceiveConnectorFound) {
            Write-ADTResult -Check 'Hybrid connector presence' -Status 'INFO' `
                -Detail 'HybridConfiguration and an Office 365 Send connector are present; no separate hybrid inbound receive connector was identified.' `
                -Why 'This is not necessarily a fault. The Hybrid Configuration wizard commonly configures the existing "Default Frontend <ServerName>" connector for inbound hybrid mail rather than creating a dedicated one, and that connector was checked above.'
        }

        # ------------------------------------------------------------------------------
        # Autodiscover internal URI
        # ------------------------------------------------------------------------------
        # Verified on Learn: Get-ClientAccessService [[-Identity] <ClientAccessServerIdParameter>]
        # is the Exchange 2013-and-later cmdlet; Get-ClientAccessServer carries the explicit
        # note "In Exchange 2013 or later, use the Get-ClientAccessService cmdlet instead."
        # AutoDiscoverServiceInternalUri is the documented property (Set-ClientAccessServer
        # -AutoDiscoverServiceInternalURI is shown in the CAS configuration article).
        try {
            $casObject = $null
            $usedDeprecated = $false

            if (Get-Command -Name 'Get-ClientAccessService' -ErrorAction SilentlyContinue) {
                $casObject = Get-ClientAccessService -Identity $serverName -ErrorAction Stop
            }
            elseif (Get-Command -Name 'Get-ClientAccessServer' -ErrorAction SilentlyContinue) {
                $casObject = Get-ClientAccessServer -Identity $serverName -ErrorAction Stop
                $usedDeprecated = $true
            }

            if ($usedDeprecated) {
                Write-ADTResult -Check 'Autodiscover cmdlet' -Status 'INFO' `
                    -Detail 'Get-ClientAccessService is not present; fell back to the deprecated Get-ClientAccessServer.' `
                    -Why 'Microsoft Learn states that from Exchange 2013 onwards Get-ClientAccessService replaces Get-ClientAccessServer and that scripts should be updated. Seeing only the old cmdlet means this is an Exchange 2010 server, which has been out of support since October 2020.'
            }

            if ($null -eq $casObject) {
                Write-ADTResult -Check 'Autodiscover internal URI' -Status 'ERROR' `
                    -Detail 'Neither Get-ClientAccessService nor Get-ClientAccessServer is available in this session.' `
                    -Fix @(('Get-ClientAccessService -Identity ' + $serverName + ' | Format-List Name,AutoDiscoverServiceInternalUri,AutoDiscoverSiteScope'))
            }
            else {
                $autoDiscoverUri = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $casObject -Name 'AutoDiscoverServiceInternalUri')
                $siteScope = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $casObject -Name 'AutoDiscoverSiteScope')

                $autoFix = @(
                    ('Get-ClientAccessService -Identity ' + $serverName + ' | Format-List Name,AutoDiscoverServiceInternalUri,AutoDiscoverSiteScope'),
                    ('Guidance only - ADT does not run this: Set-ClientAccessService -Identity ' + $serverName + ' -AutoDiscoverServiceInternalUri https://autodiscover.<yourdomain>/Autodiscover/Autodiscover.xml'),
                    'The host name in that URI must be on the certificate bound to IIS and must resolve internally.',
                    'Compare every server in the org - a single odd SCP is enough to break Outlook for the clients that land on it: Get-ClientAccessService | Format-Table Name,AutoDiscoverServiceInternalUri,AutoDiscoverSiteScope -AutoSize'
                )

                if ([string]::IsNullOrWhiteSpace($autoDiscoverUri)) {
                    Write-ADTResult -Check 'Autodiscover internal URI' -Status 'FAIL' `
                        -Detail 'AutoDiscoverServiceInternalUri is empty.' `
                        -Why 'The Service Connection Point for this server publishes no Autodiscover URI, so domain-joined Outlook clients that find this SCP have nowhere to go for their profile configuration. Outlook falls back to DNS-based discovery, which frequently lands on the wrong endpoint or prompts for credentials.' `
                        -Fix $autoFix -Data $casObject
                }
                else {
                    $uriDetail = $autoDiscoverUri
                    if (-not [string]::IsNullOrWhiteSpace($siteScope)) { $uriDetail = $uriDetail + ' (SiteScope: ' + $siteScope + ')' }

                    $parsedUri = $null
                    try { $parsedUri = [System.Uri]$autoDiscoverUri } catch { $parsedUri = $null }

                    if ($null -eq $parsedUri) {
                        Write-ADTResult -Check 'Autodiscover internal URI' -Status 'WARN' -Detail $uriDetail `
                            -Why 'The stored value is not a parseable URI, so Outlook cannot use it as an endpoint.' -Fix $autoFix -Data $casObject
                    }
                    elseif ($parsedUri.Scheme -ne 'https') {
                        Write-ADTResult -Check 'Autodiscover internal URI' -Status 'FAIL' -Detail $uriDetail `
                            -Why ('The Autodiscover internal URI uses the ' + $parsedUri.Scheme + ' scheme rather than https. Autodiscover carries mailbox and server configuration and, depending on the authentication in use, credentials - it must not travel unencrypted, and modern Outlook builds refuse plain http Autodiscover endpoints outright.') `
                            -Fix $autoFix -Data $casObject
                    }
                    elseif (-not (Test-ADTExHostResolves -HostName $parsedUri.Host)) {
                        Write-ADTResult -Check 'Autodiscover internal URI' -Status 'FAIL' -Detail $uriDetail `
                            -Why ('The host name "' + $parsedUri.Host + '" in the Autodiscover internal URI does not resolve from this server. If internal DNS cannot resolve it here, domain-joined Outlook clients will not resolve it either, and Autodiscover fails for every client that reads this Service Connection Point.') `
                            -Fix @(('Resolve-DnsName ' + $parsedUri.Host), ('nslookup ' + $parsedUri.Host), ('Test-NetConnection ' + $parsedUri.Host + ' -Port 443'), ('Guidance only: Set-ClientAccessService -Identity ' + $serverName + ' -AutoDiscoverServiceInternalUri https://<resolvable-name>/Autodiscover/Autodiscover.xml')) `
                            -Data $casObject
                    }
                    else {
                        Write-ADTResult -Check 'Autodiscover internal URI' -Status 'PASS' -Detail $uriDetail -Data $casObject
                    }
                }
            }
        }
        catch {
            Write-ADTResult -Check 'Autodiscover internal URI' -Status 'ERROR' `
                -Detail ('Client Access service lookup failed: ' + $_.Exception.Message) `
                -Fix @(('Get-ClientAccessService -Identity ' + $serverName + ' | Format-List Name,AutoDiscoverServiceInternalUri'))
        }

        # ------------------------------------------------------------------------------
        # OAuth connectivity: guidance only, deliberately not executed
        # ------------------------------------------------------------------------------
        # Command verified verbatim on Microsoft Learn ("Configure OAuth authentication
        # between Exchange and Exchange Online organizations"). ADT does not run it: it needs
        # a real target mailbox, it takes minutes, and Learn notes that the
        # "The SMTP address has no mailbox associated with it" error is expected noise -
        # exactly the kind of output an automated check would misread.
        $oauthFix = @(
            'On-premises to Exchange Online: Test-OAuthConnectivity -Service EWS -TargetUri https://outlook.office365.com/ews/exchange.asmx -Mailbox <on-premises-mailbox> -Verbose | Format-List',
            'Exchange Online to on-premises (run from Exchange Online PowerShell): Test-OAuthConnectivity -Service EWS -TargetUri https://<your-external-hostname>/metadata/json/1 -Mailbox <cloud-mailbox> -Verbose | Format-List',
            'Look for ResultType: Success at the end of the output. Ignore "The SMTP address has no mailbox associated with it" - Microsoft documents that message as expected.',
            'If the token is rejected, refresh the auth metadata: Set-AuthServer <name> -RefreshAuthMetadata, then wait ~15 minutes or run iisreset /noforce on each Exchange server.',
            'Inspect the auth server config: Get-AuthServer | Format-List Name,IssuerIdentifier,TokenIssuingEndpoint,AuthMetadataUrl,Enabled'
        )
        Write-ADTResult -Check 'OAuth connectivity (hybrid free/busy)' -Status 'INFO' `
            -Detail 'Not executed by ADT - run the commands below by hand when free/busy or cross-premises features are the complaint.' `
            -Why 'Test-OAuthConnectivity needs a real target mailbox and can take several minutes, and Microsoft documents an expected error message inside its output that an automated pass/fail check would misinterpret. It is the right tool for hybrid free/busy failures, but it belongs in the engineer''s hands, not in an unattended sweep.' `
            -Fix $oauthFix

        # ------------------------------------------------------------------------------
        # Entra Connect (ADSync) on this box
        # ------------------------------------------------------------------------------
        # Verified on Learn: the Windows service short name is ADSync ("The Microsoft Entra
        # ID Sync synchronization service (ADSync) runs on a server in your on-premises
        # environment", and the troubleshooting article says to use Services.msc to update
        # the ADSync service account password). Get-ADSyncScheduler takes no parameters and
        # returns AllowedSyncCycleInterval, CurrentlyEffectiveSyncCycleInterval,
        # CustomizedSyncCycleInterval, NextSyncCyclePolicyType, NextSyncCycleStartTimeInUTC,
        # PurgeRunHistoryInterval, SyncCycleEnabled, MaintenanceEnabled (and
        # SchedulerSuspended per Set-ADSyncScheduler). Default interval is 30 minutes.
        # Import-Module ADSync is the documented fix when the cmdlet is not available.
        try {
            $adSyncService = $null
            try { $adSyncService = Get-Service -Name 'ADSync' -ErrorAction Stop } catch { $adSyncService = $null }

            if ($null -eq $adSyncService) {
                # UNVERIFIED: the ADSync display name has changed across releases
                # ("Microsoft Azure AD Sync" / "Microsoft Entra ID Sync"), so a wildcard
                # sweep backs up the short-name lookup rather than being trusted alone.
                $syncPresentByDisplay = Test-ADTServicePresent -DisplayNameLike @('Microsoft Azure AD Sync*', 'Microsoft Entra ID Sync*', '*Azure AD Sync*')
                if ($syncPresentByDisplay) {
                    Write-ADTResult -Check 'Entra Connect (ADSync)' -Status 'WARN' `
                        -Detail 'A directory synchronisation service is installed but could not be opened by its short name "ADSync".' `
                        -Why 'The service was matched only by display name, which means either a non-standard installation or a permissions problem opening the service. Directory sync state cannot be confirmed from here.' `
                        -Fix @('Get-Service | Where-Object { $_.DisplayName -like "*Sync*" } | Format-Table Name,DisplayName,Status,StartType -AutoSize', 'Import-Module ADSync; Get-ADSyncScheduler')
                }
                else {
                    Write-ADTResult -Check 'Entra Connect (ADSync)' -Status 'INFO' `
                        -Detail ('Entra Connect is not installed on ' + $serverName + '.') `
                        -Why 'Entra Connect commonly lives on a separate member server rather than on Exchange, so its absence here is normal. If this organization is hybrid, find the box that does run it before concluding directory sync is missing.'
                }
            }
            else {
                $syncStatus = [string]$adSyncService.Status
                if ($syncStatus -ne 'Running') {
                    Write-ADTResult -Check 'Entra Connect service (ADSync)' -Status 'FAIL' `
                        -Detail ('Status=' + $syncStatus + ' StartType=' + [string]$adSyncService.StartType) `
                        -Why 'The ADSync service is installed on this server but is not running, so no directory synchronisation is happening at all. New and changed on-premises accounts stop reaching Entra ID; in a hybrid organization that also means new mailboxes, group changes and password hash sync all silently stall.' `
                        -Fix @(
                            ('[SERVICE-AFFECTING] Start-Service -Name ADSync'),
                            'Check the service account has not expired or had its password changed - that is the most common cause: Get-CimInstance Win32_Service -Filter "Name=''ADSync''" | Format-List Name,StartName,State,StartMode',
                            'Get-WinEvent -LogName Application -MaxEvents 50 | Where-Object { $_.ProviderName -like "*ADSync*" -or $_.ProviderName -like "*Directory Synchronization*" } | Format-List TimeCreated,Id,Message'
                        )
                }
                else {
                    Write-ADTResult -Check 'Entra Connect service (ADSync)' -Status 'PASS' -Detail ('Status=Running StartType=' + [string]$adSyncService.StartType)

                    $schedulerCmd = Get-Command -Name 'Get-ADSyncScheduler' -ErrorAction SilentlyContinue
                    if ($null -eq $schedulerCmd) {
                        try {
                            Import-Module -Name 'ADSync' -ErrorAction Stop
                            $schedulerCmd = Get-Command -Name 'Get-ADSyncScheduler' -ErrorAction SilentlyContinue
                        }
                        catch {
                            $schedulerCmd = $null
                        }
                    }

                    if ($null -eq $schedulerCmd) {
                        Write-ADTResult -Check 'Entra Connect scheduler' -Status 'SKIP' `
                            -Detail 'The ADSync PowerShell module is not available in this session, so the scheduler state could not be read.' `
                            -Why 'Microsoft documents this exact symptom: "If you see The sync command or cmdlet isn''t available when you run this cmdlet, then the PowerShell module isn''t loaded." It happens on domain controllers and on servers with tightened PowerShell execution settings.' `
                            -Fix @('Import-Module ADSync', 'Get-ADSyncScheduler')
                    }
                    else {
                        $scheduler = $null
                        try { $scheduler = Get-ADSyncScheduler -ErrorAction Stop } catch { $scheduler = $null }

                        if ($null -eq $scheduler) {
                            Write-ADTResult -Check 'Entra Connect scheduler' -Status 'ERROR' `
                                -Detail 'Get-ADSyncScheduler returned nothing.' -Fix @('Get-ADSyncScheduler')
                        }
                        else {
                            $syncEnabledRaw = Get-ADTExProp -InputObject $scheduler -Name 'SyncCycleEnabled'
                            $suspendedRaw = Get-ADTExProp -InputObject $scheduler -Name 'SchedulerSuspended'
                            $effectiveInterval = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $scheduler -Name 'CurrentlyEffectiveSyncCycleInterval')
                            $nextPolicy = ConvertTo-ADTExText -Value (Get-ADTExProp -InputObject $scheduler -Name 'NextSyncCyclePolicyType')
                            $nextStartRaw = Get-ADTExProp -InputObject $scheduler -Name 'NextSyncCycleStartTimeInUTC'
                            $maintenanceRaw = Get-ADTExProp -InputObject $scheduler -Name 'MaintenanceEnabled'

                            $schedulerDetail = 'SyncCycleEnabled=' + (ConvertTo-ADTExText -Value $syncEnabledRaw) + ' Interval=' + $effectiveInterval + ' NextPolicy=' + $nextPolicy + ' MaintenanceEnabled=' + (ConvertTo-ADTExText -Value $maintenanceRaw)

                            $schedulerFix = @(
                                'Get-ADSyncScheduler',
                                'Guidance only - ADT does not run this: Set-ADSyncScheduler -SyncCycleEnabled $true',
                                'Guidance only - ADT does not run this: Start-ADSyncSyncCycle -PolicyType Delta',
                                'Check whether this box is a staging server, in which case a disabled cycle can be intentional.',
                                'Get-WinEvent -LogName Application -MaxEvents 50 | Where-Object { $_.ProviderName -like "*ADSync*" } | Format-List TimeCreated,Id,Message'
                            )

                            if ($null -ne $syncEnabledRaw -and -not [bool]$syncEnabledRaw) {
                                Write-ADTResult -Check 'Entra Connect scheduler' -Status 'WARN' -Detail $schedulerDetail `
                                    -Why 'SyncCycleEnabled is false, so the scheduler is not running import, sync or export at all. This is a legitimate temporary state during troubleshooting or an upgrade, and it is also exactly what gets left behind afterwards - nothing changes in Entra ID until it is turned back on, and there is no error to notice.' `
                                    -Fix $schedulerFix -Data $scheduler
                            }
                            elseif ($null -ne $suspendedRaw -and [bool]$suspendedRaw) {
                                Write-ADTResult -Check 'Entra Connect scheduler' -Status 'WARN' -Detail ($schedulerDetail + ' SchedulerSuspended=True') `
                                    -Why 'The scheduler is suspended. Entra Connect suspends itself while the installation wizard is open and during some upgrades; if no one is actively working on it, it has been left suspended and directory sync is stalled.' `
                                    -Fix $schedulerFix -Data $scheduler
                            }
                            elseif ($null -eq $nextStartRaw) {
                                Write-ADTResult -Check 'Entra Connect scheduler' -Status 'INFO' -Detail $schedulerDetail `
                                    -Why 'The scheduler is enabled but NextSyncCycleStartTimeInUTC could not be read, so ADT cannot judge whether cycles are actually firing.' -Data $scheduler
                            }
                            else {
                                $nextStart = [datetime]$nextStartRaw
                                $utcNow = [datetime]::UtcNow
                                $minutesOverdue = [int]($utcNow - $nextStart).TotalMinutes
                                $nextText = $nextStart.ToString('yyyy-MM-dd HH:mm') + ' UTC'

                                if ($minutesOverdue -gt 120) {
                                    $staleWhy = 'The next sync cycle was scheduled for ' + $nextText + ', which is ' + $minutesOverdue.ToString() + ' minutes ago. The default cycle interval is 30 minutes, so a next-run time more than two hours in the past means cycles have stopped firing - the service is running and the scheduler says it is enabled, but nothing is actually synchronising. Directory changes are silently not reaching Entra ID. Note that ADT infers this from the scheduled next-run time because Get-ADSyncScheduler does not publish a last-successful-sync property; confirm against the run history in Synchronization Service Manager before acting.'
                                    Write-ADTResult -Check 'Entra Connect scheduler' -Status 'WARN' `
                                        -Detail ($schedulerDetail + ' NextSyncCycleStartTimeInUTC=' + $nextText + ' (' + $minutesOverdue.ToString() + ' min overdue)') `
                                        -Why $staleWhy `
                                        -Fix @(
                                            'Get-ADSyncScheduler',
                                            'Open Synchronization Service Manager (miisclient.exe) and check the Operations tab for the last successful run and any errors.',
                                            'Guidance only - ADT does not run this: Start-ADSyncSyncCycle -PolicyType Delta',
                                            'Get-WinEvent -LogName Application -MaxEvents 50 | Where-Object { $_.ProviderName -like "*ADSync*" } | Format-List TimeCreated,Id,Message'
                                        ) -Data $scheduler
                                }
                                else {
                                    Write-ADTResult -Check 'Entra Connect scheduler' -Status 'PASS' `
                                        -Detail ($schedulerDetail + ' NextSyncCycleStartTimeInUTC=' + $nextText) -Data $scheduler
                                }
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-ADTResult -Check 'Entra Connect (ADSync)' -Status 'ERROR' `
                -Detail ('Entra Connect check failed: ' + $_.Exception.Message) `
                -Fix @('Get-Service ADSync | Format-List Name,DisplayName,Status,StartType', 'Import-Module ADSync; Get-ADSyncScheduler')
        }
    }
    catch {
        Write-ADTResult -Check 'Hybrid and Entra Connect' -Status 'ERROR' -Detail ('Unhandled exception: ' + $_.Exception.Message)
    }
}

#endregion

Register-ADTModule -Name 'Exchange' -Group 'ON-PREM' -Items @(
    @{ Label = 'Exchange server health';  Function = 'Invoke-ADTExchangeHealth';   Requires = @('HasExchangeShell'); Snapshot = $true }
    @{ Label = 'Mail flow smoke test';    Function = 'Invoke-ADTExchangeMailFlow'; Requires = @('HasExchangeShell'); Snapshot = $false }
    @{ Label = 'Hybrid and Entra Connect'; Function = 'Invoke-ADTExchangeHybrid';  Requires = @('HasExchangeShell'); Snapshot = $true }
)
