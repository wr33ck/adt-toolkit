# ADT.Citrix.ps1 - CVAD Delivery Controller, VDA, StoreFront and Cloud Connector health checks.
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.
#
# Citrix documentation is thinner than Microsoft's and the SDK reference pages are rendered
# client side, so several object property names could not be read verbatim from a doc page.
# Every property in this file is therefore read through Get-ADTCtxProperty with a candidate
# list and degrades to $null rather than throwing, and anything unconfirmed carries an
# # UNVERIFIED comment on the line. A missing snap-in, service or cmdlet always produces a
# SKIP with the reason, never a crash.

#region Private helpers

function Get-ADTCtxProperty {
    <#
        .SYNOPSIS
            Read the first present, non-null property from a candidate name list. Never throws.
        .DESCRIPTION
            Citrix SDK objects vary between CVAD versions and between the on-premises snap-ins
            and the Remote PowerShell SDK. Asking for several candidate names and degrading to
            $null keeps one renamed property from taking down a whole check.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string[]]$Name
    )

    if ($null -eq $InputObject) { return $null }

    foreach ($candidate in $Name) {
        try {
            $property = $InputObject.PSObject.Properties[$candidate]
            if ($null -ne $property -and $null -ne $property.Value) { return $property.Value }
        }
        catch {
            $null = $_
        }
    }

    return $null
}

function Format-ADTCtxList {
    <#
        .SYNOPSIS
            Join a list into a readable comma-separated string, with a fallback for empty input.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Items,

        [Parameter(Mandatory = $false)]
        [string]$EmptyText = 'none'
    )

    if ($null -eq $Items) { return $EmptyText }

    $strings = @()
    foreach ($item in $Items) {
        if ($null -eq $item) { continue }
        $text = ([string]$item).Trim()
        if ([string]::IsNullOrEmpty($text)) { continue }
        $strings += $text
    }

    if ($strings.Count -eq 0) { return $EmptyText }
    return ($strings -join ', ')
}

function ConvertTo-ADTCtxArray {
    <#
        .SYNOPSIS
            Turn a possibly-null scalar or collection into a real array. Never throws.
        .DESCRIPTION
            @($null) produces a one-element array containing $null, which silently breaks
            every ".Count -gt 0" test downstream. This returns a genuinely empty array instead.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) { return @() }

    $output = @()
    try {
        foreach ($item in @($InputObject)) {
            if ($null -eq $item) { continue }
            $output += $item
        }
    }
    catch {
        return @()
    }

    return $output
}

function Format-ADTCtxMessage {
    <#
        .SYNOPSIS
            Flatten an event message onto one line and cap its length for console output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter(Mandatory = $false)]
        [int]$MaxLength = 220
    )

    if ([string]::IsNullOrEmpty($Text)) { return '(no message text)' }

    try {
        $flat = ($Text -replace '\s+', ' ').Trim()
        if ($flat.Length -gt $MaxLength) {
            $flat = $flat.Substring(0, $MaxLength) + '...'
        }
        return $flat
    }
    catch {
        return '(message could not be read)'
    }
}

function Get-ADTCtxService {
    <#
        .SYNOPSIS
            Service inventory (Name, DisplayName, State, StartMode) filtered by wildcard. Never throws.
        .DESCRIPTION
            Win32_Service is used rather than Get-Service because it exposes StartMode on every
            supported build. ServiceController.StartType only exists from .NET Framework 4.6.1,
            which a Server 2012 R2 box running Windows PowerShell 5.1 may not have. Get-Service
            is kept as a last-resort fallback with StartMode reported as Unknown.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$NameLike = @(),

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$DisplayNameLike = @()
    )

    $records = @()
    $raw = @()

    try {
        $raw = @(Get-CimInstance -ClassName 'Win32_Service' -ErrorAction Stop)
    }
    catch {
        try {
            $raw = @(Get-WmiObject -Class 'Win32_Service' -ErrorAction Stop)
        }
        catch {
            $raw = @()
        }
    }

    if ($raw.Count -gt 0) {
        foreach ($service in $raw) {
            $records += [PSCustomObject]@{
                Name        = [string]$service.Name
                DisplayName = [string]$service.DisplayName
                State       = [string]$service.State
                StartMode   = [string]$service.StartMode
            }
        }
    }
    else {
        $fallback = @()
        try {
            $fallback = @(Get-Service -ErrorAction SilentlyContinue)
        }
        catch {
            $fallback = @()
        }
        foreach ($service in $fallback) {
            $records += [PSCustomObject]@{
                Name        = [string]$service.Name
                DisplayName = [string]$service.DisplayName
                State       = [string]$service.Status
                StartMode   = 'Unknown'
            }
        }
    }

    if ($NameLike.Count -eq 0 -and $DisplayNameLike.Count -eq 0) { return $records }

    $matched = @()
    foreach ($record in $records) {
        $isMatch = $false
        foreach ($pattern in $NameLike) {
            if ([string]::IsNullOrEmpty($pattern)) { continue }
            if ($record.Name -like $pattern) { $isMatch = $true }
        }
        foreach ($pattern in $DisplayNameLike) {
            if ([string]::IsNullOrEmpty($pattern)) { continue }
            if ($record.DisplayName -like $pattern) { $isMatch = $true }
        }
        if ($isMatch) { $matched += $record }
    }

    return $matched
}

function Write-ADTCtxServiceSet {
    <#
        .SYNOPSIS
            Report one named set of Citrix services: running count, and stopped automatic
            services as a FAIL naming each. Returns nothing to the pipeline.
        .DESCRIPTION
            Only services whose StartMode is Auto are treated as a failure when stopped. Several
            Citrix services ship set to Manual or Disabled by design (diagnostics and telemetry
            helpers), and failing those would bury the real finding under noise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Check,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Service,

        [Parameter(Mandatory = $true)]
        [string]$RoleName
    )

    # The @() wrapper matters: a function returning a one-element array unrolls it to a scalar,
    # and returning @() yields $null. Wrapping restores a real array in both cases.
    $services = @(ConvertTo-ADTCtxArray -InputObject $Service)

    if ($services.Count -eq 0) {
        Write-ADTResult -Check $Check -Status SKIP `
            -Detail ('No matching services were found on this machine for the ' + $RoleName + ' role.')
        return
    }

    $running = @()
    $stoppedAuto = @()
    $stoppedOther = @()

    foreach ($service in $services) {
        if ($service.State -eq 'Running') {
            $running += $service.DisplayName
            continue
        }
        if ($service.StartMode -eq 'Auto') {
            $stoppedAuto += ($service.DisplayName + ' [' + $service.Name + ']')
        }
        else {
            $stoppedOther += ($service.DisplayName + ' (StartMode ' + $service.StartMode + ')')
        }
    }

    $summary = [string]$running.Count + ' of ' + [string]$services.Count + ' running'

    if ($stoppedAuto.Count -gt 0) {
        $failWhy = 'These services are set to start automatically but are not running, so part of the ' + $RoleName + ' role is offline on this machine. An automatic service that is stopped either failed to start at boot or was stopped by hand and never restarted.'
        $failFix = @()
        foreach ($stopped in $stoppedAuto) {
            $shortName = $stopped
            $bracket = $stopped.IndexOf('[')
            if ($bracket -ge 0) {
                $shortName = $stopped.Substring($bracket + 1).TrimEnd(']')
            }
            $failFix += ('Start-Service -Name ' + $shortName)
        }
        $failFix += 'Get-WinEvent -FilterHashtable @{LogName="System";Id=7000,7009,7024;StartTime=(Get-Date).AddDays(-2)} | Select-Object -First 20 TimeCreated,Id,Message'
        Write-ADTResult -Check $Check -Status FAIL `
            -Detail ($summary + '. Stopped automatic service(s): ' + (Format-ADTCtxList -Items $stoppedAuto) + '.') `
            -Why $failWhy -Fix $failFix -Data $services
        return
    }

    if ($stoppedOther.Count -gt 0) {
        Write-ADTResult -Check $Check -Status PASS `
            -Detail ($summary + '. Not running, but not set to start automatically: ' + (Format-ADTCtxList -Items $stoppedOther) + '.') `
            -Data $services
        return
    }

    Write-ADTResult -Check $Check -Status PASS -Detail ($summary + '.') -Data $services
}

function Get-ADTCtxEvent {
    <#
        .SYNOPSIS
            Defensive Get-WinEvent -FilterHashtable wrapper with provider discovery. Never throws.
        .DESCRIPTION
            Get-WinEvent raises an error both when a provider does not exist and when a valid
            query simply matches nothing, so the provider is probed with -ListProvider first
            (which accepts wildcards, per Microsoft Learn) and an absent provider is reported as
            ProviderMissing so the caller can skip silently. The FilterHashtable ProviderName key
            accepts wildcard characters, which is documented in "Creating Get-WinEvent queries
            with FilterHashtable" on Microsoft Learn.
        .OUTPUTS
            PSCustomObject: ProviderMissing (bool), Events (array), ErrorMessage (string).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName,

        [Parameter(Mandatory = $true)]
        [string]$ProviderPattern,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [int[]]$Id,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [int[]]$Level,

        [Parameter(Mandatory = $false)]
        [int]$MaxEvents = 400
    )

    $outcome = [PSCustomObject]@{
        ProviderMissing = $false
        Events          = @()
        ErrorMessage    = ''
    }

    try {
        $providers = @(Get-WinEvent -ListProvider $ProviderPattern -ErrorAction SilentlyContinue)
        if ($providers.Count -eq 0) {
            $outcome.ProviderMissing = $true
            return $outcome
        }
    }
    catch {
        $outcome.ProviderMissing = $true
        return $outcome
    }

    try {
        $filter = @{
            LogName      = $LogName
            ProviderName = $ProviderPattern
            StartTime    = $StartTime
        }
        # Windows event Level values: 1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose.
        if ($null -ne $Level -and $Level.Count -gt 0) { $filter['Level'] = $Level }
        if ($null -ne $Id -and $Id.Count -gt 0) { $filter['Id'] = $Id }

        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
        $outcome.Events = $events
    }
    catch {
        # A zero-match FilterHashtable query and a genuinely failed query both land here. The
        # message is kept so a caller can mention it, but neither case is allowed to be fatal.
        $outcome.Events = @()
        $outcome.ErrorMessage = $_.Exception.Message
    }

    return $outcome
}

function Get-ADTCtxRegistryValue {
    <#
        .SYNOPSIS
            Read one registry value, returning $null if the key or value is absent. Never throws.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        if ($null -eq $item) { return $null }
        $property = $item.PSObject.Properties[$Name]
        if ($null -eq $property) { return $null }
        return $property.Value
    }
    catch {
        return $null
    }
}

function Import-ADTCtxBrokerSdk {
    <#
        .SYNOPSIS
            Make the Citrix Broker admin cmdlets available in this session. Never throws.
        .DESCRIPTION
            Citrix documents loading the snap-in with Add-PSSnapin (CTX222326, CTX139335 both use
            "Add-PSSnapin Citrix.Broker.Admin.V2"); V1/V2 is the snap-in generation, and every
            XenDesktop 7 and CVAD release uses V2. Newer Remote PowerShell SDK builds ship modules
            instead of snap-ins, so a module import is attempted as a fallback.
            Loading a snap-in changes only this PowerShell session, not the target environment.
        .OUTPUTS
            PSCustomObject: Loaded (bool), Method (string), ErrorMessage (string).
    #>
    [CmdletBinding()]
    param()

    $outcome = [PSCustomObject]@{
        Loaded       = $false
        Method       = ''
        ErrorMessage = ''
    }

    try {
        $already = Get-Command -Name 'Get-BrokerSite' -ErrorAction SilentlyContinue
        if ($null -ne $already) {
            $outcome.Loaded = $true
            $outcome.Method = 'already available in this session'
            return $outcome
        }
    }
    catch {
        $null = $_
    }

    $failures = @()

    $addSnapin = $null
    try {
        $addSnapin = Get-Command -Name 'Add-PSSnapin' -ErrorAction SilentlyContinue
    }
    catch {
        $addSnapin = $null
    }

    if ($null -ne $addSnapin) {
        # Citrix.Broker.Admin.V2 is the documented snap-in name for XenDesktop 7 and every
        # Citrix Virtual Apps and Desktops release. V1 is tried only for very old sites.
        foreach ($snapinName in @('Citrix.Broker.Admin.V2', 'Citrix.Broker.Admin.V1')) {
            try {
                $null = Add-PSSnapin -Name $snapinName -ErrorAction Stop
                $confirm = Get-Command -Name 'Get-BrokerSite' -ErrorAction SilentlyContinue
                if ($null -ne $confirm) {
                    $outcome.Loaded = $true
                    $outcome.Method = 'Add-PSSnapin ' + $snapinName
                    return $outcome
                }
            }
            catch {
                $failures += ($snapinName + ': ' + $_.Exception.Message)
            }
        }
    }
    else {
        $failures += 'Add-PSSnapin is not available (PowerShell 6+ removed snap-in support).'
    }

    # UNVERIFIED: Citrix does not publish the module names shipped by the Remote PowerShell SDK.
    # Citrix.Broker.Admin.V2 is used because ADT.Common.ps1 already uses it as the SDK marker.
    foreach ($moduleName in @('Citrix.Broker.Admin.V2', 'Citrix.Broker.Admin.*')) {
        try {
            Import-Module -Name $moduleName -ErrorAction Stop
            $confirm = Get-Command -Name 'Get-BrokerSite' -ErrorAction SilentlyContinue
            if ($null -ne $confirm) {
                $outcome.Loaded = $true
                $outcome.Method = 'Import-Module ' + $moduleName
                return $outcome
            }
        }
        catch {
            $failures += ($moduleName + ': ' + $_.Exception.Message)
        }
    }

    $outcome.ErrorMessage = ($failures -join ' | ')
    return $outcome
}

function Test-ADTCtxCommand {
    <#
        .SYNOPSIS
            Is a cmdlet or function available in this session? Never throws.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {
        $found = Get-Command -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $found) { return $true }
    }
    catch {
        return $false
    }
    return $false
}

function Write-ADTCtxCitrixErrorEvents {
    <#
        .SYNOPSIS
            Report Citrix* Error events in the Application log for the last 24 hours.
            Returns nothing to the pipeline.
        .DESCRIPTION
            Shared by the Delivery Controller and Cloud Connector items. An absent Citrix event
            provider is a silent skip, because a machine can legitimately carry the role without
            ever having written a Citrix event.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Check
    )

    try {
        $since = (Get-Date).AddHours(-24)
        $query = Get-ADTCtxEvent -LogName 'Application' -ProviderPattern 'Citrix*' -StartTime $since -Level @(2) -MaxEvents 400

        if ($query.ProviderMissing) {
            return
        }

        $events = @(ConvertTo-ADTCtxArray -InputObject $query.Events)

        if ($events.Count -eq 0) {
            $detail = 'No Citrix Error events in the Application log in the last 24 hours.'
            if (-not [string]::IsNullOrEmpty($query.ErrorMessage)) {
                $detail = $detail + ' (Query note: ' + $query.ErrorMessage + ')'
            }
            Write-ADTResult -Check $Check -Status PASS -Detail $detail
            return
        }

        $newest = $events | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1
        $newestTime = ''
        $newestSource = ''
        $newestId = ''
        try { $newestTime = $newest.TimeCreated.ToString('yyyy-MM-dd HH:mm') } catch { $newestTime = 'unknown time' }
        try { $newestSource = [string]$newest.ProviderName } catch { $newestSource = 'unknown provider' }
        try { $newestId = [string]$newest.Id } catch { $newestId = '?' }

        $bySource = @{}
        foreach ($record in $events) {
            $sourceName = 'unknown'
            try { $sourceName = [string]$record.ProviderName } catch { $sourceName = 'unknown' }
            if ($bySource.ContainsKey($sourceName)) {
                $bySource[$sourceName] = $bySource[$sourceName] + 1
            }
            else {
                $bySource[$sourceName] = 1
            }
        }

        foreach ($sourceName in ($bySource.Keys | Sort-Object)) {
            Write-ADTNote -Text ($sourceName + ': ' + [string]$bySource[$sourceName] + ' error(s)')
        }

        $why = [string]$events.Count + ' Citrix Error event(s) were logged in the Application log in the last 24 hours. Newest: ' + $newestTime + ', source ' + $newestSource + ', event ID ' + $newestId + ' -- ' + (Format-ADTCtxMessage -Text ([string]$newest.Message))
        $fix = @(
            'Get-WinEvent -FilterHashtable @{LogName="Application";ProviderName="Citrix*";Level=2;StartTime=(Get-Date).AddHours(-24)} | Select-Object TimeCreated,ProviderName,Id,Message | Format-List',
            ('Get-WinEvent -FilterHashtable @{LogName="Application";ProviderName="' + $newestSource + '";StartTime=(Get-Date).AddHours(-24)} | Select-Object -First 20 TimeCreated,Id,Message')
        )
        Write-ADTResult -Check $Check -Status WARN `
            -Detail ([string]$events.Count + ' Citrix Error event(s) in the last 24 hours; newest ' + $newestTime + ' from ' + $newestSource + ' (ID ' + $newestId + ').') `
            -Why $why -Fix $fix -Data $events
    }
    catch {
        Write-ADTResult -Check $Check -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Item 1: Delivery Controller health

function Invoke-ADTCitrixDDC {
    <#
        .SYNOPSIS
            Delivery Controller health: SDK load, Citrix services, site and licensing, database
            connection, controller states, VDA registration summary and recent broker errors.
        .DESCRIPTION
            Runs on Requires=@('CitrixDDC'), so the Citrix Broker Service is known to be installed
            on this machine. Every sub-check guards its own exceptions; a missing snap-in or
            cmdlet degrades to SKIP with the reason rather than stopping the item.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Citrix Delivery Controller Health'

        # ---- Citrix service set on this box -------------------------------------------------
        # Enumerated by wildcard rather than a hard-coded list: the Citrix service set differs
        # between CVAD versions and by which components were installed on the controller.
        $citrixServices = @()
        try {
            $citrixServices = @(Get-ADTCtxService -DisplayNameLike @('Citrix*') -NameLike @('Citrix*'))
            Write-ADTCtxServiceSet -Check 'Citrix services (Delivery Controller)' -Service $citrixServices -RoleName 'Delivery Controller'
        }
        catch {
            Write-ADTResult -Check 'Citrix services (Delivery Controller)' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- PowerShell SDK ------------------------------------------------------------------
        if (-not $script:ADTCaps['HasCitrixSnapin']) {
            $sdkWhy = 'No Citrix PowerShell snap-in or module is registered on this machine, so none of the Get-Broker* cmdlets exist. The Citrix Broker Service is installed here, so this box is a Delivery Controller with the admin SDK missing (a Studio-less controller build), which is supported but leaves nothing for ADT to query.'
            $sdkFix = @(
                'Install Citrix Studio on this controller (the CVAD installer, Studio component) - it registers the Citrix.Broker.Admin.V2 snap-in.',
                'Or install the Citrix Remote PowerShell SDK from the CVAD ISO under x64\Citrix Desktop Delivery Controller, then re-run ADT.',
                'Verify afterwards: Get-PSSnapin -Registered -Name Citrix.*'
            )
            Write-ADTResult -Check 'Citrix Broker SDK' -Status SKIP `
                -Detail 'No Citrix PowerShell snap-in or module is registered on this machine.' -Why $sdkWhy -Fix $sdkFix
            Write-ADTCtxCitrixErrorEvents -Check 'Citrix errors (Application log, 24h)'
            return
        }

        $sdk = Import-ADTCtxBrokerSdk

        if (-not $sdk.Loaded) {
            $loadWhy = 'A Citrix snap-in or module is registered but the Broker admin cmdlets could not be loaded into this session, so Get-BrokerSite and the rest are unavailable. Loader errors: ' + $sdk.ErrorMessage
            $loadFix = @(
                'Add-PSSnapin Citrix.Broker.Admin.V2',
                'Get-PSSnapin -Registered -Name Citrix.*',
                'Run ADT from Windows PowerShell 5.1, not PowerShell 7 - snap-ins do not load on PowerShell 6 or later.',
                'Run ADT from an elevated session; the Citrix SDK requires local administrator rights on the controller.'
            )
            Write-ADTResult -Check 'Citrix Broker SDK' -Status FAIL `
                -Detail 'Citrix Broker admin cmdlets could not be loaded.' -Why $loadWhy -Fix $loadFix
            Write-ADTCtxCitrixErrorEvents -Check 'Citrix errors (Application log, 24h)'
            return
        }

        Write-ADTResult -Check 'Citrix Broker SDK' -Status PASS -Detail ('Broker admin cmdlets loaded (' + $sdk.Method + ').')

        # ---- Broker service status -----------------------------------------------------------
        # Get-BrokerServiceStatus "returns an object containing the status of the Broker Service
        # together with extra diagnostics information" (Citrix CVAD SDK). Read-only.
        if (Test-ADTCtxCommand -Name 'Get-BrokerServiceStatus') {
            try {
                $serviceStatus = Get-BrokerServiceStatus -ErrorAction Stop
                # UNVERIFIED: the exact property names on the returned status object are not
                # listed on a readable Citrix doc page; several candidates are tried.
                $statusText = [string](Get-ADTCtxProperty -InputObject $serviceStatus -Name @('ServiceStatus', 'Status', 'State'))
                $extraInfo = [string](Get-ADTCtxProperty -InputObject $serviceStatus -Name @('ExtraInfo', 'ExtraInformation', 'Details'))

                if ([string]::IsNullOrEmpty($statusText)) {
                    $statusText = ([string]$serviceStatus).Trim()
                }

                if ($statusText -eq 'OK') {
                    Write-ADTResult -Check 'Broker service status' -Status PASS -Detail 'Get-BrokerServiceStatus reports OK.' -Data $serviceStatus
                }
                elseif ([string]::IsNullOrEmpty($statusText)) {
                    Write-ADTResult -Check 'Broker service status' -Status INFO -Detail 'Get-BrokerServiceStatus returned an object ADT could not interpret.' -Data $serviceStatus
                }
                else {
                    $statusWhy = 'The Broker Service reports status "' + $statusText + '" rather than OK. Anything other than OK means the Broker cannot fully service brokering requests - the most common causes are a database that is unreachable, unconfigured, or at the wrong schema version. ' + $extraInfo
                    $statusFix = @(
                        'Get-BrokerServiceStatus | Format-List *',
                        'Get-BrokerDBConnection',
                        'Get-BrokerController | Format-List DNSName,State,LastActivityTime'
                    )
                    Write-ADTResult -Check 'Broker service status' -Status FAIL `
                        -Detail ('Get-BrokerServiceStatus reports ' + $statusText + '.') -Why $statusWhy -Fix $statusFix -Data $serviceStatus
                }
            }
            catch {
                Write-ADTResult -Check 'Broker service status' -Status ERROR -Detail $_.Exception.Message
            }
        }

        # ---- Site and licensing ---------------------------------------------------------------
        # Get-BrokerSite returns the single broker site object. LicensingGracePeriodActive
        # (Boolean?), LicensingGraceHoursLeft (Int32?) and LicenseServerName (String) are
        # documented properties of that object in the Citrix CVAD / DaaS SDK reference.
        $site = $null
        try {
            $site = Get-BrokerSite -ErrorAction Stop
        }
        catch {
            $siteWhy = 'Get-BrokerSite is the cheapest possible call against the Broker Service. If it fails, either the Broker Service is not running on this controller or the caller has no Citrix administrator rights in the site.'
            $siteFix = @(
                'Get-Service -Name CitrixBrokerService',
                'Get-BrokerSite -AdminAddress localhost',
                'Confirm the signed-in account holds a Citrix Studio administrator role: Get-AdminAdministrator'
            )
            Write-ADTResult -Check 'Citrix site' -Status FAIL -Detail ('Get-BrokerSite failed: ' + $_.Exception.Message) -Why $siteWhy -Fix $siteFix
        }

        if ($null -ne $site) {
            # UNVERIFIED: the site display-name property is read as Name with SiteName as a
            # fallback; the Citrix SDK page does not render its property list for verification.
            $siteName = [string](Get-ADTCtxProperty -InputObject $site -Name @('Name', 'SiteName'))
            if ([string]::IsNullOrEmpty($siteName)) { $siteName = '(unnamed)' }

            $licenseServer = [string](Get-ADTCtxProperty -InputObject $site -Name @('LicenseServerName'))
            # UNVERIFIED: LicenseServerPort as a Get-BrokerSite property name. The Citrix License
            # Server default port 27000 IS documented (docs.citrix.com Licensing, "Settings"),
            # and is used when the property is absent.
            $licensePortValue = Get-ADTCtxProperty -InputObject $site -Name @('LicenseServerPort')
            $licensePort = 27000
            try {
                if ($null -ne $licensePortValue) { $licensePort = [int]$licensePortValue }
            }
            catch {
                $licensePort = 27000
            }
            if ($licensePort -le 0) { $licensePort = 27000 }

            $siteDetail = 'Site "' + $siteName + '"'
            if (-not [string]::IsNullOrEmpty($licenseServer)) {
                $siteDetail = $siteDetail + ', license server ' + $licenseServer + ':' + [string]$licensePort
            }
            Write-ADTResult -Check 'Citrix site' -Status INFO -Detail ($siteDetail + '.') -Data $site

            # Licensing grace period.
            $graceActive = $false
            try {
                $graceValue = Get-ADTCtxProperty -InputObject $site -Name @('LicensingGracePeriodActive')
                if ($null -ne $graceValue) { $graceActive = [bool]$graceValue }
            }
            catch {
                $graceActive = $false
            }

            $graceHours = Get-ADTCtxProperty -InputObject $site -Name @('LicensingGraceHoursLeft')
            $graceHoursText = 'unknown'
            if ($null -ne $graceHours) { $graceHoursText = [string]$graceHours }

            if ($graceActive) {
                $graceWhy = 'The site is running inside the licensing grace period, which means the Broker Service cannot currently reach or check out from the License Server. Sessions keep brokering until the grace hours run out (' + $graceHoursText + ' left at the time of this check) and then new connections are refused site-wide. The usual causes are the License Server being down, its Citrix Licensing service stopped, a firewall closing TCP ' + [string]$licensePort + ', or the licence file having expired.'
                $graceFix = @(
                    'Get-BrokerSite | Format-List Name,LicenseServerName,LicenseServerPort,LicensingGracePeriodActive,LicensingGraceHoursLeft,LicensedSessionsActive'
                )
                if (-not [string]::IsNullOrEmpty($licenseServer)) {
                    $graceFix += ('Test-NetConnection -ComputerName ' + $licenseServer + ' -Port ' + [string]$licensePort)
                    $graceFix += ('Open the Citrix Licensing Manager at https://' + $licenseServer + ':8083 and confirm the licences are present and not expired.')
                    $graceFix += ('On ' + $licenseServer + ': Get-Service -Name "Citrix Licensing" and confirm the Citrix vendor daemon is listening on TCP 7279.')
                }
                $graceFix += '[SERVICE-AFFECTING] After the License Server is reachable again, re-establish the connection from a controller: Reset-BrokerLicensingConnection'
                Write-ADTResult -Check 'Citrix licensing' -Status WARN `
                    -Detail ('Licensing grace period is ACTIVE; ' + $graceHoursText + ' grace hour(s) left.') -Why $graceWhy -Fix $graceFix -Data $site
            }
            else {
                Write-ADTResult -Check 'Citrix licensing' -Status PASS -Detail 'Licensing grace period is not active.'
            }

            # License server reachability.
            if ([string]::IsNullOrEmpty($licenseServer)) {
                Write-ADTResult -Check 'License server reachability' -Status SKIP `
                    -Detail 'Get-BrokerSite did not return a LicenseServerName to test.'
            }
            else {
                try {
                    $licenseOpen = Test-ADTPort -ComputerName $licenseServer -Port $licensePort -TimeoutMs 4000
                    if ($licenseOpen) {
                        Write-ADTResult -Check 'License server reachability' -Status PASS `
                            -Detail ('TCP ' + [string]$licensePort + ' is open on ' + $licenseServer + '.')
                    }
                    else {
                        $licWhy = 'TCP ' + [string]$licensePort + ' is the Citrix License Server (License Server Manager) port. With it closed, this controller cannot check out licences; the site drops into the licensing grace period and, when that expires, refuses new connections site-wide.'
                        $licFix = @(
                            ('Test-NetConnection -ComputerName ' + $licenseServer + ' -Port ' + [string]$licensePort),
                            ('On ' + $licenseServer + ': Get-Service -Name "Citrix Licensing"; the vendor daemon also needs TCP 7279 and the Citrix Licensing Manager web service TCP 8083.'),
                            ('Confirm no firewall between this controller and ' + $licenseServer + ' blocks TCP ' + [string]$licensePort + '.')
                        )
                        Write-ADTResult -Check 'License server reachability' -Status FAIL `
                            -Detail ('TCP ' + [string]$licensePort + ' is NOT reachable on ' + $licenseServer + '.') -Why $licWhy -Fix $licFix
                    }
                }
                catch {
                    Write-ADTResult -Check 'License server reachability' -Status ERROR -Detail $_.Exception.Message
                }
            }
        }

        # ---- Site database ----------------------------------------------------------------------
        # Get-BrokerDBConnection returns the Broker Service database connection string, for example
        # "Server=serverName\SQLEXPRESS;Initial Catalog=databaseName;Integrated Security=True".
        # Only the parsed server and catalog are recorded, never the whole string.
        try {
            $connectionString = ''
            try {
                $connectionRaw = Get-BrokerDBConnection -ErrorAction Stop
                $connectionString = ([string]$connectionRaw).Trim()
            }
            catch {
                $connectionString = ''
                Write-ADTResult -Check 'Site database connection' -Status ERROR -Detail ('Get-BrokerDBConnection failed: ' + $_.Exception.Message)
            }

            if (-not [string]::IsNullOrEmpty($connectionString)) {
                $serverToken = ''
                $catalog = ''
                try {
                    $serverMatch = [regex]::Match($connectionString, '(?i)(?:^|;)\s*(?:Server|Data Source|Address|Addr|Network Address)\s*=\s*([^;]+)')
                    if ($serverMatch.Success) { $serverToken = $serverMatch.Groups[1].Value.Trim() }
                    $catalogMatch = [regex]::Match($connectionString, '(?i)(?:^|;)\s*(?:Initial Catalog|Database)\s*=\s*([^;]+)')
                    if ($catalogMatch.Success) { $catalog = $catalogMatch.Groups[1].Value.Trim() }
                }
                catch {
                    $serverToken = ''
                }

                if ([string]::IsNullOrEmpty($serverToken)) {
                    Write-ADTResult -Check 'Site database connection' -Status INFO `
                        -Detail 'A connection string is configured but ADT could not parse a server name out of it.'
                }
                else {
                    # Strip the tcp: prefix, then split an explicit ",port" and a "\instance" name.
                    $hostText = $serverToken
                    if ($hostText.ToLower().StartsWith('tcp:')) { $hostText = $hostText.Substring(4) }

                    $sqlPort = 1433
                    $portExplicit = $false
                    if ($hostText.Contains(',')) {
                        $parts = $hostText.Split(',')
                        $hostText = $parts[0].Trim()
                        try {
                            $sqlPort = [int]($parts[1].Trim())
                            $portExplicit = $true
                        }
                        catch {
                            $sqlPort = 1433
                        }
                    }

                    $instanceName = ''
                    if ($hostText.Contains('\')) {
                        $parts = $hostText.Split('\')
                        $hostText = $parts[0].Trim()
                        $instanceName = $parts[1].Trim()
                    }

                    $dbData = [PSCustomObject]@{
                        Server   = $hostText
                        Instance = $instanceName
                        Port     = $sqlPort
                        Catalog  = $catalog
                    }

                    $dbDetail = 'Server ' + $hostText
                    if (-not [string]::IsNullOrEmpty($instanceName)) { $dbDetail = $dbDetail + '\' + $instanceName }
                    if (-not [string]::IsNullOrEmpty($catalog)) { $dbDetail = $dbDetail + ', catalog ' + $catalog }
                    Write-ADTResult -Check 'Site database connection' -Status INFO -Detail ($dbDetail + '.') -Data $dbData

                    $dbOpen = $false
                    try {
                        $dbOpen = Test-ADTPort -ComputerName $hostText -Port $sqlPort -TimeoutMs 4000
                    }
                    catch {
                        $dbOpen = $false
                    }

                    if ($dbOpen) {
                        Write-ADTResult -Check 'Site database reachability' -Status PASS `
                            -Detail ('TCP ' + [string]$sqlPort + ' is open on ' + $hostText + '.')
                    }
                    elseif ((-not [string]::IsNullOrEmpty($instanceName)) -and (-not $portExplicit)) {
                        # A named instance usually listens on a dynamic port negotiated through the
                        # SQL Server Browser on UDP 1434, so a closed 1433 is not proof of a fault.
                        $namedWhy = 'The connection string names the SQL instance "' + $instanceName + '" without an explicit port, so this instance most likely listens on a dynamic port resolved through the SQL Server Browser (UDP 1434) rather than on TCP 1433. A closed 1433 is therefore inconclusive here, not proof of a broken database path.'
                        $namedFix = @(
                            ('Test-NetConnection -ComputerName ' + $hostText + ' -Port 1433'),
                            ('On ' + $hostText + ': confirm the SQL Server Browser service is running, or read the instance port from SQL Server Configuration Manager > Protocols for ' + $instanceName + ' > TCP/IP > IP Addresses > TCP Dynamic Ports.'),
                            'Get-BrokerServiceStatus   (OK proves the Broker itself can still reach the database)'
                        )
                        Write-ADTResult -Check 'Site database reachability' -Status WARN `
                            -Detail ('TCP ' + [string]$sqlPort + ' is not answering on ' + $hostText + ', but the instance uses a named instance so the port may be dynamic.') `
                            -Why $namedWhy -Fix $namedFix
                    }
                    else {
                        $dbWhy = 'The site database holds all site configuration and brokering state. With TCP ' + [string]$sqlPort + ' closed on ' + $hostText + ', the Broker Service falls back to Local Host Cache if it is enabled, and the site becomes read-only until the database returns; without Local Host Cache, brokering stops.'
                        $dbFix = @(
                            ('Test-NetConnection -ComputerName ' + $hostText + ' -Port ' + [string]$sqlPort),
                            ('On ' + $hostText + ': Get-Service -Name MSSQLSERVER   (or MSSQL$' + $instanceName + ' for a named instance)'),
                            'Get-BrokerServiceStatus',
                            'Get-BrokerDBConnection'
                        )
                        Write-ADTResult -Check 'Site database reachability' -Status FAIL `
                            -Detail ('TCP ' + [string]$sqlPort + ' is NOT reachable on ' + $hostText + '.') -Why $dbWhy -Fix $dbFix
                    }

                    # Test-BrokerDBConnection is documented by Citrix as reporting what the status
                    # WOULD be for a connection string, and states plainly that "the actual current
                    # status of the service is not changed when using this cmdlet" - so it is a read.
                    # Citrix documents it positionally: Test-BrokerDBConnection "Server=...;Database=...".
                    if (Test-ADTCtxCommand -Name 'Test-BrokerDBConnection') {
                        try {
                            $dbTest = Test-BrokerDBConnection $connectionString -ErrorAction Stop
                            # UNVERIFIED: property names on the Test-BrokerDBConnection result object.
                            $dbTestStatus = [string](Get-ADTCtxProperty -InputObject $dbTest -Name @('ServiceStatus', 'Status', 'State'))
                            $dbTestExtra = [string](Get-ADTCtxProperty -InputObject $dbTest -Name @('ExtraInfo', 'ExtraInformation', 'Details'))

                            if ([string]::IsNullOrEmpty($dbTestStatus)) {
                                Write-ADTResult -Check 'Site database connection test' -Status INFO `
                                    -Detail 'Test-BrokerDBConnection returned an object ADT could not interpret.' -Data $dbTest
                            }
                            elseif ($dbTestStatus -eq 'OK') {
                                Write-ADTResult -Check 'Site database connection test' -Status PASS `
                                    -Detail 'Test-BrokerDBConnection reports OK for the configured connection string.' -Data $dbTest
                            }
                            else {
                                $testWhy = 'Test-BrokerDBConnection reports "' + $dbTestStatus + '" for the connection string this controller is configured with, which means the Broker Service would not reach a healthy database using it. ' + $dbTestExtra
                                $testFix = @(
                                    'Test-BrokerDBConnection (Get-BrokerDBConnection) | Format-List *',
                                    'Get-BrokerServiceStatus | Format-List *',
                                    ('Confirm the Broker Service machine account has access to the site database on ' + $hostText + '.')
                                )
                                Write-ADTResult -Check 'Site database connection test' -Status FAIL `
                                    -Detail ('Test-BrokerDBConnection reports ' + $dbTestStatus + '.') -Why $testWhy -Fix $testFix -Data $dbTest
                            }
                        }
                        catch {
                            Write-ADTResult -Check 'Site database connection test' -Status ERROR -Detail $_.Exception.Message
                        }
                    }
                    else {
                        Write-ADTNote -Text 'Test-BrokerDBConnection is not available in this session; the TCP port test above is the only database check performed.'
                    }
                }
            }
        }
        catch {
            Write-ADTResult -Check 'Site database connection' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- Controllers --------------------------------------------------------------------------
        # Get-BrokerController State values are Failed, Off, On and Active; Active is the healthy
        # state for a controller that is powered on and fully operational.
        try {
            $controllers = @()
            try {
                $controllers = @(Get-BrokerController -ErrorAction Stop)
            }
            catch {
                Write-ADTResult -Check 'Delivery Controllers' -Status ERROR -Detail ('Get-BrokerController failed: ' + $_.Exception.Message)
                $controllers = @()
            }

            if ($controllers.Count -eq 0) {
                Write-ADTResult -Check 'Delivery Controllers' -Status INFO -Detail 'Get-BrokerController returned no controllers.'
            }
            else {
                Write-ADTResult -Check 'Delivery Controllers' -Status INFO -Detail ([string]$controllers.Count + ' controller(s) registered in this site.')
                if ($controllers.Count -eq 1) {
                    Write-ADTNote -Text 'This site has a single Delivery Controller - it is a single point of failure for brokering.'
                }

                foreach ($controller in $controllers) {
                    # UNVERIFIED: DNSName / MachineName / ControllerVersion / LastActivityTime as
                    # Get-BrokerController property names; each is read with fallbacks.
                    $controllerName = [string](Get-ADTCtxProperty -InputObject $controller -Name @('DNSName', 'MachineName', 'Name'))
                    if ([string]::IsNullOrEmpty($controllerName)) { $controllerName = '(unnamed controller)' }

                    $state = [string](Get-ADTCtxProperty -InputObject $controller -Name @('State'))
                    $version = [string](Get-ADTCtxProperty -InputObject $controller -Name @('ControllerVersion', 'Version'))
                    $lastActivity = Get-ADTCtxProperty -InputObject $controller -Name @('LastActivityTime')

                    $controllerDetail = 'State=' + $state
                    if (-not [string]::IsNullOrEmpty($version)) { $controllerDetail = $controllerDetail + ', version ' + $version }
                    if ($null -ne $lastActivity) {
                        try { $controllerDetail = $controllerDetail + ', last activity ' + ([datetime]$lastActivity).ToString('yyyy-MM-dd HH:mm') } catch { $null = $_ }
                    }

                    if ($state -eq 'Active') {
                        Write-ADTResult -Check ('Controller: ' + $controllerName) -Status PASS -Detail ($controllerDetail + '.') -Data $controller
                    }
                    elseif ([string]::IsNullOrEmpty($state)) {
                        Write-ADTResult -Check ('Controller: ' + $controllerName) -Status INFO -Detail 'No State property was returned for this controller.' -Data $controller
                    }
                    else {
                        $ctrlWhy = 'A Delivery Controller in state "' + $state + '" is not brokering. The documented states are Failed, Off, On and Active, and only Active means the controller is powered on and fully operational; VDAs registered to it will fail over to another controller if one is available, and users lose brokering entirely if it is the only one.'
                        $ctrlFix = @(
                            'Get-BrokerController | Format-List DNSName,State,LastActivityTime,ControllerVersion',
                            ('On ' + $controllerName + ': Get-Service -Name CitrixBrokerService'),
                            ('[SERVICE-AFFECTING] On ' + $controllerName + ': Restart-Service -Name CitrixBrokerService -Force'),
                            ('Get-WinEvent -ComputerName ' + $controllerName + ' -FilterHashtable @{LogName="Application";ProviderName="Citrix*";Level=2;StartTime=(Get-Date).AddHours(-24)} | Select-Object -First 20 TimeCreated,Id,Message')
                        )
                        Write-ADTResult -Check ('Controller: ' + $controllerName) -Status FAIL `
                            -Detail ($controllerDetail + '; expected Active.') -Why $ctrlWhy -Fix $ctrlFix -Data $controller
                    }
                }
            }
        }
        catch {
            Write-ADTResult -Check 'Delivery Controllers' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- VDA registration summary ---------------------------------------------------------------
        # Citrix documents that without -MaxRecordCount only the first 250 records are returned and a
        # warning is produced, so 5000 is requested explicitly and the warning stream is quietened via
        # the preference variable rather than a parameter (which keeps this safe on older SDK builds).
        try {
            $machines = @()
            $savedWarningPreference = $WarningPreference
            try {
                $WarningPreference = 'SilentlyContinue'
                $machines = @(Get-BrokerMachine -MaxRecordCount 5000 -ErrorAction Stop)
            }
            catch {
                Write-ADTResult -Check 'VDA registration' -Status ERROR -Detail ('Get-BrokerMachine failed: ' + $_.Exception.Message)
                $machines = @()
            }
            finally {
                $WarningPreference = $savedWarningPreference
            }

            if ($machines.Count -eq 0) {
                Write-ADTResult -Check 'VDA registration' -Status INFO -Detail 'Get-BrokerMachine returned no machines for this site.'
            }
            else {
                if ($machines.Count -ge 5000) {
                    Write-ADTNote -Text 'The 5000-record ceiling was reached; this summary may not cover every machine in the site.'
                }

                # RegistrationState values: Unregistered, Initializing, Registered, AgentError.
                # Only the categories that get reported by name are collected as objects. Appending
                # to a PowerShell array is O(n^2), and on a large site the Registered bucket holds
                # nearly every machine, so those are counted instead.
                $registeredCount = 0
                $initializingCount = 0
                $otherStateCount = 0
                $unregistered = @()
                $agentError = @()
                $maintenance = @()

                foreach ($machine in $machines) {
                    $regState = [string](Get-ADTCtxProperty -InputObject $machine -Name @('RegistrationState'))
                    switch ($regState) {
                        'Registered'   { $registeredCount = $registeredCount + 1 }
                        'Unregistered' { $unregistered += $machine }
                        'Initializing' { $initializingCount = $initializingCount + 1 }
                        'AgentError'   { $agentError += $machine }
                        default        { $otherStateCount = $otherStateCount + 1 }
                    }

                    $inMaintenance = $false
                    try {
                        $maintenanceValue = Get-ADTCtxProperty -InputObject $machine -Name @('InMaintenanceMode')
                        if ($null -ne $maintenanceValue) { $inMaintenance = [bool]$maintenanceValue }
                    }
                    catch {
                        $inMaintenance = $false
                    }
                    if ($inMaintenance) { $maintenance += $machine }
                }

                $total = $machines.Count
                $summary = [string]$total + ' machine(s): ' + [string]$registeredCount + ' Registered, ' +
                           [string]$unregistered.Count + ' Unregistered, ' + [string]$initializingCount + ' Initializing, ' +
                           [string]$agentError.Count + ' AgentError'
                if ($otherStateCount -gt 0) { $summary = $summary + ', ' + [string]$otherStateCount + ' other' }
                Write-ADTResult -Check 'VDA registration summary' -Status INFO -Detail ($summary + '.') -Data $machines

                # Unregistered machines that are actually meant to serve users: in a delivery group
                # or with an assigned user. Machines in neither are usually spare or being built.
                $noteworthy = @()
                foreach ($machine in $unregistered) {
                    $groupName = [string](Get-ADTCtxProperty -InputObject $machine -Name @('DesktopGroupName'))
                    # UNVERIFIED: AssociatedUserNames as the assigned-user property; the UPN and
                    # full-name variants are tried as fallbacks.
                    $userValue = Get-ADTCtxProperty -InputObject $machine -Name @('AssociatedUserNames', 'AssociatedUserUPNs', 'AssociatedUserFullNames')
                    $users = @(ConvertTo-ADTCtxArray -InputObject $userValue)

                    if ((-not [string]::IsNullOrEmpty($groupName)) -or ($users.Count -gt 0)) {
                        $noteworthy += $machine
                    }
                }

                $percentUnregistered = 0
                try {
                    if ($total -gt 0) { $percentUnregistered = [math]::Round((($unregistered.Count / $total) * 100), 1) }
                }
                catch {
                    $percentUnregistered = 0
                }

                if ($unregistered.Count -eq 0) {
                    Write-ADTResult -Check 'Unregistered VDAs' -Status PASS -Detail 'No machines are in the Unregistered state.'
                }
                else {
                    $names = @()
                    foreach ($machine in ($noteworthy | Select-Object -First 10)) {
                        $machineName = [string](Get-ADTCtxProperty -InputObject $machine -Name @('MachineName', 'DNSName', 'HostedMachineName'))
                        if ([string]::IsNullOrEmpty($machineName)) { $machineName = '(unnamed machine)' }
                        $groupName = [string](Get-ADTCtxProperty -InputObject $machine -Name @('DesktopGroupName'))
                        if ([string]::IsNullOrEmpty($groupName)) { $groupName = 'no delivery group' }
                        $names += ($machineName + ' (' + $groupName + ')')
                        Write-ADTNote -Text ($machineName + '  delivery group: ' + $groupName)
                    }

                    $regWhy = [string]$unregistered.Count + ' of ' + [string]$total + ' machines (' + [string]$percentUnregistered + '%) are Unregistered, ' + [string]$noteworthy.Count + ' of them in a delivery group or with an assigned user. An unregistered VDA cannot accept any session, so those users have no resource to launch. The usual causes are a wrong or empty ListOfDDCs on the VDA, TCP 80 blocked between VDA and controller, a time or DNS mismatch, or the Citrix Desktop Service being stopped on the VDA.'
                    $regFix = @(
                        'Get-BrokerMachine -MaxRecordCount 5000 -Filter { RegistrationState -eq "Unregistered" } | Select-Object MachineName,DesktopGroupName,PowerState,LastDeregistrationReason',
                        'Get-BrokerMachine -MaxRecordCount 5000 -Filter { RegistrationState -eq "Unregistered" } | Group-Object LastDeregistrationReason | Sort-Object Count -Descending',
                        'On an affected VDA: Get-ItemProperty -Path "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent" -Name ListOfDDCs',
                        'On an affected VDA: Get-Service -Name BrokerAgent',
                        'On an affected VDA: Test-NetConnection -ComputerName <controller FQDN> -Port 80'
                    )

                    if ($percentUnregistered -gt 25) {
                        Write-ADTResult -Check 'Unregistered VDAs' -Status FAIL `
                            -Detail ([string]$unregistered.Count + ' of ' + [string]$total + ' machines are Unregistered (' + [string]$percentUnregistered + '%), which is above the 25% threshold.') `
                            -Why $regWhy -Fix $regFix -Data $unregistered
                    }
                    elseif ($noteworthy.Count -gt 0) {
                        Write-ADTResult -Check 'Unregistered VDAs' -Status WARN `
                            -Detail ([string]$noteworthy.Count + ' unregistered machine(s) are in a delivery group or have an assigned user: ' + (Format-ADTCtxList -Items $names) + '.') `
                            -Why $regWhy -Fix $regFix -Data $noteworthy
                    }
                    else {
                        Write-ADTResult -Check 'Unregistered VDAs' -Status INFO `
                            -Detail ([string]$unregistered.Count + ' machine(s) are Unregistered, none of them in a delivery group or assigned to a user.') -Data $unregistered
                    }
                }

                if ($agentError.Count -gt 0) {
                    $agentWhy = [string]$agentError.Count + ' machine(s) report RegistrationState AgentError, meaning the controller reached the VDA but the Citrix Desktop Service on it returned an error rather than registering. This is a VDA-side fault, not a network one.'
                    $agentFix = @(
                        'Get-BrokerMachine -MaxRecordCount 5000 -Filter { RegistrationState -eq "AgentError" } | Select-Object MachineName,DesktopGroupName,LastDeregistrationReason',
                        'On an affected VDA: Get-WinEvent -FilterHashtable @{LogName="Application";ProviderName="Citrix Desktop Service";StartTime=(Get-Date).AddHours(-24)} | Select-Object -First 20 TimeCreated,Id,Message'
                    )
                    Write-ADTResult -Check 'VDAs in AgentError' -Status WARN `
                        -Detail ([string]$agentError.Count + ' machine(s) in AgentError.') -Why $agentWhy -Fix $agentFix -Data $agentError
                }

                if ($maintenance.Count -gt 0) {
                    $maintenanceNames = @()
                    foreach ($machine in ($maintenance | Select-Object -First 10)) {
                        $machineName = [string](Get-ADTCtxProperty -InputObject $machine -Name @('MachineName', 'DNSName'))
                        if (-not [string]::IsNullOrEmpty($machineName)) { $maintenanceNames += $machineName }
                    }
                    Write-ADTResult -Check 'Machines in maintenance mode' -Status INFO `
                        -Detail ([string]$maintenance.Count + ' machine(s) are in maintenance mode: ' + (Format-ADTCtxList -Items $maintenanceNames) + '.') -Data $maintenance
                }
                else {
                    Write-ADTResult -Check 'Machines in maintenance mode' -Status INFO -Detail 'No machines are in maintenance mode.'
                }
            }
        }
        catch {
            Write-ADTResult -Check 'VDA registration' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- Recent broker errors ---------------------------------------------------------------------
        Write-ADTCtxCitrixErrorEvents -Check 'Citrix errors (Application log, 24h)'
    }
    catch {
        Write-ADTResult -Check 'Delivery Controller health' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Item 2: VDA health

function Invoke-ADTCitrixVDA {
    <#
        .SYNOPSIS
            VDA health: Citrix Desktop Service state, the ListOfDDCs registration list, DNS and
            TCP reachability of each listed controller, recent registration events and session count.
        .DESCRIPTION
            Runs on Requires=@('CitrixVDA'), so the BrokerAgent service (Citrix Desktop Service) is
            known to be installed. Nothing here needs the Citrix SDK - a VDA usually has no snap-in.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Citrix VDA Health'

        # ---- Citrix Desktop Service ----------------------------------------------------------
        # Citrix documents "net stop brokeragent" / "net start brokeragent" as the way to restart
        # the Citrix Desktop Service, so both the short name and the display name are known good.
        $brokerAgent = $null
        try {
            $agents = @(Get-ADTCtxService -NameLike @('BrokerAgent') -DisplayNameLike @('Citrix Desktop Service'))
            if ($agents.Count -gt 0) { $brokerAgent = $agents[0] }
        }
        catch {
            $brokerAgent = $null
        }

        if ($null -eq $brokerAgent) {
            Write-ADTResult -Check 'Citrix Desktop Service' -Status SKIP `
                -Detail 'The BrokerAgent service could not be read on this machine.' `
                -Fix @('Get-Service -Name BrokerAgent')
        }
        elseif ($brokerAgent.State -eq 'Running') {
            Write-ADTResult -Check 'Citrix Desktop Service' -Status PASS `
                -Detail ('Running (StartMode: ' + $brokerAgent.StartMode + ').') -Data $brokerAgent
        }
        else {
            $agentWhy = 'The Citrix Desktop Service (BrokerAgent) is what registers this VDA with a Delivery Controller. While it is ' + $brokerAgent.State + ', this machine is unregistered and cannot accept any Citrix session, however healthy the rest of the box is.'
            $agentFix = @(
                'Start-Service -Name BrokerAgent',
                '[SERVICE-AFFECTING] Restart-Service -Name BrokerAgent -Force',
                'Alternative: net stop brokeragent',
                'Alternative: net start brokeragent',
                'Get-WinEvent -FilterHashtable @{LogName="Application";ProviderName="Citrix Desktop Service";StartTime=(Get-Date).AddHours(-24)} | Select-Object -First 20 TimeCreated,Id,Message'
            )
            Write-ADTResult -Check 'Citrix Desktop Service' -Status FAIL `
                -Detail ('Service state is ' + $brokerAgent.State + ', expected Running.') -Why $agentWhy -Fix $agentFix -Data $brokerAgent
        }

        # ---- ListOfDDCs -------------------------------------------------------------------------
        # Citrix documents the VDA registration list as the value ListOfDDCs under
        # HKLM\Software\Citrix\VirtualDesktopAgent (or the Wow6432Node view of it), holding
        # space-separated DNS names of the Controllers or Cloud Connectors for the site.
        # UNVERIFIED: HKLM\Software\Policies\Citrix\VirtualDesktopAgent as the Group Policy
        # equivalent is described in Citrix VDA-registration write-ups rather than a doc page
        # ADT could read directly; it is checked in addition to, not instead of, the local value.
        $ddcSources = @(
            [PSCustomObject]@{ Label = 'Group Policy'; Path = 'HKLM:\SOFTWARE\Policies\Citrix\VirtualDesktopAgent' }
            [PSCustomObject]@{ Label = 'Local';        Path = 'HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent' }
            [PSCustomObject]@{ Label = 'Local (WOW64)'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Citrix\VirtualDesktopAgent' }
        )

        $effectiveSource = ''
        $ddcNames = @()

        foreach ($source in $ddcSources) {
            $value = Get-ADTCtxRegistryValue -Path $source.Path -Name 'ListOfDDCs'
            if ($null -eq $value) { continue }

            $valueText = ([string]$value).Trim()
            if ([string]::IsNullOrEmpty($valueText)) { continue }

            $candidates = @()
            try {
                foreach ($token in ($valueText -split '[\s,;]+')) {
                    $trimmed = $token.Trim()
                    if (-not [string]::IsNullOrEmpty($trimmed)) { $candidates += $trimmed }
                }
            }
            catch {
                $candidates = @()
            }

            if ($candidates.Count -eq 0) { continue }

            Write-ADTNote -Text ($source.Label + ' (' + $source.Path + '): ' + (Format-ADTCtxList -Items $candidates))

            if ($ddcNames.Count -eq 0) {
                $ddcNames = $candidates
                $effectiveSource = $source.Label
            }
        }

        if ($ddcNames.Count -eq 0) {
            $ddcWhy = 'ListOfDDCs is the list of Delivery Controllers or Cloud Connectors this VDA tries to register with. With it missing or empty in every location ADT checked, the Broker Agent has nothing to contact and the VDA can never register, so no user can ever launch a session on this machine.'
            $ddcFix = @(
                'Get-ItemProperty -Path "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent" -Name ListOfDDCs',
                'Set the value (space-separated FQDNs) on the VDA: Set-ItemProperty -Path "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent" -Name ListOfDDCs -Value "ddc1.contoso.local ddc2.contoso.local"',
                'Or set it centrally: Citrix Studio > Policies > Virtual Delivery Agent Settings > Controllers (or Controller SIDs), then run gpupdate /force on the VDA.',
                '[SERVICE-AFFECTING] Restart-Service -Name BrokerAgent -Force   (required for a registry change to take effect)'
            )
            Write-ADTResult -Check 'VDA ListOfDDCs' -Status FAIL `
                -Detail 'No ListOfDDCs value was found under the local, WOW64 or Group Policy VirtualDesktopAgent keys.' -Why $ddcWhy -Fix $ddcFix
        }
        else {
            Write-ADTResult -Check 'VDA ListOfDDCs' -Status PASS `
                -Detail ([string]$ddcNames.Count + ' controller(s) listed, effective source ' + $effectiveSource + ': ' + (Format-ADTCtxList -Items $ddcNames) + '.') -Data $ddcNames
        }

        # ---- Controller reachability -------------------------------------------------------------
        # Citrix documents TCP 80 as the default VDA registration port between the VDA and the
        # Delivery Controller. VDA 2407 and later can register over SSL on 443 instead, which
        # requires trusted certificates on the controllers plus registry values on both ends, so
        # a closed 80 with an open 443 is reported as an informational SSL configuration.
        foreach ($ddcName in $ddcNames) {
            $checkName = 'DDC reachable: ' + $ddcName

            $addresses = @()
            try {
                $resolved = [System.Net.Dns]::GetHostAddresses($ddcName)
                foreach ($address in $resolved) {
                    $addressText = [string]$address
                    if (-not [string]::IsNullOrEmpty($addressText)) { $addresses += $addressText }
                }
            }
            catch {
                $addresses = @()
            }

            if ($addresses.Count -eq 0) {
                $dnsWhy = 'This VDA cannot resolve ' + $ddcName + ' in DNS, so the Broker Agent has no address to contact and registration fails before any network connection is attempted. Either the name is wrong in ListOfDDCs or this machine is using the wrong DNS servers.'
                $dnsFix = @(
                    ('Resolve-DnsName -Name ' + $ddcName),
                    'Get-DnsClientServerAddress -AddressFamily IPv4',
                    'Get-ItemProperty -Path "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent" -Name ListOfDDCs',
                    'ipconfig /flushdns'
                )
                Write-ADTResult -Check $checkName -Status FAIL -Detail 'DNS resolution failed for this controller name.' -Why $dnsWhy -Fix $dnsFix
                continue
            }

            $port80 = $false
            $port443 = $false
            try { $port80 = Test-ADTPort -ComputerName $ddcName -Port 80 -TimeoutMs 3000 } catch { $port80 = $false }
            if (-not $port80) {
                try { $port443 = Test-ADTPort -ComputerName $ddcName -Port 443 -TimeoutMs 3000 } catch { $port443 = $false }
            }

            if ($port80) {
                Write-ADTResult -Check $checkName -Status PASS `
                    -Detail ('Resolves to ' + (Format-ADTCtxList -Items $addresses) + '; TCP 80 (VDA registration) is open.')
            }
            elseif ($port443) {
                Write-ADTResult -Check $checkName -Status INFO `
                    -Detail ('Resolves to ' + (Format-ADTCtxList -Items $addresses) + '; TCP 80 is closed but TCP 443 is open, which is expected when VDA registration over SSL is configured (VDA 2407 and later).')
            }
            else {
                $portWhy = 'TCP 80 is the default VDA registration port to a Delivery Controller, and 443 is the alternative when registration over SSL is configured. Neither is answering on ' + $ddcName + ', so this VDA cannot register with it. Any firewall between the VDA and the controller must allow the configured port.'
                $portFix = @(
                    ('Test-NetConnection -ComputerName ' + $ddcName + ' -Port 80'),
                    ('Test-NetConnection -ComputerName ' + $ddcName + ' -Port 443'),
                    ('On ' + $ddcName + ': Get-Service -Name CitrixBrokerService'),
                    'Get-NetFirewallRule -DisplayName "*Citrix*" | Where-Object { $_.Enabled -eq "True" } | Select-Object DisplayName,Direction,Action'
                )
                Write-ADTResult -Check $checkName -Status FAIL `
                    -Detail ('Resolves to ' + (Format-ADTCtxList -Items $addresses) + ' but neither TCP 80 nor TCP 443 is answering.') -Why $portWhy -Fix $portFix
            }
        }

        # ---- Registration events --------------------------------------------------------------------
        # Citrix documents event ID 1017 (Warning) with the message "The Citrix Desktop Service failed
        # to register with any Delivery Controller" as the VDA-registration-failure trigger.
        # UNVERIFIED: event ID 1012 as the matching registration-success event, and the exact provider
        # name "Citrix Desktop Service"; both are widely used in Citrix troubleshooting write-ups but
        # ADT could not read them off a Citrix doc page. Absent provider is a silent skip.
        try {
            $since = (Get-Date).AddHours(-24)
            $vdaEvents = Get-ADTCtxEvent -LogName 'Application' -ProviderPattern 'Citrix Desktop Service' -StartTime $since -MaxEvents 200

            if ($vdaEvents.ProviderMissing) {
                Write-ADTResult -Check 'VDA registration events (24h)' -Status SKIP `
                    -Detail 'No "Citrix Desktop Service" event provider is registered on this machine.'
            }
            else {
                $events = @(ConvertTo-ADTCtxArray -InputObject $vdaEvents.Events)

                if ($events.Count -eq 0) {
                    Write-ADTResult -Check 'VDA registration events (24h)' -Status INFO `
                        -Detail 'The Citrix Desktop Service logged nothing in the Application log in the last 24 hours.'
                }
                else {
                    $sorted = @($events | Sort-Object -Property TimeCreated -Descending)
                    $newestSuccess = $null
                    $newestFailure = $null

                    foreach ($record in $sorted) {
                        $eventId = 0
                        try { $eventId = [int]$record.Id } catch { $eventId = 0 }

                        if ($null -eq $newestSuccess -and $eventId -eq 1012) { $newestSuccess = $record }
                        if ($null -eq $newestFailure -and $eventId -eq 1017) { $newestFailure = $record }
                    }

                    $newest = $sorted[0]
                    $newestTime = 'unknown time'
                    try { $newestTime = $newest.TimeCreated.ToString('yyyy-MM-dd HH:mm') } catch { $newestTime = 'unknown time' }

                    if ($null -ne $newestFailure) {
                        $failureTime = 'unknown time'
                        try { $failureTime = $newestFailure.TimeCreated.ToString('yyyy-MM-dd HH:mm') } catch { $failureTime = 'unknown time' }

                        $successIsNewer = $false
                        if ($null -ne $newestSuccess) {
                            try { $successIsNewer = ($newestSuccess.TimeCreated -gt $newestFailure.TimeCreated) } catch { $successIsNewer = $false }
                        }

                        if ($successIsNewer) {
                            $successTime = 'unknown time'
                            try { $successTime = $newestSuccess.TimeCreated.ToString('yyyy-MM-dd HH:mm') } catch { $successTime = 'unknown time' }
                            Write-ADTResult -Check 'VDA registration events (24h)' -Status INFO `
                                -Detail ('A registration failure was logged at ' + $failureTime + ' but a later success followed at ' + $successTime + '; the VDA recovered.') -Data $sorted
                        }
                        else {
                            $eventWhy = 'The newest registration event from the Citrix Desktop Service is a failure at ' + $failureTime + ' with no later success, so this VDA is most likely unregistered right now. Message: ' + (Format-ADTCtxMessage -Text ([string]$newestFailure.Message))
                            $eventFix = @(
                                'Get-WinEvent -FilterHashtable @{LogName="Application";ProviderName="Citrix Desktop Service";StartTime=(Get-Date).AddHours(-24)} | Select-Object -First 20 TimeCreated,Id,Message | Format-List',
                                'Get-ItemProperty -Path "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent" -Name ListOfDDCs',
                                '[SERVICE-AFFECTING] Restart-Service -Name BrokerAgent -Force',
                                'On a Delivery Controller: Get-BrokerMachine -MaxRecordCount 5000 -Filter { MachineName -like "*<this machine name>*" } | Select-Object MachineName,RegistrationState,LastDeregistrationReason'
                            )
                            Write-ADTResult -Check 'VDA registration events (24h)' -Status WARN `
                                -Detail ('Newest registration outcome is a FAILURE (event 1017) at ' + $failureTime + '.') -Why $eventWhy -Fix $eventFix -Data $sorted
                        }
                    }
                    elseif ($null -ne $newestSuccess) {
                        $successTime = 'unknown time'
                        try { $successTime = $newestSuccess.TimeCreated.ToString('yyyy-MM-dd HH:mm') } catch { $successTime = 'unknown time' }
                        Write-ADTResult -Check 'VDA registration events (24h)' -Status PASS `
                            -Detail ('Registration succeeded at ' + $successTime + ' (event 1012) with no later failure.') -Data $sorted
                    }
                    else {
                        Write-ADTResult -Check 'VDA registration events (24h)' -Status INFO `
                            -Detail ([string]$events.Count + ' Citrix Desktop Service event(s) in the last 24 hours, none of them a registration success or failure. Newest ' + $newestTime + ': ' + (Format-ADTCtxMessage -Text ([string]$newest.Message))) -Data $sorted
                    }
                }
            }
        }
        catch {
            Write-ADTResult -Check 'VDA registration events (24h)' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- Session count ---------------------------------------------------------------------------
        # quser (Microsoft Learn, Windows Commands) lists user sessions; it exits non-zero and prints
        # "No User exists for *" when there are none, which is a normal result, not a failure.
        try {
            $quser = Invoke-ADTNative -FilePath 'quser.exe' -Arguments @() -TimeoutSec 20

            if ($quser.ExitCode -eq 0 -and -not [string]::IsNullOrEmpty($quser.StdOut)) {
                $lines = @()
                foreach ($line in ($quser.StdOut -split '\r?\n')) {
                    $trimmed = $line.Trim()
                    if (-not [string]::IsNullOrEmpty($trimmed)) { $lines += $trimmed }
                }
                $sessionCount = $lines.Count - 1
                if ($sessionCount -lt 0) { $sessionCount = 0 }
                Write-ADTResult -Check 'Sessions on this VDA' -Status INFO `
                    -Detail ([string]$sessionCount + ' user session(s) reported by quser.') -Data $lines
            }
            elseif ($quser.ExitCode -eq -1) {
                Write-ADTResult -Check 'Sessions on this VDA' -Status SKIP -Detail ('quser could not be started: ' + $quser.StdErr)
            }
            else {
                Write-ADTResult -Check 'Sessions on this VDA' -Status INFO -Detail 'quser reported no user sessions on this machine.'
            }
        }
        catch {
            Write-ADTResult -Check 'Sessions on this VDA' -Status ERROR -Detail $_.Exception.Message
        }
    }
    catch {
        Write-ADTResult -Check 'VDA health' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Item 3: StoreFront health

function Invoke-ADTCitrixStoreFront {
    <#
        .SYNOPSIS
            StoreFront health: the StoreFront service set, IIS, the local HTTPS listener and the
            deployment base URL.
        .DESCRIPTION
            Runs on Requires=@('CitrixStoreFront'). The StoreFront PowerShell modules are not
            compatible with PowerShell 6 or later (documented by Citrix), so the base-URL check is
            skipped with that reason when ADT is running on PowerShell 7.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Citrix StoreFront Health'

        # ---- StoreFront service set -----------------------------------------------------------
        # The same display-name wildcards ADT.Common.ps1 uses to detect the StoreFront role. Citrix
        # names the service accounts NT SERVICE\CitrixCredentialWallet, NT SERVICE\CitrixSubscriptionsStore
        # and NT SERVICE\CitrixDefaultDomainService in "Secure your StoreFront deployment", which
        # confirms those three; the remaining two patterns come from Citrix troubleshooting articles.
        try {
            $sfPatterns = @(
                'Citrix Subscriptions Store*',
                'Citrix Credential Wallet*',
                'Citrix Default Domain Services*',
                'Citrix Peer Resolution*',
                'Citrix Configuration Replication*'
            )
            $sfServices = @(Get-ADTCtxService -DisplayNameLike $sfPatterns)
            Write-ADTCtxServiceSet -Check 'StoreFront services' -Service $sfServices -RoleName 'StoreFront'
        }
        catch {
            Write-ADTResult -Check 'StoreFront services' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- IIS --------------------------------------------------------------------------------
        # W3SVC is the World Wide Web Publishing Service (Microsoft Learn), which serves every
        # StoreFront store and website. Microsoft IIS is enabled as part of StoreFront installation.
        try {
            $iis = @(Get-ADTCtxService -NameLike @('W3SVC') -DisplayNameLike @('World Wide Web Publishing Service'))

            if ($iis.Count -eq 0) {
                $iisWhy = 'StoreFront is an IIS application, and IIS is installed as part of the StoreFront installation. If the World Wide Web Publishing Service is not present at all, this box cannot be serving stores.'
                Write-ADTResult -Check 'IIS (W3SVC)' -Status FAIL -Detail 'The W3SVC service is not installed on this machine.' -Why $iisWhy `
                    -Fix @('Get-WindowsFeature -Name Web-Server', 'Install-WindowsFeature -Name Web-Server -IncludeManagementTools')
            }
            elseif ($iis[0].State -eq 'Running') {
                Write-ADTResult -Check 'IIS (W3SVC)' -Status PASS -Detail ('Running (StartMode: ' + $iis[0].StartMode + ').') -Data $iis[0]
            }
            else {
                $iisWhy = 'The World Wide Web Publishing Service is ' + $iis[0].State + '. StoreFront stores and websites are IIS applications, so while W3SVC is stopped every user gets a connection failure at the store URL, whatever state the Citrix services are in.'
                $iisFix = @(
                    'Start-Service -Name W3SVC',
                    '[SERVICE-AFFECTING] Restart-Service -Name W3SVC -Force',
                    'Get-WinEvent -FilterHashtable @{LogName="System";ProviderName="Service Control Manager";Id=7000,7024;StartTime=(Get-Date).AddDays(-2)} | Select-Object -First 10 TimeCreated,Id,Message'
                )
                Write-ADTResult -Check 'IIS (W3SVC)' -Status FAIL -Detail ('Service state is ' + $iis[0].State + ', expected Running.') -Why $iisWhy -Fix $iisFix -Data $iis[0]
            }
        }
        catch {
            Write-ADTResult -Check 'IIS (W3SVC)' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- Local listeners -----------------------------------------------------------------------
        # TCP 443 and 80 are the documented HTTPS and HTTP ports of the World Wide Web Publishing
        # Service. Citrix requires HTTPS for StoreFront in any deployment using pass-through or
        # smart card authentication, and recommends it generally.
        try {
            $https = Test-ADTPort -ComputerName '127.0.0.1' -Port 443 -TimeoutMs 3000
            $http = Test-ADTPort -ComputerName '127.0.0.1' -Port 80 -TimeoutMs 3000

            if ($https) {
                Write-ADTResult -Check 'StoreFront HTTPS listener' -Status PASS -Detail 'TCP 443 is answering on 127.0.0.1.'
            }
            elseif ($http) {
                $tlsWhy = 'Nothing is listening on TCP 443 on this server, only TCP 80. StoreFront traffic carries user credentials, so Citrix requires HTTPS for pass-through and smart card authentication and recommends it for every deployment; on plain HTTP those credentials cross the network unprotected.'
                $tlsFix = @(
                    'Get-NetTCPConnection -State Listen -LocalPort 443',
                    'Bind a server certificate to the StoreFront site in IIS Manager > Sites > Default Web Site > Bindings > Add > https.',
                    'Then set the base URL to the https address: StoreFront console > Server Group > Change Base URL.'
                )
                Write-ADTResult -Check 'StoreFront HTTPS listener' -Status WARN -Detail 'TCP 443 is not answering on 127.0.0.1, but TCP 80 is.' -Why $tlsWhy -Fix $tlsFix
            }
            else {
                $noneWhy = 'Neither TCP 443 nor TCP 80 is answering on the loopback address, so no web listener is serving StoreFront on this machine and every user request to it will fail to connect.'
                $noneFix = @(
                    'Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -eq 80 -or $_.LocalPort -eq 443 }',
                    'Get-Service -Name W3SVC',
                    'Start-Service -Name W3SVC'
                )
                Write-ADTResult -Check 'StoreFront HTTPS listener' -Status FAIL -Detail 'Neither TCP 443 nor TCP 80 is answering on 127.0.0.1.' -Why $noneWhy -Fix $noneFix
            }
        }
        catch {
            Write-ADTResult -Check 'StoreFront HTTPS listener' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- Deployment base URL ---------------------------------------------------------------------
        # Get-STFDeployment "retrieves details of the StoreFront deployment on the current server" and
        # its output carries HostbaseUrl - both are shown in the Citrix StoreFront PowerShell examples.
        # Citrix states the StoreFront PowerShell modules are not compatible with PowerShell 6 or higher.
        try {
            if ($script:ADTCaps['IsPS7']) {
                $psWhy = 'Citrix states that the StoreFront PowerShell modules are not compatible with PowerShell 6 or higher, so Get-STFDeployment cannot run in this session.'
                $psFix = @(
                    'Re-run ADT from Windows PowerShell 5.1 on this StoreFront server.',
                    'Or read it on screen: StoreFront console > Server Group > Change Base URL.'
                )
                Write-ADTResult -Check 'StoreFront base URL' -Status SKIP -Detail 'Running on PowerShell 7; the StoreFront modules are Windows PowerShell only.' -Why $psWhy -Fix $psFix
            }
            elseif (-not (Test-ADTCtxCommand -Name 'Get-STFDeployment')) {
                $cmdFix = @(
                    'Import-Module Citrix.StoreFront',
                    'Or run the bundled loader: & "$env:ProgramFiles\Citrix\Receiver StoreFront\Scripts\ImportModules.ps1"',
                    'Then: Get-STFDeployment',
                    'Or read it on screen: StoreFront console > Server Group > Change Base URL.'
                )
                Write-ADTResult -Check 'StoreFront base URL' -Status SKIP `
                    -Detail 'Get-STFDeployment is not available in this session.' `
                    -Why 'The Citrix.StoreFront module did not autoload, which usually means ADT is not running elevated on the StoreFront server itself.' -Fix $cmdFix
            }
            else {
                $deployment = $null
                try {
                    $deployment = Get-STFDeployment -ErrorAction Stop
                }
                catch {
                    $deployWhy = 'Get-STFDeployment failed. Citrix requires the shell to run as a member of the local administrators group on the StoreFront server, and requires the StoreFront management console to be closed while the cmdlets run.'
                    $deployFix = @(
                        'Close the StoreFront management console, then re-run ADT from an elevated Windows PowerShell 5.1 session.',
                        'Get-STFDeployment'
                    )
                    Write-ADTResult -Check 'StoreFront base URL' -Status ERROR -Detail ('Get-STFDeployment failed: ' + $_.Exception.Message) -Why $deployWhy -Fix $deployFix
                    $deployment = $null
                }

                if ($null -ne $deployment) {
                    $baseUrl = [string](Get-ADTCtxProperty -InputObject $deployment -Name @('HostbaseUrl', 'HostBaseUrl'))
                    # UNVERIFIED: SiteId / IISSiteId as the IIS site identifier property name.
                    $siteId = [string](Get-ADTCtxProperty -InputObject $deployment -Name @('SiteId', 'IISSiteId'))

                    if ([string]::IsNullOrEmpty($baseUrl)) {
                        Write-ADTResult -Check 'StoreFront base URL' -Status WARN `
                            -Detail 'A StoreFront deployment exists but no base URL was returned.' `
                            -Why 'The base URL is the address StoreFront hands out to Citrix Workspace app. Without it, launch and subscription URLs are wrong or missing for every user.' `
                            -Fix @('StoreFront console > Server Group > Change Base URL', 'Set-STFDeployment -HostBaseUrl "https://storefront.contoso.com"') -Data $deployment
                    }
                    else {
                        $urlDetail = 'Base URL ' + $baseUrl
                        if (-not [string]::IsNullOrEmpty($siteId)) { $urlDetail = $urlDetail + ' (IIS site ' + $siteId + ')' }

                        if ($baseUrl.ToLower().StartsWith('http://')) {
                            $httpWhy = 'The StoreFront base URL is an http:// address, so Citrix Workspace app is handed an unencrypted address and user credentials cross the network in the clear. Citrix requires HTTPS for pass-through and smart card authentication.'
                            $httpFix = @(
                                'Bind a server certificate in IIS Manager > Sites > Default Web Site > Bindings > Add > https.',
                                'StoreFront console > Server Group > Change Base URL, and set the https address.',
                                ('Set-STFDeployment -HostBaseUrl "' + ($baseUrl -replace '(?i)^http://', 'https://') + '"')
                            )
                            Write-ADTResult -Check 'StoreFront base URL' -Status WARN -Detail ($urlDetail + ' - not HTTPS.') -Why $httpWhy -Fix $httpFix -Data $deployment
                        }
                        else {
                            Write-ADTResult -Check 'StoreFront base URL' -Status PASS -Detail ($urlDetail + '.') -Data $deployment
                        }
                    }
                }
            }
        }
        catch {
            Write-ADTResult -Check 'StoreFront base URL' -Status ERROR -Detail $_.Exception.Message
        }

        Write-ADTNote -Text 'Server group membership and store configuration are not read here; check them in the StoreFront console under Server Group and Stores.'
    }
    catch {
        Write-ADTResult -Check 'StoreFront health' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Item 4: Cloud Connector health

function Invoke-ADTCitrixCloudConnector {
    <#
        .SYNOPSIS
            Citrix Cloud Connector health: the connector service set, outbound HTTPS to the
            documented Citrix Cloud endpoints, and recent Citrix errors.
        .DESCRIPTION
            Runs on Requires=@('CitrixCloudConnector'). Proxy configuration is deliberately out of
            scope: the connectivity tests below are direct TCP 443 connects, so a site that reaches
            Citrix Cloud only through an explicit proxy will show them as unreachable. That case is
            called out in the Why text rather than guessed at.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Citrix Cloud Connector Health'

        # ---- Connector service set ---------------------------------------------------------------
        # The three display names ADT.Common.ps1 detects the role with come from the Citrix Cloud
        # Connector technical details service table. The wildcard sweep catches the rest of the set
        # (Citrix Cloud Credential Provider, Citrix High Availability Service, Citrix Remote HCL
        # Server, Citrix Session Manager Proxy and so on) without hard-coding a version-specific list.
        $connectorNames = @(
            'Citrix Remote Broker Provider',
            'Citrix Cloud Services Agent WatchDog',
            'Citrix Config Synchronizer Service'
        )

        try {
            $connectorServices = @(Get-ADTCtxService -DisplayNameLike @('Citrix*') -NameLike @('Citrix*'))
            Write-ADTCtxServiceSet -Check 'Cloud Connector services' -Service $connectorServices -RoleName 'Cloud Connector'

            $missing = @()
            foreach ($expected in $connectorNames) {
                $found = $false
                foreach ($service in $connectorServices) {
                    if ($service.DisplayName -eq $expected) { $found = $true }
                }
                if (-not $found) { $missing += $expected }
            }

            if ($missing.Count -gt 0) {
                $missingWhy = 'These core Cloud Connector services were not found by display name: ' + (Format-ADTCtxList -Items $missing) + '. Service names do vary between Cloud Connector builds, so this is worth confirming by eye rather than treating as proof of a broken install.'
                $missingFix = @(
                    'Get-Service -DisplayName "Citrix*" | Select-Object Status,Name,DisplayName | Sort-Object DisplayName',
                    'Confirm the connector is healthy in the Citrix Cloud console: Resource Locations > this resource location > Cloud Connectors.'
                )
                Write-ADTResult -Check 'Cloud Connector core services' -Status INFO `
                    -Detail ([string]$missing.Count + ' of ' + [string]$connectorNames.Count + ' expected core service(s) not matched by display name.') -Why $missingWhy -Fix $missingFix
            }
            else {
                Write-ADTResult -Check 'Cloud Connector core services' -Status PASS `
                    -Detail 'All three core Cloud Connector services are present: Citrix Remote Broker Provider, Citrix Cloud Services Agent WatchDog, Citrix Config Synchronizer Service.'
            }
        }
        catch {
            Write-ADTResult -Check 'Cloud Connector services' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- Outbound HTTPS to Citrix Cloud ---------------------------------------------------------
        # From "System and Connectivity Requirements" on docs.citrix.com: the Cloud Connector requires
        # outbound connectivity on port 443, and the common Citrix Cloud service addresses are the
        # wildcards https://*.cloud.com, https://*.citrixworkspacesapi.net and
        # https://*.citrixnetworkapi.net. A wildcard cannot be TCP tested, so one concrete host that
        # the same page names explicitly is used to represent each domain.
        $cloudEndpoints = @(
            [PSCustomObject]@{ Name = 'citrix.cloud.com';             Domain = '*.cloud.com';                Purpose = 'Citrix Cloud sign-in interface' }
            [PSCustomObject]@{ Name = 'core.citrixworkspacesapi.net'; Domain = '*.citrixworkspacesapi.net';  Purpose = 'Citrix Cloud APIs used by the services' }
            [PSCustomObject]@{ Name = 'trust.citrixnetworkapi.net';   Domain = '*.citrixnetworkapi.net';     Purpose = 'Citrix Cloud trust and registration API' }
        )

        $unreachable = @()

        foreach ($endpoint in $cloudEndpoints) {
            $checkName = 'Citrix Cloud reachable: ' + $endpoint.Name
            try {
                $open = Test-ADTPort -ComputerName $endpoint.Name -Port 443 -TimeoutMs 5000
                if ($open) {
                    Write-ADTResult -Check $checkName -Status PASS `
                        -Detail ('TCP 443 is open (' + $endpoint.Purpose + ', represents ' + $endpoint.Domain + ').')
                }
                else {
                    $unreachable += $endpoint.Name
                    $cloudWhy = 'The Cloud Connector requires outbound connectivity on port 443 to the Citrix Cloud control plane. ' + $endpoint.Name + ' represents the required domain ' + $endpoint.Domain + ' (' + $endpoint.Purpose + '). With it unreachable the connector cannot stay registered, and brokering, configuration sync and machine management through Citrix Cloud all stop. NOTE: this is a direct TCP test - if this site reaches Citrix Cloud only through an explicit HTTP proxy, a failure here is expected and not itself a fault.'
                    $cloudFix = @(
                        ('Test-NetConnection -ComputerName ' + $endpoint.Name + ' -Port 443'),
                        ('Resolve-DnsName -Name ' + $endpoint.Name),
                        ('Allow outbound TCP 443 to https://' + $endpoint.Domain + ' through the firewall (Citrix publishes domain names, not IP addresses, because the addresses change).'),
                        'Full current FQDN list: https://api.cloud.com/connectivity/v2/allowlist?customerId=<CCID>',
                        'If a proxy is in use, confirm the Cloud Connector proxy settings and that SSL interception is not applied to Citrix Cloud addresses.'
                    )
                    Write-ADTResult -Check $checkName -Status FAIL `
                        -Detail ('TCP 443 is NOT reachable (' + $endpoint.Purpose + ', represents ' + $endpoint.Domain + ').') -Why $cloudWhy -Fix $cloudFix
                }
            }
            catch {
                Write-ADTResult -Check $checkName -Status ERROR -Detail $_.Exception.Message
            }
        }

        if ($unreachable.Count -eq 0) {
            Write-ADTNote -Text 'Host and machine-creation management additionally need outbound TCP 9350-9354 to Azure Service Bus; that is not tested here.'
        }
        Write-ADTNote -Text 'Proxy configuration is out of scope for these checks - they are direct TCP 443 connects from this machine.'

        # ---- Recent connector errors -------------------------------------------------------------------
        Write-ADTCtxCitrixErrorEvents -Check 'Citrix errors (Application log, 24h)'
    }
    catch {
        Write-ADTResult -Check 'Cloud Connector health' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Module registration

Register-ADTModule -Name 'Citrix' -Group 'ON-PREM' -Items @(
    @{ Label = 'Delivery Controller health'; Function = 'Invoke-ADTCitrixDDC';            Requires = @('CitrixDDC');            Snapshot = $true }
    @{ Label = 'VDA health';                 Function = 'Invoke-ADTCitrixVDA';            Requires = @('CitrixVDA');            Snapshot = $true }
    @{ Label = 'StoreFront health';          Function = 'Invoke-ADTCitrixStoreFront';     Requires = @('CitrixStoreFront');     Snapshot = $true }
    @{ Label = 'Cloud Connector health';     Function = 'Invoke-ADTCitrixCloudConnector'; Requires = @('CitrixCloudConnector'); Snapshot = $true }
)

#endregion
