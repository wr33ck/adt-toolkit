# ADT.Common.ps1 - output engine, capability map, shared helpers and the prerequisite manager.
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.

#region Shared state
# Nothing here does I/O or runs a check. Values are only seeded if the launcher has not
# already set them, so this file is safe to dot-source more than once.

if ($null -eq $script:ADTResults)        { $script:ADTResults = @() }
if ($null -eq $script:ADTModules)        { $script:ADTModules = @() }
if ($null -eq $script:ADTCaps)           { $script:ADTCaps = @{} }
if ($null -eq $script:ADTNonInteractive) { $script:ADTNonInteractive = $false }
if ($null -eq $script:ADTCurrentModule)  { $script:ADTCurrentModule = 'ADT' }
if ($null -eq $script:ADTServiceCache)   { $script:ADTServiceCache = $null }
if ($null -eq $script:ADTRoot) {
    if ($PSScriptRoot) {
        $script:ADTRoot = Split-Path -Path $PSScriptRoot -Parent
    }
    else {
        $script:ADTRoot = (Get-Location).Path
    }
}

#endregion

#region Output engine

function Write-ADTResult {
    <#
        .SYNOPSIS
            Emit one colour-coded result line and record it for the end-of-run summary.
        .DESCRIPTION
            The only sanctioned way for a check to report. Returns nothing to the pipeline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Check,

        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO', 'SKIP', 'ERROR')]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Detail,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Why,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Fix,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Data
    )

    $tag = '[' + $Status + ']'
    $colour = 'Gray'
    switch ($Status) {
        'PASS'  { $colour = 'Green' }
        'WARN'  { $colour = 'Yellow' }
        'FAIL'  { $colour = 'Red' }
        'INFO'  { $colour = 'Gray' }
        'SKIP'  { $colour = 'Gray' }
        'ERROR' { $tag = '[ERR ]'; $colour = 'Magenta' }
    }

    Write-Host ('{0} {1} : {2}' -f $tag, $Check, $Detail) -ForegroundColor $colour

    if (-not [string]::IsNullOrEmpty($Why)) {
        Write-Host ('  WHY> {0}' -f $Why) -ForegroundColor DarkGray
    }

    if ($null -ne $Fix) {
        foreach ($fixLine in $Fix) {
            if ([string]::IsNullOrEmpty($fixLine)) { continue }
            Write-Host ('  FIX> {0}' -f $fixLine) -ForegroundColor Cyan
        }
    }

    $record = [PSCustomObject]@{
        Timestamp = (Get-Date)
        Module    = $script:ADTCurrentModule
        Check     = $Check
        Status    = $Status
        Detail    = $Detail
        Why       = $Why
        Fix       = $Fix
        Data      = $Data
    }
    $script:ADTResults += $record
}

function Write-ADTSection {
    <#
        .SYNOPSIS
            Visual separator between groups of checks. Not a result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title
    )

    $rule = '-' * 76
    Write-Host ''
    Write-Host $rule -ForegroundColor DarkCyan
    Write-Host ('  ' + $Title) -ForegroundColor Cyan
    Write-Host $rule -ForegroundColor DarkCyan
}

function Write-ADTNote {
    <#
        .SYNOPSIS
            Neutral commentary line. Not a result, never counted in the summary.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    Write-Host ('       ' + $Text) -ForegroundColor DarkGray
}

#endregion

#region Helpers

function Invoke-ADTNative {
    <#
        .SYNOPSIS
            Run an external executable and capture its output. Never throws.
        .OUTPUTS
            Hashtable with ExitCode, StdOut and StdErr. ExitCode -1 means ADT could not
            start the process at all; -2 means it was killed after the timeout.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Arguments,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 60
    )

    $result = @{ ExitCode = -1; StdOut = ''; StdErr = '' }
    $process = $null

    try {
        $argLine = ''
        if ($null -ne $Arguments) {
            $parts = @()
            foreach ($argument in $Arguments) {
                if ($null -eq $argument) { continue }
                $text = [string]$argument
                $alreadyQuoted = ($text.Length -gt 1 -and $text.StartsWith('"') -and $text.EndsWith('"'))
                if ($text -match '\s' -and -not $alreadyQuoted) {
                    $parts += ('"' + $text + '"')
                }
                else {
                    $parts += $text
                }
            }
            $argLine = ($parts -join ' ')
        }

        $startInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
        $startInfo.FileName               = $FilePath
        $startInfo.Arguments              = $argLine
        $startInfo.UseShellExecute        = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError  = $true
        $startInfo.CreateNoWindow         = $true

        $process = New-Object -TypeName System.Diagnostics.Process
        $process.StartInfo = $startInfo
        $null = $process.Start()

        # Both streams are read asynchronously. Reading one to the end synchronously can
        # deadlock once the other stream fills its pipe buffer. ReadToEndAsync is .NET 4.5,
        # which Windows PowerShell 5.1 always has.
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()

        $timeoutMs = $TimeoutSec * 1000
        if ($timeoutMs -lt 1000) { $timeoutMs = 1000 }

        if ($process.WaitForExit($timeoutMs)) {
            $process.WaitForExit()
            $result.ExitCode = $process.ExitCode
        }
        else {
            try { $process.Kill() } catch { $null = $_ }
            $result.ExitCode = -2
            $result.StdErr = ('ADT: timed out after {0} second(s).' -f $TimeoutSec)
        }

        try { $null = $outTask.Wait(5000) } catch { $null = $_ }
        try { $null = $errTask.Wait(5000) } catch { $null = $_ }
        try {
            if ($outTask.IsCompleted) { $result.StdOut = [string]$outTask.Result }
        }
        catch { $null = $_ }
        try {
            if ($errTask.IsCompleted) {
                $stdErrText = [string]$errTask.Result
                if (-not [string]::IsNullOrEmpty($stdErrText)) { $result.StdErr = $stdErrText }
            }
        }
        catch { $null = $_ }
    }
    catch {
        $result.ExitCode = -1
        $result.StdErr = $_.Exception.Message
    }
    finally {
        if ($null -ne $process) {
            try { $process.Dispose() } catch { $null = $_ }
        }
    }

    return $result
}

function Test-ADTPort {
    <#
        .SYNOPSIS
            Async TCP connect test with a hard timeout. PS 5.1 safe. Returns $true or $false.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [int]$Port,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutMs = 2000
    )

    $open = $false
    $client = $null

    try {
        $client = New-Object -TypeName System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            try {
                $client.EndConnect($async)
                $open = $true
            }
            catch {
                $open = $false
            }
        }
    }
    catch {
        $open = $false
    }
    finally {
        if ($null -ne $client) {
            try { $client.Close() } catch { $null = $_ }
        }
    }

    return $open
}

function Confirm-ADTAction {
    <#
        .SYNOPSIS
            y/N confirmation gate. ALWAYS returns $false when running non-interactively.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt
    )

    if ($script:ADTNonInteractive) {
        return $false
    }

    $answer = Read-Host -Prompt ($Prompt + ' [y/N]')
    if ($null -eq $answer) { return $false }
    return ($answer.Trim() -match '^[Yy]([Ee][Ss])?$')
}

function Initialize-ADTFolder {
    <#
        .SYNOPSIS
            Create a folder under the ADT tree on demand, quietly. Sanctioned write.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            $null = New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
        }
        return $true
    }
    catch {
        return $false
    }
}

function Get-ADTToolsPath {
    <#
        .SYNOPSIS
            Path to the Tools folder next to the launcher. Created on first use.
    #>
    [CmdletBinding()]
    param()

    $path = Join-Path -Path $script:ADTRoot -ChildPath 'Tools'
    $null = Initialize-ADTFolder -Path $path
    return $path
}

function Get-ADTLogsPath {
    <#
        .SYNOPSIS
            Path to the Logs folder next to the launcher. Created on first use.
    #>
    [CmdletBinding()]
    param()

    $path = Join-Path -Path $script:ADTRoot -ChildPath 'Logs'
    $null = Initialize-ADTFolder -Path $path
    return $path
}

function Enable-ADTTls12 {
    <#
        .SYNOPSIS
            Force TLS 1.2 for this process only. Required before any PowerShell Gallery or
            https download, because Windows PowerShell 5.1 does not enable TLS 1.2 by default.
    #>
    [CmdletBinding()]
    param()

    try {
        $current = [Net.ServicePointManager]::SecurityProtocol
        [Net.ServicePointManager]::SecurityProtocol = $current -bor [Net.SecurityProtocolType]::Tls12
        return $true
    }
    catch {
        return $false
    }
}

function Get-ADTWmi {
    <#
        .SYNOPSIS
            Fetch a single WMI/CIM instance, falling back to Get-WmiObject. Never throws.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClassName
    )

    $instance = $null
    try {
        $instance = Get-CimInstance -ClassName $ClassName -ErrorAction Stop
    }
    catch {
        try {
            $instance = Get-WmiObject -Class $ClassName -ErrorAction Stop
        }
        catch {
            $instance = $null
        }
    }

    if ($instance -is [System.Array]) {
        if ($instance.Count -gt 0) { return $instance[0] }
        return $null
    }
    return $instance
}

function Test-ADTModuleAvailable {
    <#
        .SYNOPSIS
            Is a PowerShell module present on disk? Never throws.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {
        $found = Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue
        if ($found) { return $true }
    }
    catch {
        return $false
    }
    return $false
}

function Test-ADTSnapinRegistered {
    <#
        .SYNOPSIS
            Is a PSSnapin registered on this machine? Never throws. Windows PowerShell only;
            Get-PSSnapin does not exist on PowerShell 6+, which is handled here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {
        $snapinCmd = Get-Command -Name 'Get-PSSnapin' -ErrorAction SilentlyContinue
        if ($null -eq $snapinCmd) { return $false }
        $snapin = Get-PSSnapin -Registered -Name $Name -ErrorAction SilentlyContinue
        if ($snapin) { return $true }
    }
    catch {
        return $false
    }
    return $false
}

function Test-ADTServicePresent {
    <#
        .SYNOPSIS
            Is a Windows service installed, matched by short name, exact display name, or a
            display-name wildcard? Never throws.
        .DESCRIPTION
            The service list is cached for the run. Get-ADTCapabilities clears the cache
            before every detection pass so a re-detect sees newly installed services.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$Name = @(),

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$DisplayName = @(),

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$DisplayNameLike = @()
    )

    if ($null -eq $script:ADTServiceCache) {
        try {
            $script:ADTServiceCache = @(Get-Service -ErrorAction SilentlyContinue)
        }
        catch {
            $script:ADTServiceCache = @()
        }
    }

    foreach ($service in $script:ADTServiceCache) {
        foreach ($candidate in $Name) {
            if ($service.Name -eq $candidate) { return $true }
        }
        foreach ($candidate in $DisplayName) {
            if ($service.DisplayName -eq $candidate) { return $true }
        }
        foreach ($candidate in $DisplayNameLike) {
            if ($service.DisplayName -like $candidate) { return $true }
        }
    }

    return $false
}

#endregion

#region Capability map

function Get-ADTCapabilities {
    <#
        .SYNOPSIS
            Build the capability map. Cheap, and no probe is allowed to throw.
        .DESCRIPTION
            Writes $script:ADTCaps and also returns it. Only Common writes caps; modules read.
    #>
    [CmdletBinding()]
    param()

    # Every documented key is seeded first, so a probe that fails still leaves a usable map.
    $caps = @{}
    $caps['IsElevated']           = $false
    $caps['PSVersion']            = 0
    $caps['IsPS7']                = $false
    $caps['OSCaption']            = 'Unknown'
    $caps['IsServer']             = $false
    $caps['DomainJoined']         = $false
    $caps['DomainName']           = $null
    $caps['IsDC']                 = $false
    $caps['HasADModule']          = $false
    $caps['HasDnsRole']           = $false
    $caps['HasDnsModule']         = $false
    $caps['HasDhcpRole']          = $false
    $caps['HasDhcpModule']        = $false
    $caps['HasExchangeShell']     = $false
    $caps['ExchangeVersion']      = $null
    $caps['CitrixDDC']            = $false
    $caps['CitrixVDA']            = $false
    $caps['CitrixStoreFront']     = $false
    $caps['CitrixCloudConnector'] = $false
    $caps['HasCitrixSnapin']      = $false
    $caps['HasGraphModule']       = $false
    $caps['HasAzModule']          = $false
    $caps['HasEXOModule']         = $false
    $caps['HasInternet']          = $false

    # Force one fresh service enumeration for this detection pass.
    $script:ADTServiceCache = $null

    # --- Elevation -------------------------------------------------------------------
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
        $caps['IsElevated'] = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        $caps['IsElevated'] = $false
    }

    # --- PowerShell ------------------------------------------------------------------
    try {
        $caps['PSVersion'] = [int]$PSVersionTable.PSVersion.Major
        $caps['IsPS7'] = ([int]$PSVersionTable.PSVersion.Major -ge 7)
    }
    catch {
        $caps['PSVersion'] = 0
    }

    # --- Operating system ------------------------------------------------------------
    # Win32_OperatingSystem.ProductType: 1 Work Station, 2 Domain Controller, 3 Server.
    try {
        $os = Get-ADTWmi -ClassName 'Win32_OperatingSystem'
        if ($null -ne $os) {
            if ($os.Caption) { $caps['OSCaption'] = ([string]$os.Caption).Trim() }
            $productType = 0
            if ($null -ne $os.ProductType) { $productType = [int]$os.ProductType }
            $caps['IsServer'] = ($productType -eq 2 -or $productType -eq 3)
        }
    }
    catch {
        $null = $_
    }

    # --- Domain membership and DC role -----------------------------------------------
    # Win32_ComputerSystem.DomainRole: 4 Backup Domain Controller, 5 Primary Domain Controller.
    try {
        $cs = Get-ADTWmi -ClassName 'Win32_ComputerSystem'
        if ($null -ne $cs) {
            if ($null -ne $cs.PartOfDomain) { $caps['DomainJoined'] = [bool]$cs.PartOfDomain }
            if ($caps['DomainJoined'] -and $cs.Domain) { $caps['DomainName'] = [string]$cs.Domain }
            $domainRole = -1
            if ($null -ne $cs.DomainRole) { $domainRole = [int]$cs.DomainRole }
            $caps['IsDC'] = (@(4, 5) -contains $domainRole)
        }
    }
    catch {
        $null = $_
    }

    # --- Management modules ----------------------------------------------------------
    try { $caps['HasADModule']   = Test-ADTModuleAvailable -Name 'ActiveDirectory' } catch { $null = $_ }
    try { $caps['HasDnsModule']  = Test-ADTModuleAvailable -Name 'DnsServer' }       catch { $null = $_ }
    try { $caps['HasDhcpModule'] = Test-ADTModuleAvailable -Name 'DhcpServer' }      catch { $null = $_ }

    # --- Server roles ----------------------------------------------------------------
    # The DNS Server service short name 'DNS' is confirmed on Microsoft Learn
    # (Get-Service DNS, net start DNS, Restart-Service -Name DNS).
    try {
        $caps['HasDnsRole'] = Test-ADTServicePresent -Name @('DNS') -DisplayName @('DNS Server')
    }
    catch {
        $null = $_
    }
    # UNVERIFIED: the DHCP Server service short name 'DHCPServer' is not stated on Microsoft
    # Learn. The display name 'DHCP Server' is matched too, so detection holds either way.
    try {
        $caps['HasDhcpRole'] = Test-ADTServicePresent -Name @('DHCPServer') -DisplayName @('DHCP Server')
    }
    catch {
        $null = $_
    }

    # --- Exchange on-premises --------------------------------------------------------
    # Snap-in names confirmed on Microsoft Learn:
    #   Microsoft.Exchange.Management.PowerShell.SnapIn  (Exchange 2013 and later)
    #   Microsoft.Exchange.Management.PowerShell.E2010   (Exchange 2010)
    # The version is read from ExSetup.exe under %ExchangeInstallPath%, which is the method
    # Microsoft documents for reading an Exchange build number.
    try {
        foreach ($snapinName in @('Microsoft.Exchange.Management.PowerShell.SnapIn',
                                  'Microsoft.Exchange.Management.PowerShell.E2010')) {
            if (Test-ADTSnapinRegistered -Name $snapinName) { $caps['HasExchangeShell'] = $true }
        }

        $exchangeRoot = $env:ExchangeInstallPath
        if (-not [string]::IsNullOrEmpty($exchangeRoot)) {
            $exSetup = Join-Path -Path $exchangeRoot -ChildPath 'bin\ExSetup.exe'
            if (Test-Path -LiteralPath $exSetup) {
                $caps['HasExchangeShell'] = $true
                $versionInfo = (Get-Item -LiteralPath $exSetup -ErrorAction Stop).VersionInfo
                if ($null -ne $versionInfo -and $versionInfo.ProductVersion) {
                    $caps['ExchangeVersion'] = [string]$versionInfo.ProductVersion
                }
            }
        }
    }
    catch {
        $null = $_
    }

    # --- Citrix ----------------------------------------------------------------------
    # Delivery Controller. Citrix documents the Broker as a Windows service running on a
    # Delivery Controller, and its display name as 'Citrix Broker Service'.
    # UNVERIFIED: the short name 'CitrixBrokerService' is not stated in Citrix docs; it is
    # matched in addition to the display name so detection works either way.
    try {
        $caps['CitrixDDC'] = Test-ADTServicePresent -Name @('CitrixBrokerService') -DisplayName @('Citrix Broker Service')
    }
    catch {
        $null = $_
    }

    # VDA. Citrix documents 'net stop brokeragent' / 'net start brokeragent' as the way to
    # restart the Citrix Desktop Service, so both short name and display name are known good.
    try {
        $caps['CitrixVDA'] = Test-ADTServicePresent -Name @('BrokerAgent') -DisplayName @('Citrix Desktop Service')
    }
    catch {
        $null = $_
    }

    # StoreFront. The install path 'Citrix\Receiver StoreFront' is documented by Citrix as
    # the location of the StoreFront diagnostics trace folder, so it is the reliable anchor.
    try {
        $storeFrontFound = $false
        foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
            if ([string]::IsNullOrEmpty($base)) { continue }
            $sfPath = Join-Path -Path $base -ChildPath 'Citrix\Receiver StoreFront'
            if (Test-Path -LiteralPath $sfPath) { $storeFrontFound = $true }
        }
        if (-not $storeFrontFound) {
            # UNVERIFIED: Citrix does not publish an exact list of StoreFront service names,
            # so these display-name prefixes come from Citrix troubleshooting articles.
            $sfPatterns = @(
                'Citrix Subscriptions Store*',
                'Citrix Credential Wallet*',
                'Citrix Default Domain Services*',
                'Citrix Peer Resolution*',
                'Citrix Configuration Replication*'
            )
            $storeFrontFound = Test-ADTServicePresent -DisplayNameLike $sfPatterns
        }
        $caps['CitrixStoreFront'] = $storeFrontFound
    }
    catch {
        $null = $_
    }

    # Cloud Connector. These three display names are taken verbatim from the Citrix Cloud
    # Connector Technical Details table of installed services. The ProgramData path is the
    # Cloud Connector log directory Citrix documents.
    try {
        $ccDisplayNames = @(
            'Citrix Remote Broker Provider',
            'Citrix Cloud Services Agent WatchDog',
            'Citrix Config Synchronizer Service'
        )
        $connectorFound = Test-ADTServicePresent -DisplayName $ccDisplayNames
        if (-not $connectorFound -and -not [string]::IsNullOrEmpty($env:ProgramData)) {
            $connectorPath = Join-Path -Path $env:ProgramData -ChildPath 'Citrix\WorkspaceCloud'
            if (Test-Path -LiteralPath $connectorPath) { $connectorFound = $true }
        }
        $caps['CitrixCloudConnector'] = $connectorFound
    }
    catch {
        $null = $_
    }

    # Citrix PowerShell surface: snap-ins on an on-premises DDC, modules for the Remote SDK.
    try {
        $citrixPs = $false
        $snapinCmd = Get-Command -Name 'Get-PSSnapin' -ErrorAction SilentlyContinue
        if ($null -ne $snapinCmd) {
            $citrixSnapins = Get-PSSnapin -Registered -ErrorAction SilentlyContinue |
                             Where-Object { $_.Name -like 'Citrix.*' }
            if ($citrixSnapins) { $citrixPs = $true }
        }
        if (-not $citrixPs) {
            $citrixModules = Get-Module -ListAvailable -Name 'Citrix.*' -ErrorAction SilentlyContinue
            if ($citrixModules) { $citrixPs = $true }
        }
        $caps['HasCitrixSnapin'] = $citrixPs
    }
    catch {
        $null = $_
    }

    # --- Cloud modules ---------------------------------------------------------------
    # Microsoft.Graph.Authentication is the module Microsoft documents as always required
    # when Graph sub-modules are installed individually.
    try { $caps['HasGraphModule'] = Test-ADTModuleAvailable -Name 'Microsoft.Graph.Authentication' } catch { $null = $_ }
    try { $caps['HasAzModule']    = Test-ADTModuleAvailable -Name 'Az.Accounts' }                    catch { $null = $_ }
    try { $caps['HasEXOModule']   = Test-ADTModuleAvailable -Name 'ExchangeOnlineManagement' }       catch { $null = $_ }

    # --- Internet --------------------------------------------------------------------
    # Cheap TCP 443 probe first. If that fails, one short proxy-aware https request, because
    # a proxied site blocks direct 443 while https through the proxy still works.
    try {
        $null = Enable-ADTTls12
        $reachable = Test-ADTPort -ComputerName 'www.microsoft.com' -Port 443 -TimeoutMs 2000
        if (-not $reachable) {
            $reachable = Test-ADTPort -ComputerName 'login.microsoftonline.com' -Port 443 -TimeoutMs 2000
        }
        if (-not $reachable) {
            $savedProgress = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            try {
                $probe = Invoke-WebRequest -Uri 'https://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                if ($null -ne $probe -and $probe.StatusCode -eq 200) { $reachable = $true }
            }
            catch {
                $reachable = $false
            }
            finally {
                $ProgressPreference = $savedProgress
            }
        }
        $caps['HasInternet'] = $reachable
    }
    catch {
        $caps['HasInternet'] = $false
    }

    $script:ADTCaps = $caps
    return $caps
}

#endregion

#region Module registration

function Register-ADTModule {
    <#
        .SYNOPSIS
            Register a module's menu items. Called once at the bottom of every module file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('ON-PREM', 'CLOUD', 'TOOLS')]
        [string]$Group,

        [Parameter(Mandatory = $true)]
        [object[]]$Items
    )

    $normalised = @()

    foreach ($item in $Items) {
        if ($null -eq $item) { continue }

        $label    = $null
        $function = $null
        $requires = @()
        $snapshot = $false

        if ($item -is [System.Collections.IDictionary]) {
            if ($item.Contains('Label'))    { $label    = [string]$item['Label'] }
            if ($item.Contains('Function')) { $function = [string]$item['Function'] }
            if ($item.Contains('Requires') -and $null -ne $item['Requires']) { $requires = @($item['Requires']) }
            if ($item.Contains('Snapshot')) { $snapshot = [bool]$item['Snapshot'] }
        }
        else {
            $properties = $item.PSObject.Properties
            if ($properties['Label'])    { $label    = [string]$item.Label }
            if ($properties['Function']) { $function = [string]$item.Function }
            if ($properties['Requires'] -and $null -ne $item.Requires) { $requires = @($item.Requires) }
            if ($properties['Snapshot']) { $snapshot = [bool]$item.Snapshot }
        }

        if ([string]::IsNullOrEmpty($label) -or [string]::IsNullOrEmpty($function)) {
            Write-Host ('[WARN] Register-ADTModule: skipped a malformed item in module "' + $Name + '".') -ForegroundColor Yellow
            continue
        }

        $normalised += [PSCustomObject]@{
            Label    = $label
            Function = $function
            Requires = @($requires)
            Snapshot = $snapshot
        }
    }

    $script:ADTModules += [PSCustomObject]@{
        Name  = $Name
        Group = $Group
        Items = @($normalised)
    }
}

#endregion

#region Prerequisite manager

function Get-ADTPrereqDefinition {
    <#
        .SYNOPSIS
            Internal table of everything Install-ADTPrereq knows how to fetch.
        .DESCRIPTION
            RSAT capability names are the Feature on Demand names Microsoft publishes.
            Server feature names are candidates: Install-ADTPrereq resolves the first one
            that Get-WindowsFeature actually reports on the box rather than guessing.
    #>
    [CmdletBinding()]
    param()

    return @(
        [PSCustomObject]@{
            Name        = 'RSAT-AD'
            Kind        = 'RSAT'
            Modules     = @('ActiveDirectory')
            Capability  = 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
            Features    = @('RSAT-AD-PowerShell', 'RSAT-AD-Tools', 'RSAT-ADDS-Tools')
            InstallHint = 'Client: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 | Server: Install-WindowsFeature -Name RSAT-AD-PowerShell'
        }
        [PSCustomObject]@{
            Name        = 'RSAT-DNS'
            Kind        = 'RSAT'
            Modules     = @('DnsServer')
            Capability  = 'Rsat.Dns.Tools~~~~0.0.1.0'
            Features    = @('RSAT-DNS-Server')
            InstallHint = 'Client: Add-WindowsCapability -Online -Name Rsat.Dns.Tools~~~~0.0.1.0 | Server: Install-WindowsFeature -Name RSAT-DNS-Server'
        }
        [PSCustomObject]@{
            Name        = 'RSAT-DHCP'
            Kind        = 'RSAT'
            Modules     = @('DhcpServer')
            Capability  = 'Rsat.DHCP.Tools~~~~0.0.1.0'
            Features    = @('RSAT-DHCP')
            InstallHint = 'Client: Add-WindowsCapability -Online -Name Rsat.DHCP.Tools~~~~0.0.1.0 | Server: Install-WindowsFeature -Name RSAT-DHCP'
        }
        [PSCustomObject]@{
            Name        = 'RSAT-GPMC'
            Kind        = 'RSAT'
            Modules     = @('GroupPolicy')
            Capability  = 'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
            Features    = @('GPMC')
            InstallHint = 'Client: Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0 | Server: Install-WindowsFeature -Name GPMC'
        }
        [PSCustomObject]@{
            Name        = 'GraphModule'
            Kind        = 'PSModule'
            Modules     = @(
                'Microsoft.Graph.Authentication',
                'Microsoft.Graph.Identity.DirectoryManagement',
                'Microsoft.Graph.Identity.SignIns',
                'Microsoft.Graph.Users',
                'Microsoft.Graph.Groups',
                'Microsoft.Graph.Applications',
                'Microsoft.Graph.Reports',
                'Microsoft.Graph.Devices.ServiceAnnouncement'
            )
            Capability  = $null
            Features    = @()
            InstallHint = 'Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force, plus the named sub-modules. Do NOT install the Microsoft.Graph rollup on a field machine.'
        }
        [PSCustomObject]@{
            Name        = 'AzModule'
            Kind        = 'PSModule'
            Modules     = @('Az.Accounts', 'Az.Resources', 'Az.Compute', 'Az.Network')
            Capability  = $null
            Features    = @()
            InstallHint = 'Install-Module Az.Accounts,Az.Resources,Az.Compute,Az.Network -Scope CurrentUser -Force. The full Az rollup is deliberately avoided on field machines.'
        }
        [PSCustomObject]@{
            Name        = 'EXOModule'
            Kind        = 'PSModule'
            Modules     = @('ExchangeOnlineManagement')
            Capability  = $null
            Features    = @()
            InstallHint = 'Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force'
        }
        [PSCustomObject]@{
            Name        = 'CitrixRemoteSDK'
            Kind        = 'Installer'
            Modules     = @('Citrix.Broker.Admin.V2')
            Capability  = $null
            Features    = @()
            InstallHint = 'Download the Citrix Remote PowerShell SDK from Manage > Downloads in the Citrix Cloud console, then run the installer manually.'
        }
    )
}

function Get-ADTPrereqStatus {
    <#
        .SYNOPSIS
            Report whether one prerequisite, or all of them, is installed.
        .OUTPUTS
            PSCustomObject with Name, Installed, Version and InstallHint.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Name
    )

    $definitions = @(Get-ADTPrereqDefinition)
    if (-not [string]::IsNullOrEmpty($Name)) {
        $definitions = @($definitions | Where-Object { $_.Name -eq $Name })
    }

    $output = @()

    foreach ($definition in $definitions) {
        $installed = $false
        $version   = $null

        foreach ($moduleName in $definition.Modules) {
            try {
                $found = Get-Module -ListAvailable -Name $moduleName -ErrorAction SilentlyContinue
                if ($found) {
                    $installed = $true
                    if ($null -eq $version) {
                        $newest = $found | Sort-Object -Property Version -Descending | Select-Object -First 1
                        if ($null -ne $newest -and $null -ne $newest.Version) {
                            $version = $newest.Version.ToString()
                        }
                    }
                }
            }
            catch {
                $null = $_
            }
        }

        # The Citrix Remote PowerShell SDK registers snap-ins, not modules, on Windows PowerShell.
        if (-not $installed -and $definition.Kind -eq 'Installer') {
            try {
                $snapinCmd = Get-Command -Name 'Get-PSSnapin' -ErrorAction SilentlyContinue
                if ($null -ne $snapinCmd) {
                    # UNVERIFIED: Citrix does not publish the exact snap-in name list installed by
                    # the Remote PowerShell SDK, so this matches the Broker admin snap-in family.
                    $sdkSnapins = Get-PSSnapin -Registered -ErrorAction SilentlyContinue |
                                  Where-Object { $_.Name -like 'Citrix.Broker.Admin*' }
                    if ($sdkSnapins) {
                        $installed = $true
                        $first = $sdkSnapins | Select-Object -First 1
                        if ($null -ne $first -and $null -ne $first.Version) {
                            $version = $first.Version.ToString()
                        }
                    }
                }
            }
            catch {
                $null = $_
            }
        }

        $output += [PSCustomObject]@{
            Name        = $definition.Name
            Installed   = $installed
            Version     = $version
            InstallHint = $definition.InstallHint
        }
    }

    return $output
}

function Install-ADTPrereq {
    <#
        .SYNOPSIS
            Install one prerequisite. Confirm-gated, and the ONLY function in ADT that
            installs anything. It never changes the target environment's configuration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('RSAT-AD', 'RSAT-DNS', 'RSAT-DHCP', 'RSAT-GPMC',
                     'GraphModule', 'AzModule', 'EXOModule', 'CitrixRemoteSDK')]
        [string]$Name
    )

    $checkName = 'Prerequisite: ' + $Name

    try {
        if ($null -eq $script:ADTCaps -or $script:ADTCaps.Count -eq 0) {
            $null = Get-ADTCapabilities
        }

        $definition = Get-ADTPrereqDefinition | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
        if ($null -eq $definition) {
            Write-ADTResult -Check $checkName -Status ERROR -Detail 'No definition found for that prerequisite.'
            return
        }

        $status = Get-ADTPrereqStatus -Name $Name | Select-Object -First 1
        if ($null -ne $status -and $status.Installed) {
            $detail = 'Already installed'
            if ($status.Version) { $detail = $detail + ' (version ' + $status.Version + ')' }
            Write-ADTResult -Check $checkName -Status INFO -Detail $detail
            return
        }

        # ---- Citrix Remote SDK: no verifiable download URL, so say where to get it. ----
        if ($definition.Kind -eq 'Installer') {
            $sdkFix = @(
                'Sign in to https://citrix.cloud.com, open Manage > Downloads for Citrix DaaS, and download the Citrix Remote PowerShell SDK (CitrixPoshSdk.exe).',
                'On-premises alternative: the same SDK ships on the Citrix Virtual Apps and Desktops ISO under x64\Citrix Desktop Delivery Controller.',
                'Run the installer on this machine, then re-run ADT so the snap-ins are detected.'
            )
            $sdkWhy = 'Citrix does not publish a stable, versionless direct download URL, and guessing one would be worse than saying so.'
            Write-ADTResult -Check $checkName -Status SKIP -Detail 'ADT will not download the Citrix Remote PowerShell SDK.' -Why $sdkWhy -Fix $sdkFix
            return
        }

        if (-not (Confirm-ADTAction -Prompt ('Install prerequisite "' + $Name + '" on this machine now?'))) {
            Write-ADTResult -Check $checkName -Status SKIP -Detail 'Not confirmed; nothing was installed.' -Fix @($definition.InstallHint)
            return
        }

        # ---- RSAT -----------------------------------------------------------------------
        if ($definition.Kind -eq 'RSAT') {
            if (-not $script:ADTCaps['IsElevated']) {
                $elevWhy = 'Add-WindowsCapability and Install-WindowsFeature both require local administrator rights.'
                Write-ADTResult -Check $checkName -Status FAIL -Detail 'RSAT installation needs an elevated session.' -Why $elevWhy -Fix @('Re-run ADT from an elevated PowerShell session, then choose this prerequisite again.')
                return
            }

            if ($script:ADTCaps['IsServer']) {
                $installCmd = Get-Command -Name 'Install-WindowsFeature' -ErrorAction SilentlyContinue
                if ($null -eq $installCmd) {
                    $noSmWhy = 'The ServerManager module is missing, so ADT cannot install a server feature here.'
                    Write-ADTResult -Check $checkName -Status FAIL -Detail 'Install-WindowsFeature is not available on this server.' -Why $noSmWhy -Fix @($definition.InstallHint)
                    return
                }

                $featureName = $null
                foreach ($candidate in $definition.Features) {
                    try {
                        $feature = Get-WindowsFeature -Name $candidate -ErrorAction SilentlyContinue
                        if ($null -ne $feature) {
                            $featureName = $candidate
                            break
                        }
                    }
                    catch {
                        $null = $_
                    }
                }

                if ($null -eq $featureName) {
                    $noFeatWhy = 'Feature names vary between Windows Server releases, and ADT will not install a feature it cannot confirm exists on this box.'
                    $noFeatFix = @('Get-WindowsFeature -Name RSAT*', $definition.InstallHint)
                    $noFeatDetail = 'No matching Windows feature found. Tried: ' + ($definition.Features -join ', ')
                    Write-ADTResult -Check $checkName -Status FAIL -Detail $noFeatDetail -Why $noFeatWhy -Fix $noFeatFix
                    return
                }

                Write-ADTNote -Text ('Installing Windows feature ' + $featureName + ' ...')
                $outcome = Install-WindowsFeature -Name $featureName -ErrorAction Stop
                $restartNote = ''
                if ($null -ne $outcome -and $null -ne $outcome.RestartNeeded -and ([string]$outcome.RestartNeeded) -ne 'No') {
                    $restartNote = ' A restart is pending.'
                }
                Write-ADTResult -Check $checkName -Status PASS -Detail ('Installed Windows feature ' + $featureName + '.' + $restartNote) -Data $outcome
                return
            }
            else {
                $capabilityCmd = Get-Command -Name 'Add-WindowsCapability' -ErrorAction SilentlyContinue
                if ($null -eq $capabilityCmd) {
                    $noCapWhy = 'RSAT as a Feature on Demand needs Windows 10 version 1809 or later; older clients need the downloadable RSAT package.'
                    Write-ADTResult -Check $checkName -Status FAIL -Detail 'Add-WindowsCapability is not available on this client.' -Why $noCapWhy -Fix @('Download RSAT from https://www.microsoft.com/download/details.aspx?id=45520 and install it manually.')
                    return
                }

                Write-ADTNote -Text ('Adding Windows capability ' + $definition.Capability + ' ...')
                $outcome = Add-WindowsCapability -Online -Name $definition.Capability -ErrorAction Stop
                $restartNote = ''
                if ($null -ne $outcome -and $outcome.RestartNeeded) { $restartNote = ' A restart is pending.' }
                Write-ADTResult -Check $checkName -Status PASS -Detail ('Added Windows capability ' + $definition.Capability + '.' + $restartNote) -Data $outcome
                return
            }
        }

        # ---- PowerShell modules ---------------------------------------------------------
        if ($definition.Kind -eq 'PSModule') {
            if (-not (Enable-ADTTls12)) {
                $tlsWhy = 'The PowerShell Gallery requires TLS 1.2, and Windows PowerShell 5.1 does not enable it by default.'
                Write-ADTResult -Check $checkName -Status FAIL -Detail 'Could not enable TLS 1.2 for this session.' -Why $tlsWhy -Fix @('[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12')
                return
            }

            if (-not (Test-ADTPort -ComputerName 'www.powershellgallery.com' -Port 443 -TimeoutMs 4000)) {
                $gallWhy = 'This machine cannot open an outbound HTTPS connection to www.powershellgallery.com, so Install-Module would fail.'
                $gallFix = @(
                    'Test-NetConnection www.powershellgallery.com -Port 443',
                    'Behind a proxy: [Net.WebRequest]::DefaultWebProxy = New-Object Net.WebProxy("http://PROXY:PORT"); [Net.WebRequest]::DefaultWebProxy.Credentials = [Net.CredentialCache]::DefaultCredentials',
                    'Otherwise copy the module folder onto this machine from a connected workstation.'
                )
                Write-ADTResult -Check $checkName -Status FAIL -Detail 'The PowerShell Gallery is not reachable on TCP 443.' -Why $gallWhy -Fix $gallFix
                return
            }

            $installCmd = Get-Command -Name 'Install-Module' -ErrorAction SilentlyContinue
            if ($null -eq $installCmd) {
                Write-ADTResult -Check $checkName -Status FAIL -Detail 'Install-Module is not available.' -Why 'PowerShellGet is missing on this machine.' -Fix @('Install PowerShellGet first: https://learn.microsoft.com/powershell/scripting/gallery/installing-psget')
                return
            }

            $succeeded = @()
            $failed = @()

            foreach ($moduleName in $definition.Modules) {
                if (Test-ADTModuleAvailable -Name $moduleName) {
                    $succeeded += ($moduleName + ' (already present)')
                    continue
                }
                Write-ADTNote -Text ('Installing module ' + $moduleName + ' for the current user ...')
                try {
                    Install-Module -Name $moduleName -Scope CurrentUser -Force -Repository PSGallery -ErrorAction Stop
                    $succeeded += $moduleName
                }
                catch {
                    $failed += ($moduleName + ': ' + $_.Exception.Message)
                }
            }

            if ($failed.Count -eq 0) {
                Write-ADTResult -Check $checkName -Status PASS -Detail ('Installed for the current user: ' + ($succeeded -join ', ')) -Data $succeeded
            }
            else {
                $moduleTotal = @($definition.Modules).Count
                $failDetail = [string]$failed.Count + ' of ' + [string]$moduleTotal + ' module(s) failed to install.'
                Write-ADTResult -Check $checkName -Status FAIL -Detail $failDetail -Why ($failed -join ' | ') -Fix @($definition.InstallHint) -Data $failed
            }
            return
        }

        Write-ADTResult -Check $checkName -Status ERROR -Detail ('Unhandled prerequisite kind: ' + $definition.Kind)
    }
    catch {
        Write-ADTResult -Check $checkName -Status ERROR -Detail $_.Exception.Message -Fix @('Run the documented install command by hand, then re-run ADT.')
    }
}

#endregion
