# ADT.Discovery.ps1 - environment discovery for an unknown box (local) and its domain.
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.

#region Private helpers

function Get-ADTDiscoveryWmiList {
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

function ConvertTo-ADTDiscoveryDateTime {
    <#
        .SYNOPSIS
            Normalise a WMI date value to [DateTime]. Get-CimInstance already returns a .NET
            DateTime; Get-WmiObject returns a raw WMI datetime string that needs converting.
            Never throws.
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

function Format-ADTDiscoveryBytes {
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

function Get-ADTDiscoveryServicesLike {
    <#
        .SYNOPSIS
            Get-Service against one or more name patterns (wildcards allowed). Never throws.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Pattern
    )

    if ($Pattern.Count -eq 0) { return @() }

    try {
        return @(Get-Service -Name $Pattern -ErrorAction SilentlyContinue)
    }
    catch {
        return @()
    }
}

function Get-ADTDiscoveryPendingReboot {
    <#
        .SYNOPSIS
            Check the three standard pending-reboot registry indicators.
        .DESCRIPTION
            Verified on Microsoft Learn ("List of prerequisite checks for Configuration Manager",
            section "Pending system restart on the remote SQL Server"):
              HKLM:Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending
              HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired
              HKLM:SYSTEM\CurrentControlSet\Control\Session Manager, PendingFileRenameOperations
            The same three indicators are echoed in several other Learn troubleshooting articles.
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

function Get-ADTDiscoveryRootDse {
    <#
        .SYNOPSIS
            Get-ADRootDSE, wrapped. Returns $null instead of throwing.
        .DESCRIPTION
            Verified on Microsoft Learn: Get-ADRootDSE returns configurationNamingContext and
            defaultNamingContext among other rootDSE attributes.
    #>
    [CmdletBinding()]
    param()

    try {
        return Get-ADRootDSE -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Get-ADTDiscoveryAvEdrCatalog {
    <#
        .SYNOPSIS
            Common third-party EDR/AV Windows service probe list.
        .DESCRIPTION
            Name is an exact short service name; DisplayNameLike is a wildcard fallback checked
            through Test-ADTServicePresent. Verified=$true entries were confirmed by web search
            this session (source noted per line); Verified=$false entries were not confirmed this
            session and rely only on the DisplayNameLike wildcard as a safety net - treat a miss
            on those as inconclusive, not as proof the product is absent.
    #>
    [CmdletBinding()]
    param()

    return @(
        [PSCustomObject]@{ Product = 'Microsoft Defender for Endpoint (sensor)'; Name = @('Sense');            DisplayNameLike = @();                                Verified = $true }  # Learn: defender-endpoint/mde-sap-windows-server, "Get-Service -Name sense"
        [PSCustomObject]@{ Product = 'CrowdStrike Falcon';                       Name = @('CSFalconService');   DisplayNameLike = @();                                Verified = $true }  # web search: CrowdStrike's own falcon-windows-repair scripts use this name
        [PSCustomObject]@{ Product = 'SentinelOne';                              Name = @();                    DisplayNameLike = @('SentinelOne*', 'Sentinel Agent*'); Verified = $false } # UNVERIFIED: exact short service name not confirmed this session
        [PSCustomObject]@{ Product = 'Sophos';                                   Name = @('SEDService');        DisplayNameLike = @('Sophos*');                       Verified = $true }  # web search: "Sophos Endpoint Defense Service" = SEDService.exe
        [PSCustomObject]@{ Product = 'Trend Micro Apex One / OfficeScan';        Name = @('ntrtscan');          DisplayNameLike = @('Trend Micro*');                  Verified = $false } # UNVERIFIED: ntrtscan.exe process confirmed, service short name assumed equal
        [PSCustomObject]@{ Product = 'Symantec / Broadcom Endpoint Protection';  Name = @('SepMasterService');  DisplayNameLike = @('Symantec*');                     Verified = $false } # UNVERIFIED: not confirmed this session
        [PSCustomObject]@{ Product = 'McAfee / Trellix Endpoint Security';       Name = @('macmnsvc', 'masvc'); DisplayNameLike = @('McAfee*', 'Trellix*');           Verified = $false } # UNVERIFIED: not confirmed this session
        [PSCustomObject]@{ Product = 'Malwarebytes';                             Name = @('MBAMService');       DisplayNameLike = @('Malwarebytes*');                 Verified = $true }  # web search: confirmed short service name
        [PSCustomObject]@{ Product = 'ESET';                                     Name = @('ekrn');              DisplayNameLike = @('ESET*');                         Verified = $true }  # web search: ekrn.exe is ESET's core service process
        [PSCustomObject]@{ Product = 'Webroot';                                  Name = @();                    DisplayNameLike = @('Webroot*');                      Verified = $false } # UNVERIFIED: only the WRSA.exe process name was confirmed, not a service short name
        [PSCustomObject]@{ Product = 'Cylance / BlackBerry Protect';             Name = @('CylanceSvc');        DisplayNameLike = @('Cylance*');                      Verified = $false } # UNVERIFIED: not confirmed this session
        [PSCustomObject]@{ Product = 'VMware Carbon Black';                      Name = @();                    DisplayNameLike = @('Carbon Black*', 'CB Defense*');  Verified = $false } # UNVERIFIED: not confirmed this session
        [PSCustomObject]@{ Product = 'Huntress';                                 Name = @('HuntressAgent');     DisplayNameLike = @('Huntress*');                     Verified = $false } # UNVERIFIED: not confirmed this session
        [PSCustomObject]@{ Product = 'Bitdefender GravityZone';                  Name = @();                    DisplayNameLike = @('Bitdefender*', 'EPSecurityService*'); Verified = $false } # UNVERIFIED: not confirmed this session
    )
}

#endregion

#region Local discovery (Item 1) - section helpers

function Invoke-ADTDiscoveryLocalOS {
    [CmdletBinding()]
    param()

    try {
        $os = Get-ADTWmi -ClassName 'Win32_OperatingSystem'
        if ($null -eq $os) {
            Write-ADTResult -Check 'Operating system' -Status ERROR -Detail 'Win32_OperatingSystem returned no data.'
            return
        }

        $caption = 'Unknown'
        if ($os.Caption) { $caption = ([string]$os.Caption).Trim() }
        $build = 'unknown'
        if ($os.BuildNumber) { $build = [string]$os.BuildNumber }
        $version = 'unknown'
        if ($os.Version) { $version = [string]$os.Version }

        Write-ADTResult -Check 'Operating system' -Status INFO -Detail ($caption + ' (build ' + $build + '), version ' + $version)

        $installDate = ConvertTo-ADTDiscoveryDateTime -Value $os.InstallDate
        if ($null -ne $installDate) {
            Write-ADTResult -Check 'Install date' -Status INFO -Detail $installDate.ToString('yyyy-MM-dd')
        }
        else {
            Write-ADTResult -Check 'Install date' -Status INFO -Detail 'Not available.'
        }

        $lastBoot = ConvertTo-ADTDiscoveryDateTime -Value $os.LastBootUpTime
        if ($null -ne $lastBoot) {
            $span = (Get-Date) - $lastBoot
            $uptimeText = [string][int]$span.Days + ' day(s), ' + [string][int]$span.Hours + ' hour(s)'
            Write-ADTResult -Check 'Uptime' -Status INFO -Detail ($uptimeText + ' (last boot ' + $lastBoot.ToString('yyyy-MM-dd HH:mm') + ')')
        }
        else {
            Write-ADTResult -Check 'Uptime' -Status INFO -Detail 'Last boot time not available.'
        }
    }
    catch {
        Write-ADTResult -Check 'Operating system' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTDiscoveryLocalHardware {
    [CmdletBinding()]
    param()

    try {
        $cs = Get-ADTWmi -ClassName 'Win32_ComputerSystem'
        $bios = Get-ADTWmi -ClassName 'Win32_BIOS'

        $manufacturer = 'Unknown'
        $model = 'Unknown'
        if ($null -ne $cs) {
            if ($cs.Manufacturer) { $manufacturer = ([string]$cs.Manufacturer).Trim() }
            if ($cs.Model) { $model = ([string]$cs.Model).Trim() }
        }

        $serial = 'Unknown'
        if ($null -ne $bios -and $bios.SerialNumber) { $serial = ([string]$bios.SerialNumber).Trim() }

        Write-ADTResult -Check 'Hardware' -Status INFO -Detail ($manufacturer + ' ' + $model + ', serial number ' + $serial)
    }
    catch {
        Write-ADTResult -Check 'Hardware' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTDiscoveryLocalCpuRam {
    [CmdletBinding()]
    param()

    try {
        $processors = @(Get-ADTDiscoveryWmiList -ClassName 'Win32_Processor')
        if ($processors.Count -gt 0) {
            $first = $processors[0]
            $cpuName = 'Unknown CPU'
            if ($first.Name) { $cpuName = ([string]$first.Name).Trim() }

            $totalCores = 0
            $totalLogical = 0
            foreach ($proc in $processors) {
                if ($null -ne $proc.NumberOfCores) { $totalCores = $totalCores + [int]$proc.NumberOfCores }
                if ($null -ne $proc.NumberOfLogicalProcessors) { $totalLogical = $totalLogical + [int]$proc.NumberOfLogicalProcessors }
            }

            $cpuDetail = [string]$processors.Count + ' x ' + $cpuName + ' - ' + [string]$totalCores + ' core(s), ' + [string]$totalLogical + ' logical processor(s)'
            Write-ADTResult -Check 'CPU' -Status INFO -Detail $cpuDetail
        }
        else {
            Write-ADTResult -Check 'CPU' -Status INFO -Detail 'Win32_Processor returned no data.'
        }

        $cs = Get-ADTWmi -ClassName 'Win32_ComputerSystem'
        if ($null -ne $cs -and $null -ne $cs.TotalPhysicalMemory) {
            $ramGB = [double]$cs.TotalPhysicalMemory / 1073741824
            $ramText = '{0:N1}' -f $ramGB
            Write-ADTResult -Check 'Memory (installed)' -Status INFO -Detail ($ramText + ' GB total physical memory')
        }
        else {
            Write-ADTResult -Check 'Memory (installed)' -Status INFO -Detail 'Not available.'
        }
    }
    catch {
        Write-ADTResult -Check 'CPU / memory' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTDiscoveryLocalVolumes {
    [CmdletBinding()]
    param()

    try {
        $disks = @(Get-ADTDiscoveryWmiList -ClassName 'Win32_LogicalDisk' | Where-Object { $null -ne $_.DriveType -and [int]$_.DriveType -eq 3 })

        if ($disks.Count -eq 0) {
            Write-ADTResult -Check 'Volumes' -Status INFO -Detail 'No fixed volumes found.'
            return
        }

        foreach ($disk in ($disks | Sort-Object -Property DeviceID)) {
            $sizeBytes = 0.0
            $freeBytes = 0.0
            if ($null -ne $disk.Size) { $sizeBytes = [double]$disk.Size }
            if ($null -ne $disk.FreeSpace) { $freeBytes = [double]$disk.FreeSpace }

            $pctFree = 0.0
            if ($sizeBytes -gt 0) { $pctFree = ($freeBytes / $sizeBytes) * 100 }
            $pctText = '{0:N1}' -f $pctFree

            $sizeText = Format-ADTDiscoveryBytes -Bytes $sizeBytes
            $freeText = Format-ADTDiscoveryBytes -Bytes $freeBytes
            $detail = $sizeText + ' total, ' + $freeText + ' free (' + $pctText + '% free)'

            Write-ADTResult -Check ('Volume ' + [string]$disk.DeviceID) -Status INFO -Detail $detail
        }
    }
    catch {
        Write-ADTResult -Check 'Volumes' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTDiscoveryLocalNetwork {
    [CmdletBinding()]
    param()

    try {
        $adapters = @(Get-ADTDiscoveryWmiList -ClassName 'Win32_NetworkAdapterConfiguration' | Where-Object { $_.IPEnabled })

        if ($adapters.Count -eq 0) {
            Write-ADTResult -Check 'Network adapters' -Status INFO -Detail 'No IP-enabled network adapters found.'
            return
        }

        foreach ($adapter in $adapters) {
            $desc = 'Unknown adapter'
            if ($adapter.Description) { $desc = ([string]$adapter.Description).Trim() }

            $ipText = 'none'
            if ($null -ne $adapter.IPAddress -and @($adapter.IPAddress).Count -gt 0) { $ipText = (@($adapter.IPAddress) -join ', ') }

            $gwText = 'none'
            if ($null -ne $adapter.DefaultIPGateway -and @($adapter.DefaultIPGateway).Count -gt 0) { $gwText = (@($adapter.DefaultIPGateway) -join ', ') }

            $dnsText = 'none'
            if ($null -ne $adapter.DNSServerSearchOrder -and @($adapter.DNSServerSearchOrder).Count -gt 0) { $dnsText = (@($adapter.DNSServerSearchOrder) -join ', ') }

            $detail = 'IP ' + $ipText + ' | gateway ' + $gwText + ' | DNS ' + $dnsText
            Write-ADTResult -Check ('Network adapter: ' + $desc) -Status INFO -Detail $detail
        }
    }
    catch {
        Write-ADTResult -Check 'Network adapters' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTDiscoveryLocalDomain {
    [CmdletBinding()]
    param()

    try {
        if ($script:ADTCaps['DomainJoined']) {
            $detail = 'Domain-joined: ' + [string]$script:ADTCaps['DomainName']
            if ($script:ADTCaps['IsDC']) { $detail = $detail + ' (this box is a domain controller)' }
            Write-ADTResult -Check 'Domain membership' -Status INFO -Detail $detail
        }
        else {
            $workgroup = 'unknown'
            $cs = Get-ADTWmi -ClassName 'Win32_ComputerSystem'
            if ($null -ne $cs -and $cs.Workgroup) { $workgroup = [string]$cs.Workgroup }
            Write-ADTResult -Check 'Domain membership' -Status INFO -Detail ('Workgroup: ' + $workgroup + ' (not domain-joined)')
        }
    }
    catch {
        Write-ADTResult -Check 'Domain membership' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTDiscoveryLocalRoles {
    [CmdletBinding()]
    param()

    try {
        if (-not $script:ADTCaps['IsServer']) {
            Write-ADTResult -Check 'Installed server roles' -Status SKIP -Detail 'Not applicable - this host is not running Windows Server.'
            return
        }

        $cmd = Get-Command -Name 'Get-WindowsFeature' -CommandType Cmdlet -ErrorAction SilentlyContinue
        if ($null -eq $cmd) {
            Write-ADTResult -Check 'Installed server roles' -Status SKIP -Detail 'Get-WindowsFeature is not available on this host (ServerManager module missing).'
            return
        }

        $allFeatures = @(Get-WindowsFeature -ErrorAction Stop)
        $installed = @($allFeatures | Where-Object { $_.Installed })

        # UNVERIFIED: the FeatureType property (Role / Role Service / Feature) was not shown
        # verbatim in the Get-WindowsFeature documentation fetched this session, so it is checked
        # defensively - the filter degrades to "every installed item" if it is ever absent.
        $hasFeatureType = $false
        if ($installed.Count -gt 0) {
            if ($installed[0].PSObject.Properties['FeatureType']) { $hasFeatureType = $true }
        }

        $roles = $installed
        if ($hasFeatureType) {
            $roles = @($installed | Where-Object { [string]$_.FeatureType -eq 'Role' })
        }

        if ($roles.Count -eq 0) {
            Write-ADTResult -Check 'Installed server roles' -Status INFO -Detail 'No server roles reported as installed.'
            return
        }

        foreach ($role in ($roles | Sort-Object -Property Name)) {
            Write-ADTNote -Text ([string]$role.Name + '  (' + [string]$role.DisplayName + ')')
        }

        $names = (@($roles | ForEach-Object { [string]$_.Name })) -join ', '
        Write-ADTResult -Check 'Installed server roles' -Status INFO -Detail ([string]$roles.Count + ' role(s) installed: ' + $names) -Data $roles
    }
    catch {
        Write-ADTResult -Check 'Installed server roles' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTDiscoveryLocalAvEdr {
    [CmdletBinding()]
    param()

    $found = @()

    try {
        $mpCmd = Get-Command -Name 'Get-MpComputerStatus' -ErrorAction SilentlyContinue
        if ($null -eq $mpCmd) {
            Write-ADTResult -Check 'Windows Defender' -Status INFO -Detail 'Get-MpComputerStatus is not available (module not present - Defender may be uninstalled or replaced).'
        }
        else {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            $avOn = [bool]$mp.AntivirusEnabled
            $rtOn = [bool]$mp.RealTimeProtectionEnabled
            $sigAge = 'unknown'
            if ($null -ne $mp.AntivirusSignatureAge) { $sigAge = [string]$mp.AntivirusSignatureAge + ' day(s) old' }

            if ($avOn -and $rtOn) {
                Write-ADTResult -Check 'Windows Defender' -Status INFO -Detail ('Active, real-time protection on, signatures ' + $sigAge + '.')
                $found += 'Microsoft Defender (active)'
            }
            else {
                $ddWhy = 'AntivirusEnabled=' + $avOn.ToString() + ', RealTimeProtectionEnabled=' + $rtOn.ToString() + '. This is expected if a third-party AV/EDR product runs Defender in passive mode; otherwise the endpoint is unprotected.'
                Write-ADTResult -Check 'Windows Defender' -Status WARN -Detail 'Present but not fully active.' -Why $ddWhy -Fix @('Confirm a third-party AV/EDR is the intended primary protection; otherwise: Set-MpPreference -DisableRealtimeMonitoring $false')
            }
        }
    }
    catch {
        Write-ADTResult -Check 'Windows Defender' -Status ERROR -Detail $_.Exception.Message
    }

    try {
        $catalog = @(Get-ADTDiscoveryAvEdrCatalog)
        $matched = @()

        foreach ($entry in $catalog) {
            $present = $false
            if ($entry.Name.Count -gt 0) {
                if (@(Get-ADTDiscoveryServicesLike -Pattern $entry.Name).Count -gt 0) { $present = $true }
            }
            if (-not $present -and $entry.DisplayNameLike.Count -gt 0) {
                if (Test-ADTServicePresent -DisplayNameLike $entry.DisplayNameLike) { $present = $true }
            }
            if ($present) {
                $matched += $entry.Product
                $found += $entry.Product
            }
        }

        if ($matched.Count -gt 0) {
            Write-ADTResult -Check 'Third-party EDR/AV service probe' -Status INFO -Detail ('Matched: ' + ($matched -join ', ')) -Data $matched
        }
        else {
            Write-ADTResult -Check 'Third-party EDR/AV service probe' -Status INFO -Detail 'No match against the known service-name catalog.'
        }
    }
    catch {
        Write-ADTResult -Check 'Third-party EDR/AV service probe' -Status ERROR -Detail $_.Exception.Message
    }

    if ($found.Count -gt 0) {
        Write-ADTResult -Check 'Antivirus / EDR coverage' -Status INFO -Detail ('Coverage found: ' + ($found -join '; '))
    }
    else {
        $covWhy = 'Neither Windows Defender nor any product in the known third-party service-name catalog was detected. The catalog is not exhaustive - a product outside it would still show as no coverage here.'
        $covFix = @('Confirm with the client what AV/EDR product is licensed for this box and check its service is running.', 'If Defender should be the protection: Set-MpPreference -DisableRealtimeMonitoring $false')
        Write-ADTResult -Check 'Antivirus / EDR coverage' -Status WARN -Detail 'No antivirus or EDR product detected.' -Why $covWhy -Fix $covFix
    }
}

function Invoke-ADTDiscoveryLocalProducts {
    [CmdletBinding()]
    param()

    Write-ADTSection -Title 'Detected products'

    try {
        if ($script:ADTCaps['HasExchangeShell']) {
            $exVersion = 'version unknown'
            if ($script:ADTCaps['ExchangeVersion']) { $exVersion = 'build ' + [string]$script:ADTCaps['ExchangeVersion'] }
            Write-ADTResult -Check 'Exchange Server' -Status INFO -Detail ('Detected (' + $exVersion + ').')
        }
        else {
            Write-ADTResult -Check 'Exchange Server' -Status INFO -Detail 'Not detected.'
        }
    }
    catch {
        Write-ADTResult -Check 'Exchange Server' -Status ERROR -Detail $_.Exception.Message
    }

    try {
        # Verified on Microsoft Learn: default instance service is 'MSSQLSERVER'; named
        # instances are 'MSSQL$<InstanceName>'.
        $sqlServices = @(Get-ADTDiscoveryServicesLike -Pattern @('MSSQLSERVER', 'MSSQL$*'))
        if ($sqlServices.Count -gt 0) {
            $sqlNames = (@($sqlServices | ForEach-Object { $_.Name })) -join ', '
            Write-ADTResult -Check 'SQL Server' -Status INFO -Detail ('Detected engine service(s): ' + $sqlNames) -Data $sqlServices
        }
        else {
            Write-ADTResult -Check 'SQL Server' -Status INFO -Detail 'Not detected.'
        }
    }
    catch {
        Write-ADTResult -Check 'SQL Server' -Status ERROR -Detail $_.Exception.Message
    }

    try {
        $citrixRoles = @()
        if ($script:ADTCaps['CitrixDDC'])            { $citrixRoles += 'Delivery Controller' }
        if ($script:ADTCaps['CitrixVDA'])            { $citrixRoles += 'VDA' }
        if ($script:ADTCaps['CitrixStoreFront'])     { $citrixRoles += 'StoreFront' }
        if ($script:ADTCaps['CitrixCloudConnector']) { $citrixRoles += 'Cloud Connector' }

        if ($citrixRoles.Count -gt 0) {
            Write-ADTResult -Check 'Citrix' -Status INFO -Detail ('Detected: ' + ($citrixRoles -join ', '))
        }
        else {
            Write-ADTResult -Check 'Citrix' -Status INFO -Detail 'Not detected.'
        }
    }
    catch {
        Write-ADTResult -Check 'Citrix' -Status ERROR -Detail $_.Exception.Message
    }

    try {
        # Verified on Microsoft Learn: the Microsoft Entra Connect / Azure AD Connect sync
        # service short name is 'ADSync'.
        if (Test-ADTServicePresent -Name @('ADSync')) {
            Write-ADTResult -Check 'Microsoft Entra Connect' -Status INFO -Detail 'Detected (service ADSync present).'
        }
        else {
            Write-ADTResult -Check 'Microsoft Entra Connect' -Status INFO -Detail 'Not detected.'
        }
    }
    catch {
        Write-ADTResult -Check 'Microsoft Entra Connect' -Status ERROR -Detail $_.Exception.Message
    }

    try {
        # Verified on Microsoft Learn: the AD FS Windows service short name is 'adfssrv'
        # (net stop/start adfssrv; "nt service\adfssrv" as a certificate-ACL principal).
        if (Test-ADTServicePresent -Name @('adfssrv')) {
            Write-ADTResult -Check 'AD FS' -Status INFO -Detail 'Detected (service adfssrv present).'
        }
        else {
            Write-ADTResult -Check 'AD FS' -Status INFO -Detail 'Not detected.'
        }
    }
    catch {
        Write-ADTResult -Check 'AD FS' -Status ERROR -Detail $_.Exception.Message
    }

    try {
        if (Test-ADTServicePresent -DisplayNameLike @('Veeam*')) {
            Write-ADTResult -Check 'Veeam' -Status INFO -Detail 'Detected (one or more Veeam services present).'
        }
        else {
            Write-ADTResult -Check 'Veeam' -Status INFO -Detail 'Not detected.'
        }
    }
    catch {
        Write-ADTResult -Check 'Veeam' -Status ERROR -Detail $_.Exception.Message
    }

    Invoke-ADTDiscoveryLocalAvEdr
}

function Invoke-ADTDiscoveryLocalPendingReboot {
    [CmdletBinding()]
    param()

    try {
        $result = Get-ADTDiscoveryPendingReboot
        if ($result.IsPending) {
            $why = 'One or more standard Windows pending-reboot indicators is set: ' + ($result.Reasons -join '; ') + '. Some updates, services or file changes may not be fully applied until the next restart.'
            Write-ADTResult -Check 'Pending reboot' -Status WARN -Detail 'A reboot is pending.' -Why $why -Fix @('[SERVICE-AFFECTING] Restart-Computer -Force   (schedule during a maintenance window)')
        }
        else {
            Write-ADTResult -Check 'Pending reboot' -Status INFO -Detail 'No pending-reboot indicators found.'
        }
    }
    catch {
        Write-ADTResult -Check 'Pending reboot' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTDiscoveryLocalHotfixes {
    [CmdletBinding()]
    param()

    try {
        $hotfixes = @(Get-HotFix -ErrorAction Stop)

        if ($hotfixes.Count -eq 0) {
            $emptyWhy = 'Get-HotFix / Win32_QuickFixEngineering (verified on Microsoft Learn) only returns updates supplied by Component Based Servicing. Updates delivered through Windows Update or MSI are not returned by this class, so an empty list here does not mean the box is unpatched.'
            Write-ADTResult -Check 'Recent hotfixes' -Status INFO -Detail 'No CBS-supplied hotfixes returned.' -Why $emptyWhy
            return
        }

        $parsed = @()
        foreach ($fix in $hotfixes) {
            $installedOn = $null
            if ($null -ne $fix.InstalledOn) {
                try { $installedOn = [DateTime]$fix.InstalledOn } catch { $installedOn = $null }
            }
            $parsed += [PSCustomObject]@{
                HotFixID    = $fix.HotFixID
                Description = $fix.Description
                InstalledOn = $installedOn
            }
        }

        $dated = @($parsed | Where-Object { $null -ne $_.InstalledOn } | Sort-Object -Property InstalledOn -Descending)

        if ($dated.Count -eq 0) {
            Write-ADTResult -Check 'Recent hotfixes' -Status INFO -Detail ([string]$hotfixes.Count + ' hotfix(es) found, but none carried a usable InstalledOn date.') -Data $parsed
            return
        }

        $top5 = @($dated | Select-Object -First 5)
        foreach ($fix in $top5) {
            Write-ADTNote -Text ($fix.HotFixID + '  installed ' + $fix.InstalledOn.ToString('yyyy-MM-dd') + '  ' + $fix.Description)
        }

        $noteWhy = 'This list only covers CBS-supplied hotfixes (Microsoft Learn); it does not include every Windows Update-delivered cumulative update on modern systems.'
        Write-ADTResult -Check 'Recent hotfixes' -Status INFO -Detail ([string]$top5.Count + ' most recent of ' + [string]$hotfixes.Count + ' CBS hotfix(es) shown above.') -Why $noteWhy -Data $top5
    }
    catch {
        Write-ADTResult -Check 'Recent hotfixes' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTDiscoveryLocal {
    <#
        .SYNOPSIS
            Environment discovery (this box) - the first-10-minutes answer sheet for an
            unknown server: OS, hardware, CPU/RAM, volumes, network, domain state, server
            roles, detected products and pending-reboot/patch posture.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Operating system'
        Invoke-ADTDiscoveryLocalOS

        Write-ADTSection -Title 'Hardware'
        Invoke-ADTDiscoveryLocalHardware
        Invoke-ADTDiscoveryLocalCpuRam

        Write-ADTSection -Title 'Volumes'
        Invoke-ADTDiscoveryLocalVolumes

        Write-ADTSection -Title 'Network'
        Invoke-ADTDiscoveryLocalNetwork

        Write-ADTSection -Title 'Domain membership'
        Invoke-ADTDiscoveryLocalDomain

        Write-ADTSection -Title 'Server roles'
        Invoke-ADTDiscoveryLocalRoles

        Invoke-ADTDiscoveryLocalProducts

        Write-ADTSection -Title 'Pending reboot'
        Invoke-ADTDiscoveryLocalPendingReboot

        Write-ADTSection -Title 'Recent hotfixes'
        Invoke-ADTDiscoveryLocalHotfixes
    }
    catch {
        Write-ADTResult -Check 'Environment discovery (this box)' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Domain discovery (Item 2) - section helpers

function Invoke-ADTDiscoveryDomainLevels {
    [CmdletBinding()]
    param()

    try {
        $forest = Get-ADForest -ErrorAction Stop
        $domain = Get-ADDomain -ErrorAction Stop
        Write-ADTResult -Check 'Forest functional level' -Status INFO -Detail ([string]$forest.ForestMode)
        Write-ADTResult -Check 'Domain functional level' -Status INFO -Detail ([string]$domain.DomainMode)
    }
    catch {
        Write-ADTResult -Check 'Functional levels' -Status ERROR -Detail $_.Exception.Message
    }

    try {
        $trusts = @(Get-ADTrust -Filter * -ErrorAction Stop)
        if ($trusts.Count -eq 0) {
            Write-ADTResult -Check 'Trusts' -Status INFO -Detail 'No trust relationships found.'
        }
        else {
            foreach ($trust in $trusts) {
                # UNVERIFIED: Direction and TrustType property names follow standard ADTrust
                # usage; not individually re-confirmed against Microsoft Learn text this session
                # (Target and the -Filter parameter itself were confirmed).
                Write-ADTNote -Text ([string]$trust.Target + '  direction=' + [string]$trust.Direction + '  type=' + [string]$trust.TrustType)
            }
            Write-ADTResult -Check 'Trusts' -Status INFO -Detail ([string]$trusts.Count + ' trust(s) found.') -Data $trusts
        }
    }
    catch {
        Write-ADTResult -Check 'Trusts' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTDiscoveryDomainSites {
    [CmdletBinding()]
    param()

    try {
        $sites = @(Get-ADReplicationSite -Filter * -ErrorAction Stop)
        Write-ADTResult -Check 'AD sites' -Status INFO -Detail ([string]$sites.Count + ' site(s) found.') -Data $sites
    }
    catch {
        Write-ADTResult -Check 'AD sites' -Status ERROR -Detail $_.Exception.Message
        return
    }

    try {
        $subnetCmd = Get-Command -Name 'Get-ADReplicationSubnet' -ErrorAction SilentlyContinue
        if ($null -eq $subnetCmd) {
            Write-ADTResult -Check 'AD subnets' -Status SKIP -Detail 'Get-ADReplicationSubnet is not available.'
            return
        }

        $subnets = @(Get-ADReplicationSubnet -Filter * -ErrorAction Stop)
        $unmapped = @($subnets | Where-Object { [string]::IsNullOrEmpty([string]$_.Site) })
        $subDetail = [string]$subnets.Count + ' subnet(s) found.'

        if ($unmapped.Count -gt 0) {
            $unmappedWhy = 'These subnet objects have no associated site, so clients on them fall back to automatic site coverage or a distant DC rather than the nearest one.'
            Write-ADTResult -Check 'AD subnets' -Status WARN -Detail ($subDetail + ' ' + [string]$unmapped.Count + ' unmapped (no site).') -Why $unmappedWhy -Fix @('Assign each listed subnet to a site: Set-ADReplicationSubnet -Identity "<subnet>" -Site "<site>"') -Data $unmapped
        }
        else {
            Write-ADTResult -Check 'AD subnets' -Status INFO -Detail ($subDetail + ' All mapped to a site.') -Data $subnets
        }
    }
    catch {
        Write-ADTResult -Check 'AD subnets' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTDiscoveryDomainControllers {
    [CmdletBinding()]
    param()

    try {
        # Verified on Microsoft Learn (about_ActiveDirectory_ObjectModel): Site, IsGlobalCatalog,
        # IsReadOnly and OperatingSystem are real ADDomainController properties.
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop)

        foreach ($dc in ($dcs | Sort-Object -Property Name)) {
            $gcText = 'not GC'
            if ($dc.IsGlobalCatalog) { $gcText = 'GC' }
            $roText = 'writable'
            if ($dc.IsReadOnly) { $roText = 'RODC' }
            Write-ADTNote -Text ([string]$dc.Name + '  site=' + [string]$dc.Site + '  ' + [string]$dc.OperatingSystem + '  ' + $gcText + ', ' + $roText)
        }
        Write-ADTResult -Check 'Domain controllers' -Status INFO -Detail ([string]$dcs.Count + ' domain controller(s) found.') -Data $dcs
    }
    catch {
        Write-ADTResult -Check 'Domain controllers' -Status ERROR -Detail $_.Exception.Message
    }

    try {
        $forest = Get-ADForest -ErrorAction Stop
        $domain = Get-ADDomain -ErrorAction Stop

        Write-ADTNote -Text ('Schema master:          ' + [string]$forest.SchemaMaster)
        Write-ADTNote -Text ('Domain naming master:   ' + [string]$forest.DomainNamingMaster)
        Write-ADTNote -Text ('PDC emulator:           ' + [string]$domain.PDCEmulator)
        Write-ADTNote -Text ('RID master:             ' + [string]$domain.RIDMaster)
        Write-ADTNote -Text ('Infrastructure master:  ' + [string]$domain.InfrastructureMaster)

        $fsmoDetail = 'Schema=' + [string]$forest.SchemaMaster + ', Naming=' + [string]$forest.DomainNamingMaster + ', PDC=' + [string]$domain.PDCEmulator + ', RID=' + [string]$domain.RIDMaster + ', Infra=' + [string]$domain.InfrastructureMaster
        Write-ADTResult -Check 'FSMO role holders' -Status INFO -Detail $fsmoDetail
    }
    catch {
        Write-ADTResult -Check 'FSMO role holders' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTDiscoveryDomainDns {
    [CmdletBinding()]
    param()

    if (-not $script:ADTCaps['HasDnsModule']) {
        Write-ADTResult -Check 'DNS zones' -Status SKIP -Detail 'DnsServer module not present on this box.'
        return
    }

    $target = $env:COMPUTERNAME

    try {
        if (-not $script:ADTCaps['HasDnsRole']) {
            $dcList = @()
            try { $dcList = @(Get-ADDomainController -Filter * -ErrorAction Stop) } catch { $dcList = @() }
            if ($dcList.Count -gt 0 -and $dcList[0].HostName) { $target = [string]$dcList[0].HostName }
        }

        $zones = @(Get-DnsServerZone -ComputerName $target -ErrorAction Stop)
        $primary = @($zones | Where-Object { $_.ZoneType -eq 'Primary' })
        Write-ADTResult -Check 'DNS zones' -Status INFO -Detail ([string]$zones.Count + ' zone(s) on ' + $target + ' (' + [string]$primary.Count + ' primary).') -Data $zones
    }
    catch {
        $dnsWhy = 'Could not query the DNS Server service on ' + $target + '. This can mean the DNS role is not installed there, RPC is blocked, or this account lacks rights. ' + $_.Exception.Message
        Write-ADTResult -Check 'DNS zones' -Status SKIP -Detail 'Could not enumerate DNS zones.' -Why $dnsWhy
    }
}

function Invoke-ADTDiscoveryDomainDhcp {
    [CmdletBinding()]
    param()

    try {
        $rootDse = Get-ADTDiscoveryRootDse
        if ($null -eq $rootDse) {
            Write-ADTResult -Check 'Authorised DHCP servers' -Status ERROR -Detail 'Could not read rootDSE.'
            return
        }

        # Verified on Microsoft Learn ("Troubleshooting guide: DHCP authorization failures"):
        # authorised DHCP servers are objects under CN=NetServices,CN=Services,<configuration NC>.
        # The 'DhcpRoot' object is the container marker, not a server, and is excluded by name.
        # The objectClass of an authorisation entry was not confirmed this session, so this
        # deliberately enumerates every child rather than filtering on an unverified class name.
        $searchBase = 'CN=NetServices,CN=Services,' + [string]$rootDse.configurationNamingContext
        $entries = @(Get-ADObject -SearchBase $searchBase -SearchScope OneLevel -Filter * -ErrorAction Stop | Where-Object { $_.Name -ne 'DhcpRoot' })

        if ($entries.Count -eq 0) {
            Write-ADTResult -Check 'Authorised DHCP servers' -Status INFO -Detail 'No authorised DHCP servers found in AD.'
        }
        else {
            foreach ($entry in $entries) { Write-ADTNote -Text ([string]$entry.Name) }
            Write-ADTResult -Check 'Authorised DHCP servers' -Status INFO -Detail ([string]$entries.Count + ' authorised DHCP server entry(ies) found.') -Data $entries
        }
    }
    catch {
        Write-ADTResult -Check 'Authorised DHCP servers' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTDiscoveryDomainExchange {
    [CmdletBinding()]
    param()

    try {
        $rootDse = Get-ADTDiscoveryRootDse
        if ($null -eq $rootDse) {
            Write-ADTResult -Check 'Exchange organisation' -Status ERROR -Detail 'Could not read rootDSE.'
            return
        }

        # Verified on Microsoft Learn (Exchange "Access to Active Directory" / "What changes in AD
        # when Exchange is installed"): Microsoft Exchange container sits at
        # CN=Microsoft Exchange,CN=Services,<configuration NC>, org name as immediate child, and
        # server objects live under CN=Servers,CN=Exchange Administrative Group
        # (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=<org>,CN=Microsoft Exchange,CN=Services,<configuration NC>.
        $exchangeContainer = 'CN=Microsoft Exchange,CN=Services,' + [string]$rootDse.configurationNamingContext

        $orgs = @()
        try {
            $orgs = @(Get-ADObject -SearchBase $exchangeContainer -SearchScope OneLevel -Filter * -ErrorAction Stop)
        }
        catch {
            $orgs = @()
        }

        if ($orgs.Count -eq 0) {
            Write-ADTResult -Check 'Exchange organisation' -Status INFO -Detail 'No on-premises Exchange organisation found in the configuration partition.'
            return
        }

        foreach ($org in $orgs) {
            $orgName = [string]$org.Name
            Write-ADTResult -Check 'Exchange organisation' -Status INFO -Detail ('Organisation: ' + $orgName)

            $serversBase = 'CN=Servers,CN=Exchange Administrative Group (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=' + $orgName + ',' + $exchangeContainer
            try {
                $servers = @(Get-ADObject -SearchBase $serversBase -SearchScope OneLevel -Filter * -ErrorAction Stop)
                if ($servers.Count -eq 0) {
                    Write-ADTResult -Check 'Exchange servers' -Status INFO -Detail 'No Exchange server objects found under this organisation.'
                }
                else {
                    foreach ($server in $servers) { Write-ADTNote -Text ([string]$server.Name) }
                    Write-ADTResult -Check 'Exchange servers' -Status INFO -Detail ([string]$servers.Count + ' Exchange server object(s) found.') -Data $servers
                }
            }
            catch {
                Write-ADTResult -Check 'Exchange servers' -Status ERROR -Detail $_.Exception.Message
            }
        }
    }
    catch {
        Write-ADTResult -Check 'Exchange organisation' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTDiscoveryDomainCertificateAuthorities {
    [CmdletBinding()]
    param()

    try {
        $rootDse = Get-ADTDiscoveryRootDse
        if ($null -eq $rootDse) {
            Write-ADTResult -Check 'Certificate authorities' -Status ERROR -Detail 'Could not read rootDSE.'
            return
        }

        # Verified on Microsoft Learn: enterprise CAs register a pKIEnrollmentService object
        # (schema reference: adschema/c-pkienrollmentservice) under CN=Enrollment
        # Services,CN=Public Key Services,CN=Services,<configuration NC>; dNSHostName is a
        # documented attribute on that object.
        $searchBase = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,' + [string]$rootDse.configurationNamingContext
        $cas = @(Get-ADObject -SearchBase $searchBase -SearchScope OneLevel -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName -ErrorAction Stop)

        if ($cas.Count -eq 0) {
            Write-ADTResult -Check 'Certificate authorities' -Status INFO -Detail 'No enterprise certificate authorities found in AD.'
        }
        else {
            foreach ($ca in $cas) {
                $caHost = 'unknown host'
                if ($ca.dNSHostName) { $caHost = [string]$ca.dNSHostName }
                Write-ADTNote -Text ([string]$ca.Name + '  (' + $caHost + ')')
            }
            Write-ADTResult -Check 'Certificate authorities' -Status INFO -Detail ([string]$cas.Count + ' enterprise CA(s) found.') -Data $cas
        }
    }
    catch {
        Write-ADTResult -Check 'Certificate authorities' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTDiscoveryDomainSpnScan {
    [CmdletBinding()]
    param()

    try {
        # Verified on Microsoft Learn ("Register a Service Principal Name for Kerberos
        # connections"): SQL Server registers SPNs as MSSQLSvc/<FQDN>[:port|instancename].
        $sqlSpnObjects = @(Get-ADObject -LDAPFilter '(servicePrincipalName=MSSQLSvc/*)' -Properties servicePrincipalName -ErrorAction Stop)

        if ($sqlSpnObjects.Count -eq 0) {
            Write-ADTResult -Check 'SQL instances (SPN scan)' -Status INFO -Detail 'No MSSQLSvc/* SPNs found.'
        }
        else {
            $sqlSpns = @()
            foreach ($obj in $sqlSpnObjects) {
                foreach ($spn in @($obj.servicePrincipalName)) {
                    if ($spn -like 'MSSQLSvc/*') { $sqlSpns += $spn }
                }
            }
            $uniqueSpns = @($sqlSpns | Sort-Object -Unique)
            foreach ($spn in $uniqueSpns) { Write-ADTNote -Text $spn }
            Write-ADTResult -Check 'SQL instances (SPN scan)' -Status INFO -Detail ([string]$sqlSpnObjects.Count + ' object(s) carrying an MSSQLSvc SPN; ' + [string]$uniqueSpns.Count + ' distinct SPN(s).') -Data $uniqueSpns
        }
    }
    catch {
        Write-ADTResult -Check 'SQL instances (SPN scan)' -Status ERROR -Detail $_.Exception.Message
    }

    # AD FS: honest limitation rather than a noisy or misleading filter.
    $adfsWhy = 'AD FS registers a HOST/<federation service name> SPN (Microsoft Learn, AD FS 2.0 troubleshooting), but every domain computer automatically carries HOST/ SPNs for itself, so a HOST/* scan cannot distinguish an AD FS farm from an ordinary member server.'
    Write-ADTResult -Check 'AD FS (SPN scan)' -Status SKIP -Detail 'No reliable SPN-based signal for AD FS discovery.' -Why $adfsWhy -Fix @('Identify AD FS by service probe on candidate servers (service adfssrv) or by the organisation''s known federation DNS name instead.')

    # RDS: same universality problem as TERMSRV, called out honestly rather than guessed.
    $rdsWhy = 'TERMSRV/* SPNs are registered by every Windows computer with Remote Desktop enabled, not just RD Session Host or RD Connection Broker servers, so they cannot reliably identify an RDS deployment. No distinct, universally-reliable RDS-only SPN pattern was found to substitute for it.'
    Write-ADTResult -Check 'RDS licensing/session hosts (SPN scan)' -Status SKIP -Detail 'No reliable SPN-based signal for RDS discovery.' -Why $rdsWhy -Fix @('Identify RDS role holders by service probe on candidate servers (TermService, Rdms, SessionEnv) instead of an SPN scan.')
}

function Invoke-ADTDiscoveryDomain {
    <#
        .SYNOPSIS
            Environment discovery (domain) - a domain-wide infrastructure map read from AD,
            without touching member servers.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Functional levels and trusts'
        Invoke-ADTDiscoveryDomainLevels

        Write-ADTSection -Title 'Sites and subnets'
        Invoke-ADTDiscoveryDomainSites

        Write-ADTSection -Title 'Domain controllers and FSMO roles'
        Invoke-ADTDiscoveryDomainControllers

        Write-ADTSection -Title 'DNS'
        Invoke-ADTDiscoveryDomainDns

        Write-ADTSection -Title 'DHCP'
        Invoke-ADTDiscoveryDomainDhcp

        Write-ADTSection -Title 'Exchange'
        Invoke-ADTDiscoveryDomainExchange

        Write-ADTSection -Title 'Certificate authorities'
        Invoke-ADTDiscoveryDomainCertificateAuthorities

        Write-ADTSection -Title 'Infrastructure by SPN scan'
        Invoke-ADTDiscoveryDomainSpnScan
    }
    catch {
        Write-ADTResult -Check 'Environment discovery (domain)' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

Register-ADTModule -Name 'Discovery' -Group 'ON-PREM' -Items @(
    @{ Label = 'Environment discovery (this box)'; Function = 'Invoke-ADTDiscoveryLocal';  Requires = @();                               Snapshot = $true }
    @{ Label = 'Environment discovery (domain)';   Function = 'Invoke-ADTDiscoveryDomain'; Requires = @('DomainJoined', 'HasADModule');  Snapshot = $true }
)
