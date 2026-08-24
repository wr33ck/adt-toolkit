# ADT.Network.ps1 - Network configuration sanity, AD port connectivity, and path quality checks.
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.

#region Private helpers

function Get-ADTNetAdapterConfigWmiList {
    <#
        .SYNOPSIS
            Enumerate every IP-enabled Win32_NetworkAdapterConfiguration instance.
        .DESCRIPTION
            Mirrors ADT.Common's Get-ADTWmi CIM-then-Get-WmiObject fallback pattern, but
            Get-ADTWmi always collapses its result to a single instance (by design, for
            one-per-machine classes such as Win32_ComputerSystem). That would silently
            drop every adapter but the first on a multi-homed server, so this local
            helper keeps the full result set and applies the IPEnabled filter that
            Get-ADTWmi has no parameter for. Never throws.
    #>
    [CmdletBinding()]
    param()

    $filterText = 'IPEnabled = True'

    try {
        $instances = Get-CimInstance -ClassName 'Win32_NetworkAdapterConfiguration' -Filter $filterText -ErrorAction Stop
        return @($instances)
    }
    catch {
        $null = $_
    }

    try {
        $instances = Get-WmiObject -Class 'Win32_NetworkAdapterConfiguration' -Filter $filterText -ErrorAction Stop
        return @($instances)
    }
    catch {
        return @()
    }
}

function Get-ADTNetAdapterConfig {
    <#
        .SYNOPSIS
            Normalised adapter list: name, IPv4/IPv6 addresses, gateway(s), DNS servers,
            DHCP state. Tries the NetTCPIP cmdlets first (verified at runtime, not just by
            module presence), falls back to WMI if that probe fails for any reason.
        .DESCRIPTION
            Object per adapter: Name, IPv4 (string[] "addr/prefix"), IPv4Gateway (string[]),
            DNSServers (string[]), IPv6 (string[]), DhcpEnabled ($true/$false/$null),
            Source ('NetTCPIP' or 'WMI').
    #>
    [CmdletBinding()]
    param()

    $results = @()
    $netTcpIpWorked = $false
    $configs = $null

    $probe = Get-Command -Name 'Get-NetIPConfiguration' -ErrorAction SilentlyContinue
    if ($null -ne $probe) {
        try {
            $configs = Get-NetIPConfiguration -ErrorAction Stop
            $netTcpIpWorked = $true
        }
        catch {
            $netTcpIpWorked = $false
        }
    }

    if ($netTcpIpWorked) {
        foreach ($config in @($configs)) {
            if ($null -eq $config) { continue }

            $name = $null
            if ($config.PSObject.Properties['InterfaceAlias']) { $name = [string]$config.InterfaceAlias }
            if ([string]::IsNullOrEmpty($name)) { continue }

            # UNVERIFIED: the nested property names below (IPv4Address.IPAddress /
            # .PrefixLength, IPv4DefaultGateway.NextHop, DNSServer.ServerAddresses,
            # IPv6Address.IPAddress) are not enumerated by Microsoft Learn's
            # Get-NetIPConfiguration reference page (it documents parameters, not the
            # composite output object's schema). They match this project's prior
            # experience and are consistent by convention with Get-NetIPAddress's own
            # -IPAddress/-PrefixLength parameters and Get-DnsClientServerAddress's own
            # -ServerAddresses parameter (both independently confirmed against Learn).
            # Every access below is existence-checked, so a wrong name degrades to an
            # empty field rather than throwing.
            $ipv4 = @()
            if ($config.PSObject.Properties['IPv4Address'] -and $null -ne $config.IPv4Address) {
                foreach ($addr in @($config.IPv4Address)) {
                    if ($null -eq $addr) { continue }
                    $addrText = $null
                    if ($addr.PSObject.Properties['IPAddress']) { $addrText = [string]$addr.IPAddress }
                    if ([string]::IsNullOrEmpty($addrText)) { continue }
                    $prefixText = ''
                    if ($addr.PSObject.Properties['PrefixLength']) { $prefixText = ('/' + [string]$addr.PrefixLength) }
                    $ipv4 += ($addrText + $prefixText)
                }
            }

            $gw = @()
            if ($config.PSObject.Properties['IPv4DefaultGateway'] -and $null -ne $config.IPv4DefaultGateway) {
                foreach ($route in @($config.IPv4DefaultGateway)) {
                    if ($null -eq $route) { continue }
                    if ($route.PSObject.Properties['NextHop'] -and -not [string]::IsNullOrEmpty($route.NextHop)) {
                        $gw += [string]$route.NextHop
                    }
                }
            }

            $dns = @()
            if ($config.PSObject.Properties['DNSServer'] -and $null -ne $config.DNSServer) {
                foreach ($dnsEntry in @($config.DNSServer)) {
                    if ($null -eq $dnsEntry) { continue }
                    if ($dnsEntry.PSObject.Properties['ServerAddresses'] -and $null -ne $dnsEntry.ServerAddresses) {
                        foreach ($addr in @($dnsEntry.ServerAddresses)) {
                            if (-not [string]::IsNullOrEmpty($addr)) { $dns += [string]$addr }
                        }
                    }
                }
            }
            $dns = @($dns | Select-Object -Unique)

            $ipv6 = @()
            if ($config.PSObject.Properties['IPv6Address'] -and $null -ne $config.IPv6Address) {
                foreach ($addr6 in @($config.IPv6Address)) {
                    if ($null -eq $addr6) { continue }
                    if ($addr6.PSObject.Properties['IPAddress'] -and -not [string]::IsNullOrEmpty($addr6.IPAddress)) {
                        $ipv6 += [string]$addr6.IPAddress
                    }
                }
            }

            $dhcpEnabled = $null
            try {
                $ipInterface = Get-NetIPInterface -InterfaceAlias $name -AddressFamily IPv4 -ErrorAction Stop
                $firstInterface = $ipInterface
                if ($ipInterface -is [System.Array] -and @($ipInterface).Count -gt 0) { $firstInterface = @($ipInterface)[0] }
                if ($null -ne $firstInterface -and $firstInterface.PSObject.Properties['Dhcp']) {
                    $dhcpEnabled = ([string]$firstInterface.Dhcp -eq 'Enabled')
                }
            }
            catch {
                $dhcpEnabled = $null
            }

            $results += [PSCustomObject]@{
                Name        = $name
                IPv4        = $ipv4
                IPv4Gateway = $gw
                DNSServers  = $dns
                IPv6        = $ipv6
                DhcpEnabled = $dhcpEnabled
                Source      = 'NetTCPIP'
            }
        }

        if ($results.Count -gt 0) { return $results }
    }

    # ---- WMI fallback ----
    $wmiAdapters = Get-ADTNetAdapterConfigWmiList
    foreach ($cfg in $wmiAdapters) {
        if ($null -eq $cfg) { continue }

        $ipv4 = @()
        $ipv6 = @()
        if ($null -ne $cfg.IPAddress) {
            $addressArray = @($cfg.IPAddress)
            $maskArray = @()
            if ($null -ne $cfg.IPSubnet) { $maskArray = @($cfg.IPSubnet) }

            for ($i = 0; $i -lt $addressArray.Count; $i++) {
                $addr = $addressArray[$i]
                if ([string]::IsNullOrEmpty($addr)) { continue }
                if ($addr -match ':') {
                    $ipv6 += $addr
                }
                else {
                    $maskText = ''
                    if ($i -lt $maskArray.Count -and -not [string]::IsNullOrEmpty($maskArray[$i])) {
                        $maskText = ('/' + $maskArray[$i])
                    }
                    $ipv4 += ($addr + $maskText)
                }
            }
        }

        $gw = @()
        if ($null -ne $cfg.DefaultIPGateway) {
            foreach ($gwAddr in @($cfg.DefaultIPGateway)) {
                if (-not [string]::IsNullOrEmpty($gwAddr)) { $gw += $gwAddr }
            }
        }

        $dns = @()
        if ($null -ne $cfg.DNSServerSearchOrder) {
            foreach ($dnsAddr in @($cfg.DNSServerSearchOrder)) {
                if (-not [string]::IsNullOrEmpty($dnsAddr)) { $dns += $dnsAddr }
            }
        }

        $name = $null
        if ($cfg.PSObject.Properties['Description']) { $name = [string]$cfg.Description }
        if ([string]::IsNullOrEmpty($name)) { $name = ('Adapter index ' + [string]$cfg.Index) }

        $dhcpEnabled = $null
        if ($cfg.PSObject.Properties['DHCPEnabled']) { $dhcpEnabled = [bool]$cfg.DHCPEnabled }

        $results += [PSCustomObject]@{
            Name        = $name
            IPv4        = $ipv4
            IPv4Gateway = $gw
            DNSServers  = $dns
            IPv6        = $ipv6
            DhcpEnabled = $dhcpEnabled
            Source      = 'WMI'
        }
    }

    return $results
}

function Test-ADTPublicDnsResolver {
    <#
        .SYNOPSIS
            Returns the provider name if an IP matches a well-known public DNS resolver,
            otherwise $null.
        .DESCRIPTION
            Heuristic, non-exhaustive list of publicly published resolver addresses. This
            is general public knowledge (each address is published by its own provider),
            not a Microsoft Learn fact, so it is maintained here rather than cited to a
            Learn URL. Absence from this list does not prove an address is not a public
            resolver.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )

    $knownResolvers = @{
        '8.8.8.8'         = 'Google Public DNS'
        '8.8.4.4'         = 'Google Public DNS'
        '1.1.1.1'         = 'Cloudflare DNS'
        '1.0.0.1'         = 'Cloudflare DNS'
        '9.9.9.9'         = 'Quad9'
        '149.112.112.112' = 'Quad9'
        '208.67.222.222'  = 'OpenDNS'
        '208.67.220.220'  = 'OpenDNS'
        '208.67.222.220'  = 'OpenDNS'
        '208.67.220.222'  = 'OpenDNS'
        '4.2.2.1'         = 'Level3/CenturyLink public DNS'
        '4.2.2.2'         = 'Level3/CenturyLink public DNS'
    }

    if ($knownResolvers.ContainsKey($IPAddress)) {
        return $knownResolvers[$IPAddress]
    }
    return $null
}

function Get-ADTPortRoleName {
    <#
        .SYNOPSIS
            Human-readable role for one of the AD DS firewall ports.
        .DESCRIPTION
            Mapping confirmed against "How to configure a firewall for Active Directory
            domains and trusts" (KB179442) and "Service overview and network port
            requirements for Windows" on Microsoft Learn.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    switch ($Port) {
        53   { return 'DNS' }
        88   { return 'Kerberos' }
        135  { return 'RPC Endpoint Mapper' }
        389  { return 'LDAP' }
        445  { return 'SMB' }
        464  { return 'Kerberos password change' }
        636  { return 'LDAP over SSL' }
        3268 { return 'Global Catalog LDAP' }
        3269 { return 'Global Catalog LDAP over SSL' }
        5985 { return 'WinRM (HTTP)' }
        default { return ('TCP ' + $Port) }
    }
}

function Get-ADTDomainControllerTargets {
    <#
        .SYNOPSIS
            List of domain controllers to test: Get-ADDomainController when the AD module
            is present, else a DNS SRV lookup for _ldap._tcp.dc._msdcs.<domain>.
        .DESCRIPTION
            Returns an array of objects with HostName and Source. Never throws; returns
            an empty array if neither method works.
    #>
    [CmdletBinding()]
    param()

    $list = @()

    if ($script:ADTCaps['HasADModule']) {
        try {
            $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
            foreach ($dc in @($dcs)) {
                if ($null -eq $dc) { continue }
                $hostName = $null
                if ($dc.PSObject.Properties['HostName'] -and -not [string]::IsNullOrEmpty($dc.HostName)) { $hostName = [string]$dc.HostName }
                if ([string]::IsNullOrEmpty($hostName) -and $dc.PSObject.Properties['Name']) { $hostName = [string]$dc.Name }
                if ([string]::IsNullOrEmpty($hostName)) { continue }
                $list += [PSCustomObject]@{ HostName = $hostName; Source = 'ActiveDirectory' }
            }
        }
        catch {
            $list = @()
        }
    }

    if ($list.Count -gt 0) { return $list }

    # ---- DNS SRV fallback ----
    try {
        $domainName = $script:ADTCaps['DomainName']
        if ([string]::IsNullOrEmpty($domainName)) { return @() }

        $resolveCmd = Get-Command -Name 'Resolve-DnsName' -ErrorAction SilentlyContinue
        if ($null -eq $resolveCmd) { return @() }

        $srvName = ('_ldap._tcp.dc._msdcs.' + $domainName)

        # UNVERIFIED: the SRV record's target-host property is read as NameTarget.
        # Microsoft Learn's Resolve-DnsName reference documents the -Type parameter
        # (SRV is a confirmed accepted value) but not the returned DnsRecord_SRV .NET
        # type's member names, so this specific property name could not be confirmed
        # against Learn in this session. Coded defensively: a record without a usable
        # NameTarget is skipped rather than throwing.
        $srvRecords = Resolve-DnsName -Name $srvName -Type SRV -ErrorAction Stop
        foreach ($record in @($srvRecords)) {
            if ($null -eq $record) { continue }
            $recordType = $null
            if ($record.PSObject.Properties['Type']) { $recordType = [string]$record.Type }
            if ($recordType -ne 'SRV') { continue }

            $target = $null
            if ($record.PSObject.Properties['NameTarget']) { $target = [string]$record.NameTarget }
            if ([string]::IsNullOrEmpty($target)) { continue }

            $target = $target.TrimEnd('.')
            $list += [PSCustomObject]@{ HostName = $target; Source = 'DNS SRV' }
        }
    }
    catch {
        $list = @()
    }

    return $list
}

function Get-ADTPdcName {
    <#
        .SYNOPSIS
            Best-effort PDC emulator hostname: Get-ADDomainController -Discover when the
            AD module is present, else the .NET DirectoryServices lookup (works without
            RSAT on any domain-joined box). Returns $null if neither works.
    #>
    [CmdletBinding()]
    param()

    if ($script:ADTCaps['HasADModule']) {
        try {
            $pdc = Get-ADDomainController -Discover -Service 'PrimaryDC' -ErrorAction Stop
            if ($null -ne $pdc) {
                if ($pdc.PSObject.Properties['HostName'] -and -not [string]::IsNullOrEmpty($pdc.HostName)) {
                    return [string]$pdc.HostName
                }
                if ($pdc.PSObject.Properties['Name'] -and -not [string]::IsNullOrEmpty($pdc.Name)) {
                    return [string]$pdc.Name
                }
            }
        }
        catch {
            $null = $_
        }
    }

    try {
        Add-Type -AssemblyName System.DirectoryServices -ErrorAction SilentlyContinue
        $domainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        if ($null -ne $domainObject -and $null -ne $domainObject.PdcRoleOwner) {
            return [string]$domainObject.PdcRoleOwner.Name
        }
    }
    catch {
        $null = $_
    }

    return $null
}

function Get-ADTPingSummary {
    <#
        .SYNOPSIS
            Runs ping.exe Count times against a target and parses loss% and average ms.
        .DESCRIPTION
            Test-Connection on Windows PowerShell 5.1 is the legacy WMI/Win32_PingStatus
            cmdlet - confirmed against the powershell-5.1-scoped Microsoft Learn page,
            whose full parameter set is ComputerName, AsJob, DcomAuthentication,
            WsmanAuthentication, Protocol, BufferSize, Count, Credential, Impersonation,
            ThrottleLimit, TimeToLive, Delay, Source, and Quiet. It has -BufferSize (raw
            payload size, default 32 bytes) but no -DontFragment or other DF-bit control
            at all - that was added only in the PowerShell 6+ rewrite, which replaced the
            WMI implementation outright. Without DF-bit control, an oversized 5.1
            Test-Connection ping is free to be silently fragmented and reassembled in
            transit, so it cannot reveal a path MTU problem the way ping.exe's /f switch
            can. It cannot drive the /f /l MTU probe this module needs, so ping.exe via
            Invoke-ADTNative is used for every ping in this file instead, and its console
            output is parsed. That output is localised on non-English Windows installs;
            this parser only recognises the English strings, and a locale mismatch
            degrades to Success=$false (reported as WARN, never a crash).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetAddress,

        [Parameter(Mandatory = $false)]
        [int]$Count = 4
    )

    $summary = [PSCustomObject]@{
        Target      = $TargetAddress
        Sent        = $Count
        Received    = 0
        LossPercent = 100
        AverageMs   = $null
        Success     = $false
    }

    $arguments = @('/n', [string]$Count, $TargetAddress)
    $timeoutSec = 10 + ($Count * 2)
    $result = Invoke-ADTNative -FilePath 'ping.exe' -Arguments $arguments -TimeoutSec $timeoutSec

    if ([string]::IsNullOrEmpty($result.StdOut)) {
        return $summary
    }

    $lossMatch = [regex]::Match($result.StdOut, 'Sent = (\d+), Received = (\d+), Lost = (\d+) \((\d+)% loss\)')
    if ($lossMatch.Success) {
        $summary.Sent = [int]$lossMatch.Groups[1].Value
        $summary.Received = [int]$lossMatch.Groups[2].Value
        $summary.LossPercent = [int]$lossMatch.Groups[4].Value
        $summary.Success = $true
    }

    $avgMatch = [regex]::Match($result.StdOut, 'Average = (\d+)ms')
    if ($avgMatch.Success) {
        $summary.AverageMs = [int]$avgMatch.Groups[1].Value
    }

    return $summary
}

function Invoke-ADTPingResultReport {
    <#
        .SYNOPSIS
            Shared PASS/WARN/INFO rendering for a Get-ADTPingSummary result, used for the
            gateway, each DNS server, and the PDC.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [object]$Summary
    )

    if (-not $Summary.Success) {
        $detailText = ('No usable reply parsed from ' + $Summary.Target + '.')
        $whyText = 'Either every echo request timed out, or the ping.exe output could not be parsed (a non-English Windows locale changes these strings, which this text-parsing check does not localise).'
        $fixCommand = ('ping /n ' + $Summary.Sent + ' ' + $Summary.Target)
        Write-ADTResult -Check ('Ping: ' + $Label) -Status WARN -Detail $detailText -Why $whyText -Fix @($fixCommand, 'Confirm ICMP echo is allowed end to end - some firewalls block ping while still passing real traffic.')
        return
    }

    $detailText = ($Summary.LossPercent.ToString() + '% loss (' + $Summary.Received + '/' + $Summary.Sent + ' received)')
    if ($null -ne $Summary.AverageMs) {
        $detailText = ($detailText + ', average ' + $Summary.AverageMs + ' ms')
    }

    if ($Summary.LossPercent -gt 0) {
        $whyText = 'Any packet loss on what should be a stable local/routed path is worth chasing before it is blamed on the application - duplex mismatches, a failing NIC/cable, Wi-Fi in the path, or an overloaded switch are common causes.'
        Write-ADTResult -Check ('Ping: ' + $Label) -Status WARN -Detail $detailText -Why $whyText -Fix @(('ping /n 50 ' + $Summary.Target + '   (a longer run makes an intermittent pattern easier to see)'))
    }
    elseif ($null -ne $Summary.AverageMs -and $Summary.AverageMs -gt 50) {
        $whyText = ('No loss, but ' + $Summary.AverageMs + ' ms average is high for what is normally expected to be a same-site/LAN path; worth a look if this host is supposed to be local rather than reached over a WAN/VPN link.')
        Write-ADTResult -Check ('Ping: ' + $Label) -Status INFO -Detail $detailText -Why $whyText
    }
    else {
        Write-ADTResult -Check ('Ping: ' + $Label) -Status PASS -Detail $detailText
    }
}

function Get-ADTMtuProbe {
    <#
        .SYNOPSIS
            Walks payload size 1472 -> 1400 -> 1350 with ping /f to find the largest
            unfragmented packet a path will carry.
        .DESCRIPTION
            1472 bytes is the standard probe size for a full 1500-byte Ethernet MTU
            (1500 - 20-byte IP header - 8-byte ICMP header = 1472 payload bytes; this is
            general IETF/networking arithmetic, not a Microsoft-specific fact). Returns
            an object recording whether the full size worked, the largest working size
            found (if any), whether the router-fragmentation-needed message was seen at
            any size, and whether every attempt simply went unanswered (inconclusive).
        .NOTES
            Uses the ping.exe /f /l syntax. Microsoft Learn's "Windows Commands" reference
            documents ping's syntax exclusively with forward-slash switches
            (/t /a /n /l /f /i /v /r /s /j /k /w /R /S /4 /6); this module follows that
            documented form throughout rather than the dash-style shown only in an older,
            secondary troubleshooting article, so every ping.exe/tracert.exe call in this
            file is consistently forward-slash.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetAddress
    )

    $sizesToTry = @(1472, 1400, 1350)
    $probe = [PSCustomObject]@{
        Target            = $TargetAddress
        WorkingSize       = $null
        FullSizeOk        = $false
        FragmentationSeen = $false
        AnyReply          = $false
    }

    foreach ($size in $sizesToTry) {
        $arguments = @('/f', '/n', '1', '/l', [string]$size, $TargetAddress)
        $pingResult = Invoke-ADTNative -FilePath 'ping.exe' -Arguments $arguments -TimeoutSec 10
        $output = $pingResult.StdOut

        if (-not [string]::IsNullOrEmpty($output)) {
            if ($output -match 'Reply from') {
                $probe.AnyReply = $true
                if ($null -eq $probe.WorkingSize) { $probe.WorkingSize = $size }
                if ($size -eq 1472) { $probe.FullSizeOk = $true }
                break
            }
            elseif ($output -match 'fragmented') {
                $probe.FragmentationSeen = $true
            }
        }
    }

    return $probe
}

#endregion

#region Item 1: Network configuration sanity

function Invoke-ADTNetConfig {
    <#
        .SYNOPSIS
            Adapters/IP/gateway, default-gateway count, DNS client servers, IPv6 state,
            firewall profiles, WinHTTP proxy, and NLA category.
    #>
    [CmdletBinding()]
    param()

    $script:ADTCurrentModule = 'Network'

    try {
        Write-ADTSection -Title 'Network configuration sanity'

        $adapters = Get-ADTNetAdapterConfig

        if ($adapters.Count -eq 0) {
            Write-ADTResult -Check 'Network adapters' -Status FAIL -Detail 'No adapters with an active IPv4/IPv6 configuration were found.' -Why 'A server with no usable network adapter cannot serve any of its roles, and this also means every other check in this item has nothing to test.' -Fix @('Get-NetAdapter | Format-Table Name, Status, LinkSpeed', 'ipconfig /all')
            return
        }

        Write-ADTNote -Text ('Adapter data source: ' + $adapters[0].Source)

        # ---- adapters up + IP/mask/gateway ----
        foreach ($adapter in $adapters) {
            $ipv4Text = 'none'
            if ($adapter.IPv4.Count -gt 0) { $ipv4Text = ($adapter.IPv4 -join ', ') }
            $gwText = 'none'
            if ($adapter.IPv4Gateway.Count -gt 0) { $gwText = ($adapter.IPv4Gateway -join ', ') }
            Write-ADTResult -Check ('Network adapter: ' + $adapter.Name) -Status PASS -Detail ('IPv4 ' + $ipv4Text + '; Gateway ' + $gwText) -Data $adapter
        }

        # ---- exactly-one default gateway ----
        $allGateways = @()
        foreach ($adapter in $adapters) {
            foreach ($gwAddr in $adapter.IPv4Gateway) {
                if (-not [string]::IsNullOrEmpty($gwAddr)) { $allGateways += $gwAddr }
            }
        }
        $uniqueGateways = @($allGateways | Select-Object -Unique)

        if ($uniqueGateways.Count -eq 1) {
            Write-ADTResult -Check 'Default gateway count' -Status PASS -Detail ('Exactly one default gateway configured: ' + $uniqueGateways[0])
        }
        elseif ($uniqueGateways.Count -eq 0) {
            Write-ADTResult -Check 'Default gateway count' -Status WARN -Detail 'No default gateway is configured on any adapter.' -Why 'Without a default route this host can only reach hosts on directly-connected subnets.' -Fix @('New-NetIPAddress -InterfaceAlias "<adapter>" -IPAddress <ip> -PrefixLength <n> -DefaultGateway <gateway>   (only if this host is genuinely missing one; some servers intentionally have none)')
        }
        else {
            $gwList = ($uniqueGateways -join ', ')
            Write-ADTResult -Check 'Default gateway count' -Status WARN -Detail ($uniqueGateways.Count.ToString() + ' default gateways configured: ' + $gwList) -Why 'Multiple default gateways can cause asymmetric routing: outbound traffic may leave via one gateway while the return path is expected via another, which stateful firewalls and NAT devices will silently drop.' -Fix @('Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Format-Table InterfaceAlias, NextHop, RouteMetric', 'Remove-NetRoute -DestinationPrefix 0.0.0.0/0 -NextHop <the-gateway-that-should-not-be-default> -Confirm:$false')
        }

        # ---- DNS client servers per adapter ----
        foreach ($adapter in $adapters) {
            $ipv4Dns = @($adapter.DNSServers | Where-Object { $_ -notmatch ':' })

            if ($ipv4Dns.Count -eq 0) {
                Write-ADTResult -Check ('DNS servers: ' + $adapter.Name) -Status INFO -Detail 'No IPv4 DNS servers configured on this adapter.'
                continue
            }

            $publicHits = @()
            foreach ($server in $ipv4Dns) {
                $resolverName = Test-ADTPublicDnsResolver -IPAddress $server
                if (-not [string]::IsNullOrEmpty($resolverName)) { $publicHits += ($server + ' (' + $resolverName + ')') }
            }

            if ($script:ADTCaps['DomainJoined'] -and $publicHits.Count -gt 0) {
                Write-ADTResult -Check ('DNS servers: ' + $adapter.Name) -Status FAIL -Detail ('Public DNS resolver(s) configured on a domain-joined box: ' + ($publicHits -join ', ')) -Why 'A domain-joined computer must resolve its own AD DNS zone (the SRV records that carry site topology and service location) through an internal, AD-integrated DNS server. Pointing it at a public resolver breaks domain discovery, Group Policy processing, and SYSVOL/NETLOGON access, and leaks internal name queries to the internet.' -Fix @(('Set-DnsClientServerAddress -InterfaceAlias "' + $adapter.Name + '" -ServerAddresses ("<internal-DC-DNS-1>","<internal-DC-DNS-2>")'))
                continue
            }

            if ($script:ADTCaps['IsServer'] -and $adapter.DhcpEnabled -eq $true) {
                Write-ADTResult -Check ('DNS servers: ' + $adapter.Name) -Status WARN -Detail ('DNS servers appear DHCP-assigned (adapter is DHCP-enabled): ' + ($ipv4Dns -join ', ')) -Why 'Servers should use static, predictable DNS server addresses. A DHCP-assigned DNS list can change silently on lease renewal or a DHCP scope edit, and is harder to audit. This is inferred from the adapter''s overall DHCP setting, since neither the DnsClient nor NetTCPIP module exposes a separate "DNS list came from DHCP" flag; if DNS was manually overridden with Set-DnsClientServerAddress while the adapter stays DHCP for IP addressing, this will still (incorrectly) warn.' -Fix @(('Set-NetIPInterface -InterfaceAlias "' + $adapter.Name + '" -Dhcp Disabled   (only after setting a static IP/gateway) -- or leave IP addressing on DHCP and just pin DNS: Set-DnsClientServerAddress -InterfaceAlias "' + $adapter.Name + '" -ServerAddresses ("<dns-1>","<dns-2>")'))
                continue
            }

            Write-ADTResult -Check ('DNS servers: ' + $adapter.Name) -Status PASS -Detail ('DNS servers: ' + ($ipv4Dns -join ', '))
        }

        # ---- IPv6: INFO only, never recommend disabling ----
        $ipv6Why = 'Reported for awareness only. Microsoft does not recommend disabling IPv6 on Windows - doing so can break components that assume its presence, and Windows itself uses link-local IPv6 internally even on IPv4-only routed networks.'
        foreach ($adapter in $adapters) {
            if ($adapter.IPv6.Count -eq 0) {
                Write-ADTResult -Check ('IPv6 state: ' + $adapter.Name) -Status INFO -Detail 'No IPv6 addresses configured, or IPv6 is disabled on this adapter.' -Why $ipv6Why
            }
            else {
                Write-ADTResult -Check ('IPv6 state: ' + $adapter.Name) -Status INFO -Detail ('IPv6 addresses: ' + ($adapter.IPv6 -join ', ')) -Why $ipv6Why
            }
        }

        # ---- firewall profiles ----
        try {
            $fwProbe = Get-Command -Name 'Get-NetFirewallProfile' -ErrorAction SilentlyContinue
            if ($null -eq $fwProbe) {
                Write-ADTResult -Check 'Windows Firewall profiles' -Status SKIP -Detail 'Get-NetFirewallProfile is not available on this OS (NetSecurity module not present).'
            }
            else {
                $fwProfiles = @(Get-NetFirewallProfile -All -ErrorAction Stop)
                $disabledProfiles = @()
                foreach ($fwProfile in $fwProfiles) {
                    $stateText = 'On'
                    if ($fwProfile.Enabled -eq $false) {
                        $stateText = 'Off'
                        $disabledProfiles += $fwProfile.Name
                    }
                    Write-ADTResult -Check ('Firewall profile: ' + $fwProfile.Name) -Status INFO -Detail ('State: ' + $stateText)
                }

                if ($fwProfiles.Count -gt 0 -and $disabledProfiles.Count -eq $fwProfiles.Count) {
                    $gpoNote = 'If this is intentionally managed elsewhere (a third-party firewall, or a GPO-driven security baseline), this is expected - confirm with gpresult /h report.html or the "Windows Defender Firewall Properties" node of the applicable GPO before re-enabling.'
                    Write-ADTResult -Check 'Windows Firewall profile state' -Status WARN -Detail ('All firewall profiles are disabled: ' + ($disabledProfiles -join ', ')) -Why ('With every profile off, this host has no host-based filtering at all and depends entirely on network-perimeter controls for inbound protection. ' + $gpoNote) -Fix @(('Set-NetFirewallProfile -Name ' + ($disabledProfiles -join ',') + ' -Enabled True'))
                }
            }
        }
        catch {
            Write-ADTResult -Check 'Windows Firewall profiles' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- WinHTTP proxy ----
        try {
            $proxyResult = Invoke-ADTNative -FilePath 'netsh.exe' -Arguments @('winhttp', 'show', 'proxy') -TimeoutSec 15
            if ($proxyResult.ExitCode -eq 0 -and -not [string]::IsNullOrEmpty($proxyResult.StdOut)) {
                if ($proxyResult.StdOut -match 'Direct access') {
                    Write-ADTResult -Check 'WinHTTP proxy' -Status INFO -Detail 'Direct access (no machine-level proxy configured).'
                }
                else {
                    $proxyLines = @($proxyResult.StdOut -split "`r`n|`n" | Where-Object { $_ -match 'Proxy Server' })
                    $proxyValue = ($proxyLines -join ' ').Trim()
                    if ([string]::IsNullOrEmpty($proxyValue)) { $proxyValue = $proxyResult.StdOut.Trim() }
                    Write-ADTResult -Check 'WinHTTP proxy' -Status INFO -Detail ('Non-direct WinHTTP proxy configured: ' + $proxyValue) -Why 'Machine-level services (Windows Update, many agents, scheduled tasks running as SYSTEM) use the WinHTTP proxy, not an interactive user''s browser proxy. An unexpected value here can silently break agent/update connectivity even when a logged-on user browses normally.'
                }
            }
            else {
                Write-ADTResult -Check 'WinHTTP proxy' -Status SKIP -Detail 'Could not run netsh winhttp show proxy.' -Why $proxyResult.StdErr
            }
        }
        catch {
            Write-ADTResult -Check 'WinHTTP proxy' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- NLA category ----
        if ($script:ADTCaps['DomainJoined']) {
            try {
                $ncpProbe = Get-Command -Name 'Get-NetConnectionProfile' -ErrorAction SilentlyContinue
                if ($null -eq $ncpProbe) {
                    Write-ADTResult -Check 'Network Location Awareness (NLA)' -Status SKIP -Detail 'Get-NetConnectionProfile is not available on this OS (NetConnection module not present).'
                }
                else {
                    $ncProfiles = @(Get-NetConnectionProfile -ErrorAction Stop)
                    $notDomainAuth = @($ncProfiles | Where-Object { $_.NetworkCategory -ne 'DomainAuthenticated' })

                    if ($ncProfiles.Count -eq 0) {
                        Write-ADTResult -Check 'Network Location Awareness (NLA)' -Status SKIP -Detail 'Get-NetConnectionProfile returned no connection profiles.'
                    }
                    elseif ($notDomainAuth.Count -gt 0) {
                        $names = @()
                        foreach ($p in $notDomainAuth) { $names += ($p.InterfaceAlias + '=' + $p.NetworkCategory) }
                        $nlaWhy = 'NLA decides the active firewall profile and Netlogon secure-channel behaviour. A domain-joined machine that lands on Public/Private instead of DomainAuthenticated usually means NLA could not reach a DC fast enough at boot (slow DNS, an unreachable DC, or Netlogon starting after NLA runs its check) - the classic NLA/Netlogon service-start-order race. It silently applies the wrong firewall profile and can intermittently break GPO/domain-dependent features until the profile re-evaluates.'
                        Write-ADTResult -Check 'Network Location Awareness (NLA)' -Status WARN -Detail ('Domain-joined but not on the DomainAuthenticated profile: ' + ($names -join ', ')) -Why $nlaWhy -Fix @('[SERVICE-AFFECTING] Restart-Service -Name NlaSvc -Force   (forces NLA to re-evaluate once DC reachability is confirmed fixed)', ('Confirm DC reachability first: nltest /dsgetdc:' + $script:ADTCaps['DomainName']))
                    }
                    else {
                        Write-ADTResult -Check 'Network Location Awareness (NLA)' -Status PASS -Detail 'All connection profiles report DomainAuthenticated.'
                    }
                }
            }
            catch {
                Write-ADTResult -Check 'Network Location Awareness (NLA)' -Status ERROR -Detail $_.Exception.Message
            }
        }
    }
    catch {
        Write-ADTResult -Check 'Network configuration sanity' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Item 2: AD port connectivity

function Invoke-ADTNetADPorts {
    <#
        .SYNOPSIS
            TCP port matrix (53, 88, 135, 389, 445, 464, 636, 3268, 3269, plus 5985 WinRM
            as INFO) against every discoverable domain controller.
    #>
    [CmdletBinding()]
    param()

    $script:ADTCurrentModule = 'Network'

    try {
        Write-ADTSection -Title 'AD port connectivity'

        $domainName = $script:ADTCaps['DomainName']
        $dcList = Get-ADTDomainControllerTargets

        if ($dcList.Count -eq 0) {
            $dsgetdcFix = 'nltest /dsgetdc:' + $domainName
            $srvFix = 'Resolve-DnsName -Name _ldap._tcp.dc._msdcs.' + $domainName + ' -Type SRV'
            Write-ADTResult -Check 'AD port connectivity' -Status ERROR -Detail 'No domain controllers could be enumerated (AD module unavailable and the DNS SRV lookup failed or returned nothing).' -Why 'Neither Get-ADDomainController nor a DNS SRV lookup for _ldap._tcp.dc._msdcs.<domain> returned a usable result, so there is nothing to port-test.' -Fix @($srvFix, $dsgetdcFix)
            return
        }

        $ports = @(53, 88, 135, 389, 445, 464, 636, 3268, 3269)
        $matrixResults = @{}

        foreach ($dc in $dcList) {
            $portStates = @{}
            foreach ($port in $ports) {
                $portStates[$port] = Test-ADTPort -ComputerName $dc.HostName -Port $port -TimeoutMs 2000
            }
            $matrixResults[$dc.HostName] = $portStates
        }

        # ---- render the matrix ----
        $header = 'DC'.PadRight(28)
        foreach ($port in $ports) { $header = $header + (' ' + ([string]$port).PadLeft(6)) }
        Write-ADTNote -Text $header
        foreach ($dc in $dcList) {
            $line = $dc.HostName.PadRight(28)
            foreach ($port in $ports) {
                $mark = 'open'
                if (-not $matrixResults[$dc.HostName][$port]) { $mark = 'CLOSED' }
                $line = $line + (' ' + $mark.PadLeft(6))
            }
            Write-ADTNote -Text $line
        }

        # ---- pass/fail per DC, plus WinRM INFO ----
        foreach ($dc in $dcList) {
            $closedPorts = @()
            foreach ($port in $ports) {
                if (-not $matrixResults[$dc.HostName][$port]) { $closedPorts += $port }
            }

            if ($closedPorts.Count -eq 0) {
                Write-ADTResult -Check ('AD ports: ' + $dc.HostName) -Status PASS -Detail 'All 9 tested TCP ports open (53, 88, 135, 389, 445, 464, 636, 3268, 3269).'
            }
            else {
                foreach ($port in $closedPorts) {
                    $role = Get-ADTPortRoleName -Port $port
                    $retestCmd = ('Test-NetConnection -ComputerName ' + $dc.HostName + ' -Port ' + $port)
                    $portWhy = ('Port ' + $port + ' (' + $role + ') is one of the ports Microsoft documents as required for AD DS domain controller communication - see "How to configure a firewall for Active Directory domains and trusts" (KB179442) on Microsoft Learn. A client or member server that cannot reach this port on ' + $dc.HostName + ' will fail whichever operation depends on it.')
                    Write-ADTResult -Check ('AD port ' + $port + ' (' + $role + ') on ' + $dc.HostName) -Status FAIL -Detail ('TCP ' + $port + ' is closed or filtered.') -Why $portWhy -Fix @($retestCmd, ('If this is a deliberate segmentation rule, confirm it is intended; otherwise open TCP ' + $port + ' from this host to ' + $dc.HostName + '.'))
                }
            }

            $winrmOpen = Test-ADTPort -ComputerName $dc.HostName -Port 5985 -TimeoutMs 2000
            $winrmText = 'closed'
            if ($winrmOpen) { $winrmText = 'open' }
            Write-ADTResult -Check ('WinRM (5985) on ' + $dc.HostName) -Status INFO -Detail ('TCP 5985 is ' + $winrmText + '.')
        }

        # ---- honest UDP coverage note ----
        $udpWhy = 'A true UDP test needs a protocol-aware probe (a DNS query for 53, a Kerberos exchange for 88/464, an LDAP ping for 389, w32tm for 123); a raw UDP socket send/receive is not a reliable open/closed signal because UDP has no handshake, so Test-ADTPort (a TCP connect probe) cannot be reused for it.'
        $udpFixDns = ''
        $udpFixLdap = ''
        if ($dcList.Count -gt 0) {
            $udpFixDns = ('Resolve-DnsName -Name ' + $domainName + ' -Server ' + $dcList[0].HostName)
            $udpFixLdap = ('nltest /dsgetdc:' + $domainName)
        }
        Write-ADTResult -Check 'AD port connectivity: UDP coverage' -Status INFO -Detail 'UDP 88 (Kerberos), UDP 389 (LDAP/CLDAP ping), and UDP 123 (W32Time) were NOT tested by this check - Test-ADTPort is TCP-only.' -Why $udpWhy -Fix @($udpFixLdap, $udpFixDns)
    }
    catch {
        Write-ADTResult -Check 'AD port connectivity' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Item 3: Path quality

function Invoke-ADTNetPathQuality {
    <#
        .SYNOPSIS
            Gateway/DNS/PDC ping loss and latency, an MTU black-hole probe, and an
            optional traceroute to the PDC. Deliberately excluded from the snapshot
            (Snapshot=$false) because it is slow by design.
    #>
    [CmdletBinding()]
    param()

    $script:ADTCurrentModule = 'Network'

    try {
        Write-ADTSection -Title 'Path quality'

        $adapters = Get-ADTNetAdapterConfig

        # ---- gateway: ping x10 + MTU probe ----
        $allGateways = @()
        foreach ($adapter in $adapters) {
            foreach ($gwAddr in $adapter.IPv4Gateway) {
                if (-not [string]::IsNullOrEmpty($gwAddr)) { $allGateways += $gwAddr }
            }
        }
        $gateways = @($allGateways | Select-Object -Unique)

        if ($gateways.Count -eq 0) {
            Write-ADTResult -Check 'Path quality: gateway' -Status SKIP -Detail 'No default gateway is configured; the gateway ping and MTU probe were skipped.'
        }
        else {
            foreach ($gatewayAddress in $gateways) {
                $pingSummary = Get-ADTPingSummary -TargetAddress $gatewayAddress -Count 10
                Invoke-ADTPingResultReport -Label ('Gateway ' + $gatewayAddress) -Summary $pingSummary

                $mtuProbe = Get-ADTMtuProbe -TargetAddress $gatewayAddress
                if ($mtuProbe.FullSizeOk) {
                    Write-ADTResult -Check ('Path MTU to gateway ' + $gatewayAddress) -Status PASS -Detail 'Full 1500-byte Ethernet MTU confirmed (a 1472-byte payload plus the 28-byte IP/ICMP header did not need fragmenting).'
                }
                elseif ($null -ne $mtuProbe.WorkingSize) {
                    $mtuWhy = 'Traffic larger than this size is either being fragmented or silently dropped by a device in the path. This is the classic signature of a black-hole router (a hop that will not return the "fragmentation needed" ICMP message that TCP''s Path MTU Discovery depends on) or a VPN/PPPoE/GRE overlay that reduces the effective MTU below Ethernet''s 1500. It typically shows up as large downloads or file copies stalling while small requests (DNS, an RDP login) work fine.'
                    Write-ADTResult -Check ('Path MTU to gateway ' + $gatewayAddress) -Status WARN -Detail ('Path only carries an unfragmented payload up to ' + $mtuProbe.WorkingSize + ' bytes (expected 1472 for a full 1500-byte MTU path).') -Why $mtuWhy -Fix @(('tracert /d /h 15 ' + $gatewayAddress), 'If a VPN/tunnel is in the path, set that tunnel interface''s MTU to match (commonly 1400 or 1350 for common overlays) rather than leaving clients to discover it the hard way.', '[SERVICE-AFFECTING, needs a reboot] Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name EnablePMTUBHDetect -Value 1 -Type DWord   (lets this host work around a black-hole router that will not send the ICMP message PMTU discovery needs)')
                }
                elseif ($mtuProbe.FragmentationSeen) {
                    Write-ADTResult -Check ('Path MTU to gateway ' + $gatewayAddress) -Status WARN -Detail 'Even the smallest tested payload (1350 bytes) needs fragmentation; the path MTU to the gateway is unusually small.' -Why 'Same black-hole-router/VPN-overlay concern as a partial MTU reduction, just more severe.' -Fix @(('tracert /d /h 15 ' + $gatewayAddress), 'Check for a VPN/tunnel adapter with an unusually low configured MTU and align it with what this probe found.')
                }
                else {
                    Write-ADTResult -Check ('Path MTU to gateway ' + $gatewayAddress) -Status INFO -Detail 'Could not confirm path MTU: the gateway did not answer any of the sized ping probes (1472/1400/1350 bytes).' -Why 'This is inconclusive rather than a confirmed MTU problem - it usually means ICMP echo is filtered somewhere in the path, which also prevents this specific test from working; it is not evidence of a black-hole router by itself.'
                }
            }
        }

        # ---- each DNS server: ping x4 ----
        $allDns = @()
        foreach ($adapter in $adapters) {
            foreach ($dnsAddr in $adapter.DNSServers) {
                if (-not [string]::IsNullOrEmpty($dnsAddr) -and $dnsAddr -notmatch ':') { $allDns += $dnsAddr }
            }
        }
        $dnsServers = @($allDns | Select-Object -Unique)

        if ($dnsServers.Count -eq 0) {
            Write-ADTResult -Check 'Path quality: DNS servers' -Status SKIP -Detail 'No IPv4 DNS servers configured; DNS server pings were skipped.'
        }
        else {
            foreach ($dnsServer in $dnsServers) {
                $pingSummary = Get-ADTPingSummary -TargetAddress $dnsServer -Count 4
                Invoke-ADTPingResultReport -Label ('DNS server ' + $dnsServer) -Summary $pingSummary
            }
        }

        # ---- PDC: ping x10 + optional traceroute ----
        if ($script:ADTCaps['DomainJoined']) {
            $pdcName = Get-ADTPdcName
            if ([string]::IsNullOrEmpty($pdcName)) {
                Write-ADTResult -Check 'Path quality: PDC' -Status SKIP -Detail 'Could not determine the PDC emulator (AD module unavailable and the .NET DirectoryServices lookup failed).'
            }
            else {
                $pingSummary = Get-ADTPingSummary -TargetAddress $pdcName -Count 10
                Invoke-ADTPingResultReport -Label ('PDC ' + $pdcName) -Summary $pingSummary

                $traceResult = Invoke-ADTNative -FilePath 'tracert.exe' -Arguments @('/d', '/h', '15', $pdcName) -TimeoutSec 45
                if ([string]::IsNullOrEmpty($traceResult.StdOut)) {
                    Write-ADTResult -Check ('Traceroute to PDC: ' + $pdcName) -Status SKIP -Detail 'tracert produced no output (timed out, or ICMP is filtered end to end).'
                }
                else {
                    Write-ADTNote -Text ('Traceroute to PDC ' + $pdcName + ' (max 15 hops, no reverse DNS):')
                    $traceLines = @($traceResult.StdOut -split "`r`n|`n")
                    foreach ($traceLine in $traceLines) {
                        if ([string]::IsNullOrWhiteSpace($traceLine)) { continue }
                        Write-ADTNote -Text $traceLine
                    }
                    $hopCount = @($traceLines | Where-Object { $_ -match '^\s*\d+\s' }).Count
                    Write-ADTResult -Check ('Traceroute to PDC: ' + $pdcName) -Status INFO -Detail ($hopCount.ToString() + ' hop line(s) captured; see the note lines above for the full path.') -Data $traceResult.StdOut
                }
            }
        }
    }
    catch {
        Write-ADTResult -Check 'Path quality' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Module registration

Register-ADTModule -Name 'Network' -Group 'ON-PREM' -Items @(
    @{ Label = 'Network configuration sanity'; Function = 'Invoke-ADTNetConfig';      Requires = @();               Snapshot = $true }
    @{ Label = 'AD port connectivity';         Function = 'Invoke-ADTNetADPorts';     Requires = @('DomainJoined'); Snapshot = $true }
    @{ Label = 'Path quality';                 Function = 'Invoke-ADTNetPathQuality'; Requires = @();               Snapshot = $false }
)

#endregion
