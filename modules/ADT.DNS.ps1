# ADT.DNS.ps1 - DNS server health and domain DNS record checks.
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.

#region Private helpers

function Get-ADTDnsSafeProperty {
    <#
        .SYNOPSIS
            Reads a property from an object without throwing if it is missing.
        .DESCRIPTION
            CIM instances and DnsClient record objects can vary slightly between OS
            builds and record types. This degrades to $null instead of raising an
            exception so one unexpected shape never takes down the whole check.
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
        if ($null -ne $property) { return $property.Value }
        return $null
    }
    catch {
        return $null
    }
}

function Format-ADTDnsList {
    <#
        .SYNOPSIS
            Join an array into a readable comma-separated string, with a fallback for
            empty or all-null input.
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
        $text = [string]$item
        if ([string]::IsNullOrEmpty($text)) { continue }
        $strings += $text
    }

    if ($strings.Count -eq 0) { return $EmptyText }
    return ($strings -join ', ')
}

function Test-ADTDnsPublicResolver {
    <#
        .SYNOPSIS
            True when the address is a well-known public DNS resolver.
        .DESCRIPTION
            A maintained list of well-known public resolver addresses (Google,
            Cloudflare, Quad9, OpenDNS, Verisign legacy). This is general public
            knowledge about who operates which anycast address, not a cmdlet or
            parameter, so it carries no Microsoft Learn citation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )

    $publicResolvers = @(
        '8.8.8.8', '8.8.4.4',
        '1.1.1.1', '1.0.0.1',
        '9.9.9.9', '149.112.112.112',
        '208.67.222.222', '208.67.220.220',
        '64.6.64.6', '64.6.65.6',
        '4.2.2.1', '4.2.2.2'
    )

    foreach ($candidate in $publicResolvers) {
        if ($IPAddress -eq $candidate) { return $true }
    }
    return $false
}

#endregion

#region Item 1: DNS server health

function Invoke-ADTDnsServerHealth {
    <#
        .SYNOPSIS
            DNS server health: service state, zone inventory, scavenging, forwarders,
            listening interfaces and a live SOA response test.
        .DESCRIPTION
            Runs only when Requires=@('HasDnsRole','HasDnsModule') is satisfied, so the
            DnsServer module and the DNS Server service are both known to be present.
            Every sub-check still guards its own exceptions so one bad zone, forwarder
            or query never stops the rest of the item from running.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'DNS Server Health'

        # ---- Service state ----------------------------------------------------------
        # Short name 'DNS' confirmed on Microsoft Learn (Get-Service DNS, net start DNS,
        # Restart-Service -Name DNS) - same probe Common already uses for HasDnsRole.
        try {
            $service = Get-Service -Name 'DNS' -ErrorAction Stop
            if ($service.Status -eq 'Running') {
                Write-ADTResult -Check 'DNS service state' -Status PASS `
                    -Detail ('Running (StartType: ' + $(if ($service.PSObject.Properties['StartType']) { [string]$service.StartType } else { 'n/a - pre-4.6.1 .NET' }) + ').')
            }
            else {
                $svcArgs = @{
                    Check  = 'DNS service state'
                    Status = 'FAIL'
                    Detail = 'Service state is ' + [string]$service.Status + ', expected Running.'
                    Why    = 'The DNS Server service must be running for this server to answer any query, including its own domain records.'
                    Fix    = @(
                        'Start-Service -Name DNS',
                        '[SERVICE-AFFECTING] Restart-Service -Name DNS -Force'
                    )
                }
                Write-ADTResult @svcArgs
            }
        }
        catch {
            Write-ADTResult -Check 'DNS service state' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- Zone inventory -----------------------------------------------------------
        # Get-DnsServerZone output properties ZoneName, ZoneType, IsDsIntegrated,
        # IsReverseLookupZone confirmed via the Set-DnsServerPrimaryZone -PassThru example
        # on Microsoft Learn. DynamicUpdate accepted values (None, Secure,
        # NonsecureAndSecure) confirmed via Add-DnsServerPrimaryZone / Set-DnsServerPrimaryZone.
        $zones = @()
        try {
            $zones = @(Get-DnsServerZone -ErrorAction Stop)
        }
        catch {
            Write-ADTResult -Check 'DNS zone inventory' -Status ERROR -Detail $_.Exception.Message
        }

        if ($zones.Count -eq 0) {
            Write-ADTResult -Check 'DNS zone inventory' -Status INFO -Detail 'No zones are hosted on this server.'
        }
        else {
            foreach ($zone in $zones) {
                $zoneName = [string]$zone.ZoneName
                try {
                    $zoneType       = [string](Get-ADTDnsSafeProperty -InputObject $zone -Name 'ZoneType')
                    $isDsIntegrated = [bool](Get-ADTDnsSafeProperty -InputObject $zone -Name 'IsDsIntegrated')
                    $dynamicUpdate  = [string](Get-ADTDnsSafeProperty -InputObject $zone -Name 'DynamicUpdate')
                    $isReverse      = [bool](Get-ADTDnsSafeProperty -InputObject $zone -Name 'IsReverseLookupZone')

                    $backing = 'file-backed'
                    if ($isDsIntegrated) { $backing = 'AD-integrated' }
                    $kindNote = ''
                    if ($isReverse) { $kindNote = ', reverse lookup' }

                    $detail = 'Type=' + $zoneType + ', ' + $backing + $kindNote + ', DynamicUpdate=' + $dynamicUpdate

                    if ($isDsIntegrated -and $dynamicUpdate -eq 'NonsecureAndSecure') {
                        $zoneArgs = @{
                            Check  = 'DNS zone: ' + $zoneName
                            Status = 'FAIL'
                            Detail = $detail + ' -- nonsecure dynamic updates are allowed.'
                            Why    = 'An AD-integrated zone accepting nonsecure updates lets any unauthenticated device on the network create or overwrite records in ' + $zoneName + ', including spoofing an existing hostname.'
                            Fix    = @(('Set-DnsServerPrimaryZone -Name "' + $zoneName + '" -DynamicUpdate Secure'))
                        }
                        Write-ADTResult @zoneArgs
                    }
                    elseif ($isDsIntegrated -and $dynamicUpdate -eq 'Secure') {
                        Write-ADTResult -Check ('DNS zone: ' + $zoneName) -Status PASS -Detail $detail
                    }
                    elseif ($isDsIntegrated -and $dynamicUpdate -eq 'None') {
                        $zoneArgs2 = @{
                            Check  = 'DNS zone: ' + $zoneName
                            Status = 'WARN'
                            Detail = $detail + ' -- dynamic updates are disabled on an AD-integrated zone.'
                            Why    = 'With dynamic update off, computers and domain controllers cannot self-register records in ' + $zoneName + '; records must be maintained by hand or they go stale.'
                            Fix    = @(('Set-DnsServerPrimaryZone -Name "' + $zoneName + '" -DynamicUpdate Secure'))
                        }
                        Write-ADTResult @zoneArgs2
                    }
                    else {
                        Write-ADTResult -Check ('DNS zone: ' + $zoneName) -Status INFO -Detail $detail
                    }
                }
                catch {
                    Write-ADTResult -Check ('DNS zone: ' + $zoneName) -Status ERROR -Detail $_.Exception.Message
                }
            }
        }

        # ---- Scavenging -----------------------------------------------------------------
        # Get-DnsServerScavenging properties ScavengingState / ScavengingInterval and
        # Get-DnsServerZoneAging property AgingEnabled confirmed via the matching
        # Set-DnsServerScavenging / Set-DnsServerZoneAging parameters on Microsoft Learn
        # (Set-DnsServerZoneAging's -Aging parameter carries the alias AgingEnabled,
        # which exists specifically so Get-DnsServerZoneAging output binds back into
        # Set-DnsServerZoneAging by property name - i.e. the Get- property is AgingEnabled).
        # Commands in the Fix below are copied verbatim from "Configure DNS aging and
        # scavenging" on Microsoft Learn.
        try {
            $scavenging   = Get-DnsServerScavenging -ErrorAction Stop
            $scavState    = [bool](Get-ADTDnsSafeProperty -InputObject $scavenging -Name 'ScavengingState')
            $scavInterval = Get-ADTDnsSafeProperty -InputObject $scavenging -Name 'ScavengingInterval'

            Write-ADTResult -Check 'DNS scavenging (server level)' -Status INFO `
                -Detail ('ScavengingState=' + [string]$scavState + ', ScavengingInterval=' + [string]$scavInterval)

            $adPrimaryZones = @($zones | Where-Object {
                ([bool](Get-ADTDnsSafeProperty -InputObject $_ -Name 'IsDsIntegrated')) -eq $true -and
                ([string](Get-ADTDnsSafeProperty -InputObject $_ -Name 'ZoneType')) -eq 'Primary'
            })

            $agingZoneNames = @()
            foreach ($zone in $adPrimaryZones) {
                $zoneName = [string]$zone.ZoneName
                try {
                    $aging = Get-DnsServerZoneAging -Name $zoneName -ErrorAction Stop
                    $agingEnabled = [bool](Get-ADTDnsSafeProperty -InputObject $aging -Name 'AgingEnabled')
                    Write-ADTResult -Check ('DNS zone aging: ' + $zoneName) -Status INFO `
                        -Detail ('AgingEnabled=' + [string]$agingEnabled)
                    if ($agingEnabled) { $agingZoneNames += $zoneName }
                }
                catch {
                    Write-ADTResult -Check ('DNS zone aging: ' + $zoneName) -Status ERROR -Detail $_.Exception.Message
                }
            }

            if ($agingZoneNames.Count -gt 0 -and (-not $scavState)) {
                $scavWhy = 'Aging timestamps records so stale entries can be identified, but nothing removes them unless server-level scavenging is also on. Zones with aging enabled and scavenging off accumulate dead A/PTR records from decommissioned or renamed computers indefinitely, which risks a reused IP address resolving to the wrong host.'
                $scavArgs = @{
                    Check  = 'DNS scavenging effectiveness'
                    Status = 'WARN'
                    Detail = 'Aging is enabled on ' + [string]$agingZoneNames.Count + ' zone(s) (' + (Format-ADTDnsList -Items $agingZoneNames) + ') but server-level scavenging is off, so stale records are never removed.'
                    Why    = $scavWhy
                    Fix    = @(
                        'Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval 7.00:00:00 -ApplyOnAllZones',
                        'Start-DnsServerScavenging -Verbose'
                    )
                }
                Write-ADTResult @scavArgs
            }
            elseif ($agingZoneNames.Count -gt 0 -and $scavState) {
                Write-ADTResult -Check 'DNS scavenging effectiveness' -Status PASS `
                    -Detail ('Aging enabled on ' + [string]$agingZoneNames.Count + ' zone(s) and server-level scavenging is on.')
            }
        }
        catch {
            Write-ADTResult -Check 'DNS scavenging (server level)' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- Forwarders / root hints ----------------------------------------------------
        # Get-DnsServerForwarder output property IPAddress confirmed via the matching
        # Add-DnsServerForwarder -IPAddress parameter on Microsoft Learn.
        try {
            $forwarder = Get-DnsServerForwarder -ErrorAction Stop
            $forwarderIps = @(Get-ADTDnsSafeProperty -InputObject $forwarder -Name 'IPAddress')

            if ($forwarderIps.Count -eq 0) {
                $hintCount = -1
                try { $hintCount = @(Get-DnsServerRootHint -ErrorAction Stop).Count } catch { $hintCount = -1 }
                $hintText = [string]$hintCount
                if ($hintCount -eq -1) { $hintText = 'unknown (could not read root hints)' }
                Write-ADTResult -Check 'DNS forwarders' -Status INFO `
                    -Detail ('No forwarders configured; this server resolves externally via root hints (' + $hintText + ' root hint record(s)).')
            }
            else {
                foreach ($fwdIp in $forwarderIps) {
                    $fwdIpText = [string]$fwdIp
                    try {
                        $portOpen = Test-ADTPort -ComputerName $fwdIpText -Port 53 -TimeoutMs 2000

                        if (-not $portOpen) {
                            $fwdArgs = @{
                                Check  = 'DNS forwarder: ' + $fwdIpText
                                Status = 'FAIL'
                                Detail = 'TCP 53 is not reachable on this forwarder.'
                                Why    = 'If a forwarder cannot be reached on TCP 53, this server falls back to the next forwarder or times out, slowing or breaking every external lookup that reaches this forwarder.'
                                Fix    = @(
                                    ('Test-NetConnection -ComputerName ' + $fwdIpText + ' -Port 53'),
                                    ('Confirm the forwarder is up and that no firewall between this server and ' + $fwdIpText + ' blocks TCP 53.')
                                )
                            }
                            Write-ADTResult @fwdArgs
                        }
                        elseif (-not $script:ADTCaps['HasInternet']) {
                            Write-ADTResult -Check ('DNS forwarder: ' + $fwdIpText) -Status SKIP `
                                -Detail 'TCP 53 is reachable; recursive resolution test skipped because this machine has no detected internet path.'
                        }
                        else {
                            try {
                                $resolveResult = @(Resolve-DnsName -Name 'www.microsoft.com' -Type A -Server $fwdIpText -QuickTimeout -ErrorAction Stop)
                                $answerCount = @($resolveResult | Where-Object { $_.Type -eq 'A' -or $_.Type -eq 'CNAME' }).Count
                                if ($answerCount -gt 0) {
                                    Write-ADTResult -Check ('DNS forwarder: ' + $fwdIpText) -Status PASS `
                                        -Detail ('TCP 53 open; recursive resolution through this forwarder succeeded (' + [string]$answerCount + ' record(s) for www.microsoft.com).')
                                }
                                else {
                                    $fwdArgs2 = @{
                                        Check  = 'DNS forwarder: ' + $fwdIpText
                                        Status = 'FAIL'
                                        Detail = 'TCP 53 open, but the recursive query returned no answer.'
                                        Why    = 'A forwarder that accepts the connection but returns no answer for a well-known external name cannot be relied on to resolve internet names for this server.'
                                        Fix    = @(
                                            ('Resolve-DnsName -Name www.microsoft.com -Server ' + $fwdIpText),
                                            'Check the forwarder''s own recursion setting and its internet path.'
                                        )
                                    }
                                    Write-ADTResult @fwdArgs2
                                }
                            }
                            catch {
                                $fwdArgs3 = @{
                                    Check  = 'DNS forwarder: ' + $fwdIpText
                                    Status = 'FAIL'
                                    Detail = 'TCP 53 open, but the recursive query failed: ' + $_.Exception.Message
                                    Why    = 'A forwarder that fails a live recursive query cannot be relied on to resolve internet names for this server.'
                                    Fix    = @(
                                        ('Resolve-DnsName -Name www.microsoft.com -Server ' + $fwdIpText),
                                        'Check the forwarder''s own recursion setting and its internet path.'
                                    )
                                }
                                Write-ADTResult @fwdArgs3
                            }
                        }
                    }
                    catch {
                        Write-ADTResult -Check ('DNS forwarder: ' + $fwdIpText) -Status ERROR -Detail $_.Exception.Message
                    }
                }
            }
        }
        catch {
            Write-ADTResult -Check 'DNS forwarders' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- Listening interfaces --------------------------------------------------------
        # Get-DnsServerSetting -All output property ListeningIPAddress confirmed with a
        # real example on Microsoft Learn (Get-DnsServerSetting -All sample output lists
        # "ListeningIPAddress : {172.23.90.136}"). An empty list means the DNS Server
        # service listens on every bound IP address, which is its documented default.
        try {
            $setting = Get-DnsServerSetting -All -ErrorAction Stop 3>$null 4>$null 6>$null
            $listening = @(Get-ADTDnsSafeProperty -InputObject $setting -Name 'ListeningIPAddress')
            if ($listening.Count -eq 0) {
                Write-ADTResult -Check 'DNS listening interfaces' -Status INFO `
                    -Detail 'No explicit listening addresses are set (server listens on all bound IP addresses).'
            }
            else {
                Write-ADTResult -Check 'DNS listening interfaces' -Status INFO `
                    -Detail ('Listening on: ' + (Format-ADTDnsList -Items $listening))
            }
        }
        catch {
            Write-ADTResult -Check 'DNS listening interfaces' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- Response test: SOA via 127.0.0.1 --------------------------------------------
        try {
            $domainName = $script:ADTCaps['DomainName']
            if ([string]::IsNullOrEmpty($domainName)) {
                Write-ADTResult -Check 'DNS response test (SOA via 127.0.0.1)' -Status SKIP `
                    -Detail 'No domain name was detected on this machine to query.'
            }
            else {
                $soaRecords = @()
                $soaError = $null
                try {
                    $soaResult = @(Resolve-DnsName -Name $domainName -Type SOA -Server '127.0.0.1' -QuickTimeout -ErrorAction Stop)
                    $soaRecords = @($soaResult | Where-Object { $_.Type -eq 'SOA' })
                }
                catch {
                    $soaError = $_.Exception.Message
                }

                if ($soaRecords.Count -gt 0) {
                    Write-ADTResult -Check 'DNS response test (SOA via 127.0.0.1)' -Status PASS `
                        -Detail ('The local DNS service answered the SOA query for ' + $domainName + ' over loopback.')
                }
                else {
                    $soaDetail = 'Query to 127.0.0.1 returned no SOA record for ' + $domainName + '.'
                    if (-not [string]::IsNullOrEmpty($soaError)) { $soaDetail = 'Query to 127.0.0.1 failed: ' + $soaError }
                    $soaArgs = @{
                        Check  = 'DNS response test (SOA via 127.0.0.1)'
                        Status = 'FAIL'
                        Detail = $soaDetail
                        Why    = 'This server should be able to answer for its own domain over loopback; an empty or failed answer suggests the zone is not loaded here or the service is not listening on 127.0.0.1.'
                        Fix    = @(
                            ('Resolve-DnsName -Name ' + $domainName + ' -Type SOA -Server 127.0.0.1'),
                            ('Get-DnsServerZone -Name ' + $domainName),
                            'Get-DnsServerSetting -All'
                        )
                    }
                    Write-ADTResult @soaArgs
                }
            }
        }
        catch {
            Write-ADTResult -Check 'DNS response test (SOA via 127.0.0.1)' -Status ERROR -Detail $_.Exception.Message
        }
    }
    catch {
        Write-ADTResult -Check 'DNS server health' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Item 2: Domain DNS records

function Invoke-ADTDnsDomainRecords {
    <#
        .SYNOPSIS
            Domain DNS record health from any domain member: the four DC-locator SRV
            records, A-record resolution for every DC they name, and this box's own
            resolver configuration.
        .DESCRIPTION
            Runs on Requires=@('DomainJoined') only - Resolve-DnsName and
            Get-DnsClientServerAddress both ship in-box on the DnsClient module and need
            no DNS server role or DnsServer module.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Domain DNS Records'

        $domainName = $script:ADTCaps['DomainName']
        if ([string]::IsNullOrEmpty($domainName)) {
            Write-ADTResult -Check 'Domain DNS records' -Status ERROR -Detail 'DomainName capability is empty; cannot build SRV queries.'
            return
        }

        # The four locator records requested for this check.
        $srvQueries = @(
            ('_ldap._tcp.' + $domainName),
            ('_ldap._tcp.dc._msdcs.' + $domainName),
            ('_kerberos._tcp.' + $domainName),
            ('_ldap._tcp.pdc._msdcs.' + $domainName)
        )

        # The classic Netlogon re-registration guidance, reused on every SRV failure.
        # net stop/net start netlogon and ipconfig /flushdns + /registerdns are quoted
        # verbatim from "Verify DNS Functionality to Support Directory Replication" on
        # Microsoft Learn. nltest /dsregdns is the switch requested for this check by
        # name; its exact behaviour text could not be located on Microsoft Learn in this
        # session (see completion report), so it is offered as a secondary option only.
        $netlogonFix = @(
            '[SERVICE-AFFECTING] Restart-Service -Name Netlogon -Force   (run on a domain controller to force DNS re-registration)',
            'Alternative: net stop netlogon',
            'Alternative: net start netlogon',
            'ipconfig /flushdns',
            'ipconfig /registerdns',
            # UNVERIFIED: nltest /dsregdns switch text not confirmed against Microsoft Learn this session.
            'nltest /dsregdns'
        )

        $dcTargets = @()

        foreach ($srvName in $srvQueries) {
            $srvRecords = @()
            $srvError = $null
            try {
                $srvResult = @(Resolve-DnsName -Name $srvName -Type SRV -ErrorAction Stop)
                $srvRecords = @($srvResult | Where-Object { $_.Type -eq 'SRV' })
            }
            catch {
                $srvError = $_.Exception.Message
            }

            if ($srvRecords.Count -eq 0) {
                $srvDetail = 'No SRV records were returned.'
                if (-not [string]::IsNullOrEmpty($srvError)) { $srvDetail = 'Query failed: ' + $srvError }
                $srvArgs = @{
                    Check  = 'SRV record: ' + $srvName
                    Status = 'FAIL'
                    Detail = $srvDetail
                    Why    = 'This record is registered by the Netlogon service on each domain controller. A missing record means clients using this name cannot locate a domain controller for this service.'
                    Fix    = $netlogonFix
                }
                Write-ADTResult @srvArgs
            }
            else {
                $targetList = @()
                foreach ($record in $srvRecords) {
                    # UNVERIFIED: NameTarget is the long-standing property name used for
                    # the SRV target on Resolve-DnsName's DnsRecord_SRV output; the
                    # Microsoft Learn Resolve-DnsName page documents cmdlet parameters
                    # only and does not enumerate this record type's output members.
                    $target = [string](Get-ADTDnsSafeProperty -InputObject $record -Name 'NameTarget')
                    $port   = Get-ADTDnsSafeProperty -InputObject $record -Name 'Port'
                    if (-not [string]::IsNullOrEmpty($target)) {
                        $targetList += ($target + ':' + [string]$port)
                        if (-not ($dcTargets -contains $target)) { $dcTargets += $target }
                    }
                }
                Write-ADTResult -Check ('SRV record: ' + $srvName) -Status PASS `
                    -Detail ([string]$srvRecords.Count + ' record(s): ' + (Format-ADTDnsList -Items $targetList))
            }
        }

        foreach ($target in $dcTargets) {
            $aRecords = @()
            $aError = $null
            try {
                $aResult = @(Resolve-DnsName -Name $target -Type A -ErrorAction Stop)
                $aRecords = @($aResult | Where-Object { $_.Type -eq 'A' })
            }
            catch {
                $aError = $_.Exception.Message
            }

            if ($aRecords.Count -gt 0) {
                $ips = @()
                foreach ($rec in $aRecords) {
                    $ipValue = Get-ADTDnsSafeProperty -InputObject $rec -Name 'IPAddress'
                    if ($null -ne $ipValue) { $ips += [string]$ipValue }
                }
                Write-ADTResult -Check ('DC target resolves: ' + $target) -Status PASS `
                    -Detail ('-> ' + (Format-ADTDnsList -Items $ips))
            }
            else {
                $aDetail = 'No A record was returned for this SRV target.'
                if (-not [string]::IsNullOrEmpty($aError)) { $aDetail = 'Query failed: ' + $aError }
                $aArgs = @{
                    Check  = 'DC target resolves: ' + $target
                    Status = 'FAIL'
                    Detail = $aDetail
                    Why    = 'A domain controller advertised by an SRV record must also have a resolvable A record, or clients cannot connect to it once they have the name.'
                    Fix    = @(
                        ('Resolve-DnsName -Name ' + $target + ' -Type A'),
                        ('ipconfig /registerdns   (run on ' + $target + ' if this is the affected DC)')
                    )
                }
                Write-ADTResult @aArgs
            }
        }

        # ---- This box's own resolver configuration ---------------------------------------
        try {
            $configuredServers = @()
            # UNVERIFIED: ServerAddresses is the long-standing property name used for the
            # per-interface server list on Get-DnsClientServerAddress output; the
            # Microsoft Learn page documents cmdlet parameters only and does not
            # enumerate output object members.
            $clientAddresses = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop)
            foreach ($entry in $clientAddresses) {
                $addresses = @(Get-ADTDnsSafeProperty -InputObject $entry -Name 'ServerAddresses')
                foreach ($address in $addresses) {
                    $addressText = [string]$address
                    if ([string]::IsNullOrEmpty($addressText)) { continue }
                    if (-not ($configuredServers -contains $addressText)) { $configuredServers += $addressText }
                }
            }

            $publicResolversFound = @()
            foreach ($address in $configuredServers) {
                if (Test-ADTDnsPublicResolver -IPAddress $address) { $publicResolversFound += $address }
            }

            if ($publicResolversFound.Count -gt 0) {
                $resolverArgs = @{
                    Check  = 'Resolver configuration'
                    Status = 'FAIL'
                    Detail = 'This domain-joined computer is configured to use public resolver(s): ' + (Format-ADTDnsList -Items $publicResolversFound) + '.'
                    Why    = 'A domain member must resolve through internal/AD-integrated DNS to find SRV and domain records; a public resolver cannot answer those queries, and it also sends internal name lookups off-network.'
                    Fix    = @('Set-DnsClientServerAddress -InterfaceAlias "<NIC name>" -ServerAddresses ("<internal DNS/DC IP 1>","<internal DNS/DC IP 2>")')
                }
                Write-ADTResult @resolverArgs
            }
            elseif ($script:ADTCaps['IsDC']) {
                $nonLoopback = @($configuredServers | Where-Object { $_ -ne '127.0.0.1' -and $_ -ne '::1' })
                if ($configuredServers.Count -gt 0 -and $nonLoopback.Count -eq 0) {
                    $dcWhy = 'Per Microsoft Learn troubleshooting guidance for DNS Event ID 4013, pointing a domain controller at a single DNS server, including 127.0.0.1, is a single point of failure - tolerable only in a forest with exactly one domain controller. In a multi-DC forest, a hub-site DC should list another DC/DNS server first and itself (loopback or static IP) as the last alternate.'
                    $dcArgs = @{
                        Check  = 'Resolver configuration'
                        Status = 'WARN'
                        Detail = 'This domain controller''s only configured DNS server is the loopback address (' + (Format-ADTDnsList -Items $configuredServers) + ').'
                        Why    = $dcWhy
                        Fix    = @('Set-DnsClientServerAddress -InterfaceAlias "<NIC name>" -ServerAddresses ("<partner DC IP>","127.0.0.1")')
                    }
                    Write-ADTResult @dcArgs
                }
                else {
                    Write-ADTResult -Check 'Resolver configuration' -Status PASS `
                        -Detail ('DNS client uses internal server(s): ' + (Format-ADTDnsList -Items $configuredServers) + '.')
                }
            }
            else {
                Write-ADTResult -Check 'Resolver configuration' -Status PASS `
                    -Detail ('DNS client uses internal server(s): ' + (Format-ADTDnsList -Items $configuredServers) + '.')
            }
        }
        catch {
            Write-ADTResult -Check 'Resolver configuration' -Status ERROR -Detail $_.Exception.Message
        }
    }
    catch {
        Write-ADTResult -Check 'Domain DNS records' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Module registration

Register-ADTModule -Name 'DNS' -Group 'ON-PREM' -Items @(
    @{ Label = 'DNS server health';  Function = 'Invoke-ADTDnsServerHealth';  Requires = @('HasDnsRole', 'HasDnsModule'); Snapshot = $true }
    @{ Label = 'Domain DNS records'; Function = 'Invoke-ADTDnsDomainRecords'; Requires = @('DomainJoined');               Snapshot = $true }
)

#endregion
