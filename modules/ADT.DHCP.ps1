# ADT.DHCP.ps1 - DHCP server health: authorization, scopes, failover, DNS integration.
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.

#region Private helpers

function Get-ADTDhcpSafeProperty {
    <#
        .SYNOPSIS
            Reads a property from an object without throwing if it is missing.
        .DESCRIPTION
            CIM instances returned by the DhcpServer module can vary slightly between
            OS builds. This degrades to $null instead of raising an exception so one
            unexpected shape never takes down the whole check.
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

function Format-ADTDhcpList {
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

function Test-ADTDhcpPublicResolver {
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

function Get-ADTDhcpOptionDnsValues {
    <#
        .SYNOPSIS
            Returns the flattened string values of DHCP option 006 (DNS Servers) for a
            given Get-DhcpServerv4OptionValue result set. Never throws.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$OptionValues
    )

    $values = @()
    if ($null -eq $OptionValues) { return $values }

    foreach ($optionValue in $OptionValues) {
        $rawValues = @(Get-ADTDhcpSafeProperty -InputObject $optionValue -Name 'Value')
        foreach ($rawValue in $rawValues) {
            if ($null -eq $rawValue) { continue }
            $text = [string]$rawValue
            if ([string]::IsNullOrEmpty($text)) { continue }
            $values += $text
        }
    }
    return $values
}

#endregion

#region Item: DHCP server health

function Invoke-ADTDhcpHealth {
    <#
        .SYNOPSIS
            DHCP server health: service state, AD authorization, scope inventory and
            utilization, failover relationships, conflict detection, audit logging, the
            DNS dynamic-update credential, and option 006 (DNS Servers) sanity.
        .DESCRIPTION
            Runs only when Requires=@('HasDhcpRole','HasDhcpModule') is satisfied, so the
            DhcpServer module and the DHCP Server service are both known to be present.
            Every sub-check still guards its own exceptions so one bad scope or a missing
            optional feature never stops the rest of the item from running.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'DHCP Server Health'

        # ---- Service state ----------------------------------------------------------
        # Short name 'DHCPServer' confirmed on Microsoft Learn: "Restart-Service dhcpserver"
        # (Deploy DHCP Using Windows PowerShell) and 'Start-Service -Name "DHCPServer"'
        # (Migrate a DHCP server installation to another Windows Server).
        $dhcpServiceRunning = $false
        try {
            $service = Get-Service -Name 'DHCPServer' -ErrorAction Stop
            $dhcpServiceRunning = ($service.Status -eq 'Running')
            if ($dhcpServiceRunning) {
                Write-ADTResult -Check 'DHCP service state' -Status PASS `
                    -Detail ('Running (StartType: ' + [string]$service.StartType + ').')
            }
            else {
                $svcArgs = @{
                    Check  = 'DHCP service state'
                    Status = 'FAIL'
                    Detail = 'Service state is ' + [string]$service.Status + ', expected Running.'
                    Why    = 'The DHCP Server service must be running to lease addresses; while it is down, clients on scopes served only by this server cannot renew or obtain a lease.'
                    Fix    = @(
                        'Start-Service -Name DHCPServer',
                        '[SERVICE-AFFECTING] Restart-Service -Name DHCPServer -Force'
                    )
                }
                Write-ADTResult @svcArgs
            }
        }
        catch {
            Write-ADTResult -Check 'DHCP service state' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- Authorization -------------------------------------------------------------
        # Get-DhcpServerInDC output properties IPAddress and DnsName confirmed with a
        # real example on Microsoft Learn ("Deploy DHCP Using Windows PowerShell"):
        #   IPAddress    DnsName
        #   ---------    -------
        #   10.0.0.3     DHCP1.corp.contoso.com
        try {
            $localHostFqdn = $env:COMPUTERNAME
            try {
                $localHostFqdn = [System.Net.Dns]::GetHostEntry('').HostName
            }
            catch {
                $localHostFqdn = $env:COMPUTERNAME
            }

            $localIps = @()
            try {
                $hostEntry = [System.Net.Dns]::GetHostEntry($localHostFqdn)
                foreach ($addr in $hostEntry.AddressList) { $localIps += $addr.IPAddressToString }
            }
            catch {
                $localIps = @()
            }

            $authorized = @()
            $authError = $null
            try {
                $authorized = @(Get-DhcpServerInDC -ErrorAction Stop)
            }
            catch {
                $authError = $_.Exception.Message
            }

            if (-not [string]::IsNullOrEmpty($authError)) {
                if (-not $script:ADTCaps['DomainJoined']) {
                    Write-ADTResult -Check 'DHCP authorization' -Status INFO `
                        -Detail 'This server is not domain-joined; Active Directory-based DHCP authorization does not apply.'
                }
                else {
                    Write-ADTResult -Check 'DHCP authorization' -Status ERROR -Detail $authError
                }
            }
            else {
                $isAuthorized = $false
                foreach ($entry in $authorized) {
                    $entryDns = [string](Get-ADTDhcpSafeProperty -InputObject $entry -Name 'DnsName')
                    $entryIp  = [string](Get-ADTDhcpSafeProperty -InputObject $entry -Name 'IPAddress')
                    if ((-not [string]::IsNullOrEmpty($entryDns)) -and $entryDns -eq $localHostFqdn) { $isAuthorized = $true }
                    if ((-not [string]::IsNullOrEmpty($entryIp)) -and ($localIps -contains $entryIp)) { $isAuthorized = $true }
                }

                if ($isAuthorized) {
                    Write-ADTResult -Check 'DHCP authorization' -Status PASS `
                        -Detail ('This server (' + $localHostFqdn + ') is authorized in Active Directory.')
                }
                elseif ($dhcpServiceRunning) {
                    $authArgs = @{
                        Check  = 'DHCP authorization'
                        Status = 'FAIL'
                        Detail = 'This server (' + $localHostFqdn + ') is running the DHCP Server service but is not in the list of ' + [string]$authorized.Count + ' server(s) authorized in Active Directory.'
                        Why    = 'An unauthorized DHCP server in a domain is treated as rogue: Windows disables its own scopes once it detects this, so leases it appears to be issuing cannot be trusted.'
                        Fix    = @(
                            ('Add-DhcpServerInDC -DnsName ' + $localHostFqdn + ' -IPAddress <this server''s IP address>'),
                            'Get-DhcpServerInDC'
                        )
                    }
                    Write-ADTResult @authArgs
                }
                else {
                    Write-ADTResult -Check 'DHCP authorization' -Status INFO `
                        -Detail ('This server (' + $localHostFqdn + ') is not in the authorized list, but the DHCP service is not running.')
                }
            }
        }
        catch {
            Write-ADTResult -Check 'DHCP authorization' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- Scope table: state, utilization, per-scope option 006 ----------------------
        # Get-DhcpServerv4Scope property State confirmed via the Remove-DhcpServerv4Scope
        # example ($_.State -Eq "Inactive"). Get-DhcpServerv4ScopeStatistics property
        # PercentageInUse confirmed via its own example
        # ($_.PercentageInUse -Gt 80). Get-DhcpServerv4OptionValue -OptionId 6 / -Value
        # confirmed as "DNS server" (option ID 6) via Set-DhcpServerv4OptionValue examples.
        $scopes = @()
        try {
            $scopes = @(Get-DhcpServerv4Scope -ErrorAction Stop)
        }
        catch {
            Write-ADTResult -Check 'DHCP scope inventory' -Status ERROR -Detail $_.Exception.Message
        }

        if ($scopes.Count -eq 0) {
            Write-ADTResult -Check 'DHCP scope inventory' -Status INFO -Detail 'No IPv4 scopes are configured on this server.'
        }
        else {
            $allStats = @()
            try {
                $allStats = @(Get-DhcpServerv4ScopeStatistics -ErrorAction Stop)
            }
            catch {
                Write-ADTResult -Check 'DHCP scope statistics' -Status ERROR -Detail $_.Exception.Message
            }

            foreach ($scope in $scopes) {
                $scopeId     = Get-ADTDhcpSafeProperty -InputObject $scope -Name 'ScopeId'
                $scopeIdText = [string]$scopeId
                $scopeName   = [string](Get-ADTDhcpSafeProperty -InputObject $scope -Name 'Name')
                $scopeState  = [string](Get-ADTDhcpSafeProperty -InputObject $scope -Name 'State')
                $scopeLabel  = $scopeName + ' (' + $scopeIdText + ')'

                try {
                    if ($scopeState -eq 'Inactive') {
                        Write-ADTResult -Check ('DHCP scope: ' + $scopeLabel) -Status INFO -Detail 'Scope is inactive.'
                    }
                    else {
                        $stat = $null
                        foreach ($candidate in $allStats) {
                            $candidateScopeId = [string](Get-ADTDhcpSafeProperty -InputObject $candidate -Name 'ScopeId')
                            if ($candidateScopeId -eq $scopeIdText) { $stat = $candidate; break }
                        }

                        if ($null -eq $stat) {
                            Write-ADTResult -Check ('DHCP scope: ' + $scopeLabel) -Status INFO -Detail 'Active, but no statistics were returned for this scope.'
                        }
                        else {
                            $pctRaw = Get-ADTDhcpSafeProperty -InputObject $stat -Name 'PercentageInUse'
                            $pct = 0.0
                            if ($null -ne $pctRaw) { $pct = [double]$pctRaw }
                            $freeCount  = Get-ADTDhcpSafeProperty -InputObject $stat -Name 'Free'
                            $inUseCount = Get-ADTDhcpSafeProperty -InputObject $stat -Name 'InUse'
                            $statDetail = 'In use: ' + [string]$pct + '% (InUse=' + [string]$inUseCount + ', Free=' + [string]$freeCount + ').'

                            if ($pct -gt 95) {
                                $scopeArgs = @{
                                    Check  = 'DHCP scope: ' + $scopeLabel
                                    Status = 'FAIL'
                                    Detail = $statDetail
                                    Why    = 'At over 95 percent of the range in use, this scope is at serious risk of exhaustion; new clients will fail to get a lease.'
                                    Fix    = @(
                                        ('Set-DhcpServerv4Scope -ScopeId ' + $scopeIdText + ' -StartRange <new start> -EndRange <new end>   (expand the range now if free address space exists in this subnet)'),
                                        'Add-DhcpServerv4Scope -Name "<new scope name>" -StartRange <..> -EndRange <..> -SubnetMask <..>   (add a second scope for this subnet and group it with the existing one as a superscope if there is no more room to expand)'
                                    )
                                }
                                Write-ADTResult @scopeArgs
                            }
                            elseif ($pct -gt 85) {
                                $scopeArgs2 = @{
                                    Check  = 'DHCP scope: ' + $scopeLabel
                                    Status = 'WARN'
                                    Detail = $statDetail
                                    Why    = 'Over 85 percent utilization gives little headroom before the scope runs out of addresses to lease.'
                                    Fix    = @(
                                        ('Set-DhcpServerv4Scope -ScopeId ' + $scopeIdText + ' -StartRange <new start> -EndRange <new end>   (expand the range if free address space exists in this subnet)'),
                                        'Review and reclaim stale reservations or exclusions in this scope before the range runs out.'
                                    )
                                }
                                Write-ADTResult @scopeArgs2
                            }
                            else {
                                Write-ADTResult -Check ('DHCP scope: ' + $scopeLabel) -Status PASS -Detail $statDetail
                            }
                        }

                        # ---- Per-scope option 006 (DNS Servers) sanity ---------------------
                        # UNVERIFIED: whether Get-DhcpServerv4OptionValue -ScopeId x -OptionId 6
                        # returns the server-level value as an inherited default when nothing is
                        # explicitly overridden at the scope, or simply returns nothing/errors,
                        # is not documented on Microsoft Learn. Handled defensively: only a
                        # successful, non-empty result is reported here.
                        try {
                            $scopeOptions = @(Get-DhcpServerv4OptionValue -ScopeId $scopeId -OptionId 6 -ErrorAction Stop)
                            $scopeDnsValues = Get-ADTDhcpOptionDnsValues -OptionValues $scopeOptions
                            if ($scopeDnsValues.Count -gt 0) {
                                $scopePublicHits = @($scopeDnsValues | Where-Object { Test-ADTDhcpPublicResolver -IPAddress $_ })
                                if ($scopePublicHits.Count -gt 0) {
                                    $optArgs = @{
                                        Check  = 'DHCP option 006 (scope ' + $scopeLabel + ')'
                                        Status = 'FAIL'
                                        Detail = 'Hands out public resolver(s): ' + (Format-ADTDhcpList -Items $scopePublicHits) + '.'
                                        Why    = 'Clients in this scope should receive the domain''s internal DNS servers so they can resolve AD/SRV records; a public resolver as the DHCP-assigned DNS server breaks domain name resolution for those clients.'
                                        Fix    = @(('Set-DhcpServerv4OptionValue -ScopeId ' + $scopeIdText + ' -OptionId 6 -Value "<internal DNS/DC IP 1>","<internal DNS/DC IP 2>"'))
                                    }
                                    Write-ADTResult @optArgs
                                }
                                else {
                                    Write-ADTResult -Check ('DHCP option 006 (scope ' + $scopeLabel + ')') -Status PASS `
                                        -Detail ('Hands out: ' + (Format-ADTDhcpList -Items $scopeDnsValues) + '.')
                                }
                            }
                        }
                        catch {
                            # No scope-level override of option 006; this scope inherits the
                            # server-level setting, which is checked separately below.
                        }
                    }
                }
                catch {
                    Write-ADTResult -Check ('DHCP scope: ' + $scopeLabel) -Status ERROR -Detail $_.Exception.Message
                }
            }
        }

        # ---- Failover relationships -------------------------------------------------------
        # TCP port 647 for DHCP failover confirmed on Microsoft Learn ("DHCP failover
        # overview": "DHCP failover uses TCP port 647 to listen for failover messages").
        # Mode confirmed via the Set-DhcpServerv4Failover -Mode parameter; PartnerServer
        # and ServerRole (Active/Standby) confirmed via Add-DhcpServerv4Failover.
        try {
            $failovers = @(Get-DhcpServerv4Failover -ErrorAction Stop)
            if ($failovers.Count -eq 0) {
                Write-ADTResult -Check 'DHCP failover' -Status INFO `
                    -Detail 'No failover relationship is configured. This server has no automatic resilience if it goes offline; consider a load-balance or hot-standby partner for any scope serving production clients.'
            }
            else {
                foreach ($fo in $failovers) {
                    $foName    = [string](Get-ADTDhcpSafeProperty -InputObject $fo -Name 'Name')
                    $foPartner = [string](Get-ADTDhcpSafeProperty -InputObject $fo -Name 'PartnerServer')
                    $foMode    = [string](Get-ADTDhcpSafeProperty -InputObject $fo -Name 'Mode')
                    $foRole    = [string](Get-ADTDhcpSafeProperty -InputObject $fo -Name 'ServerRole')
                    # UNVERIFIED: exact State enum text not confirmed on Microsoft Learn;
                    # shown for visibility only, never compared against a literal value.
                    $foState   = [string](Get-ADTDhcpSafeProperty -InputObject $fo -Name 'State')

                    try {
                        $foDetail = 'Mode=' + $foMode + ', State=' + $foState + ', Partner=' + $foPartner
                        if (-not [string]::IsNullOrEmpty($foRole)) { $foDetail = $foDetail + ', ServerRole=' + $foRole }

                        if ([string]::IsNullOrEmpty($foPartner)) {
                            Write-ADTResult -Check ('DHCP failover: ' + $foName) -Status ERROR -Detail ($foDetail + ' -- no partner server name returned.')
                        }
                        else {
                            $partnerReachable = Test-ADTPort -ComputerName $foPartner -Port 647 -TimeoutMs 2000
                            if ($partnerReachable) {
                                Write-ADTResult -Check ('DHCP failover: ' + $foName) -Status PASS -Detail ($foDetail + ' -- partner reachable on TCP 647.')
                            }
                            else {
                                $foArgs = @{
                                    Check  = 'DHCP failover: ' + $foName
                                    Status = 'FAIL'
                                    Detail = $foDetail + ' -- partner NOT reachable on TCP 647.'
                                    Why    = 'DHCP failover partners exchange lease state over TCP 647; if that port cannot be reached, this relationship cannot synchronize and the two servers can independently hand out the same address.'
                                    Fix    = @(
                                        ('Test-NetConnection -ComputerName ' + $foPartner + ' -Port 647'),
                                        ('Confirm the Microsoft-Windows-DHCP-Failover-TCP-In/Out firewall rules are enabled on both ' + $env:COMPUTERNAME + ' and ' + $foPartner + '.')
                                    )
                                }
                                Write-ADTResult @foArgs
                            }
                        }
                    }
                    catch {
                        Write-ADTResult -Check ('DHCP failover: ' + $foName) -Status ERROR -Detail $_.Exception.Message
                    }
                }
            }
        }
        catch {
            Write-ADTResult -Check 'DHCP failover' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- Conflict detection attempts -------------------------------------------------
        # Get-DhcpServerSetting property ConflictDetectionAttempts confirmed via the
        # identically named Set-DhcpServerSetting parameter on Microsoft Learn.
        try {
            $dhcpSetting = Get-DhcpServerSetting -ErrorAction Stop
            $attempts = Get-ADTDhcpSafeProperty -InputObject $dhcpSetting -Name 'ConflictDetectionAttempts'
            if ($null -eq $attempts) {
                Write-ADTResult -Check 'DHCP conflict detection' -Status ERROR -Detail 'ConflictDetectionAttempts property was not present on the returned object.'
            }
            elseif ([int]$attempts -eq 0) {
                Write-ADTResult -Check 'DHCP conflict detection' -Status INFO `
                    -Detail 'ConflictDetectionAttempts is 0: the server does not ping-test an address before offering it.'
            }
            else {
                Write-ADTResult -Check 'DHCP conflict detection' -Status PASS -Detail ('ConflictDetectionAttempts is ' + [string]$attempts + '.')
            }
        }
        catch {
            Write-ADTResult -Check 'DHCP conflict detection' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- Audit logging ------------------------------------------------------------
        # Set-DhcpServerAuditLog confirms the parameter is -Enable (not -Enabled).
        # UNVERIFIED: whether Get-DhcpServerAuditLog's matching output property is named
        # Enable or Enabled is not documented on Microsoft Learn; both are tried.
        try {
            $auditLog = Get-DhcpServerAuditLog -ErrorAction Stop
            $auditValue = Get-ADTDhcpSafeProperty -InputObject $auditLog -Name 'Enable'
            if ($null -eq $auditValue) { $auditValue = Get-ADTDhcpSafeProperty -InputObject $auditLog -Name 'Enabled' }

            if ($null -eq $auditValue) {
                Write-ADTResult -Check 'DHCP audit logging' -Status ERROR -Detail 'Could not read an Enable/Enabled property from the returned object.'
            }
            elseif ([bool]$auditValue) {
                $auditPath = Get-ADTDhcpSafeProperty -InputObject $auditLog -Name 'Path'
                Write-ADTResult -Check 'DHCP audit logging' -Status PASS -Detail ('Enabled. Path=' + [string]$auditPath)
            }
            else {
                $auditArgs = @{
                    Check  = 'DHCP audit logging'
                    Status = 'WARN'
                    Detail = 'Audit logging is disabled.'
                    Why    = 'Audit logging is the forensic trail of every lease assigned, renewed and released; with it off there is no local record to investigate a duplicate-address complaint or a suspected rogue client after the fact.'
                    Fix    = @('Set-DhcpServerAuditLog -Enable $true')
                }
                Write-ADTResult @auditArgs
            }
        }
        catch {
            Write-ADTResult -Check 'DHCP audit logging' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- DNS dynamic-update credential -------------------------------------------
        # Set-DhcpServerDnsCredential -Credential/-ComputerName confirmed on Microsoft
        # Learn. UNVERIFIED: the exact Get-DhcpServerDnsCredential output property name
        # is not enumerated on Microsoft Learn; UserName is the natural pairing implied
        # by the cmdlet's own description ("gets the domain name and user name for the
        # account"), read defensively.
        try {
            $cred = Get-DhcpServerDnsCredential -ErrorAction Stop
            $userName = Get-ADTDhcpSafeProperty -InputObject $cred -Name 'UserName'
            if ([string]::IsNullOrEmpty([string]$userName)) {
                $credArgs = @{
                    Check  = 'DHCP DNS dynamic-update credential'
                    Status = 'WARN'
                    Detail = 'No credential is configured for DHCP-driven DNS registration.'
                    Why    = 'Without a dedicated credential, the DHCP server registers client A/PTR records under its own computer account. There is then no single consistent owner enforcing secure update on those records, which opens the door to name-squatting by another authenticated device.'
                    Fix    = @(
                        '$cred = Get-Credential',
                        ('Set-DhcpServerDnsCredential -Credential $cred -ComputerName ' + $env:COMPUTERNAME)
                    )
                }
                Write-ADTResult @credArgs
            }
            else {
                Write-ADTResult -Check 'DHCP DNS dynamic-update credential' -Status PASS -Detail ('Configured account: ' + [string]$userName)
            }
        }
        catch {
            Write-ADTResult -Check 'DHCP DNS dynamic-update credential' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- Server-level option 006 (DNS Servers) ---------------------------------------
        try {
            $serverOptions = @(Get-DhcpServerv4OptionValue -OptionId 6 -ErrorAction Stop)
            $serverDnsValues = Get-ADTDhcpOptionDnsValues -OptionValues $serverOptions
            if ($serverDnsValues.Count -eq 0) {
                Write-ADTResult -Check 'DHCP option 006 (server level)' -Status INFO -Detail 'No server-level DNS Servers option is configured.'
            }
            else {
                $serverPublicHits = @($serverDnsValues | Where-Object { Test-ADTDhcpPublicResolver -IPAddress $_ })
                if ($serverPublicHits.Count -gt 0) {
                    $srvOptArgs = @{
                        Check  = 'DHCP option 006 (server level)'
                        Status = 'FAIL'
                        Detail = 'Hands out public resolver(s): ' + (Format-ADTDhcpList -Items $serverPublicHits) + '.'
                        Why    = 'Clients should receive the domain''s internal DNS servers so they can resolve AD/SRV records; a public resolver as the server-wide default DNS option breaks domain name resolution for every scope that does not override it.'
                        Fix    = @('Set-DhcpServerv4OptionValue -OptionId 6 -Value "<internal DNS/DC IP 1>","<internal DNS/DC IP 2>"')
                    }
                    Write-ADTResult @srvOptArgs
                }
                else {
                    Write-ADTResult -Check 'DHCP option 006 (server level)' -Status PASS -Detail ('Hands out: ' + (Format-ADTDhcpList -Items $serverDnsValues) + '.')
                }
            }
        }
        catch {
            Write-ADTResult -Check 'DHCP option 006 (server level)' -Status INFO -Detail 'No server-level DNS Servers option is configured (or it could not be read).'
        }
    }
    catch {
        Write-ADTResult -Check 'DHCP server health' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Module registration

Register-ADTModule -Name 'DHCP' -Group 'ON-PREM' -Items @(
    @{ Label = 'DHCP server health'; Function = 'Invoke-ADTDhcpHealth'; Requires = @('HasDhcpRole', 'HasDhcpModule'); Snapshot = $true }
)

#endregion
