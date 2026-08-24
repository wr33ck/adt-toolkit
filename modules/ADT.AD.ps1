# ADT.AD.ps1 - Active Directory core: overview, replication, SYSVOL/DFSR, time/auth, event sweep.
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.

#region Private helpers

function Get-ADTADRootDse {
    <#
        .SYNOPSIS
            Bind to RootDSE via ADSI (no AD module needed). Never throws.
    #>
    [CmdletBinding()]
    param()

    try {
        $rootDse = [ADSI]'LDAP://RootDSE'
        if ($null -eq $rootDse.distinguishedName) { return $null }

        return [PSCustomObject]@{
            DefaultNamingContext       = [string]$rootDse.defaultNamingContext[0]
            ConfigurationNamingContext = [string]$rootDse.configurationNamingContext[0]
            SchemaNamingContext        = [string]$rootDse.schemaNamingContext[0]
            RootDomainNamingContext    = [string]$rootDse.rootDomainNamingContext[0]
            DnsHostName                = [string]$rootDse.dnsHostName[0]
        }
    }
    catch {
        return $null
    }
}

function Get-ADTADTombstoneLifetime {
    <#
        .SYNOPSIS
            Read tombstoneLifetime from the Directory Service config object via ADSI.
            Returns an int (60 is the documented internal default when the attribute is
            not present), or $null if it could not be read at all.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigurationNamingContext
    )

    try {
        $dsPath = 'LDAP://CN=Directory Service,CN=Windows NT,CN=Services,' + $ConfigurationNamingContext
        $dsEntry = [ADSI]$dsPath
        $rawValue = $dsEntry.Properties['tombstoneLifetime']
        if ($null -ne $rawValue -and $rawValue.Count -gt 0) {
            return [int]$rawValue[0]
        }
        return 60
    }
    catch {
        return $null
    }
}

function Get-ADTADCsvField {
    <#
        .SYNOPSIS
            Whitespace- and case-insensitive property lookup on a ConvertFrom-Csv row.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Row,

        [Parameter(Mandatory = $true)]
        [string[]]$CandidateNames
    )

    if ($null -eq $Row) { return $null }

    try {
        $properties = $Row.PSObject.Properties
        foreach ($candidate in $CandidateNames) {
            $candidateKey = ($candidate -replace '\s', '').ToLowerInvariant()
            foreach ($property in $properties) {
                $propertyKey = ($property.Name -replace '\s', '').ToLowerInvariant()
                if ($propertyKey -eq $candidateKey) {
                    return $property.Value
                }
            }
        }
        return $null
    }
    catch {
        return $null
    }
}

function ConvertFrom-ADTADRepadminCsv {
    <#
        .SYNOPSIS
            Parse "repadmin /showrepl * /csv" output using repadmin own header row.
            Returns an object array, or $null if it could not be parsed at all.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$RawCsv
    )

    try {
        $lines = @($RawCsv -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($lines.Count -lt 2) { return $null }
        $objects = @($lines | ConvertFrom-Csv -ErrorAction Stop)
        if ($objects.Count -eq 0) { return $null }
        return $objects
    }
    catch {
        return $null
    }
}

function Get-ADTADMachineAccountAge {
    <#
        .SYNOPSIS
            Native (ADSI) lookup of this computer AD object pwdLastSet. Never throws.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DefaultNamingContext
    )

    $searcher = $null
    try {
        $searchRoot = [ADSI]('LDAP://' + $DefaultNamingContext)
        $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = $searchRoot
        $searcher.Filter = '(&(objectClass=computer)(sAMAccountName=' + $env:COMPUTERNAME + '$))'
        $null = $searcher.PropertiesToLoad.Add('pwdLastSet')
        $searcher.PageSize = 1
        $result = $searcher.FindOne()
        if ($null -eq $result) { return $null }

        $pwdLastSetRaw = $result.Properties['pwdlastset']
        if ($null -eq $pwdLastSetRaw -or $pwdLastSetRaw.Count -eq 0) { return $null }

        $fileTimeValue = [int64]$pwdLastSetRaw[0]
        if ($fileTimeValue -le 0) { return $null }

        return [DateTime]::FromFileTime($fileTimeValue)
    }
    catch {
        return $null
    }
    finally {
        if ($null -ne $searcher) {
            try { $searcher.Dispose() } catch { $null = $_ }
        }
    }
}

function Get-ADTADDfsrReplicatedFolderInfo {
    <#
        .SYNOPSIS
            Query the DfsrReplicatedFolderInfo WMI class (root\microsoftdfs). Never throws.
        .DESCRIPTION
            root\microsoftdfs is not the default CIM namespace, so this cannot use the
            shared Get-ADTWmi helper (single-class, default-namespace only). Property
            names (ReplicationGroupName, ReplicatedFolderName, State) follow long-standing
            DFSR troubleshooting documentation; State 4=Normal is the value this file
            actually relies on for a pass/fail decision, the rest are display text only.
    #>
    [CmdletBinding()]
    param()

    try {
        return @(Get-CimInstance -Namespace 'root\microsoftdfs' -ClassName 'DfsrReplicatedFolderInfo' -ErrorAction Stop)
    }
    catch {
        try {
            return @(Get-WmiObject -Namespace 'root\microsoftdfs' -Class 'DfsrReplicatedFolderInfo' -ErrorAction Stop)
        }
        catch {
            return @()
        }
    }
}

function Get-ADTADDfsrStateText {
    <#
        .SYNOPSIS
            Map a DfsrReplicatedFolderInfo State integer to display text.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$State
    )

    switch ($State) {
        0 { return 'Uninitialized' }
        1 { return 'Initialized' }
        2 { return 'Initial Sync' }
        3 { return 'Auto Recovery' }
        4 { return 'Normal' }
        5 { return 'In Error' }
        default { return ('Unknown (' + $State.ToString() + ')') }
    }
}

function Get-ADTADEventSummary {
    <#
        .SYNOPSIS
            Defensive Get-WinEvent -FilterHashtable wrapper. Never throws.
        .OUTPUTS
            PSCustomObject: Success (bool), LogMissing (bool), Events (array), ErrorMessage.
            Success=$true and Events=@() covers both "log exists, nothing matched" and
            "log does not exist" - callers that care about the difference check LogMissing.
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
        [int[]]$Level,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$ProviderName,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $false)]
        [int]$MaxEvents = 500
    )

    $outcome = @{ Success = $false; LogMissing = $false; Events = @(); ErrorMessage = '' }

    try {
        $filter = @{ LogName = $LogName; StartTime = $StartTime }
        if ($null -ne $Id -and $Id.Count -gt 0) { $filter['Id'] = $Id }
        if ($null -ne $Level -and $Level.Count -gt 0) { $filter['Level'] = $Level }
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

function Get-ADTADFsmoNative {
    <#
        .SYNOPSIS
            Best-effort "netdom query fsmo" parse. Returns a hashtable Role->Holder, or
            $null. Used only as a cross-check note, never as the pass/fail source - Item 1
            drives its FAIL decisions from Get-ADForest/Get-ADDomain instead, which are
            guaranteed available there (Requires includes HasADModule).
    #>
    [CmdletBinding()]
    param()

    try {
        $result = Invoke-ADTNative -FilePath 'netdom.exe' -Arguments @('query', 'fsmo') -TimeoutSec 30
        if ($result.ExitCode -ne 0) { return $null }

        $map = @{}
        $lines = @($result.StdOut -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

        foreach ($line in $lines) {
            if ($line -match '^\s*Schema\s+master\s+(\S+)') { $map['Schema Master'] = $Matches[1] }
            elseif ($line -match '^\s*Domain\s+naming\s+master\s+(\S+)') { $map['Domain Naming Master'] = $Matches[1] }
            elseif ($line -match '^\s*PDC\s+(\S+)') { $map['PDC Emulator'] = $Matches[1] }
            elseif ($line -match '^\s*RID\s+pool\s+manager\s+(\S+)') { $map['RID Master'] = $Matches[1] }
            elseif ($line -match '^\s*Infrastructure\s+master\s+(\S+)') { $map['Infrastructure Master'] = $Matches[1] }
        }

        if ($map.Count -eq 0) { return $null }
        return $map
    }
    catch {
        return $null
    }
}

function Get-ADTADDomainDn {
    <#
        .SYNOPSIS
            Turn a DNS domain name (contoso.com) into its default naming context DN
            (DC=contoso,DC=com). Simple, standard transform. Returns $null on bad input.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$DomainName
    )

    if ([string]::IsNullOrEmpty($DomainName)) { return $null }
    return ('DC=' + ($DomainName -replace '\.', ',DC='))
}

#endregion

#region Menu entries

function Invoke-ADTADOverview {
    <#
        .SYNOPSIS
            Item 1: DC and domain overview.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'DC and domain overview'

        $forest = $null
        $domain = $null
        try { $forest = Get-ADForest -ErrorAction Stop } catch { $forest = $null }
        try { $domain = Get-ADDomain -ErrorAction Stop } catch { $domain = $null }

        if ($null -eq $forest -or $null -eq $domain) {
            Write-ADTResult -Check 'AD module connectivity' -Status 'ERROR' `
                -Detail 'Get-ADForest/Get-ADDomain failed even though HasADModule is true.' `
                -Why 'Cannot reach a domain controller for LDAP, or the current credentials cannot bind.' `
                -Fix @(('Confirm DNS and a DC are reachable: nltest /dsgetdc:' + [string]$script:ADTCaps['DomainName']))
            return
        }

        # --- Functional levels ------------------------------------------------------
        $forestModeText = [string]$forest.ForestMode
        $domainModeText = [string]$domain.DomainMode
        $modernForestLevels = @('Windows2016Forest', 'Windows2025Forest')
        $modernDomainLevels = @('Windows2016Domain', 'Windows2025Domain')

        if ($modernForestLevels -contains $forestModeText) {
            Write-ADTResult -Check 'Forest functional level' -Status 'PASS' -Detail $forestModeText
        }
        else {
            Write-ADTResult -Check 'Forest functional level' -Status 'WARN' -Detail $forestModeText `
                -Why 'Below Windows Server 2016 forest functional level misses newer AD security defaults, and older levels are approaching or past mainstream support.' `
                -Fix @(('Raise once every domain in the forest is at the target level: Set-ADForestMode -Identity ' + $forest.Name + ' -ForestMode Windows2016Forest'))
        }

        if ($modernDomainLevels -contains $domainModeText) {
            Write-ADTResult -Check 'Domain functional level' -Status 'PASS' -Detail $domainModeText
        }
        else {
            Write-ADTResult -Check 'Domain functional level' -Status 'WARN' -Detail $domainModeText `
                -Why 'Below Windows Server 2016 domain functional level misses newer AD security defaults.' `
                -Fix @(('Raise once every DC in the domain is at the target OS level: Set-ADDomainMode -Identity ' + $domain.DNSRoot + ' -DomainMode Windows2016Domain'))
        }

        # --- FSMO role holders --------------------------------------------------------
        Write-ADTNote -Text 'Resolving FSMO role holders (AD module primary, netdom cross-check note).'
        $fsmoNative = Get-ADTADFsmoNative

        $fsmoHolders = [ordered]@{
            'Schema Master'         = $forest.SchemaMaster
            'Domain Naming Master'  = $forest.DomainNamingMaster
            'PDC Emulator'          = $domain.PDCEmulator
            'RID Master'            = $domain.RIDMaster
            'Infrastructure Master' = $domain.InfrastructureMaster
        }

        foreach ($roleName in $fsmoHolders.Keys) {
            $holder = $fsmoHolders[$roleName]
            if ([string]::IsNullOrEmpty($holder)) {
                Write-ADTResult -Check ('FSMO: ' + $roleName) -Status 'FAIL' -Detail 'No holder returned by the AD module.' `
                    -Why 'A FSMO role with no resolvable holder blocks the operations that role serializes.' `
                    -Fix @('netdom query fsmo', ('repadmin /showrepl ' + $env:COMPUTERNAME))
                continue
            }

            $reachable = Test-ADTPort -ComputerName $holder -Port 389 -TimeoutMs 2000
            if ($reachable) {
                Write-ADTResult -Check ('FSMO: ' + $roleName) -Status 'PASS' -Detail $holder
            }
            else {
                Write-ADTResult -Check ('FSMO: ' + $roleName) -Status 'FAIL' -Detail ($holder + ' (LDAP port 389 unreachable from this box)') `
                    -Why 'This FSMO holder cannot be reached on LDAP. If it is really down, operations that role serializes are blocked domain/forest-wide.' `
                    -Fix @(('Confirm from another host before assuming it is down: Test-NetConnection ' + $holder + ' -Port 389'), 'netdom query fsmo')
            }

            if ($null -ne $fsmoNative -and $fsmoNative.ContainsKey($roleName)) {
                $nativeHolder = $fsmoNative[$roleName]
                $shortName = ($holder -split '\.')[0]
                if (-not [string]::IsNullOrEmpty($nativeHolder) -and ($nativeHolder -notmatch [regex]::Escape($shortName))) {
                    Write-ADTNote -Text ('  netdom reports a different holder for ' + $roleName + ': ' + $nativeHolder + ' (AD module said ' + $holder + ')')
                }
            }
        }

        # --- DC inventory --------------------------------------------------------------
        $allDCs = @()
        try { $allDCs = @(Get-ADDomainController -Filter '*' -ErrorAction Stop) } catch { $allDCs = @() }

        if ($allDCs.Count -eq 0) {
            Write-ADTResult -Check 'DC inventory' -Status 'ERROR' -Detail 'Get-ADDomainController -Filter * returned nothing or failed.'
        }
        else {
            foreach ($dc in $allDCs) {
                $roleTags = @()
                if ($dc.IsGlobalCatalog) { $roleTags += 'GC' }
                if ($dc.IsReadOnly) { $roleTags += 'RODC' }
                $tagText = ''
                if ($roleTags.Count -gt 0) { $tagText = ' [' + ($roleTags -join ',') + ']' }
                $detail = $dc.HostName + ' - site ' + $dc.Site + ' - ' + $dc.OperatingSystem + $tagText
                Write-ADTResult -Check ('DC: ' + $dc.Name) -Status 'INFO' -Detail $detail
            }
        }

        # --- SYSVOL / NETLOGON on this box, only if this box is a DC ------------------
        if ($script:ADTCaps['IsDC']) {
            $sysvolOk = $false
            $netlogonOk = $false
            try { $sysvolOk = Test-Path -Path ('\\' + $env:COMPUTERNAME + '\SYSVOL') -ErrorAction Stop } catch { $sysvolOk = $false }
            try { $netlogonOk = Test-Path -Path ('\\' + $env:COMPUTERNAME + '\NETLOGON') -ErrorAction Stop } catch { $netlogonOk = $false }

            if ($sysvolOk -and $netlogonOk) {
                Write-ADTResult -Check 'SYSVOL and NETLOGON shares (local)' -Status 'PASS' -Detail 'Both shares are present and browsable on this DC.'
            }
            else {
                $missing = @()
                if (-not $sysvolOk) { $missing += 'SYSVOL' }
                if (-not $netlogonOk) { $missing += 'NETLOGON' }
                Write-ADTResult -Check 'SYSVOL and NETLOGON shares (local)' -Status 'FAIL' -Detail ('Missing: ' + ($missing -join ', ')) `
                    -Why 'A DC not advertising SYSVOL/NETLOGON will not process logons or GPOs correctly for clients that land on it.' `
                    -Fix @('dcdiag /test:netlogons /test:advertising', 'dfsrmig /getglobalstate')
            }
        }

        # --- krbtgt password age --------------------------------------------------------
        try {
            $krbtgt = Get-ADUser -Identity 'krbtgt' -Properties 'PasswordLastSet' -ErrorAction Stop
            if ($null -eq $krbtgt.PasswordLastSet) {
                Write-ADTResult -Check 'krbtgt password age' -Status 'ERROR' -Detail 'PasswordLastSet was empty.'
            }
            else {
                $ageDays = [int]((Get-Date) - $krbtgt.PasswordLastSet).TotalDays
                $ageDetail = $ageDays.ToString() + ' days (last set ' + $krbtgt.PasswordLastSet.ToString('yyyy-MM-dd') + ')'
                if ($ageDays -gt 180) {
                    Write-ADTResult -Check 'krbtgt password age' -Status 'WARN' -Detail $ageDetail `
                        -Why 'A long-lived krbtgt secret gives a Golden Ticket forged from a compromised copy an equally long shelf life. Microsoft recommends resetting it periodically.' `
                        -Fix @('[SERVICE-AFFECTING] Reset the krbtgt password TWICE, at least 10 hours apart - password history is 2, so a single reset leaves the previous key still valid.', 'Use Microsoft published New-KrbtgtKeys.ps1, or Active Directory Users and Computers: krbtgt account, Reset Password, wait 10+ hours, repeat once more.')
                }
                else {
                    Write-ADTResult -Check 'krbtgt password age' -Status 'PASS' -Detail $ageDetail
                }
            }
        }
        catch {
            Write-ADTResult -Check 'krbtgt password age' -Status 'ERROR' -Detail ('Get-ADUser krbtgt failed: ' + $_.Exception.Message)
        }

        # --- AD Recycle Bin ---------------------------------------------------------------
        try {
            $recycleBin = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop
            if ($null -eq $recycleBin) {
                Write-ADTResult -Check 'AD Recycle Bin' -Status 'ERROR' -Detail 'Get-ADOptionalFeature returned nothing for Recycle Bin Feature.'
            }
            else {
                # UNVERIFIED: EnabledScopes property name/shape was not independently
                # confirmed against Microsoft Learn this session (search results kept
                # surfacing Enable-ADOptionalFeature rather than the feature object
                # itself). Read defensively so a shape mismatch cannot produce a false PASS.
                $enabledScopes = $null
                $scopesReadable = $false
                try {
                    if ($recycleBin.PSObject.Properties['EnabledScopes']) {
                        $enabledScopes = $recycleBin.EnabledScopes
                        $scopesReadable = $true
                    }
                }
                catch { $enabledScopes = $null }
                $isEnabled = ($null -ne $enabledScopes) -and (@($enabledScopes).Count -gt 0)

                $rbDetail = 'Not enabled (or state could not be confirmed).'
                if ($scopesReadable -and -not $isEnabled) { $rbDetail = 'Not enabled (EnabledScopes is empty - confirmed).' }
                if ($isEnabled) {
                    Write-ADTResult -Check 'AD Recycle Bin' -Status 'PASS' -Detail 'Enabled.'
                }
                else {
                    Write-ADTResult -Check 'AD Recycle Bin' -Status 'WARN' -Detail $rbDetail `
                        -Why 'Without the Recycle Bin, an accidentally deleted object can only be recovered by an authoritative restore from backup rather than a simple restore-object operation. Enabling it is irreversible forest-wide, so this is guidance only.' `
                        -Fix @(('[SERVICE-AFFECTING] Irreversible once enabled - confirm with the client first: Enable-ADOptionalFeature -Identity "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target ' + $forest.Name))
                }
            }
        }
        catch {
            Write-ADTResult -Check 'AD Recycle Bin' -Status 'ERROR' -Detail ('Get-ADOptionalFeature failed: ' + $_.Exception.Message)
        }

        # --- Tombstone lifetime -------------------------------------------------------------
        $rootDse = Get-ADTADRootDse
        if ($null -eq $rootDse) {
            Write-ADTResult -Check 'Tombstone lifetime' -Status 'ERROR' -Detail 'Could not bind to RootDSE.'
        }
        else {
            $tsl = Get-ADTADTombstoneLifetime -ConfigurationNamingContext $rootDse.ConfigurationNamingContext
            if ($null -eq $tsl) {
                Write-ADTResult -Check 'Tombstone lifetime' -Status 'ERROR' -Detail 'Could not read tombstoneLifetime from the Directory Service configuration object.'
            }
            elseif ($tsl -eq 60) {
                Write-ADTResult -Check 'Tombstone lifetime' -Status 'WARN' -Detail ($tsl.ToString() + ' days') `
                    -Why 'A value of exactly 60 usually means the object still carries the old pre-2003-SP1 default. Confirm this is intentional - it bounds how far back a system-state backup can be and still be restorable, and how long deleted-object metadata survives for replication reconciliation.' `
                    -Fix @(('Cross-check intent with the client before changing. If raising it: Set-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,' + $rootDse.ConfigurationNamingContext + '" -Replace @{tombstoneLifetime=180}'))
            }
            else {
                Write-ADTResult -Check 'Tombstone lifetime' -Status 'INFO' -Detail ($tsl.ToString() + ' days')
            }
        }

        # --- Default domain password policy --------------------------------------------------
        try {
            $pwdPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
            $minLen = [int]$pwdPolicy.MinPasswordLength
            $lockoutThreshold = [int]$pwdPolicy.LockoutThreshold

            if ($minLen -lt 8) {
                Write-ADTResult -Check 'Password policy: minimum length' -Status 'FAIL' -Detail ($minLen.ToString() + ' characters') `
                    -Why 'A minimum password length under 8 characters is well below any current baseline (NIST SP 800-63B / CIS) and is trivially brute-forceable offline once a hash is obtained.' `
                    -Fix @(('Set-ADDefaultDomainPasswordPolicy -Identity ' + $domain.DNSRoot + ' -MinPasswordLength 14'))
            }
            else {
                Write-ADTResult -Check 'Password policy: minimum length' -Status 'INFO' -Detail ($minLen.ToString() + ' characters')
            }

            if ($lockoutThreshold -eq 0) {
                Write-ADTResult -Check 'Password policy: account lockout' -Status 'WARN' -Detail 'LockoutThreshold=0 (lockout disabled)' `
                    -Why 'With account lockout disabled, the domain has no built-in defence against online password-guessing or spray attacks.' `
                    -Fix @(('Set-ADDefaultDomainPasswordPolicy -Identity ' + $domain.DNSRoot + ' -LockoutThreshold 10 -LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00'))
            }
            else {
                Write-ADTResult -Check 'Password policy: account lockout' -Status 'INFO' -Detail ('Threshold=' + $lockoutThreshold.ToString() + ' Duration=' + $pwdPolicy.LockoutDuration.ToString())
            }

            Write-ADTResult -Check 'Password policy: other settings' -Status 'INFO' `
                -Detail ('ComplexityEnabled=' + $pwdPolicy.ComplexityEnabled.ToString() + ' MaxPasswordAge=' + $pwdPolicy.MaxPasswordAge.ToString() + ' MinPasswordAge=' + $pwdPolicy.MinPasswordAge.ToString() + ' PasswordHistoryCount=' + $pwdPolicy.PasswordHistoryCount.ToString())
        }
        catch {
            Write-ADTResult -Check 'Default domain password policy' -Status 'ERROR' -Detail ('Get-ADDefaultDomainPasswordPolicy failed: ' + $_.Exception.Message)
        }
    }
    catch {
        Write-ADTResult -Check 'DC and domain overview' -Status 'ERROR' -Detail ('Unhandled exception: ' + $_.Exception.Message)
    }
}

function Invoke-ADTReplication {
    <#
        .SYNOPSIS
            Item 2: Replication health.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Replication health'

        $domainName = $script:ADTCaps['DomainName']
        $domainDn = Get-ADTADDomainDn -DomainName $domainName

        # --- repadmin /replsummary -------------------------------------------------------
        $summaryResult = Invoke-ADTNative -FilePath 'repadmin.exe' -Arguments @('/replsummary') -TimeoutSec 60

        if ($summaryResult.ExitCode -eq -1) {
            Write-ADTResult -Check 'repadmin availability' -Status 'SKIP' -Detail 'repadmin.exe was not found on this box.' `
                -Why 'repadmin.exe ships with the AD DS server role and should be present on every DC. Its absence here is itself worth investigating.'
        }
        elseif ([string]::IsNullOrWhiteSpace($summaryResult.StdOut)) {
            Write-ADTResult -Check 'repadmin /replsummary' -Status 'ERROR' -Detail 'No output returned.'
        }
        else {
            $summaryLines = @($summaryResult.StdOut -split "`r?`n")
            $sourceHeaderIndex = -1
            for ($i = 0; $i -lt $summaryLines.Count; $i++) {
                if ($summaryLines[$i] -match '^\s*Source\s+DSA\b') { $sourceHeaderIndex = $i; break }
            }

            if ($sourceHeaderIndex -lt 0) {
                Write-ADTResult -Check 'repadmin /replsummary' -Status 'ERROR' `
                    -Detail ('Could not find the Source DSA table header in repadmin output. Raw first lines: ' + (($summaryLines | Select-Object -First 3) -join ' | '))
            }
            else {
                $dataLines = @($summaryLines[($sourceHeaderIndex + 1)..($summaryLines.Count - 1)] | Where-Object {
                        (-not [string]::IsNullOrWhiteSpace($_)) -and ($_ -notmatch '^\s*Destination\s+DSA\b')
                    })

                $parsedAny = $false

                foreach ($line in $dataLines) {
                    $tokens = @($line -split '\s+' | Where-Object { $_ -ne '' })
                    if ($tokens.Count -lt 3) { continue }

                    $dsaName = $tokens[0]
                    $delta = $tokens[1] + ' ' + $tokens[2]
                    $failToken = $tokens[$tokens.Count - 1]

                    $failCount = 0
                    $totalCount = 0
                    if ($failToken -match '^(\d+)\s*/\s*(\d+)$') {
                        $failCount = [int]$Matches[1]
                        $totalCount = [int]$Matches[2]
                    }
                    elseif ($tokens.Count -ge 5 -and $tokens[$tokens.Count - 2] -match '^\d+$' -and $failToken -match '^\d+$') {
                        $failCount = [int]$tokens[$tokens.Count - 2]
                        $totalCount = [int]$failToken
                    }
                    else {
                        continue
                    }

                    $parsedAny = $true
                    $deltaMinutes = 0
                    if ($delta -match '(\d+)d') { $deltaMinutes += [int]$Matches[1] * 24 * 60 }
                    if ($delta -match '(\d+)h') { $deltaMinutes += [int]$Matches[1] * 60 }
                    if ($delta -match '(\d+)m') { $deltaMinutes += [int]$Matches[1] }

                    if ($failCount -gt 0) {
                        $replicateFix = 'repadmin /replicate <dest-dc> ' + $dsaName + ' "<naming-context>"'
                        if (-not [string]::IsNullOrEmpty($domainDn)) {
                            $replicateFix = 'repadmin /replicate <dest-dc> ' + $dsaName + ' "' + $domainDn + '"  (adjust the NC if the failure is on Schema/Configuration rather than the domain partition)'
                        }
                        Write-ADTResult -Check ('Replication summary: ' + $dsaName) -Status 'FAIL' `
                            -Detail ('largest delta ' + $delta + ', ' + $failCount.ToString() + '/' + $totalCount.ToString() + ' partners failing') `
                            -Why 'One or more replication partners for this DC are failing outright, not just delayed. Left alone, the copy of AD on this DC drifts from the rest of the domain.' `
                            -Fix @(('repadmin /showrepl ' + $dsaName + ' /errorsonly'), $replicateFix)
                    }
                    elseif ($deltaMinutes -gt 60) {
                        Write-ADTResult -Check ('Replication summary: ' + $dsaName) -Status 'WARN' `
                            -Detail ('largest delta ' + $delta + ', 0 failures') `
                            -Why 'No hard failures, but this DC has not successfully replicated in over an hour, which is unusual on a healthy LAN-connected topology.' `
                            -Fix @(('repadmin /showrepl ' + $dsaName))
                    }
                    else {
                        Write-ADTResult -Check ('Replication summary: ' + $dsaName) -Status 'PASS' -Detail ('largest delta ' + $delta + ', 0 failures')
                    }
                }

                if (-not $parsedAny) {
                    if ($dataLines.Count -eq 0) {
                        Write-ADTResult -Check 'repadmin /replsummary' -Status 'PASS' `
                            -Detail 'Table headers present with no partner rows - this DC reports no replication partners (single-DC domain).' `
                            -Why 'With one domain controller there is nothing to replicate with. If this domain SHOULD have more than one DC, that absence is itself the finding.'
                    }
                    else {
                        Write-ADTResult -Check 'repadmin /replsummary' -Status 'ERROR' `
                            -Detail ('Header was found but no data rows could be parsed. Raw lines: ' + (($dataLines | Select-Object -First 3) -join ' | '))
                    }
                }
            }
        }

        # --- repadmin /showrepl /csv -----------------------------------------------------
        $csvResult = Invoke-ADTNative -FilePath 'repadmin.exe' -Arguments @('/showrepl', '*', '/csv') -TimeoutSec 90

        if ($csvResult.ExitCode -eq -1) {
            Write-ADTResult -Check 'repadmin /showrepl /csv' -Status 'SKIP' -Detail 'repadmin.exe was not found on this box.'
        }
        elseif ([string]::IsNullOrWhiteSpace($csvResult.StdOut)) {
            Write-ADTResult -Check 'repadmin /showrepl /csv' -Status 'PASS' `
                -Detail 'No output - this DC has no inbound replication neighbours to report (single-DC domain).'
        }
        else {
            $csvRows = ConvertFrom-ADTADRepadminCsv -RawCsv $csvResult.StdOut
            if ($null -eq $csvRows) {
                $rawPreview = ''
                if (-not [string]::IsNullOrEmpty($csvResult.StdOut)) {
                    $rawPreview = (($csvResult.StdOut -split "`r?`n" | Select-Object -First 3) -join ' | ')
                }
                Write-ADTResult -Check 'repadmin /showrepl /csv' -Status 'ERROR' -Detail ('Could not parse CSV output. Raw first lines: ' + $rawPreview)
            }
            else {
                foreach ($row in $csvRows) {
                    $destDsa = Get-ADTADCsvField -Row $row -CandidateNames @('Destination DSA')
                    $sourceDsa = Get-ADTADCsvField -Row $row -CandidateNames @('Source DSA')
                    $namingContext = Get-ADTADCsvField -Row $row -CandidateNames @('Naming Context')
                    $numFailures = Get-ADTADCsvField -Row $row -CandidateNames @('Number of Failures')
                    $lastSuccess = Get-ADTADCsvField -Row $row -CandidateNames @('Last Success Time')
                    $lastFailureStatus = Get-ADTADCsvField -Row $row -CandidateNames @('Last Failure Status')

                    if ([string]::IsNullOrEmpty($sourceDsa) -or [string]::IsNullOrEmpty($destDsa)) { continue }

                    $failCountVal = 0
                    if (-not [string]::IsNullOrEmpty($numFailures)) { [void][int]::TryParse($numFailures, [ref]$failCountVal) }

                    $checkName = 'Repl partner: ' + $destDsa + ' from ' + $sourceDsa
                    $detailText = 'NC=' + $namingContext + ' LastSuccess=' + $lastSuccess + ' Failures=' + $numFailures

                    if ($failCountVal -gt 0) {
                        Write-ADTResult -Check $checkName -Status 'FAIL' -Detail ($detailText + ' LastError=' + $lastFailureStatus) `
                            -Why ([string]$numFailures + ' consecutive replication failure(s) from ' + $sourceDsa + ' for this partition. Changes on the source are not reaching this destination.') `
                            -Fix @(('repadmin /replicate ' + $destDsa + ' ' + $sourceDsa + ' "' + $namingContext + '"'), ('repadmin /showrepl ' + $destDsa + ' /errorsonly'))
                    }
                    else {
                        Write-ADTResult -Check $checkName -Status 'PASS' -Detail $detailText
                    }
                }
            }
        }

        # --- repadmin /queue --------------------------------------------------------------
        # UNVERIFIED: exact per-line grammar of "repadmin /queue" output was not confirmed
        # against Microsoft Learn this session (the switch existence and general purpose -
        # pending inbound replication work for a DC - is well established). Only a
        # confidently recognised phrase drives PASS/WARN; anything else surfaces as INFO
        # with the raw text rather than being guessed.
        $queueResult = Invoke-ADTNative -FilePath 'repadmin.exe' -Arguments @('/queue', $env:COMPUTERNAME) -TimeoutSec 30

        if ($queueResult.ExitCode -eq -1) {
            Write-ADTResult -Check 'repadmin /queue' -Status 'SKIP' -Detail 'repadmin.exe was not found on this box.'
        }
        else {
            $queueText = [string]$queueResult.StdOut
            if ($queueText -match '(?i)queue\s+contains\s+0\s+items' -or $queueText -match '(?i)is\s+empty') {
                Write-ADTResult -Check 'repadmin /queue depth' -Status 'PASS' -Detail '0 items queued.'
            }
            elseif ($queueText -match '(\d+)\s+entries?\s+in\s+queue' -or $queueText -match '(?i)queue\s+contains\s+(\d+)\s+items') {
                $queueDepth = [int]$Matches[1]
                if ($queueDepth -gt 50) {
                    Write-ADTResult -Check 'repadmin /queue depth' -Status 'WARN' -Detail ($queueDepth.ToString() + ' items queued.') `
                        -Why 'A deep, non-draining inbound replication queue points at a partner that cannot keep up, or a link that cannot carry the change volume.' `
                        -Fix @(('repadmin /queue ' + $env:COMPUTERNAME + '  (re-run after a few minutes to see whether it is draining)'), 'repadmin /replsummary')
                }
                else {
                    Write-ADTResult -Check 'repadmin /queue depth' -Status 'PASS' -Detail ($queueDepth.ToString() + ' items queued.')
                }
            }
            else {
                $rawPreview = (($queueText -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 3) -join ' | ')
                Write-ADTResult -Check 'repadmin /queue depth' -Status 'INFO' -Detail ('Output format not recognised, raw: ' + $rawPreview)
            }
        }

        # --- repadmin /showbackup vs tombstone lifetime --------------------------------------
        $rootDse = Get-ADTADRootDse
        $tsl = $null
        if ($null -ne $rootDse) {
            $tsl = Get-ADTADTombstoneLifetime -ConfigurationNamingContext $rootDse.ConfigurationNamingContext
        }

        # UNVERIFIED: exact per-line grammar of "repadmin /showbackup" output was not
        # confirmed against Microsoft Learn this session (the switch existence and purpose -
        # last-backup time per naming context, from AD replication metadata - is well
        # established). Parsed defensively via a date-shaped token search; anything not
        # confidently parsed becomes ERROR with raw text, never a guessed PASS.
        $backupResult = Invoke-ADTNative -FilePath 'repadmin.exe' -Arguments @('/showbackup') -TimeoutSec 60

        if ($backupResult.ExitCode -eq -1) {
            Write-ADTResult -Check 'repadmin /showbackup' -Status 'SKIP' -Detail 'repadmin.exe was not found on this box.'
        }
        elseif ([string]::IsNullOrWhiteSpace($backupResult.StdOut)) {
            Write-ADTResult -Check 'repadmin /showbackup' -Status 'ERROR' -Detail 'No output returned.'
        }
        else {
            $backupLines = @($backupResult.StdOut -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            $parsedBackupAny = $false

            # Real output shape (verified on Server 2025): each naming context on its own
            # line (starts DC=/CN=), followed by an indented metadata row whose timestamp
            # (yyyy-MM-dd HH:mm:ss) is the dSASignature time. On a DC that has never had a
            # system-state backup that timestamp is effectively the promotion time.
            $currentNc = $null
            foreach ($line in $backupLines) {
                $trimmedLine = $line.Trim()
                if ($trimmedLine -match '^(DC=|CN=)') { $currentNc = $trimmedLine; continue }

                $dateText = $null
                if ($trimmedLine -match '(\d{4}-\d{2}-\d{2}\s+\d{1,2}:\d{2}:\d{2})') { $dateText = $Matches[1] }
                elseif ($trimmedLine -match '(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?)') { $dateText = $Matches[1] }

                if ($null -ne $dateText -and $null -ne $currentNc) {
                    $ncName = $currentNc
                    $currentNc = $null
                    $parsedDate = New-Object -TypeName System.DateTime
                    $isDate = [System.DateTime]::TryParse($dateText, [ref]$parsedDate)
                    if (-not $isDate) { continue }

                    $parsedBackupAny = $true
                    $ageDays = [int]((Get-Date) - $parsedDate).TotalDays

                    if ($null -eq $tsl) {
                        Write-ADTResult -Check ('Last backup: ' + $ncName) -Status 'INFO' -Detail ($dateText + ' (' + $ageDays.ToString() + ' days ago; tombstone lifetime unknown, cannot compare)')
                    }
                    elseif ($ageDays -gt ($tsl / 2)) {
                        Write-ADTResult -Check ('Last backup: ' + $ncName) -Status 'WARN' -Detail ($dateText + ' (' + $ageDays.ToString() + ' days ago; tombstone lifetime is ' + $tsl.ToString() + ' days)') `
                            -Why 'A backup older than half the tombstone lifetime risks ageing past the point where lingering objects can be safely reintroduced before their tombstones are garbage-collected elsewhere.' `
                            -Fix @('Schedule/verify a system-state (or equivalent AD-aware) backup of a DC covering this partition soon.')
                    }
                    else {
                        Write-ADTResult -Check ('Last backup: ' + $ncName) -Status 'PASS' -Detail ($dateText + ' (' + $ageDays.ToString() + ' days ago)')
                    }
                }
                elseif ($line -match '(?i)never\s+backed\s+up' -or $line -match '(?i)no\s+backup') {
                    $parsedBackupAny = $true
                    Write-ADTResult -Check 'repadmin /showbackup' -Status 'FAIL' -Detail $line.Trim() `
                        -Why 'A naming context with no recorded backup has no AD-aware recovery point at all for that partition.' `
                        -Fix @('Schedule a system-state (or equivalent AD-aware) backup of a DC covering this partition immediately.')
                }
            }

            if (-not $parsedBackupAny) {
                Write-ADTResult -Check 'repadmin /showbackup' -Status 'ERROR' `
                    -Detail ('Could not confidently parse any line. Raw first lines: ' + (($backupLines | Select-Object -First 3) -join ' | '))
            }
        }

        # --- Get-ADReplicationFailure enrichment (only when the AD module is present) ------
        if ($script:ADTCaps['HasADModule'] -and -not [string]::IsNullOrEmpty($domainName)) {
            try {
                $failures = @(Get-ADReplicationFailure -Target $domainName -Scope Domain -ErrorAction Stop)
                if ($failures.Count -eq 0) {
                    Write-ADTResult -Check 'Get-ADReplicationFailure (domain scope)' -Status 'PASS' -Detail 'No recorded replication failures for the domain.'
                }
                else {
                    foreach ($failure in $failures) {
                        Write-ADTResult -Check ('AD module failure: ' + [string]$failure.Server) -Status 'FAIL' `
                            -Detail ('FirstFailureTime=' + [string]$failure.FirstFailureTime + ' FailureCount=' + [string]$failure.FailureCount + ' Type=' + [string]$failure.FailureType) `
                            -Why 'The ADReplicationFailure object confirms this partner has an outstanding, unresolved replication failure as tracked by the AD module - enrichment on the repadmin findings above, not a separate problem.' `
                            -Fix @(('repadmin /showrepl ' + [string]$failure.Server + ' /errorsonly'))
                    }
                }
            }
            catch {
                Write-ADTResult -Check 'Get-ADReplicationFailure (domain scope)' -Status 'ERROR' -Detail ('Enrichment call failed: ' + $_.Exception.Message)
            }
        }
    }
    catch {
        Write-ADTResult -Check 'Replication health' -Status 'ERROR' -Detail ('Unhandled exception: ' + $_.Exception.Message)
    }
}

function Invoke-ADTSysvol {
    <#
        .SYNOPSIS
            Item 3: SYSVOL / DFSR health.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'SYSVOL / DFSR health'

        # --- dfsrmig /getglobalstate -------------------------------------------------------
        $migResult = Invoke-ADTNative -FilePath 'dfsrmig.exe' -Arguments @('/getglobalstate') -TimeoutSec 30

        if ($migResult.ExitCode -eq -1) {
            Write-ADTResult -Check 'SYSVOL replication engine (dfsrmig)' -Status 'SKIP' -Detail 'dfsrmig.exe was not found on this box.'
        }
        else {
            $migText = [string]$migResult.StdOut
            if ($migText -match '(?i)Eliminated') {
                Write-ADTResult -Check 'SYSVOL replication engine (dfsrmig)' -Status 'PASS' -Detail 'Migration state: Eliminated (SYSVOL is on DFSR, FRS retired).'
            }
            elseif ($migText -match '(?i)(Start|Prepared|Redirected)') {
                $stateWord = $Matches[1]
                Write-ADTResult -Check 'SYSVOL replication engine (dfsrmig)' -Status 'WARN' -Detail ('Migration state: ' + $stateWord + ' (not yet Eliminated).') `
                    -Why 'While migration has not reached Eliminated, SYSVOL may still depend on the legacy File Replication Service (FRS), which is deprecated and removed from newer Windows Server releases. A stalled mid-migration state is also a known source of SYSVOL inconsistency.' `
                    -Fix @('Review the current state and next step: dfsrmig /getmigrationstate', 'When ready to proceed, schedule as a planned change: dfsrmig /setglobalstate 3')
            }
            else {
                $rawPreview = (($migText -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 3) -join ' | ')
                Write-ADTResult -Check 'SYSVOL replication engine (dfsrmig)' -Status 'ERROR' -Detail ('Could not recognise the migration state text. Raw: ' + $rawPreview)
            }
        }

        # --- DFSR service state ------------------------------------------------------------
        try {
            $dfsrService = Get-Service -Name 'DFSR' -ErrorAction Stop
            if ($dfsrService.Status -eq 'Running') {
                Write-ADTResult -Check 'DFSR service' -Status 'PASS' -Detail ('Status=' + $dfsrService.Status.ToString() + ' StartType=' + $dfsrService.StartType.ToString())
            }
            else {
                Write-ADTResult -Check 'DFSR service' -Status 'FAIL' -Detail ('Status=' + $dfsrService.Status.ToString()) `
                    -Why 'The DFS Replication service is not running on a DC, so SYSVOL and any other DFSR-replicated folder is not replicating to or from this box.' `
                    -Fix @('[SERVICE-AFFECTING] Start-Service -Name DFSR', 'Get-WinEvent -LogName "DFS Replication" -MaxEvents 20')
            }
        }
        catch {
            Write-ADTResult -Check 'DFSR service' -Status 'ERROR' -Detail ('Get-Service DFSR failed: ' + $_.Exception.Message)
        }

        # --- SYSVOL replicated-folder state via WMI/CIM ------------------------------------
        $rfInfo = Get-ADTADDfsrReplicatedFolderInfo
        if ($rfInfo.Count -eq 0) {
            Write-ADTResult -Check 'SYSVOL replicated-folder state (DfsrReplicatedFolderInfo)' -Status 'ERROR' `
                -Detail 'root\microsoftdfs\DfsrReplicatedFolderInfo returned nothing (WMI/CIM query failed or DFSR is not installed).'
        }
        else {
            $sysvolFolder = @($rfInfo | Where-Object {
                    $nameOk = $false
                    try { $nameOk = ($_.ReplicatedFolderName -match '(?i)sysvol') } catch { $nameOk = $false }
                    $nameOk
                })

            if ($sysvolFolder.Count -eq 0) {
                Write-ADTResult -Check 'SYSVOL replicated-folder state (DfsrReplicatedFolderInfo)' -Status 'WARN' `
                    -Detail ('No replicated folder named like SYSVOL found among ' + $rfInfo.Count.ToString() + ' replicated folder(s) reported.') `
                    -Why 'Either this DC genuinely has no SYSVOL DFSR object yet (mid FRS-to-DFSR migration) or the folder is named unexpectedly.' `
                    -Fix @('dfsrmig /getmigrationstate', 'Get-CimInstance -Namespace root\microsoftdfs -ClassName DfsrReplicatedFolderInfo | Select-Object ReplicatedFolderName, State')
            }
            else {
                foreach ($folder in $sysvolFolder) {
                    try {
                        $stateInt = [int]$folder.State
                        $groupNameText = 'unknown-group'
                        if ($null -ne $folder.PSObject.Properties['ReplicationGroupName']) { $groupNameText = [string]$folder.ReplicationGroupName }
                        $stateText = Get-ADTADDfsrStateText -State $stateInt

                        if ($stateInt -eq 4) {
                            Write-ADTResult -Check ('SYSVOL replicated-folder state: ' + $groupNameText) -Status 'PASS' -Detail ('State=' + $stateInt.ToString() + ' (' + $stateText + ')')
                        }
                        else {
                            Write-ADTResult -Check ('SYSVOL replicated-folder state: ' + $groupNameText) -Status 'FAIL' -Detail ('State=' + $stateInt.ToString() + ' (' + $stateText + ')') `
                                -Why 'SYSVOL DFSR replicated folder is not in the Normal state, so Group Policy and scripts in SYSVOL on this DC may be stale or not replicating.' `
                                -Fix @('dfsrdiag replicationstate', 'Get-WinEvent -LogName "DFS Replication" -MaxEvents 50')
                        }
                    }
                    catch {
                        Write-ADTResult -Check 'SYSVOL replicated-folder state (DfsrReplicatedFolderInfo)' -Status 'ERROR' -Detail ('Could not read State/ReplicationGroupName from a returned instance: ' + $_.Exception.Message)
                    }
                }
            }
        }

        # --- Backlog to each partner --------------------------------------------------------
        $backlogHandled = $false
        $dfsrdiagResult = Invoke-ADTNative -FilePath 'dfsrdiag.exe' -Arguments @('backlog', '/RGName:Domain System Volume', '/RFName:SYSVOL Share', '/SMem:*', ('/RMem:' + $env:COMPUTERNAME)) -TimeoutSec 30

        if ($dfsrdiagResult.ExitCode -ne -1) {
            # UNVERIFIED: dfsrdiag.exe backlog switch names (/RGName /RFName /SMem /RMem)
            # were not independently confirmed against Microsoft Learn this session - the
            # tool is legacy and no dedicated syntax page was found. Best-effort native
            # attempt only: a confidently recognised count phrase drives a result, anything
            # else falls through to the Get-DfsrBacklog module attempt below.
            $dfsrdiagText = [string]$dfsrdiagResult.StdOut
            if ($dfsrdiagResult.ExitCode -eq 0 -and $dfsrdiagText -match '(?i)backlog\s+item\s+count\s*:\s*(\d+)') {
                $backlogCount = [int]$Matches[1]
                $backlogHandled = $true
                if ($backlogCount -eq 0) {
                    Write-ADTResult -Check 'SYSVOL backlog (dfsrdiag)' -Status 'PASS' -Detail '0 items backlogged.'
                }
                else {
                    Write-ADTResult -Check 'SYSVOL backlog (dfsrdiag)' -Status 'WARN' -Detail ($backlogCount.ToString() + ' item(s) backlogged toward ' + $env:COMPUTERNAME + '.') `
                        -Why 'A non-zero SYSVOL backlog means Group Policy or script changes made elsewhere have not yet replicated to this DC.' `
                        -Fix @(('dfsrdiag backlog /RGName:"Domain System Volume" /RFName:"SYSVOL Share" /SMem:<partner-dc> /RMem:' + $env:COMPUTERNAME))
                }
            }
        }

        if (-not $backlogHandled) {
            if ($script:ADTCaps['HasADModule'] -and (Test-ADTModuleAvailable -Name 'DFSR')) {
                try {
                    Import-Module -Name 'DFSR' -ErrorAction Stop
                    $partners = @(Get-ADDomainController -Filter '*' -ErrorAction Stop | Where-Object { $_.Name -ne $env:COMPUTERNAME })

                    if ($partners.Count -eq 0) {
                        Write-ADTResult -Check 'SYSVOL backlog (Get-DfsrBacklog)' -Status 'SKIP' -Detail 'No other DCs found to compare against.'
                    }
                    else {
                        foreach ($partner in $partners) {
                            try {
                                $verboseOutput = @(Get-DfsrBacklog -GroupName 'Domain System Volume' -FolderName 'SYSVOL Share' -SourceComputerName $partner.Name -DestinationComputerName $env:COMPUTERNAME -Verbose 4>&1 -ErrorAction Stop)
                                $countRecord = $verboseOutput | Where-Object { $_.Message -match 'Count:\s*(\d+)' } | Select-Object -First 1

                                if ($null -ne $countRecord -and $countRecord.Message -match 'Count:\s*(\d+)') {
                                    $count = [int]$Matches[1]
                                    if ($count -eq 0) {
                                        Write-ADTResult -Check ('SYSVOL backlog: ' + $partner.Name + ' to ' + $env:COMPUTERNAME) -Status 'PASS' -Detail '0 items backlogged.'
                                    }
                                    else {
                                        Write-ADTResult -Check ('SYSVOL backlog: ' + $partner.Name + ' to ' + $env:COMPUTERNAME) -Status 'WARN' -Detail ($count.ToString() + ' item(s) backlogged.') `
                                            -Why 'A non-zero SYSVOL backlog means Group Policy or script changes have not yet replicated between these two DCs.' `
                                            -Fix @(('Get-DfsrBacklog -GroupName "Domain System Volume" -FolderName "SYSVOL Share" -SourceComputerName ' + $partner.Name + ' -DestinationComputerName ' + $env:COMPUTERNAME + ' -Verbose'))
                                    }
                                }
                                else {
                                    Write-ADTResult -Check ('SYSVOL backlog: ' + $partner.Name + ' to ' + $env:COMPUTERNAME) -Status 'PASS' -Detail '0 items backlogged (no pending updates returned).'
                                }
                            }
                            catch {
                                Write-ADTResult -Check ('SYSVOL backlog: ' + $partner.Name + ' to ' + $env:COMPUTERNAME) -Status 'ERROR' -Detail ('Get-DfsrBacklog failed: ' + $_.Exception.Message)
                            }
                        }
                    }
                }
                catch {
                    Write-ADTResult -Check 'SYSVOL backlog' -Status 'SKIP' `
                        -Detail 'Neither dfsrdiag.exe nor the DFSR PowerShell module could be used on this box.' `
                        -Why ('Importing the DFSR module failed: ' + $_.Exception.Message)
                }
            }
            else {
                Write-ADTResult -Check 'SYSVOL backlog' -Status 'SKIP' `
                    -Detail 'Neither dfsrdiag.exe nor the DFSR PowerShell module (Get-DfsrBacklog) is available on this box.' `
                    -Why 'Backlog counts need either dfsrdiag.exe or RSAT-DFS-Mgmt-Con DFSR module; there is no simple WMI class exposing backlog counts to fall back to.' `
                    -Fix @('Run interactively from a box that has RSAT-DFS-Mgmt-Con, or install it here: Install-WindowsFeature RSAT-DFS-Mgmt-Con')
            }
        }

        # --- DFS Replication event log, last 7 days -----------------------------------------
        $dfsrEventIds = @(2213, 4012, 5002, 5008)
        $startTime = (Get-Date).AddDays(-7)
        $dfsrEvents = Get-ADTADEventSummary -LogName 'DFS Replication' -Id $dfsrEventIds -StartTime $startTime -MaxEvents 500

        if (-not $dfsrEvents.Success) {
            Write-ADTResult -Check 'DFS Replication event log (7 days)' -Status 'ERROR' -Detail ('Get-WinEvent failed: ' + $dfsrEvents.ErrorMessage)
        }
        elseif ($dfsrEvents.LogMissing) {
            Write-ADTResult -Check 'DFS Replication event log (7 days)' -Status 'SKIP' -Detail 'The DFS Replication event log does not exist on this box.'
        }
        elseif ($dfsrEvents.Events.Count -eq 0) {
            Write-ADTResult -Check 'DFS Replication event log (7 days)' -Status 'PASS' -Detail 'No events with IDs 2213/4012/5002/5008 in the last 7 days.'
        }
        else {
            $grouped = $dfsrEvents.Events | Group-Object -Property Id
            foreach ($group in $grouped) {
                $latest = $group.Group | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1
                $idNote = ''
                if ([int]$group.Name -eq 5002) { $idNote = ' (event 5002 is corroborated by community/support guidance rather than a single authoritative KB - treat as a softer signal)' }

                $status = 'WARN'
                if ([int]$group.Name -eq 2213) { $status = 'FAIL' }

                Write-ADTResult -Check ('DFS Replication event ' + $group.Name) -Status $status `
                    -Detail ($group.Count.ToString() + ' occurrence(s), most recent ' + $latest.TimeCreated.ToString('yyyy-MM-dd HH:mm') + ': ' + $latest.Message.Split("`n")[0] + $idNote) `
                    -Why 'This DFS Replication event indicates a journal wrap, database recovery, or a replicated-folder state that needs attention.' `
                    -Fix @('Get-WinEvent -LogName "DFS Replication" -MaxEvents 20 | Format-List TimeCreated, Id, Message', 'dfsrdiag replicationstate')
            }
        }

        # --- SYSVOL / NETLOGON shares present -------------------------------------------------
        $sysvolOk = $false
        $netlogonOk = $false
        try { $sysvolOk = Test-Path -Path ('\\' + $env:COMPUTERNAME + '\SYSVOL') -ErrorAction Stop } catch { $sysvolOk = $false }
        try { $netlogonOk = Test-Path -Path ('\\' + $env:COMPUTERNAME + '\NETLOGON') -ErrorAction Stop } catch { $netlogonOk = $false }

        if ($sysvolOk -and $netlogonOk) {
            Write-ADTResult -Check 'SYSVOL and NETLOGON shares' -Status 'PASS' -Detail 'Both shares are present and browsable.'
        }
        else {
            $missing = @()
            if (-not $sysvolOk) { $missing += 'SYSVOL' }
            if (-not $netlogonOk) { $missing += 'NETLOGON' }
            Write-ADTResult -Check 'SYSVOL and NETLOGON shares' -Status 'FAIL' -Detail ('Missing: ' + ($missing -join ', ')) `
                -Why 'A DC not advertising SYSVOL/NETLOGON will fail logons and GPO processing for clients that land on it.' `
                -Fix @('dcdiag /test:netlogons /test:advertising')
        }
    }
    catch {
        Write-ADTResult -Check 'SYSVOL / DFSR health' -Status 'ERROR' -Detail ('Unhandled exception: ' + $_.Exception.Message)
    }
}

function Invoke-ADTTimeAuth {
    <#
        .SYNOPSIS
            Item 4: Time and authentication.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Time and authentication'

        $domainName = $script:ADTCaps['DomainName']

        # --- w32tm /query /status ------------------------------------------------------------
        $statusResult = Invoke-ADTNative -FilePath 'w32tm.exe' -Arguments @('/query', '/status') -TimeoutSec 30

        if ($statusResult.ExitCode -eq -1) {
            Write-ADTResult -Check 'w32tm /query /status' -Status 'SKIP' -Detail 'w32tm.exe was not found on this box.'
        }
        elseif ($statusResult.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($statusResult.StdOut)) {
            Write-ADTResult -Check 'w32tm /query /status' -Status 'ERROR' -Detail ('w32tm returned exit code ' + $statusResult.ExitCode.ToString() + '. ' + $statusResult.StdErr)
        }
        else {
            $statusText = $statusResult.StdOut
            $sourceMatch = [regex]::Match($statusText, '(?m)^Source:\s*(.+)$')
            $stratumMatch = [regex]::Match($statusText, '(?m)^Stratum:\s*(\d+)')
            $lastSyncMatch = [regex]::Match($statusText, '(?m)^Last Successful Sync Time:\s*(.+)$')

            if (-not $sourceMatch.Success) {
                Write-ADTResult -Check 'w32tm /query /status' -Status 'ERROR' `
                    -Detail ('Could not find a Source line in w32tm output. Raw first lines: ' + (($statusText -split "`r?`n" | Select-Object -First 3) -join ' | '))
            }
            else {
                $sourceText = $sourceMatch.Groups[1].Value.Trim()
                $stratumText = 'unknown'
                if ($stratumMatch.Success) { $stratumText = $stratumMatch.Groups[1].Value }

                $ageText = 'unknown'
                if ($lastSyncMatch.Success) {
                    $lastSyncRaw = $lastSyncMatch.Groups[1].Value.Trim()
                    $lastSyncDate = New-Object -TypeName System.DateTime
                    if ([System.DateTime]::TryParse($lastSyncRaw, [ref]$lastSyncDate)) {
                        $ageHours = [int]((Get-Date) - $lastSyncDate).TotalHours
                        $ageText = $ageHours.ToString() + 'h ago (' + $lastSyncRaw + ')'
                    }
                    else {
                        $ageText = $lastSyncRaw
                    }
                }

                $detailText = 'Source=' + $sourceText + ' Stratum=' + $stratumText + ' LastSync=' + $ageText

                # UNVERIFIED: the literal string "Free-running" as a w32tm source value was
                # not independently confirmed against Microsoft Learn this session, so it is
                # matched leniently (case-insensitive substring) alongside the well-documented
                # "Local CMOS Clock" - both describe a DC with no real upstream time source.
                if ($script:ADTCaps['IsDC'] -and ($sourceText -match '(?i)Local CMOS Clock' -or $sourceText -match '(?i)Free.?running')) {
                    Write-ADTResult -Check 'Time source' -Status 'FAIL' -Detail $detailText `
                        -Why 'A domain controller synchronising from its own hardware clock, rather than the PDC emulator chain or an external NTP source, means the whole domain Kerberos time base is only as good as this one machine drift - large offsets break authentication domain-wide.' `
                        -Fix @('If this is the PDC emulator: w32tm /config /manualpeerlist:"time.windows.com,0x8 pool.ntp.org,0x8" /syncfromflags:manual /reliable:YES /update', 'If this is NOT the PDC emulator: w32tm /config /syncfromflags:domhier /update', '[SERVICE-AFFECTING] net stop w32time; net start w32time')
                }
                else {
                    Write-ADTResult -Check 'Time source' -Status 'PASS' -Detail $detailText
                }
            }
        }

        # --- w32tm /query /configuration -------------------------------------------------------
        $configResult = Invoke-ADTNative -FilePath 'w32tm.exe' -Arguments @('/query', '/configuration') -TimeoutSec 30

        if ($configResult.ExitCode -eq -1) {
            Write-ADTResult -Check 'w32tm /query /configuration' -Status 'SKIP' -Detail 'w32tm.exe was not found on this box.'
        }
        elseif ($configResult.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($configResult.StdOut)) {
            Write-ADTResult -Check 'w32tm /query /configuration' -Status 'ERROR' -Detail ('w32tm returned exit code ' + $configResult.ExitCode.ToString())
        }
        else {
            $typeMatch = [regex]::Match($configResult.StdOut, '(?m)^Type:\s*(\S+)')
            if (-not $typeMatch.Success) {
                Write-ADTResult -Check 'w32tm /query /configuration' -Status 'ERROR' `
                    -Detail ('Could not find a Type line. Raw first lines: ' + (($configResult.StdOut -split "`r?`n" | Select-Object -First 3) -join ' | '))
            }
            else {
                $typeValue = $typeMatch.Groups[1].Value.Trim()
                $isPdcEmulator = $false
                try {
                    $domainObj = Get-ADDomain -ErrorAction Stop
                    if ($domainObj.PDCEmulator -match [regex]::Escape($env:COMPUTERNAME)) { $isPdcEmulator = $true }
                }
                catch {
                    $isPdcEmulator = $false
                }

                if ($isPdcEmulator) {
                    if ($typeValue -match '(?i)^(NTP|AllSync)$') {
                        Write-ADTResult -Check 'w32tm configuration Type (PDC emulator)' -Status 'PASS' -Detail ('Type=' + $typeValue)
                    }
                    else {
                        Write-ADTResult -Check 'w32tm configuration Type (PDC emulator)' -Status 'WARN' -Detail ('Type=' + $typeValue) `
                            -Why 'This box holds the PDC emulator role, where the domain time hierarchy is rooted. It should point at an external/NTP source, not NT5DS (nothing above it to follow) or NoSync. If this DC is itself a VM, also confirm the hypervisor host-time-sync/integration-service feature is DISABLED for this guest, or the two time sources will fight each other.' `
                            -Fix @('w32tm /config /manualpeerlist:"time.windows.com,0x8 pool.ntp.org,0x8" /syncfromflags:manual /reliable:YES /update', '[SERVICE-AFFECTING] net stop w32time; net start w32time')
                    }
                }
                else {
                    if ($typeValue -match '(?i)^NT5DS$') {
                        Write-ADTResult -Check 'w32tm configuration Type' -Status 'PASS' -Detail ('Type=' + $typeValue + ' (follows the domain hierarchy, as expected off the PDC emulator)')
                    }
                    else {
                        Write-ADTResult -Check 'w32tm configuration Type' -Status 'WARN' -Detail ('Type=' + $typeValue) `
                            -Why 'Machines other than the PDC emulator should normally follow the domain hierarchy (NT5DS) rather than an external source of their own, so the whole domain shares one time base.' `
                            -Fix @('w32tm /config /syncfromflags:domhier /update', '[SERVICE-AFFECTING] net stop w32time; net start w32time')
                    }
                }
            }
        }

        # --- offset vs PDC ------------------------------------------------------------------------
        $pdcName = $null
        try {
            $domainObj2 = Get-ADDomain -ErrorAction Stop
            $pdcName = $domainObj2.PDCEmulator
        }
        catch {
            $pdcName = $null
        }

        if ([string]::IsNullOrEmpty($pdcName)) {
            Write-ADTResult -Check 'Offset vs PDC emulator' -Status 'SKIP' -Detail 'Could not resolve the PDC emulator (AD module unavailable or lookup failed).'
        }
        elseif ($pdcName -match [regex]::Escape($env:COMPUTERNAME)) {
            Write-ADTResult -Check 'Offset vs PDC emulator' -Status 'SKIP' -Detail 'This box is the PDC emulator; there is nothing to compare it against.'
        }
        else {
            $stripResult = Invoke-ADTNative -FilePath 'w32tm.exe' -Arguments @('/stripchart', ('/computer:' + $pdcName), '/samples:2', '/dataonly') -TimeoutSec 30

            if ($stripResult.ExitCode -eq -1) {
                Write-ADTResult -Check 'Offset vs PDC emulator' -Status 'SKIP' -Detail 'w32tm.exe was not found on this box.'
            }
            elseif ([string]::IsNullOrWhiteSpace($stripResult.StdOut)) {
                Write-ADTResult -Check 'Offset vs PDC emulator' -Status 'ERROR' -Detail ('No output from w32tm /stripchart. ' + $stripResult.StdErr)
            }
            else {
                $offsetMatches = [regex]::Matches($stripResult.StdOut, '(?i)o:([+-]?\d+(?:\.\d+)?)s')
                if ($offsetMatches.Count -eq 0) {
                    Write-ADTResult -Check 'Offset vs PDC emulator' -Status 'ERROR' `
                        -Detail ('Could not parse an offset value from w32tm /stripchart output. Raw first lines: ' + (($stripResult.StdOut -split "`r?`n" | Select-Object -First 3) -join ' | '))
                }
                else {
                    $lastOffset = [double]$offsetMatches[$offsetMatches.Count - 1].Groups[1].Value
                    $absOffset = [Math]::Abs($lastOffset)
                    $offsetDetail = $lastOffset.ToString('0.###') + 's vs ' + $pdcName

                    if ($absOffset -gt 5) {
                        Write-ADTResult -Check 'Offset vs PDC emulator' -Status 'FAIL' -Detail $offsetDetail `
                            -Why 'Kerberos by default rejects authentication once clock skew exceeds 5 minutes, but an offset already in the seconds range indicates the time service is not tracking the domain hierarchy correctly and will get worse.' `
                            -Fix @('w32tm /resync /rediscover', 'w32tm /config /syncfromflags:domhier /update  (on this box, if not the PDC emulator)')
                    }
                    elseif ($absOffset -gt 1) {
                        Write-ADTResult -Check 'Offset vs PDC emulator' -Status 'WARN' -Detail $offsetDetail `
                            -Why 'More than a second of drift against the PDC emulator is worth correcting before it grows toward the 5-minute Kerberos tolerance.' `
                            -Fix @('w32tm /resync')
                    }
                    else {
                        Write-ADTResult -Check 'Offset vs PDC emulator' -Status 'PASS' -Detail $offsetDetail
                    }
                }
            }
        }

        # --- Secure channel -----------------------------------------------------------------------
        if (-not [string]::IsNullOrEmpty($domainName)) {
            $scResult = Invoke-ADTNative -FilePath 'nltest.exe' -Arguments @(('/sc_query:' + $domainName)) -TimeoutSec 30

            if ($scResult.ExitCode -eq -1) {
                Write-ADTResult -Check 'Secure channel (nltest)' -Status 'SKIP' -Detail 'nltest.exe was not found on this box.'
            }
            else {
                $scText = (([string]$scResult.StdOut) + "`n" + ([string]$scResult.StdErr)).Trim()
                $singleDc = $false
                if ($script:ADTCaps['IsDC'] -and $script:ADTCaps['HasADModule']) {
                    try { $singleDc = (@(Get-ADDomainController -Filter * -ErrorAction Stop).Count -eq 1) } catch { $singleDc = $false }
                }
                if ($scText -match '(?i)The\s+command\s+completed\s+successfully' -and $scResult.ExitCode -eq 0) {
                    Write-ADTResult -Check 'Secure channel (nltest)' -Status 'PASS' -Detail ('Secure channel to ' + $domainName + ' is healthy.')
                }
                elseif ($singleDc -and ($scText -match '1355' -or $scText -match '(?i)ERROR_NO_SUCH_DOMAIN')) {
                    Write-ADTResult -Check 'Secure channel (nltest)' -Status 'INFO' `
                        -Detail 'nltest /sc_query returned status 1355 (ERROR_NO_SUCH_DOMAIN). Expected on the only DC in a domain: there is no partner DC to hold a secure channel with.' `
                        -Why 'On a multi-DC domain this same status from a DC would be a real finding - it would mean this DC cannot locate a peer. Verified single-DC here via Get-ADDomainController.'
                }
                else {
                    $fixLines = @()
                    if ($script:ADTCaps['IsDC']) {
                        $fixLines = @('Test-ComputerSecureChannel is NOT reliable on a domain controller (known false positives) - use nltest/netdom instead:', ('nltest /sc_reset:' + $domainName), 'netdom resetpwd /server:<another-DC> /userd:<domain>\<admin> /passwordd:*')
                    }
                    else {
                        $fixLines = @(('Test-ComputerSecureChannel -Server ' + $domainName + ' -Repair'), ('nltest /sc_reset:' + $domainName + '  (native alternative)'))
                    }
                    Write-ADTResult -Check 'Secure channel (nltest)' -Status 'FAIL' -Detail ('nltest /sc_query:' + $domainName + ' did not report success. Raw: ' + (($scText -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 3) -join ' | ')) `
                        -Why 'A broken secure channel means this machine cannot authenticate itself to the domain, which blocks user and computer logon alike.' `
                        -Fix $fixLines
                }
            }
        }
        else {
            Write-ADTResult -Check 'Secure channel (nltest)' -Status 'SKIP' -Detail 'Domain name is unknown (DomainJoined capability had no DomainName).'
        }

        # --- Machine account password age -----------------------------------------------------------
        $rootDseForMachine = Get-ADTADRootDse
        if ($null -eq $rootDseForMachine) {
            Write-ADTResult -Check 'Machine account password age' -Status 'ERROR' -Detail 'Could not bind to RootDSE to look up the computer object.'
        }
        else {
            $machineAge = Get-ADTADMachineAccountAge -DefaultNamingContext $rootDseForMachine.DefaultNamingContext
            if ($null -eq $machineAge) {
                Write-ADTResult -Check 'Machine account password age' -Status 'ERROR' -Detail ('Could not read pwdLastSet for computer object ' + $env:COMPUTERNAME + '$.')
            }
            else {
                $ageDays = [int]((Get-Date) - $machineAge).TotalDays
                $detail = $ageDays.ToString() + ' days (last set ' + $machineAge.ToString('yyyy-MM-dd') + ')'
                if ($ageDays -gt 60) {
                    Write-ADTResult -Check 'Machine account password age' -Status 'INFO' -Detail ($detail + ' - default machine password change interval is 30 days, so this is older than usual though not necessarily broken.')
                }
                else {
                    Write-ADTResult -Check 'Machine account password age' -Status 'INFO' -Detail $detail
                }
            }
        }

        # --- klist -------------------------------------------------------------------------------------
        $klistResult = Invoke-ADTNative -FilePath 'klist.exe' -Arguments @('tickets') -TimeoutSec 15

        if ($klistResult.ExitCode -eq -1) {
            Write-ADTResult -Check 'Kerberos tickets (klist)' -Status 'SKIP' -Detail 'klist.exe was not found on this box.'
        }
        else {
            $klistText = [string]$klistResult.StdOut
            $ticketMatches = [regex]::Matches($klistText, '(?im)^#\d+>')
            if ($ticketMatches.Count -gt 0) {
                Write-ADTResult -Check 'Kerberos tickets (klist)' -Status 'INFO' -Detail ($ticketMatches.Count.ToString() + ' cached ticket(s) for the current session.')
            }
            elseif ($klistText -match '(?i)No\s+tickets\s+(are\s+)?cached' -or $klistText -match '(?i)cache\s+is\s+empty') {
                Write-ADTResult -Check 'Kerberos tickets (klist)' -Status 'INFO' -Detail 'No cached tickets for the current session.'
            }
            else {
                Write-ADTResult -Check 'Kerberos tickets (klist)' -Status 'INFO' -Detail ('klist ran (exit ' + $klistResult.ExitCode.ToString() + '); output format not specifically parsed.')
            }
        }
    }
    catch {
        Write-ADTResult -Check 'Time and authentication' -Status 'ERROR' -Detail ('Unhandled exception: ' + $_.Exception.Message)
    }
}

function Invoke-ADTADEvents {
    <#
        .SYNOPSIS
            Item 5: AD event sweep (last 7 days). DFSR events are covered by Invoke-ADTSysvol,
            not repeated here.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'AD event sweep (last 7 days)'

        $domainName = $script:ADTCaps['DomainName']
        $startTime = (Get-Date).AddDays(-7)
        $maxEventsPerQuery = 500

        # --- Directory Service log: specific, verified event IDs -----------------------------
        $dsEventIds = @(1311, 2042, 1988, 2887)
        $dsEvents = Get-ADTADEventSummary -LogName 'Directory Service' -Id $dsEventIds -StartTime $startTime -MaxEvents $maxEventsPerQuery

        if (-not $dsEvents.Success) {
            Write-ADTResult -Check 'Directory Service log (1311/2042/1988/2887)' -Status 'ERROR' -Detail ('Get-WinEvent failed: ' + $dsEvents.ErrorMessage)
        }
        elseif ($dsEvents.LogMissing) {
            Write-ADTResult -Check 'Directory Service log (1311/2042/1988/2887)' -Status 'SKIP' -Detail 'The Directory Service event log does not exist on this box.'
        }
        elseif ($dsEvents.Events.Count -eq 0) {
            Write-ADTResult -Check 'Directory Service log (1311/2042/1988/2887)' -Status 'PASS' -Detail 'No occurrences of these IDs in the last 7 days.'
        }
        else {
            $grouped = $dsEvents.Events | Group-Object -Property Id
            foreach ($group in $grouped) {
                $latest = $group.Group | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1
                $idMeaning = switch ([int]$group.Name) {
                    1311 { 'KCC could not build a spanning tree topology - a site link or connectivity problem.' }
                    2042 { 'It has been too long since this DC last replicated - a tombstone-lifetime-related warning.' }
                    1988 { 'A lingering object was detected from a source DC that has been offline past the tombstone lifetime.' }
                    2887 { 'Unsigned or cleartext LDAP bind volume - relevant to the LDAP signing hardening rollout.' }
                    default { 'Reported generically.' }
                }
                Write-ADTResult -Check ('Directory Service event ' + $group.Name) -Status 'WARN' `
                    -Detail ($group.Count.ToString() + ' occurrence(s), most recent ' + $latest.TimeCreated.ToString('yyyy-MM-dd HH:mm') + ': ' + $latest.Message.Split("`n")[0]) `
                    -Why $idMeaning `
                    -Fix @(('Get-WinEvent -LogName "Directory Service" -FilterXPath "*[System[(EventID=' + $group.Name + ')]]" -MaxEvents 20 | Format-List TimeCreated, Message'))
            }
        }

        # --- DNS Server log, only when this box holds the DNS role ---------------------------
        if ($script:ADTCaps['HasDnsRole']) {
            $dnsEvents = Get-ADTADEventSummary -LogName 'DNS Server' -Id @(4013) -StartTime $startTime -MaxEvents $maxEventsPerQuery

            if (-not $dnsEvents.Success) {
                Write-ADTResult -Check 'DNS Server event 4013' -Status 'ERROR' -Detail ('Get-WinEvent failed: ' + $dnsEvents.ErrorMessage)
            }
            elseif ($dnsEvents.LogMissing) {
                Write-ADTResult -Check 'DNS Server event 4013' -Status 'SKIP' -Detail 'The DNS Server event log does not exist on this box.'
            }
            elseif ($dnsEvents.Events.Count -eq 0) {
                Write-ADTResult -Check 'DNS Server event 4013' -Status 'PASS' -Detail 'No occurrences in the last 7 days.'
            }
            else {
                $latest = $dnsEvents.Events | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1
                # Correlate against every boot in the window (System 6005 event-log-start
                # markers plus the current LastBootUpTime), not just the most recent boot -
                # a DC rebooted several times in 7 days logs a benign 4013 burst per boot.
                $bootMarkers = @()
                try { $bootMarkers += (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime } catch { $null = $_ }
                try {
                    $startEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 6005; StartTime = $startTime } -MaxEvents 25 -ErrorAction Stop)
                    foreach ($se in $startEvents) { $bootMarkers += $se.TimeCreated }
                }
                catch { $null = $_ }
                $allBootCorrelated = $false
                if ($bootMarkers.Count -gt 0) {
                    $allBootCorrelated = $true
                    foreach ($dnsEv in $dnsEvents.Events) {
                        $nearBoot = $false
                        foreach ($bm in $bootMarkers) {
                            $mins = ($dnsEv.TimeCreated - $bm).TotalMinutes
                            if ($mins -ge -2 -and $mins -le 30) { $nearBoot = $true; break }
                        }
                        if (-not $nearBoot) { $allBootCorrelated = $false; break }
                    }
                }
                if ($allBootCorrelated) {
                    Write-ADTResult -Check 'DNS Server event 4013' -Status 'INFO' `
                        -Detail ($dnsEvents.Events.Count.ToString() + ' occurrence(s), all within 30 minutes of a system start - normal DNS-waiting-for-AD startup sequence, not a replication problem.')
                }
                else {
                    Write-ADTResult -Check 'DNS Server event 4013' -Status 'WARN' `
                        -Detail ($dnsEvents.Events.Count.ToString() + ' occurrence(s), most recent ' + $latest.TimeCreated.ToString('yyyy-MM-dd HH:mm') + ': ' + $latest.Message.Split("`n")[0]) `
                        -Why 'Event 4013 outside a boot window signals the DNS Server service stuck waiting on AD-integrated zone data - it points at replication trouble feeding the DNS zone.' `
                        -Fix @('Get-WinEvent -LogName "DNS Server" -FilterXPath "*[System[(EventID=4013)]]" -MaxEvents 20 | Format-List TimeCreated, Message')
                }
            }
        }
        else {
            Write-ADTResult -Check 'DNS Server event 4013' -Status 'SKIP' -Detail 'This box does not hold the DNS Server role (HasDnsRole is false).'
        }

        # --- System log: Netlogon 5719 ----------------------------------------------------------
        $netlogonEvents = Get-ADTADEventSummary -LogName 'System' -Id @(5719) -ProviderName 'Netlogon' -StartTime $startTime -MaxEvents $maxEventsPerQuery

        if (-not $netlogonEvents.Success) {
            Write-ADTResult -Check 'System log: Netlogon event 5719' -Status 'ERROR' -Detail ('Get-WinEvent failed: ' + $netlogonEvents.ErrorMessage)
        }
        elseif ($netlogonEvents.Events.Count -eq 0) {
            Write-ADTResult -Check 'System log: Netlogon event 5719' -Status 'PASS' -Detail 'No occurrences in the last 7 days.'
        }
        else {
            $latest = $netlogonEvents.Events | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1
            $dsGetDcFix = 'nltest /dsgetdc:' + [string]$domainName
            Write-ADTResult -Check 'System log: Netlogon event 5719' -Status 'WARN' `
                -Detail ($netlogonEvents.Events.Count.ToString() + ' occurrence(s), most recent ' + $latest.TimeCreated.ToString('yyyy-MM-dd HH:mm') + ': ' + $latest.Message.Split("`n")[0]) `
                -Why 'Netlogon 5719 means this box could not locate a DC for the domain at that moment - a DNS SRV record, network path, or DC availability problem.' `
                -Fix @($dsGetDcFix, 'ipconfig /all   (confirm DNS servers point at AD-integrated DNS)')
        }

        # --- Kerberos-Key-Distribution-Center notable errors (generic sweep) ---------------------
        # UNVERIFIED: the task specifies "notable errors" without candidate event IDs, and no
        # specific KDC event ID was confirmed against Microsoft Learn this session. Rather than
        # guess IDs, this sweeps the KDC operational log for Critical/Error-level entries
        # generically (Level 1-2) and reports what is actually there. The log name itself
        # (Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational) is the standard,
        # widely-documented channel name but was not re-confirmed via a dedicated Learn page
        # this session; a wrong name fails gracefully to SKIP via Get-ADTADEventSummary,
        # never a false PASS.
        $kdcEvents = Get-ADTADEventSummary -LogName 'Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational' -Level @(1, 2) -StartTime $startTime -MaxEvents $maxEventsPerQuery

        if (-not $kdcEvents.Success) {
            Write-ADTResult -Check 'Kerberos KDC operational log (errors)' -Status 'ERROR' -Detail ('Get-WinEvent failed: ' + $kdcEvents.ErrorMessage)
        }
        elseif ($kdcEvents.LogMissing) {
            Write-ADTResult -Check 'Kerberos KDC operational log (errors)' -Status 'SKIP' -Detail 'This log is not present or not enabled on this box (disabled by default on many builds).'
        }
        elseif ($kdcEvents.Events.Count -eq 0) {
            Write-ADTResult -Check 'Kerberos KDC operational log (errors)' -Status 'PASS' -Detail 'No Critical/Error-level entries in the last 7 days.'
        }
        else {
            $grouped = $kdcEvents.Events | Group-Object -Property Id
            foreach ($group in $grouped) {
                $latest = $group.Group | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1
                Write-ADTResult -Check ('Kerberos KDC event ' + $group.Name) -Status 'WARN' `
                    -Detail ($group.Count.ToString() + ' occurrence(s), most recent ' + $latest.TimeCreated.ToString('yyyy-MM-dd HH:mm') + ': ' + $latest.Message.Split("`n")[0]) `
                    -Why 'Reported generically - this specific event ID was not in the task verified list, so no specific interpretation is given. Read the message text for detail.' `
                    -Fix @(('Get-WinEvent -LogName "Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational" -FilterXPath "*[System[(EventID=' + $group.Name + ')]]" -MaxEvents 20 | Format-List TimeCreated, Message'))
            }
        }

        # --- NTDS ISAM / database complaints (generic sweep) -----------------------------------------
        # UNVERIFIED: the task specifies "NTDS ISAM/database complaints" without candidate event
        # IDs, and no specific ESENT/NTDS database event ID was confirmed against Microsoft Learn
        # this session. Swept generically by source (ESENT) within the Directory Service log at
        # Critical/Error/Warning level rather than guessing IDs.
        # The ESE provider in the Directory Service log is 'NTDS ISAM' on current builds
        # ('ESENT' writes to the Application log and is a different instance). Fall back to
        # a provider-agnostic Critical/Error sweep if the provider name is not registered.
        $esentEvents = Get-ADTADEventSummary -LogName 'Directory Service' -ProviderName 'NTDS ISAM' -Level @(1, 2, 3) -StartTime $startTime -MaxEvents $maxEventsPerQuery
        if (-not $esentEvents.Success) {
            $esentEvents = Get-ADTADEventSummary -LogName 'Directory Service' -Level @(1, 2) -StartTime $startTime -MaxEvents $maxEventsPerQuery
        }

        if (-not $esentEvents.Success) {
            Write-ADTResult -Check 'NTDS database (ESENT) complaints' -Status 'ERROR' -Detail ('Get-WinEvent failed: ' + $esentEvents.ErrorMessage)
        }
        elseif ($esentEvents.Events.Count -eq 0) {
            Write-ADTResult -Check 'NTDS database (ESENT) complaints' -Status 'PASS' -Detail 'No database-related Critical/Error entries in the Directory Service log in the last 7 days.'
        }
        else {
            $grouped = $esentEvents.Events | Group-Object -Property Id
            foreach ($group in $grouped) {
                $latest = $group.Group | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1
                Write-ADTResult -Check ('NTDS database (ESENT) event ' + $group.Name) -Status 'WARN' `
                    -Detail ($group.Count.ToString() + ' occurrence(s), most recent ' + $latest.TimeCreated.ToString('yyyy-MM-dd HH:mm') + ': ' + $latest.Message.Split("`n")[0]) `
                    -Why 'Reported generically - this specific event ID was not in the task verified list, so no specific interpretation is given. ESENT entries at Error/Critical level on the NTDS database warrant a look at disk space, corruption, or defrag state.' `
                    -Fix @(('Get-WinEvent -LogName "Directory Service" -FilterXPath "*[System[Provider[@Name=''ESENT''] and (EventID=' + $group.Name + ')]]" -MaxEvents 20 | Format-List TimeCreated, Message'), '[SERVICE-AFFECTING] ntdsutil "activate instance ntds" files integrity quit quit   (requires NTDS offline/DSRM, plan a maintenance window)')
            }
        }
    }
    catch {
        Write-ADTResult -Check 'AD event sweep' -Status 'ERROR' -Detail ('Unhandled exception: ' + $_.Exception.Message)
    }
}

#endregion

Register-ADTModule -Name 'AD core' -Group 'ON-PREM' -Items @(
    @{ Label = 'DC and domain overview';  Function = 'Invoke-ADTADOverview'; Requires = @('DomainJoined', 'HasADModule'); Snapshot = $true }
    @{ Label = 'Replication health';      Function = 'Invoke-ADTReplication'; Requires = @('IsDC');                       Snapshot = $true }
    @{ Label = 'SYSVOL / DFSR health';    Function = 'Invoke-ADTSysvol';      Requires = @('IsDC');                       Snapshot = $true }
    @{ Label = 'Time and authentication'; Function = 'Invoke-ADTTimeAuth';    Requires = @('DomainJoined');               Snapshot = $true }
    @{ Label = 'AD event sweep';          Function = 'Invoke-ADTADEvents';    Requires = @('IsDC');                       Snapshot = $true }
)
