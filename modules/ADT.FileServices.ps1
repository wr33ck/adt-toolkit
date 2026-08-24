# ADT.FileServices.ps1 - SMB / file services health check.
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.

#region Private helpers

function Format-ADTByteSize {
    <#
        .SYNOPSIS
            Renders a byte count as a human-readable "N.NN <unit>" string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [double]$Bytes
    )

    $units = @('bytes', 'KB', 'MB', 'GB', 'TB', 'PB')
    $value = $Bytes
    $unitIndex = 0

    while ([Math]::Abs($value) -ge 1024 -and $unitIndex -lt ($units.Count - 1)) {
        $value = $value / 1024
        $unitIndex = $unitIndex + 1
    }

    if ($unitIndex -eq 0) {
        return ([string]([int64]$value) + ' ' + $units[$unitIndex])
    }
    return ($value.ToString('N2') + ' ' + $units[$unitIndex])
}

function Get-ADTLogicalDiskList {
    <#
        .SYNOPSIS
            Enumerate every fixed local disk (Win32_LogicalDisk, DriveType=3).
        .DESCRIPTION
            Mirrors ADT.Network's Get-ADTNetAdapterConfigWmiList pattern: Get-ADTWmi in
            Common always collapses to a single instance, which would silently drop every
            volume but the first on a multi-volume file server. This local helper keeps
            the full result set and applies the DriveType=3 filter (3 = "Local Disk" per
            the Win32_LogicalDisk class reference on Microsoft Learn) that Get-ADTWmi has
            no parameter for. Never throws.
        .OUTPUTS
            PSCustomObject[] with DeviceID, SizeBytes, FreeBytes.
    #>
    [CmdletBinding()]
    param()

    $filterText = 'DriveType=3'
    $instances = $null

    try {
        $instances = Get-CimInstance -ClassName 'Win32_LogicalDisk' -Filter $filterText -ErrorAction Stop
    }
    catch {
        try {
            $instances = Get-WmiObject -Class 'Win32_LogicalDisk' -Filter $filterText -ErrorAction Stop
        }
        catch {
            return @()
        }
    }

    $results = @()
    foreach ($disk in @($instances)) {
        if ($null -eq $disk) { continue }
        if (-not $disk.PSObject.Properties['DeviceID']) { continue }

        $sizeBytes = 0
        $freeBytes = 0
        if ($disk.PSObject.Properties['Size'] -and $null -ne $disk.Size) { $sizeBytes = [double]$disk.Size }
        if ($disk.PSObject.Properties['FreeSpace'] -and $null -ne $disk.FreeSpace) { $freeBytes = [double]$disk.FreeSpace }

        $results += [PSCustomObject]@{
            DeviceID  = [string]$disk.DeviceID
            SizeBytes = $sizeBytes
            FreeBytes = $freeBytes
        }
    }

    return $results
}

function Get-ADTShadowCopySummary {
    <#
        .SYNOPSIS
            Runs "vssadmin list shadows /for=<volume>" for one volume and parses the
            snapshot count and newest creation date.
        .DESCRIPTION
            vssadmin's /for=<ForVolumeSpec> parameter is confirmed against Microsoft
            Learn's "vssadmin list shadows" reference, which documents the syntax but not
            the free-text output format vssadmin prints. The parsing below (matching
            "Contained N shadow cop(y|ies) at creation time: <date>" lines, and the
            "No items found that satisfy the query" no-snapshot message) is based on this
            project's prior observation of real vssadmin output, NOT on a Learn-documented
            schema - flagged here and in the completion report as UNVERIFIED. It also
            depends on English console output; a non-English Windows locale changes both
            of those strings, which this parser does not localise, and date parsing
            depends on the console's current culture, so a locale mismatch degrades this
            to ParseOk=$false rather than throwing or reporting a wrong date.
        .OUTPUTS
            PSCustomObject: VolumeSpec, HasAny (bool), Count (int), NewestDate
            (DateTime or $null), ParseOk (bool - did the underlying vssadmin call succeed
            and produce output this parser could understand at all).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VolumeSpec
    )

    $summary = [PSCustomObject]@{
        VolumeSpec = $VolumeSpec
        HasAny     = $false
        Count      = 0
        NewestDate = $null
        ParseOk    = $false
    }

    $result = Invoke-ADTNative -FilePath 'vssadmin.exe' -Arguments @('list', 'shadows', ('/for=' + $VolumeSpec)) -TimeoutSec 30

    if ([string]::IsNullOrEmpty($result.StdOut)) {
        return $summary
    }

    if ($result.StdOut -match 'No items found') {
        $summary.HasAny = $false
        $summary.Count = 0
        $summary.ParseOk = $true
        return $summary
    }

    $matches = [regex]::Matches($result.StdOut, 'Contained (\d+) shadow cop(?:y|ies) at creation time:\s*(.+)')
    if ($matches.Count -eq 0) {
        # Output was produced but did not match the expected pattern - inconclusive
        # rather than "zero snapshots"; ParseOk stays $false so the caller can SKIP.
        return $summary
    }

    $totalCount = 0
    $newestDate = $null
    foreach ($match in $matches) {
        $countText = $match.Groups[1].Value
        $dateText = $match.Groups[2].Value.Trim()

        $parsedCount = 0
        if ([int]::TryParse($countText, [ref]$parsedCount)) {
            $totalCount = $totalCount + $parsedCount
        }
        else {
            $totalCount = $totalCount + 1
        }

        $parsedDate = [DateTime]::MinValue
        if ([DateTime]::TryParse($dateText, [ref]$parsedDate)) {
            if ($null -eq $newestDate -or $parsedDate -gt $newestDate) {
                $newestDate = $parsedDate
            }
        }
    }

    $summary.HasAny = ($totalCount -gt 0)
    $summary.Count = $totalCount
    $summary.NewestDate = $newestDate
    $summary.ParseOk = $true
    return $summary
}

#endregion

#region Invoke-ADTFileServices (single registered item)

function Invoke-ADTFileServices {
    <#
        .SYNOPSIS
            SMB server configuration, SMB1 exposure, share inventory and ACL red flags,
            session/open-file counts, per-volume free space, shadow copy freshness, and
            optional Data Deduplication / FSRM quota status.
    #>
    [CmdletBinding()]
    param()

    $script:ADTCurrentModule = 'File services'

    try {
        Write-ADTSection -Title 'SMB / file services health'

        $smbProbe = Get-Command -Name 'Get-SmbServerConfiguration' -ErrorAction SilentlyContinue
        if ($null -eq $smbProbe) {
            Write-ADTResult -Check 'SMB / file services health' -Status ERROR -Detail 'Get-SmbServerConfiguration is not available (SmbShare module not present on this OS).' -Why 'The SmbShare module ships in the box on Windows 8.1/Server 2012 R2 and later, so its absence here is unexpected and stops every other check in this item from running.'
            return
        }

        # ---- 1. Get-SmbServerConfiguration: SMB1, signing, encryption ----
        try {
            $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop

            if ($smbConfig.PSObject.Properties['EnableSMB1Protocol'] -and $smbConfig.EnableSMB1Protocol -eq $true) {
                $smb1Why = 'SMB1 is a legacy protocol with well-documented security weaknesses (no protection against man-in-the-middle relay in older configurations, weaker cryptography than SMB2/3) and Microsoft has recommended removing it for years. It is only needed if something on this network genuinely cannot speak SMB2 or later - old NAS appliances, some network scanners/printers, and Windows XP/Server 2003 hosts are the classic remaining cases.'
                Write-ADTResult -Check 'SMB1 protocol' -Status FAIL -Detail 'EnableSMB1Protocol is True - the SMB1 server protocol is active.' -Why $smb1Why -Fix @('[SERVICE-AFFECTING] Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false', 'Before disabling, confirm no legacy client actually needs it - check for connections still negotiating SMB1: Get-SmbSession | Where-Object { $_.Dialect -eq "1.0" -or $_.Dialect -eq "1.5" }')
            }
            elseif ($smbConfig.PSObject.Properties['EnableSMB1Protocol']) {
                Write-ADTResult -Check 'SMB1 protocol' -Status PASS -Detail 'EnableSMB1Protocol is False.'
            }
            else {
                Write-ADTResult -Check 'SMB1 protocol' -Status SKIP -Detail 'EnableSMB1Protocol property was not present on the returned configuration object.'
            }

            if ($smbConfig.PSObject.Properties['RequireSecuritySignature'] -and $smbConfig.RequireSecuritySignature -eq $false) {
                $signingWhy = 'Without required signing, SMB traffic is not protected against tampering or relay-style man-in-the-middle attacks on the wire. See "What is Server Message Block signing?" on Microsoft Learn for current guidance and the client/server interaction table. This does not retroactively affect already-established sessions once changed.'
                Write-ADTResult -Check 'SMB signing' -Status WARN -Detail 'RequireSecuritySignature is False - SMB signing is not required by this server.' -Why $signingWhy -Fix @('Set-SmbServerConfiguration -RequireSecuritySignature $true -Confirm:$false', 'Confirm no unsigned-only legacy client depends on this first (very old third-party SMB clients only).')
            }
            elseif ($smbConfig.PSObject.Properties['RequireSecuritySignature']) {
                Write-ADTResult -Check 'SMB signing' -Status PASS -Detail 'RequireSecuritySignature is True.'
            }
            else {
                Write-ADTResult -Check 'SMB signing' -Status SKIP -Detail 'RequireSecuritySignature property was not present on the returned configuration object.'
            }

            $encryptText = 'not reported'
            if ($smbConfig.PSObject.Properties['EncryptData']) { $encryptText = [string]$smbConfig.EncryptData }
            $ciphersText = 'not reported'
            if ($smbConfig.PSObject.Properties['EncryptionCiphers'] -and -not [string]::IsNullOrEmpty([string]$smbConfig.EncryptionCiphers)) {
                $ciphersText = [string]$smbConfig.EncryptionCiphers
            }
            Write-ADTResult -Check 'SMB encryption capability' -Status INFO -Detail ('Server-wide EncryptData: ' + $encryptText + '; EncryptionCiphers: ' + $ciphersText) -Why 'Encryption can also be set per-share (New-SmbShare/Set-SmbShare -EncryptData); a server-wide False does not mean individual shares cannot still require it.'
        }
        catch {
            Write-ADTResult -Check 'SMB server configuration' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- 2. Get-WindowsFeature FS-SMB1 (servers only) ----
        if (-not $script:ADTCaps['IsServer']) {
            Write-ADTResult -Check 'SMB1 Windows Feature' -Status SKIP -Detail 'Get-WindowsFeature is a Windows Server (ServerManager module) cmdlet; this host is not reporting as a server.'
        }
        else {
            $featureProbe = Get-Command -Name 'Get-WindowsFeature' -ErrorAction SilentlyContinue
            if ($null -eq $featureProbe) {
                Write-ADTResult -Check 'SMB1 Windows Feature' -Status SKIP -Detail 'Get-WindowsFeature is not available on this host (ServerManager module not present).'
            }
            else {
                try {
                    # UNVERIFIED: the literal feature name 'FS-SMB1' could not be confirmed
                    # against a Microsoft Learn page in this session (Learn documents the
                    # Get-WindowsFeature cmdlet itself, not a canonical list of every
                    # feature Name string). Handled defensively: a $null/empty result is
                    # treated as "not recognised on this OS build", not an error.
                    $smb1Feature = Get-WindowsFeature -Name 'FS-SMB1' -ErrorAction Stop
                    $smb1Feature = $smb1Feature | Select-Object -First 1

                    if ($null -eq $smb1Feature) {
                        Write-ADTResult -Check 'SMB1 Windows Feature' -Status SKIP -Detail 'Get-WindowsFeature -Name FS-SMB1 returned no matching feature on this OS build.'
                    }
                    elseif ($smb1Feature.PSObject.Properties['Installed'] -and $smb1Feature.Installed -eq $true) {
                        Write-ADTResult -Check 'SMB1 Windows Feature' -Status FAIL -Detail 'The FS-SMB1 Windows Feature is installed.' -Why 'This is the underlying Windows Feature behind the SMB1 protocol; having it installed is what makes EnableSMB1Protocol capable of being True at all, and it carries the same legacy-protocol risk noted above.' -Fix @('[SERVICE-AFFECTING, needs a reboot] Uninstall-WindowsFeature -Name FS-SMB1', 'Confirm no legacy client still needs SMB1 first (see the SMB1 protocol check above).')
                    }
                    else {
                        Write-ADTResult -Check 'SMB1 Windows Feature' -Status PASS -Detail 'The FS-SMB1 Windows Feature is confirmed not installed.'
                    }
                }
                catch {
                    Write-ADTResult -Check 'SMB1 Windows Feature' -Status SKIP -Detail ('Get-WindowsFeature -Name FS-SMB1 could not be queried: ' + $_.Exception.Message)
                }
            }
        }

        # ---- 3. Share inventory (non-default shares) ----
        $nonDefaultShares = @()
        try {
            $nonDefaultShares = @(Get-SmbShare -Special $false -ErrorAction Stop)
            Write-ADTResult -Check 'Non-default SMB shares' -Status INFO -Detail ($nonDefaultShares.Count.ToString() + ' non-default share(s) found.') -Data $nonDefaultShares
        }
        catch {
            Write-ADTResult -Check 'Non-default SMB shares' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- 4. Share ACL red flags ----
        if ($nonDefaultShares.Count -gt 0) {
            # Locale-dependent: these are the English well-known-group names. A non-English
            # Windows build localises "Everyone"/"Authenticated Users" in some contexts,
            # which this literal-string match will not catch - disclosed in the report.
            $riskyAccounts = @('Everyone', 'Authenticated Users', 'NT AUTHORITY\Authenticated Users', 'BUILTIN\Users')

            foreach ($share in $nonDefaultShares) {
                if (-not $share.PSObject.Properties['Name']) { continue }
                $shareName = [string]$share.Name

                if ($shareName -eq 'SYSVOL' -or $shareName -eq 'NETLOGON') {
                    Write-ADTResult -Check ('Share ACL: ' + $shareName) -Status INFO `
                        -Detail 'DC system share - excluded from the broad-ACE red-flag check. Its share-layer ACL (including Authenticated Users Full Control on SYSVOL) is the OS default; effective access is governed by NTFS and Group Policy.'
                    continue
                }

                try {
                    $aceList = @(Get-SmbShareAccess -Name $shareName -ErrorAction Stop)
                    $riskyAces = @($aceList | Where-Object {
                        $_.PSObject.Properties['AccessControlType'] -and $_.PSObject.Properties['AccessRight'] -and $_.PSObject.Properties['AccountName'] -and
                        [string]$_.AccessControlType -eq 'Allow' -and
                        [string]$_.AccessRight -eq 'Full' -and
                        ($riskyAccounts -contains [string]$_.AccountName)
                    })

                    if ($riskyAces.Count -gt 0) {
                        $accountsText = (($riskyAces | ForEach-Object { [string]$_.AccountName }) -join ', ')
                        $aclWhy = 'Full Control at the share layer for a broad built-in group (Everyone/Authenticated Users/Users) means the share ACL itself places no meaningful restriction - whatever access control exists is entirely up to NTFS permissions on the underlying folder. If NTFS is equally broad, any authenticated user (or, for Everyone, potentially unauthenticated/guest sessions depending on server settings) can read and write there.'
                        Write-ADTResult -Check ('Share ACL: ' + $shareName) -Status WARN -Detail ('Full Control granted to: ' + $accountsText) -Why $aclWhy -Fix @('Get-Acl -Path "<the share''s local path>" | Format-List   (check whether NTFS already restricts this before assuming it is wide open)', ('Revoke-SmbShareAccess -Name "' + $shareName + '" -AccountName "<the broad group above>" -Force'), ('Grant-SmbShareAccess -Name "' + $shareName + '" -AccountName "<specific group that should have access>" -AccessRight Full -Force'))
                    }
                    else {
                        Write-ADTResult -Check ('Share ACL: ' + $shareName) -Status PASS -Detail 'No Full Control ACE for a broad built-in group (Everyone/Authenticated Users/Users) at the share layer.'
                    }
                }
                catch {
                    Write-ADTResult -Check ('Share ACL: ' + $shareName) -Status ERROR -Detail $_.Exception.Message
                }
            }
        }

        # ---- 5. Open sessions / open files counts ----
        try {
            $sessionProbe = Get-Command -Name 'Get-SmbSession' -ErrorAction SilentlyContinue
            if ($null -eq $sessionProbe) {
                Write-ADTResult -Check 'SMB sessions' -Status SKIP -Detail 'Get-SmbSession is not available on this OS.'
            }
            else {
                $sessions = @(Get-SmbSession -ErrorAction Stop)
                Write-ADTResult -Check 'SMB sessions' -Status INFO -Detail ($sessions.Count.ToString() + ' active SMB session(s).')
            }
        }
        catch {
            Write-ADTResult -Check 'SMB sessions' -Status ERROR -Detail $_.Exception.Message
        }

        try {
            $openFileProbe = Get-Command -Name 'Get-SmbOpenFile' -ErrorAction SilentlyContinue
            if ($null -eq $openFileProbe) {
                Write-ADTResult -Check 'SMB open files' -Status SKIP -Detail 'Get-SmbOpenFile is not available on this OS.'
            }
            else {
                $openFiles = @(Get-SmbOpenFile -ErrorAction Stop)
                Write-ADTResult -Check 'SMB open files' -Status INFO -Detail ($openFiles.Count.ToString() + ' open file handle(s) reported.')
            }
        }
        catch {
            Write-ADTResult -Check 'SMB open files' -Status ERROR -Detail $_.Exception.Message
        }

        # ---- 6 & 7. Per-volume free space and shadow copies ----
        $disks = Get-ADTLogicalDiskList

        if ($disks.Count -eq 0) {
            Write-ADTResult -Check 'Fixed volume free space' -Status SKIP -Detail 'No fixed local disks (Win32_LogicalDisk DriveType=3) were found.'
        }
        else {
            foreach ($disk in $disks) {
                if ($disk.SizeBytes -le 0) {
                    Write-ADTResult -Check ('Free space: ' + $disk.DeviceID) -Status SKIP -Detail 'Reported volume size is zero; cannot compute a free-space percentage.'
                    continue
                }

                $percentFree = ($disk.FreeBytes / $disk.SizeBytes) * 100
                $percentText = $percentFree.ToString('N1')
                $freeText = Format-ADTByteSize -Bytes $disk.FreeBytes
                $sizeText = Format-ADTByteSize -Bytes $disk.SizeBytes
                $detailText = ($freeText + ' free of ' + $sizeText + ' (' + $percentText + '% free)')

                if ($percentFree -lt 5) {
                    Write-ADTResult -Check ('Free space: ' + $disk.DeviceID) -Status FAIL -Detail $detailText -Why 'Under 5% free on a volume risks the OS/application-level low-disk-space failures that show up as failed writes, failed database checkpoints, or a volume that cannot even create a shadow copy for its next backup.' -Fix @(('Get-ChildItem -Path "' + $disk.DeviceID + '\" -Recurse -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 20 FullName, Length'), 'Review shadow copy storage usage too - it can itself consume significant space: vssadmin list shadowstorage')
                }
                elseif ($percentFree -lt 10) {
                    Write-ADTResult -Check ('Free space: ' + $disk.DeviceID) -Status WARN -Detail $detailText -Why 'Under 10% free is worth planning for before it becomes an under-5% emergency.' -Fix @(('Get-ChildItem -Path "' + $disk.DeviceID + '\" -Recurse -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 20 FullName, Length'))
                }
                else {
                    Write-ADTResult -Check ('Free space: ' + $disk.DeviceID) -Status PASS -Detail $detailText
                }

                # ---- shadow copies for this same volume ----
                $shadowSummary = Get-ADTShadowCopySummary -VolumeSpec $disk.DeviceID
                if (-not $shadowSummary.ParseOk) {
                    Write-ADTResult -Check ('Shadow copies: ' + $disk.DeviceID) -Status SKIP -Detail 'vssadmin list shadows produced no output this check could parse (see the module notes on English-locale-only text parsing).'
                }
                elseif (-not $shadowSummary.HasAny) {
                    Write-ADTResult -Check ('Shadow copies: ' + $disk.DeviceID) -Status INFO -Detail 'No shadow copies (Volume Shadow Copy snapshots) exist for this volume.'
                }
                else {
                    $newestText = 'unknown date'
                    $ageWarn = $false
                    if ($null -ne $shadowSummary.NewestDate) {
                        $ageDays = (New-TimeSpan -Start $shadowSummary.NewestDate -End (Get-Date)).TotalDays
                        $newestText = $shadowSummary.NewestDate.ToString('yyyy-MM-dd HH:mm')
                        if ($ageDays -gt 7) { $ageWarn = $true }
                    }
                    $shadowDetail = ($shadowSummary.Count.ToString() + ' shadow cop' + $(if ($shadowSummary.Count -eq 1) { 'y' } else { 'ies' }) + '; newest ' + $newestText)

                    if ($ageWarn -and $script:ADTCaps['IsServer']) {
                        Write-ADTResult -Check ('Shadow copies: ' + $disk.DeviceID) -Status WARN -Detail $shadowDetail -Why 'The newest shadow copy on this volume is more than 7 days old. On a file server, shadow copies are the usual "restore yesterday''s version of this file myself" self-service recovery path; a stale schedule means users effectively lost that safety net without anyone noticing.' -Fix @(('vssadmin list shadows /for=' + $disk.DeviceID), 'Check the scheduled task that should be creating these: Get-ScheduledTask | Where-Object { $_.TaskName -like "*ShadowCopyVolume*" }')
                    }
                    else {
                        Write-ADTResult -Check ('Shadow copies: ' + $disk.DeviceID) -Status INFO -Detail $shadowDetail
                    }
                }
            }
        }

        # ---- 8. Data Deduplication (optional module, true silent skip if absent) ----
        $hasDedupModule = Test-ADTModuleAvailable -Name 'Deduplication'
        if ($hasDedupModule) {
            try {
                $dedupStatuses = @(Get-DedupStatus -ErrorAction Stop)
                if ($dedupStatuses.Count -eq 0) {
                    Write-ADTResult -Check 'Data Deduplication' -Status INFO -Detail 'Deduplication module is present but no volumes currently have deduplication metadata.'
                }
                else {
                    foreach ($dedupStatus in $dedupStatuses) {
                        # UNVERIFIED: "Volume" as the identifying output property name was
                        # not directly confirmed on Microsoft Learn in this session (Learn
                        # confirmed -Volume as the *input* parameter and confirmed
                        # LastOptimizationResult/LastOptimizationResultMessage/
                        # LastOptimizationTime/SavingsRate as real output fields). Accessed
                        # defensively so a wrong guess degrades rather than throws.
                        $volLabel = 'volume'
                        if ($dedupStatus.PSObject.Properties['Volume'] -and -not [string]::IsNullOrEmpty([string]$dedupStatus.Volume)) {
                            $volLabel = [string]$dedupStatus.Volume
                        }
                        $savingsText = 'not reported'
                        if ($dedupStatus.PSObject.Properties['SavingsRate']) { $savingsText = ([string]$dedupStatus.SavingsRate + '%') }
                        $lastResultText = 'not reported'
                        if ($dedupStatus.PSObject.Properties['LastOptimizationResult']) { $lastResultText = [string]$dedupStatus.LastOptimizationResult }
                        Write-ADTResult -Check ('Data Deduplication: ' + $volLabel) -Status INFO -Detail ('Savings rate ' + $savingsText + '; last optimization result code ' + $lastResultText + ' (0 = success).') -Data $dedupStatus
                    }
                }
            }
            catch {
                Write-ADTResult -Check 'Data Deduplication' -Status ERROR -Detail $_.Exception.Message
            }
        }
        else {
            Write-ADTNote -Text 'Data Deduplication module not present on this host - dedup status check skipped (this is expected on most servers; not an error).'
        }

        # ---- 9. FSRM quotas (optional module, true silent skip if absent) ----
        $hasFsrmModule = Test-ADTModuleAvailable -Name 'FileServerResourceManager'
        if ($hasFsrmModule) {
            try {
                $quotas = @(Get-FsrmQuota -ErrorAction Stop)
                Write-ADTResult -Check 'FSRM quotas' -Status INFO -Detail ($quotas.Count.ToString() + ' FSRM quota(s) configured.') -Data $quotas
            }
            catch {
                Write-ADTResult -Check 'FSRM quotas' -Status ERROR -Detail $_.Exception.Message
            }
        }
        else {
            Write-ADTNote -Text 'FileServerResourceManager module not present on this host - FSRM quota check skipped (this is expected unless the FSRM role service is installed; not an error).'
        }
    }
    catch {
        Write-ADTResult -Check 'SMB / file services health' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Module registration

Register-ADTModule -Name 'File services' -Group 'ON-PREM' -Items @(
    @{ Label = 'SMB / file services health'; Function = 'Invoke-ADTFileServices'; Requires = @(); Snapshot = $true }
)

#endregion
