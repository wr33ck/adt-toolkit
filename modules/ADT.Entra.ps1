# ADT.Entra.ps1 - Microsoft Entra ID tenant, privileged access, security posture, MFA and sync checks.
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.

#region Constants

# Role template IDs are immutable. Global Administrator's is confirmed on Microsoft Learn in
# three separate places (Microsoft Entra built-in roles, the tenantGovernanceServices
# roleTemplate resource type, and the Graph Security API 403 troubleshooting article).
if ($null -eq $script:ADTEntraGlobalAdminTemplateId) {
    $script:ADTEntraGlobalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'
}

# The other roles this module counts. These are matched by DisplayName rather than by template
# ID on purpose: only the Global Administrator template ID could be confirmed on Microsoft
# Learn in this session, and an invented GUID would silently match nothing. The display names
# are the ones published in "Microsoft Entra built-in roles".
if ($null -eq $script:ADTEntraOtherPrivilegedRoles) {
    $script:ADTEntraOtherPrivilegedRoles = @(
        'Privileged Role Administrator',
        'Exchange Administrator',
        'SharePoint Administrator',
        'User Administrator'
    )
}

# Judgement thresholds, kept in one place so a reviewer can see and argue with them.
if ($null -eq $script:ADTEntraGaCeiling)        { $script:ADTEntraGaCeiling = 5 }
if ($null -eq $script:ADTEntraSkuHeadroomPct)   { $script:ADTEntraSkuHeadroomPct = 95 }
if ($null -eq $script:ADTEntraMfaFloorPct)      { $script:ADTEntraMfaFloorPct = 70 }
if ($null -eq $script:ADTEntraSyncMaxAgeHours)  { $script:ADTEntraSyncMaxAgeHours = 2 }
if ($null -eq $script:ADTEntraUserSampleSize)   { $script:ADTEntraUserSampleSize = 999 }
if ($null -eq $script:ADTEntraNameListMax)      { $script:ADTEntraNameListMax = 15 }

#endregion

#region Private helpers

function Get-ADTEntraProperty {
    <#
        .SYNOPSIS
            Read a property from an object without throwing when it is absent.
        .DESCRIPTION
            Graph SDK model objects change shape between major versions and many nested members
            arrive as untyped AdditionalProperties. Degrading to $null beats an exception.
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
        if ($InputObject -is [System.Collections.IDictionary]) {
            if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
            return $null
        }
        $property = $InputObject.PSObject.Properties[$Name]
        if ($null -ne $property) { return $property.Value }
        return $null
    }
    catch {
        return $null
    }
}

function Format-ADTEntraList {
    <#
        .SYNOPSIS
            Join a list into readable text, capped so one result line cannot flood the console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Items,

        [Parameter(Mandatory = $false)]
        [string]$EmptyText = 'none',

        [Parameter(Mandatory = $false)]
        [int]$Maximum = 0
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

    $cap = $Maximum
    if ($cap -le 0) { $cap = $script:ADTEntraNameListMax }

    if ($strings.Count -le $cap) { return ($strings -join ', ') }

    $shown = @($strings | Select-Object -First $cap)
    return (($shown -join ', ') + ', and ' + [string]($strings.Count - $cap) + ' more')
}

function Get-ADTEntraObjectLabel {
    <#
        .SYNOPSIS
            Best available human label for a directory object returned by Graph.
        .DESCRIPTION
            Get-MgDirectoryRoleMember returns directoryObject instances. In the Graph PowerShell
            SDK the type-specific fields (displayName, userPrincipalName, @odata.type) arrive in
            the AdditionalProperties dictionary rather than as typed members, so both shapes are
            read here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) { return 'unknown' }

    $displayName = [string](Get-ADTEntraProperty -InputObject $InputObject -Name 'DisplayName')
    $upn         = [string](Get-ADTEntraProperty -InputObject $InputObject -Name 'UserPrincipalName')
    $objectId    = [string](Get-ADTEntraProperty -InputObject $InputObject -Name 'Id')
    $odataType   = ''

    $extra = Get-ADTEntraProperty -InputObject $InputObject -Name 'AdditionalProperties'
    if ($null -ne $extra) {
        if ([string]::IsNullOrEmpty($displayName)) { $displayName = [string](Get-ADTEntraProperty -InputObject $extra -Name 'displayName') }
        if ([string]::IsNullOrEmpty($upn))         { $upn         = [string](Get-ADTEntraProperty -InputObject $extra -Name 'userPrincipalName') }
        $odataType = [string](Get-ADTEntraProperty -InputObject $extra -Name '@odata.type')
    }

    $label = $upn
    if ([string]::IsNullOrEmpty($label)) { $label = $displayName }
    if ([string]::IsNullOrEmpty($label)) { $label = $objectId }
    if ([string]::IsNullOrEmpty($label)) { return 'unknown' }

    # A group or service principal holding a privileged role matters more than a user does,
    # so say what kind of object it is when Graph tells us and it is not a plain user.
    if (-not [string]::IsNullOrEmpty($odataType) -and $odataType -notlike '*.user') {
        $shortType = $odataType
        $lastDot = $shortType.LastIndexOf('.')
        if ($lastDot -ge 0 -and $lastDot -lt ($shortType.Length - 1)) { $shortType = $shortType.Substring($lastDot + 1) }
        return ($label + ' [' + $shortType + ']')
    }

    return $label
}

function Test-ADTEntraGraphConnected {
    <#
        .SYNOPSIS
            Gate every Entra check. Emits the SKIP itself and returns $false when Graph is down.
        .DESCRIPTION
            The contract forbids a check from auto-connecting, so this only reports.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Check
    )

    $context = $null
    try {
        $context = Get-ADTCloudContext
    }
    catch {
        $context = $null
    }

    if ($null -ne $context -and $context.Graph.Connected) { return $true }

    $skipFix = @(
        'Connect-ADTGraph',
        'Connect-ADTGraph -DeviceCode   (browserless jump box)',
        'Get-ADTCloudContext'
    )
    Write-ADTResult -Check $Check -Status SKIP `
        -Detail 'not connected - run Connect Microsoft Graph first' `
        -Why 'Every check in this module reads the tenant over Microsoft Graph. ADT never opens a cloud session on your behalf inside a check.' `
        -Fix $skipFix
    return $false
}

function Test-ADTEntraLicenceGate {
    <#
        .SYNOPSIS
            Does this failure look like a licence gate rather than a real fault?
        .DESCRIPTION
            Microsoft Entra returns a premium-tenant error for data that needs Entra ID P1 or P2
            (sign-in logs, several report endpoints). The exact wording is not published as a
            stable contract, so this matches a set of tokens seen in those responses. It is
            deliberately generous: a false positive downgrades a result to SKIP, which is far
            better than reporting a licensing limit as a broken tenant.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$ErrorRecord
    )

    if ($null -eq $ErrorRecord) { return $false }

    $message = ''
    try { $message = [string]$ErrorRecord.Exception.Message } catch { $message = '' }
    if ([string]::IsNullOrEmpty($message)) {
        try { $message = [string]$ErrorRecord } catch { $message = '' }
    }
    if ([string]::IsNullOrEmpty($message)) { return $false }

    # UNVERIFIED: Microsoft does not publish the exact error strings for premium-licence gating,
    # so these tokens come from observed Graph responses, not from a documented contract.
    $tokens = @(
        'RequestFromNonPremiumTenant',
        'NonPremiumTenant',
        'Directory_Premium',
        'AadPremium',
        'premium license',
        'premium licence',
        'Premium',
        'not licensed',
        'license',
        'licence'
    )

    foreach ($token in $tokens) {
        if ($message -like ('*' + $token + '*')) { return $true }
    }
    return $false
}

function Test-ADTEntraAccessDenied {
    <#
        .SYNOPSIS
            Does this failure look like a missing Graph scope or a role the operator lacks?
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$ErrorRecord
    )

    if ($null -eq $ErrorRecord) { return $false }

    $message = ''
    try { $message = [string]$ErrorRecord.Exception.Message } catch { $message = '' }
    if ([string]::IsNullOrEmpty($message)) { return $false }

    # UNVERIFIED: matched on the Graph error codes Microsoft returns for authorisation failures;
    # the code names are documented but the surrounding message text is not a stable contract.
    $tokens = @(
        'Authorization_RequestDenied',
        'Insufficient privileges',
        'Access is denied',
        'Forbidden',
        '(403)'
    )

    foreach ($token in $tokens) {
        if ($message -like ('*' + $token + '*')) { return $true }
    }
    return $false
}

function Write-ADTEntraDegraded {
    <#
        .SYNOPSIS
            Turn one Graph failure into the right result: SKIP for a licence or permission gate,
            ERROR for anything genuinely broken.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Check,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$ErrorRecord,

        [Parameter(Mandatory = $true)]
        [string]$Licence,

        [Parameter(Mandatory = $true)]
        [string]$Scope
    )

    $message = ''
    try { $message = [string]$ErrorRecord.Exception.Message } catch { $message = 'unknown error' }

    if (Test-ADTEntraLicenceGate -ErrorRecord $ErrorRecord) {
        $licenceWhy = 'This data is gated behind ' + $Licence + '. The tenant is not broken; it simply does not carry the licence that exposes it, so ADT reports SKIP rather than a fault.'
        $licenceFix = @(
            ('Confirm the tenant''s licences: Get-MgSubscribedSku | Select-Object SkuPartNumber, ConsumedUnits'),
            ('Entra admin centre > Identity > Overview > Licenses to see whether ' + $Licence + ' is present.')
        )
        Write-ADTResult -Check $Check -Status SKIP `
            -Detail ('licence-gated (' + $Licence + '): ' + $message) -Why $licenceWhy -Fix $licenceFix
        return
    }

    if (Test-ADTEntraAccessDenied -ErrorRecord $ErrorRecord) {
        $deniedWhy = 'Graph refused the request. The signed-in account either did not consent to ' + $Scope + ' or does not hold a directory role that can read this data.'
        $deniedFix = @(
            'Get-MgContext | Select-Object -ExpandProperty Scopes',
            ('Ask a Global Administrator to grant admin consent for ' + $Scope + ', then run Connect-ADTGraph again.'),
            'Connect-ADTGraph'
        )
        Write-ADTResult -Check $Check -Status SKIP -Detail ('access denied: ' + $message) -Why $deniedWhy -Fix $deniedFix
        return
    }

    Write-ADTResult -Check $Check -Status ERROR -Detail $message `
        -Fix @('Get-MgContext', 'Connect-ADTGraph')
}

function Get-ADTEntraOrganization {
    <#
        .SYNOPSIS
            The tenant's organization object, or $null. Never throws.
        .DESCRIPTION
            Get-MgOrganization (Microsoft.Graph.Identity.DirectoryManagement, graph-powershell-1.0)
            lists the currently authenticated organization, so the first item is this tenant.
    #>
    [CmdletBinding()]
    param()

    try {
        $organizations = @(Get-MgOrganization -ErrorAction Stop)
        if ($organizations.Count -gt 0) { return $organizations[0] }
        return $null
    }
    catch {
        return $null
    }
}

#endregion

#region Item 1: Tenant overview

function Invoke-ADTEntraOverview {
    <#
        .SYNOPSIS
            Who this tenant is: name, tenant id, directory sync flag, verified domains and the
            licence position of every SKU the organisation owns.
        .DESCRIPTION
            Cmdlets and properties verified on Microsoft Learn:
              Get-MgOrganization   (Microsoft.Graph.Identity.DirectoryManagement, graph-powershell-1.0)
                                   organization resource type (graph-rest-1.0): displayName, id,
                                   onPremisesSyncEnabled, onPremisesLastSyncDateTime,
                                   createdDateTime, tenantType, verifiedDomains.
              Get-MgDomain         (same module) - domain resource type: id (the FQDN),
                                   isDefault, isVerified, isInitial, authenticationType
                                   (Managed or Federated).
              Get-MgSubscribedSku  (same module) - subscribedSku resource type: skuPartNumber,
                                   consumedUnits, appliesTo, capabilityStatus and prepaidUnits
                                   (licenseUnitsDetail: enabled, suspended, warning, lockedOut).
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Entra ID: Tenant Overview'

        if (-not (Test-ADTEntraGraphConnected -Check 'Tenant overview')) { return }

        # ---- Organization ----------------------------------------------------------------
        $organization = $null
        try {
            $organization = Get-ADTEntraOrganization
            if ($null -eq $organization) { throw 'Get-MgOrganization returned no organization object.' }

            $orgName    = [string](Get-ADTEntraProperty -InputObject $organization -Name 'DisplayName')
            $orgId      = [string](Get-ADTEntraProperty -InputObject $organization -Name 'Id')
            $orgCreated = Get-ADTEntraProperty -InputObject $organization -Name 'CreatedDateTime'
            $orgType    = [string](Get-ADTEntraProperty -InputObject $organization -Name 'TenantType')
            $syncFlag   = Get-ADTEntraProperty -InputObject $organization -Name 'OnPremisesSyncEnabled'

            # onPremisesSyncEnabled is nullable: null means "never synced from on-premises".
            $syncText = 'false (cloud-only)'
            if ($null -ne $syncFlag -and [bool]$syncFlag) { $syncText = 'true (directory synchronisation is on)' }

            $createdText = 'unknown'
            if ($null -ne $orgCreated) {
                try { $createdText = ([datetime]$orgCreated).ToString('yyyy-MM-dd') } catch { $createdText = [string]$orgCreated }
            }

            $orgDetail = 'Name=' + $orgName + ', TenantId=' + $orgId + ', OnPremisesSyncEnabled=' + $syncText + ', Created=' + $createdText
            if (-not [string]::IsNullOrEmpty($orgType)) { $orgDetail = $orgDetail + ', TenantType=' + $orgType }

            Write-ADTResult -Check 'Tenant identity' -Status INFO -Detail $orgDetail -Data $organization
        }
        catch {
            Write-ADTEntraDegraded -Check 'Tenant identity' -ErrorRecord $_ -Licence 'Microsoft Entra ID (any edition)' -Scope 'Organization.Read.All'
        }

        # ---- Verified domains ------------------------------------------------------------
        try {
            $domains = @(Get-MgDomain -All -ErrorAction Stop)

            if ($domains.Count -eq 0) {
                Write-ADTResult -Check 'Verified domains' -Status INFO -Detail 'Graph returned no domain objects for this tenant.'
            }
            else {
                $verified = @($domains | Where-Object { [bool](Get-ADTEntraProperty -InputObject $_ -Name 'IsVerified') })
                $defaultDomain = $domains | Where-Object { [bool](Get-ADTEntraProperty -InputObject $_ -Name 'IsDefault') } | Select-Object -First 1
                $defaultText = 'none flagged'
                if ($null -ne $defaultDomain) { $defaultText = [string](Get-ADTEntraProperty -InputObject $defaultDomain -Name 'Id') }

                $unverified = @($domains | Where-Object { -not [bool](Get-ADTEntraProperty -InputObject $_ -Name 'IsVerified') })

                $domainDetail = [string]$domains.Count + ' domain(s), ' + [string]$verified.Count + ' verified. Default: ' + $defaultText + '.'
                Write-ADTResult -Check 'Verified domains' -Status INFO -Detail $domainDetail -Data $domains

                if ($unverified.Count -gt 0) {
                    $unverifiedNames = @()
                    foreach ($domain in $unverified) { $unverifiedNames += [string](Get-ADTEntraProperty -InputObject $domain -Name 'Id') }
                    $unverifiedWhy = 'A domain sitting in the tenant unverified cannot be used for mail or sign-in, and is usually either an abandoned onboarding attempt or a domain someone added and never finished proving ownership of.'
                    $unverifiedFix = @(
                        ('Get-MgDomain -DomainId "' + $unverifiedNames[0] + '" | Format-List'),
                        ('Get-MgDomainVerificationDnsRecord -DomainId "' + $unverifiedNames[0] + '"'),
                        'Entra admin centre > Identity > Settings > Domain names to finish or remove the verification.'
                    )
                    Write-ADTResult -Check 'Unverified domains' -Status INFO `
                        -Detail ([string]$unverified.Count + ' unverified domain(s): ' + (Format-ADTEntraList -Items $unverifiedNames)) `
                        -Why $unverifiedWhy -Fix $unverifiedFix -Data $unverified
                }

                # Federated domains change where authentication actually happens, so they are
                # always called out by name with their authentication type.
                $federated = @($domains | Where-Object { ([string](Get-ADTEntraProperty -InputObject $_ -Name 'AuthenticationType')) -eq 'Federated' })
                if ($federated.Count -eq 0) {
                    Write-ADTResult -Check 'Domain authentication type' -Status INFO -Detail 'All domains are Managed (Entra ID performs authentication). No federated domains.'
                }
                else {
                    $federatedText = @()
                    foreach ($domain in $federated) {
                        $domainName = [string](Get-ADTEntraProperty -InputObject $domain -Name 'Id')
                        $authType   = [string](Get-ADTEntraProperty -InputObject $domain -Name 'AuthenticationType')
                        $federatedText += ($domainName + ' (' + $authType + ')')
                    }
                    $fedWhy = 'A federated domain means sign-in for those users is handled by an external identity provider such as AD FS, not by Entra ID. Conditional Access, MFA behaviour and outage blast radius all differ for those users, and an expiring federation certificate takes them offline.'
                    $fedFix = @(
                        ('Get-MgDomainFederationConfiguration -DomainId "' + ([string](Get-ADTEntraProperty -InputObject $federated[0] -Name 'Id')) + '"'),
                        'On the AD FS server: Get-AdfsCertificate -CertificateType Token-Signing'
                    )
                    Write-ADTResult -Check 'Domain authentication type' -Status INFO `
                        -Detail ([string]$federated.Count + ' federated domain(s): ' + (Format-ADTEntraList -Items $federatedText)) `
                        -Why $fedWhy -Fix $fedFix -Data $federated
                }
            }
        }
        catch {
            Write-ADTEntraDegraded -Check 'Verified domains' -ErrorRecord $_ -Licence 'Microsoft Entra ID (any edition)' -Scope 'Directory.Read.All'
        }

        # ---- Licences --------------------------------------------------------------------
        try {
            $skus = @(Get-MgSubscribedSku -All -ErrorAction Stop)

            if ($skus.Count -eq 0) {
                Write-ADTResult -Check 'Licence inventory' -Status INFO -Detail 'This tenant owns no subscribed SKUs.'
            }
            else {
                Write-ADTResult -Check 'Licence inventory' -Status INFO -Detail ([string]$skus.Count + ' SKU(s) owned by this tenant.') -Data $skus

                foreach ($sku in $skus) {
                    $partNumber = [string](Get-ADTEntraProperty -InputObject $sku -Name 'SkuPartNumber')
                    if ([string]::IsNullOrEmpty($partNumber)) { $partNumber = 'unnamed SKU' }
                    $checkName = 'Licence: ' + $partNumber

                    try {
                        $consumed = 0
                        $consumedRaw = Get-ADTEntraProperty -InputObject $sku -Name 'ConsumedUnits'
                        if ($null -ne $consumedRaw) { $consumed = [int]$consumedRaw }

                        $prepaid = Get-ADTEntraProperty -InputObject $sku -Name 'PrepaidUnits'
                        $enabled = 0
                        $suspended = 0
                        $warning = 0
                        if ($null -ne $prepaid) {
                            $enabledRaw   = Get-ADTEntraProperty -InputObject $prepaid -Name 'Enabled'
                            $suspendedRaw = Get-ADTEntraProperty -InputObject $prepaid -Name 'Suspended'
                            $warningRaw   = Get-ADTEntraProperty -InputObject $prepaid -Name 'Warning'
                            if ($null -ne $enabledRaw)   { $enabled   = [int]$enabledRaw }
                            if ($null -ne $suspendedRaw) { $suspended = [int]$suspendedRaw }
                            if ($null -ne $warningRaw)   { $warning   = [int]$warningRaw }
                        }

                        $appliesTo  = [string](Get-ADTEntraProperty -InputObject $sku -Name 'AppliesTo')
                        $capability = [string](Get-ADTEntraProperty -InputObject $sku -Name 'CapabilityStatus')

                        $suffix = ''
                        if (-not [string]::IsNullOrEmpty($appliesTo))  { $suffix = $suffix + ', AppliesTo=' + $appliesTo }
                        if (-not [string]::IsNullOrEmpty($capability)) { $suffix = $suffix + ', Status=' + $capability }
                        if ($suspended -gt 0) { $suffix = $suffix + ', Suspended=' + [string]$suspended }
                        if ($warning -gt 0)   { $suffix = $suffix + ', Warning=' + [string]$warning }

                        $baseDetail = [string]$consumed + ' of ' + [string]$enabled + ' assigned' + $suffix

                        if ($enabled -le 0) {
                            Write-ADTResult -Check $checkName -Status INFO `
                                -Detail ($baseDetail + ' -- no enabled units on this SKU.') -Data $sku
                            continue
                        }

                        $percent = [math]::Round((($consumed * 100.0) / $enabled), 1)

                        if ($consumed -eq 0) {
                            $shelfWhy = 'Nobody in the tenant holds this licence. Either it was bought for a project that never happened or the assignment was removed and the subscription was not cancelled, and it is billed either way.'
                            $shelfFix = @(
                                ('Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -eq "' + $partNumber + '" } | Format-List'),
                                'Microsoft 365 admin centre > Billing > Your products to reduce the seat count or cancel the subscription.'
                            )
                            Write-ADTResult -Check $checkName -Status INFO `
                                -Detail ($baseDetail + ' -- shelfware: ' + [string]$enabled + ' paid seat(s) with zero assignments.') `
                                -Why $shelfWhy -Fix $shelfFix -Data $sku
                        }
                        elseif ($percent -ge $script:ADTEntraSkuHeadroomPct) {
                            $free = $enabled - $consumed
                            $headroomWhy = 'At ' + [string]$percent + '% consumed there are only ' + [string]$free + ' seat(s) left on ' + $partNumber + '. The next new starter, mailbox or licence-driven service enablement will fail with a licence error rather than a clear message.'
                            $headroomFix = @(
                                ('Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -eq "' + $partNumber + '" } | Select-Object SkuPartNumber, ConsumedUnits, @{Name="Enabled";Expression={$_.PrepaidUnits.Enabled}}'),
                                'Microsoft 365 admin centre > Billing > Your products > select the subscription > Buy licenses.',
                                ('Or reclaim seats: Get-MgUser -All -Property userPrincipalName,assignedLicenses,accountEnabled | Where-Object { -not $_.AccountEnabled -and $_.AssignedLicenses.Count -gt 0 } | Select-Object UserPrincipalName')
                            )
                            Write-ADTResult -Check $checkName -Status WARN `
                                -Detail ($baseDetail + ' (' + [string]$percent + '%) -- no headroom.') `
                                -Why $headroomWhy -Fix $headroomFix -Data $sku
                        }
                        else {
                            Write-ADTResult -Check $checkName -Status PASS `
                                -Detail ($baseDetail + ' (' + [string]$percent + '%).') -Data $sku
                        }
                    }
                    catch {
                        Write-ADTResult -Check $checkName -Status ERROR -Detail $_.Exception.Message
                    }
                }
            }
        }
        catch {
            Write-ADTEntraDegraded -Check 'Licence inventory' -ErrorRecord $_ -Licence 'Microsoft Entra ID (any edition)' -Scope 'Organization.Read.All'
        }
    }
    catch {
        Write-ADTResult -Check 'Tenant overview' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Item 2: Privileged access

function Invoke-ADTEntraPrivileged {
    <#
        .SYNOPSIS
            Who holds Global Administrator, and how many other privileged roles are in use.
        .DESCRIPTION
            Cmdlets verified on Microsoft Learn (Microsoft.Graph.Identity.DirectoryManagement,
            graph-powershell-1.0):
              Get-MgDirectoryRole [-All]                     - lists ACTIVATED directory roles.
                  Microsoft states "The role must be activated in tenant for a successful
                  response", so a role nobody has ever held simply will not appear. Output
                  carries DisplayName, Id and RoleTemplateId.
              Get-MgDirectoryRoleMember -DirectoryRoleId <id> [-All]
                  Microsoft states the object ID and the template ID both work as the id, but
                  this module resolves the object ID from the listing first so one call covers
                  every role and the "role not activated" case is handled without a 404.
            Both need Directory.Read.All, which is in the ADT scope set.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Entra ID: Privileged Access'

        if (-not (Test-ADTEntraGraphConnected -Check 'Privileged access')) { return }

        $roles = @()
        try {
            $roles = @(Get-MgDirectoryRole -All -ErrorAction Stop)
        }
        catch {
            Write-ADTEntraDegraded -Check 'Privileged access' -ErrorRecord $_ -Licence 'Microsoft Entra ID (any edition)' -Scope 'Directory.Read.All'
            return
        }

        if ($roles.Count -eq 0) {
            Write-ADTResult -Check 'Directory roles' -Status INFO `
                -Detail 'No activated directory roles were returned.' `
                -Why 'A directory role only appears once it has been activated in the tenant, so an empty list normally means the signed-in account cannot read role assignments rather than that nobody is an administrator.' `
                -Fix @('Get-MgContext | Select-Object -ExpandProperty Scopes', 'Get-MgDirectoryRole | Select-Object DisplayName, RoleTemplateId')
            return
        }

        Write-ADTResult -Check 'Directory roles' -Status INFO -Detail ([string]$roles.Count + ' activated directory role(s) in this tenant.') -Data $roles

        # ---- Global Administrator ---------------------------------------------------------
        $gaRole = $roles |
                  Where-Object { ([string](Get-ADTEntraProperty -InputObject $_ -Name 'RoleTemplateId')) -eq $script:ADTEntraGlobalAdminTemplateId } |
                  Select-Object -First 1

        if ($null -eq $gaRole) {
            $noGaWhy = 'Directory roles must be activated before Graph returns them. Global Administrator is normally always activated, so its absence points at a permissions problem on the signed-in account rather than a tenant with no Global Administrators.'
            $noGaFix = @(
                ('Get-MgDirectoryRole -DirectoryRoleId ' + $script:ADTEntraGlobalAdminTemplateId),
                'Get-MgDirectoryRole | Select-Object DisplayName, RoleTemplateId',
                'Entra admin centre > Identity > Roles and admins > Global Administrator.'
            )
            Write-ADTResult -Check 'Global Administrator count' -Status INFO `
                -Detail ('The Global Administrator role (template ' + $script:ADTEntraGlobalAdminTemplateId + ') is not present in the activated role list.') `
                -Why $noGaWhy -Fix $noGaFix
        }
        else {
            $gaRoleId = [string](Get-ADTEntraProperty -InputObject $gaRole -Name 'Id')
            try {
                $gaMembers = @(Get-MgDirectoryRoleMember -DirectoryRoleId $gaRoleId -All -ErrorAction Stop)
                $gaLabels = @()
                foreach ($member in $gaMembers) { $gaLabels += (Get-ADTEntraObjectLabel -InputObject $member) }
                $gaCount = $gaMembers.Count
                $memberText = Format-ADTEntraList -Items $gaLabels

                if ($gaCount -eq 0) {
                    $zeroWhy = 'A tenant with no Global Administrator cannot be administered at all. This is far more likely to be a read permission problem than a genuine state.'
                    $zeroFix = @(
                        ('Get-MgDirectoryRoleMember -DirectoryRoleId ' + $gaRoleId),
                        'Entra admin centre > Identity > Roles and admins > Global Administrator > Assignments.'
                    )
                    Write-ADTResult -Check 'Global Administrator count' -Status WARN `
                        -Detail 'Graph reported zero Global Administrator members.' -Why $zeroWhy -Fix $zeroFix
                }
                elseif ($gaCount -eq 1) {
                    $soloWhy = 'One Global Administrator is a single point of failure: if that account is locked out, loses its MFA method, or leaves the business, nobody can administer the tenant and recovery goes through Microsoft support. Microsoft''s guidance is to keep at least two, with a cloud-only break-glass account excluded from Conditional Access.'
                    $soloFix = @(
                        ('Get-MgDirectoryRoleMember -DirectoryRoleId ' + $gaRoleId + ' | ForEach-Object { $_.AdditionalProperties.userPrincipalName }'),
                        'Entra admin centre > Identity > Roles and admins > Global Administrator > Add assignments, and create a cloud-only break-glass account on the .onmicrosoft.com domain.',
                        'Document the break-glass credential in the password vault and exclude it from every Conditional Access policy.'
                    )
                    Write-ADTResult -Check 'Global Administrator count' -Status WARN `
                        -Detail ('1 Global Administrator: ' + $memberText + ' -- no break-glass redundancy.') `
                        -Why $soloWhy -Fix $soloFix -Data $gaMembers
                }
                elseif ($gaCount -gt $script:ADTEntraGaCeiling) {
                    $manyWhy = 'Microsoft''s guidance is to keep fewer than five permanent Global Administrators, because every one of them is a full-tenant compromise if the account is taken over. Anyone who only needs part of the job should hold a scoped role such as User Administrator or Exchange Administrator, or take Global Administrator just-in-time through Privileged Identity Management.'
                    $manyFix = @(
                        ('Get-MgDirectoryRoleMember -DirectoryRoleId ' + $gaRoleId + ' | ForEach-Object { $_.AdditionalProperties.userPrincipalName }'),
                        'Entra admin centre > Identity > Roles and admins > Global Administrator > Assignments, and move each holder to the least-privileged role that covers their work.',
                        'With Entra ID P2, move the remaining holders to eligible assignments in Privileged Identity Management.'
                    )
                    Write-ADTResult -Check 'Global Administrator count' -Status WARN `
                        -Detail ([string]$gaCount + ' Global Administrators (guidance is fewer than ' + [string]($script:ADTEntraGaCeiling + 1) + '): ' + $memberText) `
                        -Why $manyWhy -Fix $manyFix -Data $gaMembers
                }
                else {
                    Write-ADTResult -Check 'Global Administrator count' -Status PASS `
                        -Detail ([string]$gaCount + ' Global Administrators: ' + $memberText) -Data $gaMembers
                }
            }
            catch {
                Write-ADTEntraDegraded -Check 'Global Administrator count' -ErrorRecord $_ -Licence 'Microsoft Entra ID (any edition)' -Scope 'Directory.Read.All'
            }
        }

        # ---- Other privileged roles --------------------------------------------------------
        $otherTotal = 0
        $otherSummary = @()
        foreach ($roleName in $script:ADTEntraOtherPrivilegedRoles) {
            $role = $roles |
                    Where-Object { ([string](Get-ADTEntraProperty -InputObject $_ -Name 'DisplayName')) -eq $roleName } |
                    Select-Object -First 1

            if ($null -eq $role) {
                $otherSummary += ($roleName + '=not activated')
                continue
            }

            $roleId = [string](Get-ADTEntraProperty -InputObject $role -Name 'Id')
            try {
                $members = @(Get-MgDirectoryRoleMember -DirectoryRoleId $roleId -All -ErrorAction Stop)
                $otherTotal = $otherTotal + $members.Count
                $otherSummary += ($roleName + '=' + [string]$members.Count)
            }
            catch {
                $otherSummary += ($roleName + '=unreadable')
            }
        }

        $otherWhy = 'These four roles are the ones an attacker reaches for after Global Administrator: they can reset passwords, read or export mail, take over SharePoint content, or hand themselves more roles. The count is informational, but every holder should be a named person whose job needs it.'
        $otherFix = @(
            'Get-MgDirectoryRole | Select-Object DisplayName, Id',
            'Get-MgDirectoryRoleMember -DirectoryRoleId "<role id from above>" | ForEach-Object { $_.AdditionalProperties.userPrincipalName }',
            'Entra admin centre > Identity > Roles and admins to review each assignment.'
        )
        Write-ADTResult -Check 'Other privileged roles' -Status INFO `
            -Detail ([string]$otherTotal + ' assignment(s) across the tracked roles -- ' + ($otherSummary -join ', ')) `
            -Why $otherWhy -Fix $otherFix -Data $otherSummary
    }
    catch {
        Write-ADTResult -Check 'Privileged access' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Item 3: Security posture

function Invoke-ADTEntraSecurity {
    <#
        .SYNOPSIS
            Conditional Access inventory, two clearly-labelled coverage heuristics, and the
            security defaults state.
        .DESCRIPTION
            Cmdlets and values verified on Microsoft Learn:
              Get-MgIdentityConditionalAccessPolicy [-All]
                  (Microsoft.Graph.Identity.SignIns, graph-powershell-1.0, needs Policy.Read.All).
                  conditionalAccessPolicy state values are exactly: enabled, disabled,
                  enabledForReportingButNotEnforced.
                  conditionalAccessGrantControls.builtInControls values include block and mfa.
                  conditionalAccessConditionSet.clientAppTypes values are: all, browser,
                  mobileAppsAndDesktopClients, exchangeActiveSync, easSupported, other.
                  conditionalAccessUsers.includeUsers accepts the literal All; includeRoles is a
                  collection of role IDs.
              Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
                  (same module, needs Policy.Read.All). IsEnabled is the tenant flag.
            The two gap checks below are HEURISTICS, not a Microsoft-published assessment. They
            read policy shape only; they cannot see whether a policy is actually effective for a
            given user once exclusions, groups and named locations are taken into account.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Entra ID: Security Posture'

        if (-not (Test-ADTEntraGraphConnected -Check 'Security posture')) { return }

        # ---- Conditional Access inventory --------------------------------------------------
        $policies = @()
        $policiesRead = $false
        try {
            $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
            $policiesRead = $true
        }
        catch {
            Write-ADTEntraDegraded -Check 'Conditional Access policies' -ErrorRecord $_ -Licence 'Microsoft Entra ID P1' -Scope 'Policy.Read.All'
        }

        $enabledPolicies = @()

        if ($policiesRead) {
            $enabledPolicies  = @($policies | Where-Object { ([string](Get-ADTEntraProperty -InputObject $_ -Name 'State')) -eq 'enabled' })
            $reportOnly       = @($policies | Where-Object { ([string](Get-ADTEntraProperty -InputObject $_ -Name 'State')) -eq 'enabledForReportingButNotEnforced' })
            $disabledPolicies = @($policies | Where-Object { ([string](Get-ADTEntraProperty -InputObject $_ -Name 'State')) -eq 'disabled' })

            $caDetail = [string]$policies.Count + ' policy/policies: ' +
                        [string]$enabledPolicies.Count + ' enabled, ' +
                        [string]$reportOnly.Count + ' report-only, ' +
                        [string]$disabledPolicies.Count + ' disabled.'

            if ($policies.Count -eq 0) {
                $noCaWhy = 'With no Conditional Access policies at all, the only identity protection available is security defaults, and nothing can be tailored - no per-app rules, no trusted locations, no legacy authentication block.'
                $noCaFix = @(
                    'Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State',
                    'Entra admin centre > Protection > Conditional Access > Policies > New policy from template.'
                )
                Write-ADTResult -Check 'Conditional Access policies' -Status WARN -Detail $caDetail -Why $noCaWhy -Fix $noCaFix
            }
            else {
                Write-ADTResult -Check 'Conditional Access policies' -Status INFO -Detail $caDetail -Data $policies

                if ($reportOnly.Count -gt 0) {
                    $roNames = @()
                    foreach ($policy in $reportOnly) { $roNames += [string](Get-ADTEntraProperty -InputObject $policy -Name 'DisplayName') }
                    $roWhy = 'Report-only policies log what they would have done but enforce nothing. A policy left in report-only for months is usually a rollout that was never finished, and it gives false comfort on a compliance review.'
                    $roFix = @(
                        'Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" } | Select-Object DisplayName, ModifiedDateTime',
                        'Entra admin centre > Protection > Conditional Access > Insights and reporting to review the impact, then switch each policy to On.'
                    )
                    Write-ADTResult -Check 'Conditional Access report-only policies' -Status INFO `
                        -Detail ([string]$reportOnly.Count + ' in report-only: ' + (Format-ADTEntraList -Items $roNames)) `
                        -Why $roWhy -Fix $roFix -Data $reportOnly
                }
            }

            # ---- Heuristic (a): broad MFA requirement --------------------------------------
            try {
                $mfaPolicies = @()
                foreach ($policy in $enabledPolicies) {
                    $grant = Get-ADTEntraProperty -InputObject $policy -Name 'GrantControls'
                    $builtIn = @(Get-ADTEntraProperty -InputObject $grant -Name 'BuiltInControls')
                    $requiresMfa = $false
                    foreach ($control in $builtIn) {
                        if (([string]$control).ToLower() -eq 'mfa') { $requiresMfa = $true }
                    }
                    if (-not $requiresMfa) { continue }

                    $conditions = Get-ADTEntraProperty -InputObject $policy -Name 'Conditions'
                    $users = Get-ADTEntraProperty -InputObject $conditions -Name 'Users'
                    $includeUsers = @(Get-ADTEntraProperty -InputObject $users -Name 'IncludeUsers')
                    $includeRoles = @(Get-ADTEntraProperty -InputObject $users -Name 'IncludeRoles')

                    $targetsAllUsers = $false
                    foreach ($entry in $includeUsers) {
                        if (([string]$entry).ToLower() -eq 'all') { $targetsAllUsers = $true }
                    }
                    $targetsAdminRoles = ($includeRoles.Count -gt 0)

                    if ($targetsAllUsers -or $targetsAdminRoles) {
                        $scopeText = 'admin roles'
                        if ($targetsAllUsers) { $scopeText = 'all users' }
                        $mfaPolicies += ([string](Get-ADTEntraProperty -InputObject $policy -Name 'DisplayName') + ' (' + $scopeText + ')')
                    }
                }

                if ($mfaPolicies.Count -gt 0) {
                    Write-ADTResult -Check 'CA heuristic: broad MFA requirement' -Status PASS `
                        -Detail ([string]$mfaPolicies.Count + ' enabled policy/policies require MFA for all users or for admin roles: ' + (Format-ADTEntraList -Items $mfaPolicies)) `
                        -Data $mfaPolicies
                }
                else {
                    $mfaWhy = 'HEURISTIC, not a definitive assessment: ADT looked for an enabled Conditional Access policy whose grant controls include mfa and whose user conditions either include the literal All or name at least one directory role. It found none, which normally means password-only sign-in is possible for administrators. It reads policy shape only - a policy that requires MFA via an authentication strength, or that targets a group containing everyone, will not be recognised here, so confirm before acting.'
                    $mfaFix = @(
                        'Get-MgIdentityConditionalAccessPolicy -All | Where-Object { $_.State -eq "enabled" } | Select-Object DisplayName, @{Name="Grant";Expression={$_.GrantControls.BuiltInControls -join ","}}, @{Name="Users";Expression={$_.Conditions.Users.IncludeUsers -join ","}}',
                        'Entra admin centre > Protection > Conditional Access > Policies > New policy from template > "Require multifactor authentication for admins".',
                        'Exclude the break-glass account from the new policy before switching it on.'
                    )
                    Write-ADTResult -Check 'CA heuristic: broad MFA requirement' -Status WARN `
                        -Detail 'No enabled policy was found that requires MFA for all users or for all admins.' `
                        -Why $mfaWhy -Fix $mfaFix
                }
            }
            catch {
                Write-ADTResult -Check 'CA heuristic: broad MFA requirement' -Status ERROR -Detail $_.Exception.Message
            }

            # ---- Heuristic (b): legacy authentication block --------------------------------
            try {
                $legacyPolicies = @()
                foreach ($policy in $enabledPolicies) {
                    $grant = Get-ADTEntraProperty -InputObject $policy -Name 'GrantControls'
                    $builtIn = @(Get-ADTEntraProperty -InputObject $grant -Name 'BuiltInControls')
                    $blocks = $false
                    foreach ($control in $builtIn) {
                        if (([string]$control).ToLower() -eq 'block') { $blocks = $true }
                    }
                    if (-not $blocks) { continue }

                    $conditions = Get-ADTEntraProperty -InputObject $policy -Name 'Conditions'
                    $clientAppTypes = @(Get-ADTEntraProperty -InputObject $conditions -Name 'ClientAppTypes')
                    $targetsLegacy = $false
                    foreach ($clientApp in $clientAppTypes) {
                        $clientAppText = ([string]$clientApp).ToLower()
                        if ($clientAppText -eq 'exchangeactivesync' -or $clientAppText -eq 'other' -or $clientAppText -eq 'easunsupported') {
                            $targetsLegacy = $true
                        }
                    }

                    if ($targetsLegacy) {
                        $legacyPolicies += ([string](Get-ADTEntraProperty -InputObject $policy -Name 'DisplayName') + ' (' + ($clientAppTypes -join '/') + ')')
                    }
                }

                if ($legacyPolicies.Count -gt 0) {
                    Write-ADTResult -Check 'CA heuristic: legacy authentication blocked' -Status PASS `
                        -Detail ([string]$legacyPolicies.Count + ' enabled policy/policies block legacy authentication clients: ' + (Format-ADTEntraList -Items $legacyPolicies)) `
                        -Data $legacyPolicies
                }
                else {
                    $legacyWhy = 'HEURISTIC, not a definitive assessment: ADT looked for an enabled Conditional Access policy whose grant controls include block and whose client app conditions include exchangeActiveSync or other. It found none. Legacy authentication protocols cannot present an MFA challenge, so while any of them remain reachable a stolen password is enough to sign in - which is how the large majority of password spray attacks succeed. Microsoft has retired most legacy protocols in Exchange Online, so a tenant may already be safe without such a policy; confirm against the sign-in logs before acting.'
                    $legacyFix = @(
                        'Get-MgIdentityConditionalAccessPolicy -All | Where-Object { $_.State -eq "enabled" } | Select-Object DisplayName, @{Name="ClientApps";Expression={$_.Conditions.ClientAppTypes -join ","}}, @{Name="Grant";Expression={$_.GrantControls.BuiltInControls -join ","}}',
                        'Entra admin centre > Protection > Conditional Access > Policies > New policy from template > "Block legacy authentication".',
                        'Entra admin centre > Identity > Monitoring and health > Sign-in logs, filter Client app = Exchange ActiveSync + Other clients, to find what still uses it before you switch the policy on.'
                    )
                    Write-ADTResult -Check 'CA heuristic: legacy authentication blocked' -Status WARN `
                        -Detail 'No enabled policy was found that blocks legacy authentication clients.' `
                        -Why $legacyWhy -Fix $legacyFix
                }
            }
            catch {
                Write-ADTResult -Check 'CA heuristic: legacy authentication blocked' -Status ERROR -Detail $_.Exception.Message
            }
        }

        # ---- Security defaults --------------------------------------------------------------
        try {
            $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
            $sdEnabled = $false
            $sdRaw = Get-ADTEntraProperty -InputObject $securityDefaults -Name 'IsEnabled'
            if ($null -ne $sdRaw) { $sdEnabled = [bool]$sdRaw }

            $hasEnabledCa = ($enabledPolicies.Count -gt 0)

            if (-not $policiesRead) {
                # The Conditional Access read failed above, so "no enabled CA policy" is unknown,
                # not proven. Claiming FAIL here would be a confident wrong diagnosis.
                $unknownWhy = 'Conditional Access policies could not be read on this run, so ADT cannot tell whether anything is enforcing identity protection. It will not report a baseline failure it has not proven.'
                $unknownFix = @(
                    'Get-MgIdentityConditionalAccessPolicy -All | Select-Object DisplayName, State',
                    'Get-MgContext | Select-Object -ExpandProperty Scopes',
                    'Entra admin centre > Identity > Overview > Properties > Manage security defaults.'
                )
                $sdText = 'Disabled'
                if ($sdEnabled) { $sdText = 'Enabled' }
                Write-ADTResult -Check 'Security defaults' -Status INFO `
                    -Detail ($sdText + '. Conditional Access state is unknown, so no overall baseline verdict is given.') `
                    -Why $unknownWhy -Fix $unknownFix -Data $securityDefaults
            }
            elseif ($sdEnabled -and $hasEnabledCa) {
                $bothWhy = 'Security defaults and Conditional Access are two separate enforcement engines. Entra ID normally refuses to have both on at once, so a tenant reporting both is unusual and worth confirming in the portal - and if security defaults really is on, the Conditional Access policies below it are not the thing actually enforcing MFA.'
                $bothFix = @(
                    'Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | Select-Object DisplayName, IsEnabled',
                    'Entra admin centre > Identity > Overview > Properties > Manage security defaults.',
                    'Decide on one model: security defaults for a small tenant with no P1, or Conditional Access with security defaults off.'
                )
                Write-ADTResult -Check 'Security defaults' -Status INFO `
                    -Detail ('Enabled, and ' + [string]$enabledPolicies.Count + ' Conditional Access policy/policies are also enabled.') `
                    -Why $bothWhy -Fix $bothFix -Data $securityDefaults
            }
            elseif ($sdEnabled) {
                Write-ADTResult -Check 'Security defaults' -Status PASS `
                    -Detail 'Enabled. Baseline identity protection (MFA registration and admin MFA) is being enforced tenant-wide.' -Data $securityDefaults
            }
            elseif ($hasEnabledCa) {
                Write-ADTResult -Check 'Security defaults' -Status PASS `
                    -Detail ('Disabled, which is correct: ' + [string]$enabledPolicies.Count + ' enabled Conditional Access policy/policies are enforcing identity protection instead.') `
                    -Data $securityDefaults
            }
            else {
                $noneWhy = 'Security defaults are off and there is no enabled Conditional Access policy, so nothing forces multifactor authentication on anyone - including Global Administrators. A single stolen or sprayed password is enough to sign in as any user in this tenant.'
                $noneFix = @(
                    'Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | Select-Object IsEnabled',
                    'Get-MgIdentityConditionalAccessPolicy -All | Select-Object DisplayName, State',
                    'No Entra ID P1: Entra admin centre > Identity > Overview > Properties > Manage security defaults > Enable.',
                    'With Entra ID P1: Entra admin centre > Protection > Conditional Access > Policies > New policy from template > "Require multifactor authentication for admins", excluding the break-glass account, then extend to all users.'
                )
                Write-ADTResult -Check 'Security defaults' -Status FAIL `
                    -Detail 'Disabled, and no Conditional Access policy is enabled -- no baseline identity protection.' `
                    -Why $noneWhy -Fix $noneFix -Data $securityDefaults
            }
        }
        catch {
            Write-ADTEntraDegraded -Check 'Security defaults' -ErrorRecord $_ -Licence 'Microsoft Entra ID (any edition)' -Scope 'Policy.Read.All'
        }
    }
    catch {
        Write-ADTResult -Check 'Security posture' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Item 4: MFA registration

function Invoke-ADTEntraMfa {
    <#
        .SYNOPSIS
            How much of the tenant has actually registered a strong authentication method, and
            whether any administrator has not.
        .DESCRIPTION
            Verified on Microsoft Learn: Get-MgReportAuthenticationMethodUserRegistrationDetail
            (Microsoft.Graph.Reports, graph-powershell-1.0). Its documented delegated permission
            is AuditLog.Read.All - NOT Reports.Read.All - and both are in the ADT scope set.
            userRegistrationDetails properties used here: IsAdmin, IsMfaRegistered, IsMfaCapable,
            UserPrincipalName, UserDisplayName, UserType, MethodsRegistered.
            The report has no accountEnabled field, so the denominator is every user the report
            covers, not just enabled accounts; that is stated in the result rather than glossed.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Entra ID: MFA Registration'

        if (-not (Test-ADTEntraGraphConnected -Check 'MFA registration')) { return }

        Write-ADTNote -Text 'Reading the authentication method registration report for every user. On a large tenant this can take a minute.'

        $records = @()
        try {
            # -All pages the whole report; -PageSize 999 is the largest page Graph accepts and
            # keeps the request count down. A -Top truncation was deliberately avoided here
            # because a partial read would produce a wrong percentage, which is worse than slow.
            $records = @(Get-MgReportAuthenticationMethodUserRegistrationDetail -All -PageSize 999 -ErrorAction Stop)
        }
        catch {
            Write-ADTEntraDegraded -Check 'MFA registration' -ErrorRecord $_ -Licence 'Microsoft Entra ID P1' -Scope 'AuditLog.Read.All'
            return
        }

        if ($records.Count -eq 0) {
            Write-ADTResult -Check 'MFA registration' -Status INFO `
                -Detail 'The registration report returned no records.' `
                -Why 'The authentication methods activity report is populated by Entra ID and can be empty in a brand-new tenant or where the signed-in account cannot read it.' `
                -Fix @('Get-MgReportAuthenticationMethodUserRegistrationDetail -Top 5', 'Entra admin centre > Protection > Authentication methods > User registration details.')
            return
        }

        $registered = @()
        $notRegistered = @()
        $adminsNotRegistered = @()

        foreach ($record in $records) {
            $isRegistered = $false
            $raw = Get-ADTEntraProperty -InputObject $record -Name 'IsMfaRegistered'
            if ($null -ne $raw) { $isRegistered = [bool]$raw }

            $isAdmin = $false
            $adminRaw = Get-ADTEntraProperty -InputObject $record -Name 'IsAdmin'
            if ($null -ne $adminRaw) { $isAdmin = [bool]$adminRaw }

            $label = [string](Get-ADTEntraProperty -InputObject $record -Name 'UserPrincipalName')
            if ([string]::IsNullOrEmpty($label)) { $label = [string](Get-ADTEntraProperty -InputObject $record -Name 'UserDisplayName') }
            if ([string]::IsNullOrEmpty($label)) { $label = [string](Get-ADTEntraProperty -InputObject $record -Name 'Id') }

            if ($isRegistered) {
                $registered += $label
            }
            else {
                $notRegistered += $label
                if ($isAdmin) { $adminsNotRegistered += $label }
            }
        }

        $total = $records.Count
        $percent = [math]::Round((($registered.Count * 100.0) / $total), 1)
        $baseDetail = [string]$registered.Count + ' of ' + [string]$total + ' users in the report have registered MFA (' + [string]$percent + '%); ' + [string]$notRegistered.Count + ' have not.'

        if ($percent -lt $script:ADTEntraMfaFloorPct) {
            $coverageWhy = 'Under ' + [string]$script:ADTEntraMfaFloorPct + '% registered means most of the tenant still signs in with a password alone, and switching on an MFA policy now would lock those users out at the next sign-in rather than protect them. The ' + [string]$script:ADTEntraMfaFloorPct + '% figure is ADT''s judgement threshold for "registration campaign needed before enforcement", not a Microsoft-published number. Note that the denominator is every user this report covers, including disabled and guest accounts, because the report carries no accountEnabled field.'
            $coverageFix = @(
                'Get-MgReportAuthenticationMethodUserRegistrationDetail -All | Where-Object { -not $_.IsMfaRegistered } | Select-Object UserPrincipalName, UserType | Export-Csv -Path .\mfa-not-registered.csv -NoTypeInformation',
                'Entra admin centre > Protection > Authentication methods > Registration campaign to nudge users onto the Authenticator app.',
                'Entra admin centre > Protection > Conditional Access > Policies > New policy from template > "Require multifactor authentication registration" (report-only first).'
            )
            Write-ADTResult -Check 'MFA registration coverage' -Status WARN -Detail $baseDetail -Why $coverageWhy -Fix $coverageFix -Data $records
        }
        else {
            Write-ADTResult -Check 'MFA registration coverage' -Status PASS -Detail $baseDetail -Data $records
        }

        if ($adminsNotRegistered.Count -gt 0) {
            $adminWhy = 'An administrator without a registered strong authentication method can be taken over with a password alone, and that password is the whole tenant. This is the single highest-value account class in the environment, and the report flags these accounts as admins itself via the isAdmin property.'
            $adminFix = @(
                'Get-MgReportAuthenticationMethodUserRegistrationDetail -All | Where-Object { $_.IsAdmin -and -not $_.IsMfaRegistered } | Select-Object UserPrincipalName, UserDisplayName',
                'Entra admin centre > Identity > Users > select the account > Authentication methods > Add authentication method.',
                'Have each named admin complete registration at https://aka.ms/mfasetup, then re-run this check.'
            )
            Write-ADTResult -Check 'Admin MFA registration' -Status FAIL `
                -Detail ([string]$adminsNotRegistered.Count + ' administrator(s) have NOT registered MFA: ' + (Format-ADTEntraList -Items $adminsNotRegistered)) `
                -Why $adminWhy -Fix $adminFix -Data $adminsNotRegistered
        }
        else {
            Write-ADTResult -Check 'Admin MFA registration' -Status PASS -Detail 'Every account the report flags as an administrator has registered MFA.'
        }
    }
    catch {
        Write-ADTResult -Check 'MFA registration' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Item 5: Entra Connect (cloud view)

function Invoke-ADTEntraSync {
    <#
        .SYNOPSIS
            What the cloud can see about directory synchronisation: whether it is on, when it
            last ran, and whether objects are failing to provision.
        .DESCRIPTION
            Verified on Microsoft Learn: the organization resource type (graph-rest-1.0) carries
            onPremisesSyncEnabled (nullable - null means never synced) and
            onPremisesLastSyncDateTime. Start-ADSyncSyncCycle -PolicyType Delta and the default
            30-minute scheduler interval are documented in "Microsoft Entra Connect Sync:
            Scheduler" and the ADSync PowerShell reference.
            No verifiable $filter expression for onPremisesProvisioningErrors could be found on
            Microsoft Learn, so this check does NOT guess one: it selects the property with the
            documented -Property parameter over a bounded page of users and counts client-side,
            saying so in the result.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Entra ID: Entra Connect (cloud view)'

        if (-not (Test-ADTEntraGraphConnected -Check 'Entra Connect (cloud view)')) { return }

        $organization = $null
        try {
            $organization = Get-ADTEntraOrganization
            if ($null -eq $organization) { throw 'Get-MgOrganization returned no organization object.' }
        }
        catch {
            Write-ADTEntraDegraded -Check 'Entra Connect (cloud view)' -ErrorRecord $_ -Licence 'Microsoft Entra ID (any edition)' -Scope 'Organization.Read.All'
            return
        }

        $syncEnabled = $false
        $syncRaw = Get-ADTEntraProperty -InputObject $organization -Name 'OnPremisesSyncEnabled'
        if ($null -ne $syncRaw) { $syncEnabled = [bool]$syncRaw }

        if (-not $syncEnabled) {
            Write-ADTResult -Check 'Directory synchronisation' -Status INFO `
                -Detail 'cloud-only tenant -- onPremisesSyncEnabled is not true, so no on-premises directory is being synchronised into this tenant.' `
                -Data $organization
            return
        }

        # ---- Sync freshness ----------------------------------------------------------------
        $lastSyncRaw = Get-ADTEntraProperty -InputObject $organization -Name 'OnPremisesLastSyncDateTime'

        $syncFixLines = @(
            'On the Entra Connect server: Import-Module ADSync; Get-ADSyncScheduler',
            'On the Entra Connect server: Start-ADSyncSyncCycle -PolicyType Delta',
            'On the Entra Connect server: Get-EventLog -LogName Application -Source "Directory Synchronization" -Newest 20',
            'Check the Microsoft Entra Connect Health blade, or the Synchronization Service Manager Operations tab, for a failing connector run.'
        )

        if ($null -eq $lastSyncRaw) {
            $neverWhy = 'Directory synchronisation is switched on for this tenant but Entra ID has never recorded a completed sync, so the on-premises directory and the cloud are not in step and no on-premises change is reaching users.'
            Write-ADTResult -Check 'Directory sync freshness' -Status WARN `
                -Detail 'onPremisesSyncEnabled is true but onPremisesLastSyncDateTime is empty.' `
                -Why $neverWhy -Fix $syncFixLines
        }
        else {
            $lastSync = $null
            try { $lastSync = [datetime]$lastSyncRaw } catch { $lastSync = $null }

            if ($null -eq $lastSync) {
                Write-ADTResult -Check 'Directory sync freshness' -Status WARN `
                    -Detail ('Could not read onPremisesLastSyncDateTime as a date: ' + [string]$lastSyncRaw) `
                    -Why 'Without a readable last-sync timestamp ADT cannot tell whether directory synchronisation is current.' `
                    -Fix $syncFixLines
            }
            else {
                $ageHours = 0
                try {
                    $span = New-TimeSpan -Start $lastSync.ToUniversalTime() -End ([datetime]::UtcNow)
                    $ageHours = [math]::Round($span.TotalHours, 1)
                }
                catch {
                    $ageHours = -1
                }

                $lastSyncText = $lastSync.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'

                if ($ageHours -lt 0) {
                    Write-ADTResult -Check 'Directory sync freshness' -Status INFO `
                        -Detail ('Last sync ' + $lastSyncText + '; age could not be calculated on this machine.') -Fix $syncFixLines
                }
                elseif ($ageHours -gt $script:ADTEntraSyncMaxAgeHours) {
                    $staleWhy = 'Microsoft Entra Connect runs a delta sync every 30 minutes by default, so a gap of ' + [string]$ageHours + ' hour(s) means the scheduler is disabled, the server is off, the connector is erroring, or the server is in staging mode. While it is stale, new starters do not appear in the cloud, leavers keep working, and password hash changes do not reach Entra ID.'
                    Write-ADTResult -Check 'Directory sync freshness' -Status WARN `
                        -Detail ('Last sync ' + $lastSyncText + ' -- ' + [string]$ageHours + ' hour(s) ago (threshold ' + [string]$script:ADTEntraSyncMaxAgeHours + 'h).') `
                        -Why $staleWhy -Fix $syncFixLines -Data $lastSync
                }
                else {
                    Write-ADTResult -Check 'Directory sync freshness' -Status PASS `
                        -Detail ('Last sync ' + $lastSyncText + ' -- ' + [string]$ageHours + ' hour(s) ago.') -Data $lastSync
                }
            }
        }

        # ---- Provisioning errors ------------------------------------------------------------
        # No $filter expression for onPremisesProvisioningErrors is documented on Microsoft Learn
        # for the v1.0 user resource, so ADT selects the property and counts locally over one
        # bounded page rather than guessing a filter that would silently return nothing.
        $provisioningFix = @(
            ('Get-MgUser -All -Property userPrincipalName,onPremisesProvisioningErrors | Where-Object { $_.OnPremisesProvisioningErrors.Count -gt 0 } | Select-Object UserPrincipalName -ExpandProperty OnPremisesProvisioningErrors'),
            'Entra admin centre > Identity > Hybrid management > Microsoft Entra Connect > Connect Sync, and review the sync errors report.',
            'On the Entra Connect server: open Synchronization Service Manager > Operations, select the failed Export run, and read the error per object.'
        )

        try {
            $sample = @(Get-MgUser -Property 'id', 'userPrincipalName', 'onPremisesSyncEnabled', 'onPremisesProvisioningErrors' -Top $script:ADTEntraUserSampleSize -ErrorAction Stop)

            $withErrors = @()
            foreach ($user in $sample) {
                $errors = @(Get-ADTEntraProperty -InputObject $user -Name 'OnPremisesProvisioningErrors')
                if ($errors.Count -eq 0) { continue }

                $upn = [string](Get-ADTEntraProperty -InputObject $user -Name 'UserPrincipalName')
                if ([string]::IsNullOrEmpty($upn)) { $upn = [string](Get-ADTEntraProperty -InputObject $user -Name 'Id') }

                $causes = @()
                foreach ($provisioningError in $errors) {
                    $category = [string](Get-ADTEntraProperty -InputObject $provisioningError -Name 'Category')
                    $property = [string](Get-ADTEntraProperty -InputObject $provisioningError -Name 'PropertyCausingError')
                    $piece = $category
                    if (-not [string]::IsNullOrEmpty($property)) { $piece = $piece + '/' + $property }
                    if (-not [string]::IsNullOrEmpty($piece)) { $causes += $piece }
                }

                $entry = $upn
                if ($causes.Count -gt 0) { $entry = $upn + ' (' + ($causes -join '; ') + ')' }
                $withErrors += $entry
            }

            $truncated = ($sample.Count -ge $script:ADTEntraUserSampleSize)
            $scopeText = 'across all ' + [string]$sample.Count + ' user object(s) read'
            if ($truncated) {
                $scopeText = 'in the first ' + [string]$sample.Count + ' user object(s); the page limit was reached, so there may be more'
            }

            if ($withErrors.Count -eq 0) {
                Write-ADTResult -Check 'Directory sync provisioning errors' -Status PASS `
                    -Detail ('No onPremisesProvisioningErrors found ' + $scopeText + '.')
            }
            else {
                $errorWhy = 'A provisioning error means Entra Connect exported an object and Entra ID rejected it, so that user is out of step with on-premises Active Directory - typically a duplicate proxyAddresses or userPrincipalName, an invalid character, or a value that collides with an existing cloud object. The user keeps whatever stale attributes the cloud already held until the source data is fixed on-premises.'
                Write-ADTResult -Check 'Directory sync provisioning errors' -Status WARN `
                    -Detail ([string]$withErrors.Count + ' user(s) with provisioning errors ' + $scopeText + ': ' + (Format-ADTEntraList -Items $withErrors)) `
                    -Why $errorWhy -Fix $provisioningFix -Data $withErrors
            }
        }
        catch {
            if ((Test-ADTEntraLicenceGate -ErrorRecord $_) -or (Test-ADTEntraAccessDenied -ErrorRecord $_)) {
                Write-ADTEntraDegraded -Check 'Directory sync provisioning errors' -ErrorRecord $_ -Licence 'Microsoft Entra ID (any edition)' -Scope 'Directory.Read.All'
            }
            else {
                $guidanceWhy = 'ADT could not read onPremisesProvisioningErrors from Graph on this run, and it will not guess a $filter expression that Microsoft does not document - a wrong filter returns an empty result and reads as a clean bill of health. Check it by hand instead.'
                Write-ADTResult -Check 'Directory sync provisioning errors' -Status INFO `
                    -Detail ('Not read automatically: ' + $_.Exception.Message) `
                    -Why $guidanceWhy -Fix $provisioningFix
            }
        }
    }
    catch {
        Write-ADTResult -Check 'Entra Connect (cloud view)' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Module registration

Register-ADTModule -Name 'Entra' -Group 'CLOUD' -Items @(
    @{ Label = 'Tenant overview';             Function = 'Invoke-ADTEntraOverview';   Requires = @('HasGraphModule'); Snapshot = $false }
    @{ Label = 'Privileged access';           Function = 'Invoke-ADTEntraPrivileged'; Requires = @('HasGraphModule'); Snapshot = $false }
    @{ Label = 'Security posture';            Function = 'Invoke-ADTEntraSecurity';   Requires = @('HasGraphModule'); Snapshot = $false }
    @{ Label = 'MFA registration';            Function = 'Invoke-ADTEntraMfa';        Requires = @('HasGraphModule'); Snapshot = $false }
    @{ Label = 'Entra Connect (cloud view)';  Function = 'Invoke-ADTEntraSync';       Requires = @('HasGraphModule'); Snapshot = $false }
)

#endregion
