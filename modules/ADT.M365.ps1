# ADT.M365.ps1 - Microsoft 365 posture: service health, Exchange Online, SharePoint/OneDrive/Teams.
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.

#region Private helpers

function Get-ADTM365CloudState {
    <#
        .SYNOPSIS
            Defensively read the Graph or EXO connection state off Get-ADTCloudContext.
            Never throws.
        .DESCRIPTION
            The contract documents Get-ADTCloudContext as returning a PSCustomObject shaped
            "Graph/Az/EXO -> connected?, tenant, account". This reads
            <Service>.Connected / .Tenant / .Account defensively (PSObject.Properties checks
            rather than direct dot-access) so a minor shape difference in CloudCommon
            degrades to "not connected" - a safe SKIP - instead of an exception.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Graph', 'EXO')]
        [string]$Service
    )

    $state = @{ Connected = $false; Tenant = ''; Account = '' }

    try {
        $cloudContextCmd = Get-Command -Name 'Get-ADTCloudContext' -ErrorAction SilentlyContinue
        if ($null -eq $cloudContextCmd) { return $state }

        $context = Get-ADTCloudContext
        if ($null -eq $context -or -not $context.PSObject.Properties[$Service]) { return $state }

        $serviceState = $context.$Service
        if ($null -eq $serviceState) { return $state }

        if ($serviceState.PSObject.Properties['Connected']) { $state.Connected = [bool]$serviceState.Connected }
        if ($serviceState.PSObject.Properties['Tenant'] -and $null -ne $serviceState.Tenant) { $state.Tenant = [string]$serviceState.Tenant }
        if ($serviceState.PSObject.Properties['Account'] -and $null -ne $serviceState.Account) { $state.Account = [string]$serviceState.Account }
    }
    catch {
        return @{ Connected = $false; Tenant = ''; Account = '' }
    }

    return $state
}

function Test-ADTM365Cmdlet {
    <#
        .SYNOPSIS
            Is a cmdlet actually loaded right now? Never throws.
        .DESCRIPTION
            Several cmdlets this file needs (service health, SharePoint admin settings) ship
            in Graph sub-modules that are NOT part of ADT default GraphModule prereq set
            (see ADT.Common.ps1 Get-ADTPrereqDefinition). HasGraphModule only proves
            Microsoft.Graph.Authentication is present, not that the specific sub-module is
            imported. Checking the cmdlet directly lets a missing sub-module degrade to a
            clean SKIP with install guidance instead of a hard error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {
        return ($null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue))
    }
    catch {
        return $false
    }
}

function Resolve-ADTM365DnsRecords {
    <#
        .SYNOPSIS
            Resolve-DnsName wrapper for MX/TXT lookups against live public DNS, run from this
            box (not through EXO). Returns a plain string array, empty array for "resolved but
            nothing found", or $null on failure. Never throws.
        .DESCRIPTION
            Resolve-DnsName ships in the DnsClient module (Windows 8/Server 2012+ client OS).
            -Type MX/TXT and record shape (NameExchange for MX, Strings for TXT) verified on
            Microsoft Learn (DnsClient module, Resolve-DnsName).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('MX', 'TXT')]
        [string]$Type
    )

    try {
        $records = @(Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop)
        if ($records.Count -eq 0) { return @() }

        $values = @()
        foreach ($record in $records) {
            if ($Type -eq 'MX' -and $record.PSObject.Properties['NameExchange'] -and -not [string]::IsNullOrEmpty($record.NameExchange)) {
                $values += ([string]$record.NameExchange).TrimEnd('.')
            }
            elseif ($Type -eq 'TXT' -and $record.PSObject.Properties['Strings'] -and $null -ne $record.Strings) {
                $values += (@($record.Strings) -join '')
            }
        }
        return $values
    }
    catch {
        return $null
    }
}

#endregion

#region Menu entries

function Invoke-ADTM365ServiceHealth {
    <#
        .SYNOPSIS
            Item 1: M365 service health - per-service status, open incidents, advisory count.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'M365 service health'

        $graphState = Get-ADTM365CloudState -Service 'Graph'
        if (-not $graphState.Connected) {
            Write-ADTResult -Check 'M365 service health' -Status 'SKIP' `
                -Detail 'not connected - run Connect Microsoft Graph first' `
                -Why 'Service health and message-center data come from Microsoft Graph, and ADT never auto-connects inside a check.' `
                -Fix @('Connect-ADTGraph')
            return
        }

        if (-not (Test-ADTM365Cmdlet -Name 'Get-MgServiceAnnouncementHealthOverview')) {
            Write-ADTResult -Check 'M365 service health' -Status 'SKIP' -Detail 'Microsoft.Graph.Devices.ServiceAnnouncement module is not loaded.' `
                -Why 'Get-MgServiceAnnouncementHealthOverview and Get-MgServiceAnnouncementIssue ship in the Microsoft.Graph.Devices.ServiceAnnouncement sub-module, which is not part of ADT default Graph module set (Authentication, Identity.DirectoryManagement, Identity.SignIns, Users, Groups, Applications, Reports).' `
                -Fix @('Install-Module Microsoft.Graph.Devices.ServiceAnnouncement -Scope CurrentUser -Force', 'Import-Module Microsoft.Graph.Devices.ServiceAnnouncement')
            return
        }

        # --- Per-service health overview ---------------------------------------------------
        # serviceHealth.status / serviceHealthIssue.status share the serviceHealthStatus enum
        # (serviceOperational, investigating, serviceDegradation, serviceInterruption, ...);
        # verified on Microsoft Learn (graph/api/resources/servicehealth,
        # graph/api/resources/servicehealthissue).
        try {
            $overview = @(Get-MgServiceAnnouncementHealthOverview -ErrorAction Stop)
            if ($overview.Count -eq 0) {
                Write-ADTResult -Check 'M365 service health overview' -Status 'INFO' -Detail 'No subscribed services were returned.'
            }
            else {
                $notOperational = @($overview | Where-Object { [string]$_.Status -ne 'serviceOperational' })
                if ($notOperational.Count -eq 0) {
                    Write-ADTResult -Check 'M365 service health overview' -Status 'PASS' -Detail ($overview.Count.ToString() + ' subscribed service(s), all serviceOperational.')
                }
                else {
                    foreach ($service in $notOperational) {
                        Write-ADTResult -Check ('Service health: ' + [string]$service.Service) -Status 'WARN' `
                            -Detail ('Status=' + [string]$service.Status) `
                            -Why 'Microsoft reports this service as not fully operational right now - this answers "is it Microsoft or is it us" before any local troubleshooting starts.' `
                            -Fix @('https://admin.microsoft.com/#/servicehealth  (Service health blade - filter to this service for the current post/timeline)')
                    }
                }
            }
        }
        catch {
            Write-ADTResult -Check 'M365 service health overview' -Status 'ERROR' -Detail ('Get-MgServiceAnnouncementHealthOverview failed: ' + $_.Exception.Message)
        }

        # --- Open issues: unresolved incidents (WARN each) + advisory count (INFO) ----------
        # classification: advisory|incident, isResolved: Boolean - both verified on Microsoft
        # Learn (graph/api/resources/servicehealthissue). -Filter uses the REST/OData property
        # name (isResolved), which is lowercase even though the PowerShell object exposes the
        # PascalCase IsResolved.
        try {
            $issues = $null
            try {
                $issues = @(Get-MgServiceAnnouncementIssue -Filter 'isResolved eq false' -All -ErrorAction Stop)
            }
            catch {
                # Server-side $filter support on this property was not independently proven
                # for every tenant/API surface; fall back to an unfiltered pull and filter
                # client-side rather than failing the whole check over a filter mismatch.
                $issues = @(Get-MgServiceAnnouncementIssue -All -ErrorAction Stop | Where-Object { -not $_.IsResolved })
            }

            $incidents = @($issues | Where-Object { [string]$_.Classification -eq 'incident' })
            $advisories = @($issues | Where-Object { [string]$_.Classification -eq 'advisory' })

            if ($incidents.Count -eq 0) {
                Write-ADTResult -Check 'M365 active incidents' -Status 'PASS' -Detail 'No unresolved incidents.'
            }
            else {
                foreach ($incident in $incidents) {
                    Write-ADTResult -Check ('Incident: ' + [string]$incident.Id) -Status 'WARN' `
                        -Detail ([string]$incident.Title + ' (affects ' + [string]$incident.Service + ', status=' + [string]$incident.Status + ')') `
                        -Why 'An open, unresolved Microsoft incident against a subscribed service - this is the "is it Microsoft or is it us" answer before spending time on local diagnosis.' `
                        -Fix @(('Microsoft 365 admin center: Health > Service health - open the issue with ID ' + [string]$incident.Id + ' for the live post and affected-user scope.'))
                }
            }

            Write-ADTResult -Check 'M365 open advisories' -Status 'INFO' -Detail ($advisories.Count.ToString() + ' unresolved advisory(ies).')
        }
        catch {
            Write-ADTResult -Check 'M365 open issues' -Status 'ERROR' -Detail ('Get-MgServiceAnnouncementIssue failed: ' + $_.Exception.Message)
        }
    }
    catch {
        Write-ADTResult -Check 'M365 service health' -Status 'ERROR' -Detail ('Unhandled exception: ' + $_.Exception.Message)
    }
}

function Invoke-ADTM365Exo {
    <#
        .SYNOPSIS
            Item 2: Exchange Online posture - org config flags, accepted domains vs live DNS,
            DKIM, connectors, recent message trace failures.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Exchange Online posture'

        $exoState = Get-ADTM365CloudState -Service 'EXO'
        if (-not $exoState.Connected) {
            Write-ADTResult -Check 'Exchange Online posture' -Status 'SKIP' `
                -Detail 'not connected - run Connect Exchange Online first' `
                -Why 'Every check in this item runs Exchange Online management cmdlets, and ADT never auto-connects inside a check.' `
                -Fix @('Connect-ADTEXO')
            return
        }

        # --- Org-wide red flags --------------------------------------------------------------
        # CORRECTION from the build spec: SmtpClientAuthenticationDisabled is verified on
        # Microsoft Learn as a Get-TransportConfig property, NOT Get-OrganizationConfig - the
        # official verification steps for SMTP AUTH literally run
        # "Get-TransportConfig | Format-List SmtpClientAuthenticationDisabled"
        # (learn.microsoft.com/dynamics365/business-central/admin-multi-tenant-smtp). Read
        # from Get-TransportConfig here rather than guessing it is also on
        # Get-OrganizationConfig. AuditDisabled IS confirmed on the OrganizationConfig
        # surface (Set-OrganizationConfig -AuditDisabled, exchangepowershell docs), so that
        # one still comes from Get-OrganizationConfig as specified.
        try {
            $transportConfig = Get-TransportConfig -ErrorAction Stop
            if ($transportConfig.SmtpClientAuthenticationDisabled -eq $false) {
                Write-ADTResult -Check 'SMTP AUTH (legacy client submission)' -Status 'WARN' -Detail 'SmtpClientAuthenticationDisabled=False (enabled org-wide)' `
                    -Why 'Org-wide legacy SMTP AUTH is a well-known password-spray target and is disabled by default in new tenants. Leaving it on for the whole org - rather than per-mailbox where it is actually needed - widens the attack surface unnecessarily.' `
                    -Fix @('Set-TransportConfig -SmtpClientAuthenticationDisabled $true', 'Then re-enable only for mailboxes that still need it: Set-CASMailbox -Identity <mailbox> -SmtpClientAuthenticationDisabled $false')
            }
            else {
                Write-ADTResult -Check 'SMTP AUTH (legacy client submission)' -Status 'PASS' -Detail 'SmtpClientAuthenticationDisabled=True (disabled org-wide)'
            }
        }
        catch {
            Write-ADTResult -Check 'SMTP AUTH (legacy client submission)' -Status 'ERROR' -Detail ('Get-TransportConfig failed: ' + $_.Exception.Message)
        }

        try {
            $orgConfig = Get-OrganizationConfig -ErrorAction Stop
            if ($orgConfig.AuditDisabled -eq $true) {
                Write-ADTResult -Check 'Unified audit logging' -Status 'FAIL' -Detail 'AuditDisabled=True' `
                    -Why 'With auditing disabled org-wide, mailbox and admin actions are not being logged - there is no trail to investigate a compromise or answer a compliance question after the fact.' `
                    -Fix @('Set-OrganizationConfig -AuditDisabled $false')
            }
            else {
                Write-ADTResult -Check 'Unified audit logging' -Status 'PASS' -Detail 'AuditDisabled=False'
            }
        }
        catch {
            Write-ADTResult -Check 'Unified audit logging' -Status 'ERROR' -Detail ('Get-OrganizationConfig failed: ' + $_.Exception.Message)
        }

        # --- Accepted domains cross-checked against live public DNS -------------------------
        $acceptedDomains = @()
        try {
            $acceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop)
        }
        catch {
            Write-ADTResult -Check 'Get-AcceptedDomain' -Status 'ERROR' -Detail ('Failed: ' + $_.Exception.Message)
        }

        if ($acceptedDomains.Count -eq 0) {
            Write-ADTResult -Check 'Accepted domains' -Status 'INFO' -Detail 'No accepted domains returned.'
        }

        foreach ($domain in $acceptedDomains) {
            $domainName = [string]$domain.DomainName
            if ([string]::IsNullOrEmpty($domainName)) { continue }

            Write-ADTNote -Text ('Checking DNS for accepted domain ' + $domainName + ' (' + [string]$domain.DomainType + ') ...')

            # MX
            $mxValues = Resolve-ADTM365DnsRecords -Name $domainName -Type 'MX'
            if ($null -eq $mxValues) {
                Write-ADTResult -Check ('MX record: ' + $domainName) -Status 'ERROR' -Detail 'Resolve-DnsName failed.' `
                    -Fix @(('Resolve-DnsName -Name ' + $domainName + ' -Type MX'))
            }
            elseif ($mxValues.Count -eq 0) {
                Write-ADTResult -Check ('MX record: ' + $domainName) -Status 'WARN' -Detail 'No MX record found.' `
                    -Why 'An accepted domain with no MX record cannot receive inbound mail at all.' `
                    -Fix @(('Resolve-DnsName -Name ' + $domainName + ' -Type MX'))
            }
            else {
                $mxHost = $mxValues[0]
                if ($mxHost -match '(?i)\.mail\.protection\.outlook\.com$') {
                    Write-ADTResult -Check ('MX record: ' + $domainName) -Status 'PASS' -Detail $mxHost
                }
                else {
                    Write-ADTResult -Check ('MX record: ' + $domainName) -Status 'INFO' -Detail ('MX points to ' + $mxHost + ' (not *.mail.protection.outlook.com)') `
                        -Why 'This does not necessarily mean mail is broken - it could be a gateway (spam filter, hybrid on-prem server, third-party security product) sitting in front of Exchange Online on purpose. Confirm the actual mail path with the client rather than assuming a misconfiguration.'
                }
            }

            # SPF
            $spfValues = Resolve-ADTM365DnsRecords -Name $domainName -Type 'TXT'
            $spfRecord = $null
            if ($null -ne $spfValues) {
                $spfRecord = $spfValues | Where-Object { $_ -match '(?i)^v=spf1' } | Select-Object -First 1
            }
            if ($null -eq $spfValues) {
                Write-ADTResult -Check ('SPF: ' + $domainName) -Status 'ERROR' -Detail 'Resolve-DnsName failed.' -Fix @(('Resolve-DnsName -Name ' + $domainName + ' -Type TXT'))
            }
            elseif ($null -eq $spfRecord) {
                Write-ADTResult -Check ('SPF: ' + $domainName) -Status 'WARN' -Detail 'No v=spf1 TXT record found.' `
                    -Why 'Without SPF, receiving mail systems have no authorised-sender list to check for this domain, which weakens anti-spoofing and can hurt deliverability.' `
                    -Fix @(('Publish a TXT record on ' + $domainName + ':  v=spf1 include:spf.protection.outlook.com -all'))
            }
            elseif ($spfRecord -notmatch '(?i)include:spf\.protection\.outlook\.com') {
                Write-ADTResult -Check ('SPF: ' + $domainName) -Status 'WARN' -Detail $spfRecord `
                    -Why 'This domain sends mail through Exchange Online but its SPF record does not include Microsoft sending IPs, so legitimately-sent mail can fail SPF at the receiving end.' `
                    -Fix @(('Add include:spf.protection.outlook.com to the existing SPF TXT record on ' + $domainName + '.'))
            }
            else {
                Write-ADTResult -Check ('SPF: ' + $domainName) -Status 'PASS' -Detail $spfRecord
            }

            # DMARC
            $dmarcName = '_dmarc.' + $domainName
            $dmarcValues = Resolve-ADTM365DnsRecords -Name $dmarcName -Type 'TXT'
            $dmarcRecord = $null
            if ($null -ne $dmarcValues) {
                $dmarcRecord = $dmarcValues | Where-Object { $_ -match '(?i)^v=DMARC1' } | Select-Object -First 1
            }
            if ($null -eq $dmarcValues) {
                Write-ADTResult -Check ('DMARC: ' + $domainName) -Status 'ERROR' -Detail 'Resolve-DnsName failed.' -Fix @(('Resolve-DnsName -Name ' + $dmarcName + ' -Type TXT'))
            }
            elseif ($null -eq $dmarcRecord) {
                Write-ADTResult -Check ('DMARC: ' + $domainName) -Status 'WARN' -Detail ('No DMARC record found at ' + $dmarcName + '.') `
                    -Why 'Without DMARC, this domain gives receiving mail systems no policy for what to do with mail that fails SPF/DKIM, and the domain owner gets no aggregate reports of spoofing attempts.' `
                    -Fix @(('Publish a TXT record on ' + $dmarcName + ':  v=DMARC1; p=none; rua=mailto:dmarc-reports@' + $domainName + '   (start at p=none to observe before enforcing)'))
            }
            else {
                $dmarcDetail = $dmarcRecord
                if ($dmarcRecord -match '(?i)p=none') {
                    Write-ADTResult -Check ('DMARC: ' + $domainName) -Status 'INFO' -Detail $dmarcDetail `
                        -Why 'p=none means DMARC is only observing (aggregate reports) and not instructing receivers to quarantine or reject mail that fails - worth confirming with the client whether this is a deliberate monitoring phase or something that was never moved to enforcement.'
                }
                else {
                    Write-ADTResult -Check ('DMARC: ' + $domainName) -Status 'PASS' -Detail $dmarcDetail
                }
            }
        }

        # --- DKIM -----------------------------------------------------------------------------
        try {
            $dkimConfigs = @(Get-DkimSigningConfig -ErrorAction Stop)
            foreach ($dkim in $dkimConfigs) {
                # UNVERIFIED: a distinct "Domain" property on the Get-DkimSigningConfig output
                # object was not directly confirmed on Microsoft Learn this session (only
                # -Identity <domain> usage in examples). Read defensively: prefer .Domain if
                # present, otherwise fall back to .Identity, which the documented examples show
                # equals the domain name for custom domains.
                $dkimDomain = $null
                if ($dkim.PSObject.Properties['Domain'] -and -not [string]::IsNullOrEmpty([string]$dkim.Domain)) {
                    $dkimDomain = [string]$dkim.Domain
                }
                else {
                    $dkimDomain = [string]$dkim.Identity
                }

                if ($dkim.Enabled -eq $true) {
                    Write-ADTResult -Check ('DKIM: ' + $dkimDomain) -Status 'PASS' -Detail 'Enabled=True'
                }
                else {
                    $cname1 = [string]$dkim.Selector1CNAME
                    $cname2 = [string]$dkim.Selector2CNAME
                    Write-ADTResult -Check ('DKIM: ' + $dkimDomain) -Status 'WARN' -Detail ('Enabled=False (Status=' + [string]$dkim.Status + ')') `
                        -Why 'Without DKIM signing, outbound mail from this domain has one less authentication signal, which weakens DMARC alignment and makes spoofed mail claiming to be from this domain harder for recipients to reject.' `
                        -Fix @(
                            ('Publish CNAME  selector1._domainkey.' + $dkimDomain + '  ->  ' + $cname1),
                            ('Publish CNAME  selector2._domainkey.' + $dkimDomain + '  ->  ' + $cname2),
                            ('Then enable: Set-DkimSigningConfig -Identity ' + [string]$dkim.Identity + ' -Enabled $true')
                        )
                }
            }
        }
        catch {
            Write-ADTResult -Check 'Get-DkimSigningConfig' -Status 'ERROR' -Detail ('Failed: ' + $_.Exception.Message)
        }

        # --- Connectors -------------------------------------------------------------------
        try {
            $inboundConnectors = @(Get-InboundConnector -ErrorAction Stop)
            if ($inboundConnectors.Count -eq 0) {
                Write-ADTResult -Check 'Inbound connectors' -Status 'INFO' -Detail '0 inbound connectors configured.'
            }
            else {
                $inboundNames = (@(($inboundConnectors | ForEach-Object { [string]$_.Name + ' (' + [string]$_.ConnectorType + ')' }))) -join ', '
                Write-ADTResult -Check 'Inbound connectors' -Status 'INFO' -Detail ($inboundConnectors.Count.ToString() + ' configured: ' + $inboundNames)
            }
        }
        catch {
            Write-ADTResult -Check 'Inbound connectors' -Status 'ERROR' -Detail ('Get-InboundConnector failed: ' + $_.Exception.Message)
        }

        try {
            $outboundConnectors = @(Get-OutboundConnector -ErrorAction Stop)
            if ($outboundConnectors.Count -eq 0) {
                Write-ADTResult -Check 'Outbound connectors' -Status 'INFO' -Detail '0 outbound connectors configured.'
            }
            else {
                foreach ($connector in $outboundConnectors) {
                    $tlsText = [string]$connector.TlsSettings
                    if ([string]::IsNullOrEmpty($tlsText)) {
                        # UNVERIFIED: no documented TlsAuthLevel value on New-/Set-OutboundConnector
                        # (EncryptionOnly, CertificateValidation, DomainValidation) means "TLS
                        # forced off" - an unset TlsSettings means opportunistic TLS, which
                        # Microsoft documents as its own default and as sufficient for most
                        # organisations (learn.microsoft.com/purview/exchange-online-uses-tls-to-
                        # secure-email-connections). The build spec asked to WARN when this
                        # property verifies a "forced off" state; that state does not exist in
                        # the documented enum, so this stays INFO rather than guessing a WARN
                        # condition that cannot be confirmed.
                        Write-ADTResult -Check ('Outbound connector: ' + [string]$connector.Name) -Status 'INFO' `
                            -Detail ('Type=' + [string]$connector.ConnectorType + ' TlsSettings=(not set - opportunistic TLS, the documented default)')
                    }
                    else {
                        Write-ADTResult -Check ('Outbound connector: ' + [string]$connector.Name) -Status 'INFO' `
                            -Detail ('Type=' + [string]$connector.ConnectorType + ' TlsSettings=' + $tlsText)
                    }
                }
            }
        }
        catch {
            Write-ADTResult -Check 'Outbound connectors' -Status 'ERROR' -Detail ('Get-OutboundConnector failed: ' + $_.Exception.Message)
        }

        # --- Recent delivery failures (last 24h) -------------------------------------------
        # Get-MessageTraceV2 confirmed as the CURRENT cmdlet on Microsoft Learn (Message trace
        # in the Exchange admin center / Get-MessageTraceV2 reference); the legacy
        # Get-MessageTrace is deliberately not called. Requires ExchangeOnlineManagement
        # module 3.7.0+.
        if (-not (Test-ADTM365Cmdlet -Name 'Get-MessageTraceV2')) {
            Write-ADTResult -Check 'Recent message failures' -Status 'SKIP' -Detail 'Get-MessageTraceV2 is not available.' `
                -Why 'Get-MessageTraceV2 needs ExchangeOnlineManagement module version 3.7.0 or later; an older module version only has the legacy Get-MessageTrace cmdlet, which this file deliberately does not call.' `
                -Fix @('Update-Module ExchangeOnlineManagement -Force')
        }
        else {
            try {
                $traceEnd = Get-Date
                $traceStart = $traceEnd.AddHours(-24)
                $failures = @(Get-MessageTraceV2 -StartDate $traceStart -EndDate $traceEnd -Status 'Failed' -ResultSize 5000 -ErrorAction Stop)

                if ($failures.Count -eq 0) {
                    Write-ADTResult -Check 'Recent message failures (24h)' -Status 'PASS' -Detail '0 failed messages in the last 24 hours.'
                }
                else {
                    $topRecipients = (@(($failures | Group-Object -Property RecipientAddress | Sort-Object -Property Count -Descending | Select-Object -First 5 | ForEach-Object { [string]$_.Name + ' (' + [string]$_.Count + ')' }))) -join ', '
                    $topSenders = (@(($failures | Group-Object -Property SenderAddress | Sort-Object -Property Count -Descending | Select-Object -First 5 | ForEach-Object { [string]$_.Name + ' (' + [string]$_.Count + ')' }))) -join ', '
                    $failDetail = ('count=' + $failures.Count.ToString() + ' | top recipients: ' + $topRecipients + ' | top senders: ' + $topSenders)

                    if ($failures.Count -gt 50) {
                        Write-ADTResult -Check 'Recent message failures (24h)' -Status 'WARN' -Detail $failDetail `
                            -Why 'More than 50 failed message deliveries in 24 hours is a meaningful volume - worth checking whether one sender/recipient pair or one specific failure reason dominates.' `
                            -Fix @('Get-MessageTraceV2 -StartDate (Get-Date).AddHours(-24) -EndDate (Get-Date) -Status Failed | Get-MessageTraceDetailV2')
                    }
                    else {
                        Write-ADTResult -Check 'Recent message failures (24h)' -Status 'INFO' -Detail $failDetail
                    }
                }
            }
            catch {
                Write-ADTResult -Check 'Recent message failures (24h)' -Status 'ERROR' -Detail ('Get-MessageTraceV2 failed: ' + $_.Exception.Message)
            }
        }
    }
    catch {
        Write-ADTResult -Check 'Exchange Online posture' -Status 'ERROR' -Detail ('Unhandled exception: ' + $_.Exception.Message)
    }
}

function Invoke-ADTM365Spo {
    <#
        .SYNOPSIS
            Item 3: SharePoint / OneDrive / Teams posture - tenant sharing capability, storage
            usage guidance, Teams pointer.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'SharePoint / OneDrive / Teams posture'

        $graphState = Get-ADTM365CloudState -Service 'Graph'
        if (-not $graphState.Connected) {
            Write-ADTResult -Check 'SharePoint / OneDrive / Teams posture' -Status 'SKIP' `
                -Detail 'not connected - run Connect Microsoft Graph first' `
                -Why 'Tenant sharing settings come from Microsoft Graph, and ADT never auto-connects inside a check.' `
                -Fix @('Connect-ADTGraph')
            return
        }

        # --- Tenant-level sharing capability -------------------------------------------------
        # Get-MgAdminSharepointSetting and its SharingCapability property (values: disabled,
        # externalUserSharingOnly, externalUserAndGuestSharing, existingExternalUserSharingOnly)
        # verified on Microsoft Learn (Microsoft.Graph.Sites module,
        # graph/api/resources/sharepointsettings).
        if (-not (Test-ADTM365Cmdlet -Name 'Get-MgAdminSharepointSetting')) {
            Write-ADTResult -Check 'SharePoint / OneDrive sharing capability' -Status 'SKIP' -Detail 'Microsoft.Graph.Sites module is not loaded.' `
                -Why 'Get-MgAdminSharepointSetting ships in the Microsoft.Graph.Sites sub-module, which is not part of ADT default Graph module set.' `
                -Fix @('Install-Module Microsoft.Graph.Sites -Scope CurrentUser -Force', 'Import-Module Microsoft.Graph.Sites')
        }
        else {
            try {
                $spoSettings = Get-MgAdminSharepointSetting -ErrorAction Stop
                $sharingCapability = [string]$spoSettings.SharingCapability

                if ($sharingCapability -eq 'externalUserAndGuestSharing') {
                    Write-ADTResult -Check 'SharePoint / OneDrive sharing capability' -Status 'WARN' -Detail ('SharingCapability=' + $sharingCapability) `
                        -Why 'This is the broadest tenant-wide sharing level - anyone with a link can open content without signing in or being verified as a guest. Worth confirming with the client this is a deliberate business decision and not a default nobody has revisited.' `
                        -Fix @('Review with the client, then tighten if appropriate: Update-MgAdminSharepointSetting -SharingCapability ExternalUserSharingOnly')
                }
                else {
                    Write-ADTResult -Check 'SharePoint / OneDrive sharing capability' -Status 'INFO' -Detail ('SharingCapability=' + $sharingCapability)
                }
            }
            catch {
                Write-ADTResult -Check 'SharePoint / OneDrive sharing capability' -Status 'ERROR' -Detail ('Get-MgAdminSharepointSetting failed: ' + $_.Exception.Message)
            }
        }

        # --- Storage usage: guidance only, not pulled --------------------------------------
        # Verified on Microsoft Learn: Get-MgReportSharePointSiteUsageStorage requires a
        # mandatory -OutFile <path> (it streams a CSV to disk, it does not return objects),
        # and Get-MgReportSharePointSiteUsageDetail's documented Outputs type is opaque
        # (System.Boolean in the reference page, consistent with the same OutFile/PassThru
        # pattern). Per the build spec, when a report cmdlet does not verify as returning
        # parseable in-memory data, emit guidance instead of adding a write-to-disk-then-
        # reparse path for a v1 light check.
        Write-ADTResult -Check 'SharePoint / OneDrive storage usage' -Status 'INFO' `
            -Detail 'Not pulled by ADT - see guidance.' `
            -Why 'Get-MgReportSharePointSiteUsageStorage/-Detail write their CSV to a mandatory -OutFile path rather than returning objects ADT can read in memory; that extra write-and-reparse surface was not judged worth it for a v1 light check.' `
            -Fix @('Microsoft 365 admin center: Reports > Usage > SharePoint sites / OneDrive', 'Or from PowerShell: Get-MgReportSharePointSiteUsageDetail -Period D7 -OutFile <path.csv>  then inspect the CSV')

        # --- Teams ---------------------------------------------------------------------------
        Write-ADTResult -Check 'Teams' -Status 'INFO' `
            -Detail 'Service health is covered by the M365 service health item.' `
            -Why 'Deep Teams policy work (meeting policies, calling, voice routing) needs the MicrosoftTeams module, which is out of v1 scope for ADT.'
    }
    catch {
        Write-ADTResult -Check 'SharePoint / OneDrive / Teams posture' -Status 'ERROR' -Detail ('Unhandled exception: ' + $_.Exception.Message)
    }
}

#endregion

Register-ADTModule -Name 'M365' -Group 'CLOUD' -Items @(
    @{ Label = 'M365 service health';                    Function = 'Invoke-ADTM365ServiceHealth'; Requires = @('HasGraphModule'); Snapshot = $false }
    @{ Label = 'Exchange Online posture';                Function = 'Invoke-ADTM365Exo';            Requires = @('HasEXOModule');   Snapshot = $false }
    @{ Label = 'SharePoint / OneDrive / Teams posture';  Function = 'Invoke-ADTM365Spo';            Requires = @('HasGraphModule'); Snapshot = $false }
)
