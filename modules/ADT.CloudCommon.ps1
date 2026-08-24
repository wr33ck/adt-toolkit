# ADT.CloudCommon.ps1 - cloud connection framework for Microsoft Graph, Azure and Exchange Online.
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.

#region Shared state

# THE read-only Graph scope set for the whole toolkit. Every cloud module authenticates through
# Connect-ADTGraph, so this one list is the entire Graph permission surface ADT ever asks for.
# Never add a *.ReadWrite.* scope here.
#   Organization.Read.All              tenant object (Get-MgOrganization, Get-MgSubscribedSku)
#   Directory.Read.All                 domains, directory roles and role members
#   Policy.Read.All                    Conditional Access + security defaults policies
#   Reports.Read.All                   usage/activity reports consumed by the M365 module
#   AuditLog.Read.All                  sign-in logs AND the authentication method registration report
#   UserAuthenticationMethod.Read.All  per-user registered authentication methods
#   SecurityEvents.Read.All            Defender/secure score style security alerts
#   ServiceHealth.Read.All             service health overviews and issues  (added for M365 module)
#   ServiceMessage.Read.All            message centre service announcements  (added for M365 module)
# The last two are additions beyond the contract v1.0 list; both are read-only delegated
# permissions documented on the Microsoft Graph permissions reference and are the only
# permissions the service communications API accepts, so the M365 service-health checks
# cannot be written without them.
if ($null -eq $script:ADTCloudGraphScopes) {
    $script:ADTCloudGraphScopes = @(
        'Organization.Read.All',
        'Directory.Read.All',
        'Policy.Read.All',
        'Reports.Read.All',
        'AuditLog.Read.All',
        'UserAuthenticationMethod.Read.All',
        'SecurityEvents.Read.All',
        'ServiceHealth.Read.All',
        'ServiceMessage.Read.All'
    )
}

#endregion

#region Private helpers

function Get-ADTCloudProperty {
    <#
        .SYNOPSIS
            Read a property from an object without throwing when it is absent.
        .DESCRIPTION
            The Graph, Az and Exchange Online context objects all change shape between module
            versions. Degrading to $null beats an exception that kills the whole check.
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

function ConvertTo-ADTCloudText {
    <#
        .SYNOPSIS
            Flatten a context value (string, GUID, or a nested object with an Id) to display text.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $false)]
        [string]$EmptyText = ''
    )

    if ($null -eq $Value) { return $EmptyText }

    try {
        if ($Value -is [string]) {
            if ([string]::IsNullOrEmpty($Value)) { return $EmptyText }
            return $Value
        }

        $inner = Get-ADTCloudProperty -InputObject $Value -Name 'Id'
        if ($null -ne $inner) {
            $innerText = [string]$inner
            if (-not [string]::IsNullOrEmpty($innerText)) { return $innerText }
        }

        $text = [string]$Value
        if ([string]::IsNullOrEmpty($text)) { return $EmptyText }
        return $text
    }
    catch {
        return $EmptyText
    }
}

function Test-ADTCloudCommand {
    <#
        .SYNOPSIS
            Is a cmdlet importable in this session? Never throws.
        .DESCRIPTION
            Get-Command auto-loads the owning module from PSModulePath, so this doubles as
            "is the module installed and loadable".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {
        $command = Get-Command -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $command) { return $true }
    }
    catch {
        return $false
    }
    return $false
}

function Read-ADTCloudTenant {
    <#
        .SYNOPSIS
            Return the tenant to connect to, prompting when one was not supplied.
        .DESCRIPTION
            An empty return value means "let the identity platform pick the home tenant of the
            account that signs in", which is the correct behaviour for a single-tenant engineer.
            Never prompts when $script:ADTNonInteractive is set, so it can never block a run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Supplied,

        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    if (-not [string]::IsNullOrEmpty($Supplied)) { return $Supplied.Trim() }

    if ($script:ADTNonInteractive) {
        Write-ADTNote -Text ('No tenant supplied for ' + $ServiceName + '; using the home tenant of the signing-in account.')
        return ''
    }

    $answer = Read-Host -Prompt ('Tenant for ' + $ServiceName + ' (domain or GUID, blank = home tenant)')
    if ($null -eq $answer) { return '' }
    return $answer.Trim()
}

function Get-ADTCloudGraphContext {
    <#
        .SYNOPSIS
            Current Microsoft Graph session context, or $null. Never throws.
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-ADTCloudCommand -Name 'Get-MgContext')) { return $null }

    try {
        return Get-MgContext -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Get-ADTCloudAzContext {
    <#
        .SYNOPSIS
            Current Azure Resource Manager context, or $null. Never throws.
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-ADTCloudCommand -Name 'Get-AzContext')) { return $null }

    try {
        return Get-AzContext -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Get-ADTCloudExoConnection {
    <#
        .SYNOPSIS
            Current Exchange Online REST connection, or $null. Never throws.
        .DESCRIPTION
            Get-ConnectionInformation is the documented way to enumerate REST-based Exchange
            Online connections and exists only in module version 3.0.0 and later; Microsoft
            states it is the replacement for Get-PSSession, which does not return REST
            connections. Older v2 module builds still used remote PowerShell sessions with the
            Microsoft.Exchange configuration name, so that is the documented fallback.
    #>
    [CmdletBinding()]
    param()

    if (Test-ADTCloudCommand -Name 'Get-ConnectionInformation') {
        try {
            $connections = @(Get-ConnectionInformation -ErrorAction Stop)
            if ($connections.Count -eq 0) { return $null }

            $connected = @($connections | Where-Object { ([string](Get-ADTCloudProperty -InputObject $_ -Name 'State')) -eq 'Connected' })
            if ($connected.Count -gt 0) { return $connected[0] }
            return $connections[0]
        }
        catch {
            return $null
        }
    }

    try {
        $sessions = @(Get-PSSession -ErrorAction SilentlyContinue |
                      Where-Object {
                          ([string]$_.ConfigurationName) -eq 'Microsoft.Exchange' -and
                          ([string]$_.State) -eq 'Opened'
                      })
        if ($sessions.Count -gt 0) { return $sessions[0] }
    }
    catch {
        return $null
    }
    return $null
}

function Write-ADTCloudModuleMissing {
    <#
        .SYNOPSIS
            One consistent FAIL result for "the module this connect needs is not installed".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Check,

        [Parameter(Mandatory = $true)]
        [string]$CmdletName,

        [Parameter(Mandatory = $true)]
        [string]$PrereqName
    )

    $hint = ''
    try {
        $status = Get-ADTPrereqStatus -Name $PrereqName | Select-Object -First 1
        if ($null -ne $status) { $hint = [string]$status.InstallHint }
    }
    catch {
        $hint = ''
    }

    $fixLines = @(('Install-ADTPrereq -Name ' + $PrereqName))
    if (-not [string]::IsNullOrEmpty($hint)) { $fixLines += $hint }

    $why = 'ADT will not fabricate a cloud session; ' + $CmdletName + ' is not present in this PowerShell session, so there is nothing to connect with.'
    Write-ADTResult -Check $Check -Status FAIL -Detail ($CmdletName + ' is not available on this machine.') -Why $why -Fix $fixLines
}

#endregion

#region Connect: Microsoft Graph

function Connect-ADTGraph {
    <#
        .SYNOPSIS
            Interactive, read-only Microsoft Graph sign-in for the ADT cloud modules.
        .DESCRIPTION
            One of the three sanctioned interactive-authentication paths in ADT. Requests only
            the scopes in $script:ADTCloudGraphScopes, all of which are read scopes.
            Verified on Microsoft Learn (Microsoft.Graph.Authentication, graph-powershell-1.0):
            Connect-MgGraph -Scopes <string[]> -TenantId <string> -UseDeviceCode -NoWelcome.
        .PARAMETER TenantId
            Tenant domain or GUID. Prompted for when omitted; blank means the home tenant.
        .PARAMETER DeviceCode
            Use device code flow instead of an interactive browser, for browserless jump boxes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$TenantId,

        [Parameter(Mandatory = $false)]
        [switch]$DeviceCode
    )

    $checkName = 'Connect Microsoft Graph'

    try {
        Write-ADTSection -Title 'Connect Microsoft Graph'

        if (-not (Test-ADTCloudCommand -Name 'Connect-MgGraph')) {
            Write-ADTCloudModuleMissing -Check $checkName -CmdletName 'Connect-MgGraph' -PrereqName 'GraphModule'
            return
        }

        # Honesty about token storage. ADT itself writes no credential material anywhere, but
        # Microsoft documents that the Graph PowerShell SDK caches its own token so that sign-in
        # persists across PowerShell sessions when the context scope is CurrentUser (the default).
        Write-ADTNote -Text 'ADT never writes tokens or credentials to disk.'
        Write-ADTNote -Text 'The Graph PowerShell SDK does cache its own token under your user profile so sign-in survives a new PowerShell session.'
        Write-ADTNote -Text 'On a shared jump box, run "Disconnect all cloud sessions" (or Disconnect-MgGraph) before you hand the machine back.'

        $tenant = Read-ADTCloudTenant -Supplied $TenantId -ServiceName 'Microsoft Graph'

        $connectArgs = @{
            Scopes      = $script:ADTCloudGraphScopes
            NoWelcome   = $true
            ErrorAction = 'Stop'
        }
        if (-not [string]::IsNullOrEmpty($tenant)) { $connectArgs['TenantId'] = $tenant }
        if ($DeviceCode) {
            $connectArgs['UseDeviceCode'] = $true
            Write-ADTNote -Text 'Device code flow: a URL and a one-time code will be printed. Complete sign-in in a browser on any other machine.'
        }

        Write-ADTNote -Text ('Requesting ' + [string]@($script:ADTCloudGraphScopes).Count + ' read-only scope(s).')
        $null = Connect-MgGraph @connectArgs

        $context = Get-ADTCloudGraphContext
        if ($null -eq $context) {
            $noCtxWhy = 'Connect-MgGraph returned without error but Get-MgContext reports no session, so no Graph check would work.'
            $noCtxFix = @(
                'Get-MgContext',
                ('Connect-MgGraph -Scopes ' + ($script:ADTCloudGraphScopes -join ',')),
                'Connect-ADTGraph -DeviceCode   (if the interactive browser could not complete)'
            )
            Write-ADTResult -Check $checkName -Status FAIL -Detail 'No Graph context after connect.' -Why $noCtxWhy -Fix $noCtxFix
            return
        }

        $tenantText  = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $context -Name 'TenantId')  -EmptyText 'unknown'
        $accountText = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $context -Name 'Account')   -EmptyText 'unknown'
        $appText     = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $context -Name 'AppName')   -EmptyText 'unknown'
        $authText    = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $context -Name 'AuthType')  -EmptyText 'unknown'
        $granted     = @(Get-ADTCloudProperty -InputObject $context -Name 'Scopes')

        Write-ADTNote -Text ('Tenant  : ' + $tenantText)
        Write-ADTNote -Text ('Account : ' + $accountText)
        Write-ADTNote -Text ('App     : ' + $appText + ' (' + $authText + ')')
        if ($granted.Count -eq 0) {
            Write-ADTNote -Text 'Scopes  : none reported'
        }
        else {
            Write-ADTNote -Text ('Scopes  : ' + (($granted | Sort-Object) -join ', '))
        }

        # A consented scope set can legitimately be smaller than the requested set, which is
        # exactly why the Entra and M365 checks emit SKIP rather than ERROR on a 403.
        $missing = @()
        foreach ($wanted in $script:ADTCloudGraphScopes) {
            if (-not ($granted -contains $wanted)) { $missing += $wanted }
        }

        if ($missing.Count -gt 0) {
            $partialWhy = 'The signed-in account consented to fewer scopes than ADT asked for. Checks needing a missing scope will fail with a 403 and are reported as SKIP, not as a broken tenant.'
            $partialFix = @(
                ('Ask a Global Administrator to grant admin consent for: ' + ($missing -join ', ')),
                'Get-MgContext | Select-Object -ExpandProperty Scopes'
            )
            Write-ADTResult -Check $checkName -Status PASS `
                -Detail ('Connected to tenant ' + $tenantText + ' as ' + $accountText + ' with ' + [string]$granted.Count + ' scope(s).') `
                -Data $context
            Write-ADTResult -Check 'Graph scope coverage' -Status WARN `
                -Detail ([string]$missing.Count + ' requested scope(s) were not granted: ' + ($missing -join ', ')) `
                -Why $partialWhy -Fix $partialFix -Data $missing
        }
        else {
            Write-ADTResult -Check $checkName -Status PASS `
                -Detail ('Connected to tenant ' + $tenantText + ' as ' + $accountText + '; all ' + [string]@($script:ADTCloudGraphScopes).Count + ' read-only scope(s) granted.') `
                -Data $context
        }
    }
    catch {
        $errFix = @(
            'Connect-ADTGraph -DeviceCode   (browserless or blocked-browser jump box)',
            'Connect-ADTGraph -TenantId contoso.onmicrosoft.com   (guest or multi-tenant account)',
            'Test-NetConnection login.microsoftonline.com -Port 443'
        )
        Write-ADTResult -Check $checkName -Status ERROR -Detail $_.Exception.Message -Fix $errFix
    }
}

#endregion

#region Connect: Azure

function Connect-ADTAzure {
    <#
        .SYNOPSIS
            Interactive Azure Resource Manager sign-in, with a subscription picker.
        .DESCRIPTION
            Verified on Microsoft Learn (Az.Accounts, azps-16.2.0): the parameter is -Tenant
            (aliases Domain, TenantId), the subscription parameter is -Subscription, and the
            device code switch is -UseDeviceAuthentication (aliases DeviceCode, DeviceAuth,
            Device). Set-AzContext is a Set- cmdlet but changes only this PowerShell session's
            context - it makes no change to any Azure resource - so it does not breach the
            read-only rule.
        .PARAMETER TenantId
            Tenant domain or GUID. Prompted for when omitted; blank means the home tenant.
        .PARAMETER SubscriptionId
            Subscription id or name. When omitted and the account can see more than one
            subscription, ADT lists them and asks which to target.
        .PARAMETER DeviceCode
            Use device code flow instead of an interactive browser.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$TenantId,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $false)]
        [switch]$DeviceCode
    )

    $checkName = 'Connect Azure'

    try {
        Write-ADTSection -Title 'Connect Azure'

        if (-not (Test-ADTCloudCommand -Name 'Connect-AzAccount')) {
            Write-ADTCloudModuleMissing -Check $checkName -CmdletName 'Connect-AzAccount' -PrereqName 'AzModule'
            return
        }

        Write-ADTNote -Text 'ADT never writes tokens or credentials to disk.'
        Write-ADTNote -Text 'Az PowerShell keeps its own token cache under your user profile; use "Disconnect all cloud sessions" before handing a shared jump box back.'

        $tenant = Read-ADTCloudTenant -Supplied $TenantId -ServiceName 'Azure'

        $connectArgs = @{ ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrEmpty($tenant))         { $connectArgs['Tenant'] = $tenant }
        if (-not [string]::IsNullOrEmpty($SubscriptionId)) { $connectArgs['Subscription'] = $SubscriptionId }
        if ($DeviceCode) {
            $connectArgs['UseDeviceAuthentication'] = $true
            Write-ADTNote -Text 'Device code flow: a URL and a one-time code will be printed. Complete sign-in in a browser on any other machine.'
        }

        $null = Connect-AzAccount @connectArgs

        $context = Get-ADTCloudAzContext
        if ($null -eq $context) {
            $noCtxWhy = 'Connect-AzAccount returned without error but Get-AzContext reports no context, so no Azure check would work.'
            $noCtxFix = @(
                'Get-AzContext -ListAvailable',
                'Connect-ADTAzure -DeviceCode',
                'Test-NetConnection login.microsoftonline.com -Port 443'
            )
            Write-ADTResult -Check $checkName -Status FAIL -Detail 'No Azure context after connect.' -Why $noCtxWhy -Fix $noCtxFix
            return
        }

        # ---- Subscription picker --------------------------------------------------------
        # Only when the engineer did not name a subscription. Get-AzSubscription output columns
        # Name, Id, TenantId, State are confirmed on Microsoft Learn.
        if ([string]::IsNullOrEmpty($SubscriptionId)) {
            $subscriptions = @()
            try {
                $subscriptions = @(Get-AzSubscription -ErrorAction Stop)
            }
            catch {
                Write-ADTResult -Check 'Azure subscriptions' -Status WARN `
                    -Detail ('Could not enumerate subscriptions: ' + $_.Exception.Message) `
                    -Why 'Without the subscription list ADT cannot confirm which subscription later Azure checks will target; the current context is used as-is.' `
                    -Fix @('Get-AzSubscription', 'Set-AzContext -Subscription "<subscription id>"')
                $subscriptions = @()
            }

            if ($subscriptions.Count -gt 1) {
                if ($script:ADTNonInteractive) {
                    $currentSub = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $context -Name 'Subscription') -EmptyText 'none'
                    Write-ADTNote -Text ('Non-interactive run: keeping the current subscription context (' + $currentSub + ') out of ' + [string]$subscriptions.Count + '.')
                }
                else {
                    Write-ADTNote -Text ([string]$subscriptions.Count + ' subscription(s) visible to this account:')
                    for ($index = 0; $index -lt $subscriptions.Count; $index++) {
                        $subscription = $subscriptions[$index]
                        $subName  = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $subscription -Name 'Name')  -EmptyText 'unnamed'
                        $subId    = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $subscription -Name 'Id')    -EmptyText 'unknown'
                        $subState = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $subscription -Name 'State') -EmptyText 'unknown'
                        Write-ADTNote -Text ('  [' + [string]($index + 1) + '] ' + $subName + '  ' + $subId + '  (' + $subState + ')')
                    }

                    $choice = Read-Host -Prompt ('Subscription number to target [1-' + [string]$subscriptions.Count + '], blank to keep the current context')
                    if (-not [string]::IsNullOrEmpty($choice)) {
                        $parsed = 0
                        if ([int]::TryParse($choice.Trim(), [ref]$parsed) -and $parsed -ge 1 -and $parsed -le $subscriptions.Count) {
                            $chosen = $subscriptions[$parsed - 1]
                            $chosenId = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $chosen -Name 'Id') -EmptyText ''
                            if (-not [string]::IsNullOrEmpty($chosenId)) {
                                try {
                                    # Session-local context change only. Nothing in Azure is modified.
                                    $null = Set-AzContext -Subscription $chosenId -ErrorAction Stop
                                    $context = Get-ADTCloudAzContext
                                }
                                catch {
                                    Write-ADTResult -Check 'Azure subscription selection' -Status WARN `
                                        -Detail ('Set-AzContext failed: ' + $_.Exception.Message) `
                                        -Why 'The session is still authenticated but is pointed at whichever subscription Az chose by default, so later Azure checks may read the wrong subscription.' `
                                        -Fix @(('Set-AzContext -Subscription "' + $chosenId + '"'))
                                }
                            }
                        }
                        else {
                            Write-ADTNote -Text 'Not a valid number; keeping the current subscription context.'
                        }
                    }
                }
            }
            elseif ($subscriptions.Count -eq 1) {
                $onlyName = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $subscriptions[0] -Name 'Name') -EmptyText 'unnamed'
                Write-ADTNote -Text ('One subscription visible: ' + $onlyName + '.')
            }
        }

        $accountText = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $context -Name 'Account')      -EmptyText 'unknown'
        $tenantText  = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $context -Name 'Tenant')       -EmptyText 'unknown'
        $subText     = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $context -Name 'Subscription') -EmptyText 'none'
        $envText     = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $context -Name 'Environment')  -EmptyText 'unknown'

        Write-ADTNote -Text ('Tenant       : ' + $tenantText)
        Write-ADTNote -Text ('Account      : ' + $accountText)
        Write-ADTNote -Text ('Subscription : ' + $subText)
        Write-ADTNote -Text ('Environment  : ' + $envText)

        Write-ADTResult -Check $checkName -Status PASS `
            -Detail ('Connected to tenant ' + $tenantText + ' as ' + $accountText + '; subscription ' + $subText + '.') `
            -Data $context
    }
    catch {
        $errFix = @(
            'Connect-ADTAzure -DeviceCode',
            'Connect-ADTAzure -TenantId contoso.onmicrosoft.com',
            'Test-NetConnection login.microsoftonline.com -Port 443'
        )
        Write-ADTResult -Check $checkName -Status ERROR -Detail $_.Exception.Message -Fix $errFix
    }
}

#endregion

#region Connect: Exchange Online

function Connect-ADTEXO {
    <#
        .SYNOPSIS
            Interactive Exchange Online PowerShell sign-in.
        .DESCRIPTION
            Verified on Microsoft Learn (ExchangeOnlineManagement, exchange-ps): the device code
            switch is -Device, the banner suppression is -ShowBanner:$false, and -Organization is
            a string parameter. Microsoft documents -Device as working in PowerShell 7.0.3 or
            later with module 2.0.4 or later, so on Windows PowerShell 5.1 it may not be honoured.
        .PARAMETER Organization
            The organisation to connect to, normally the tenant's onmicrosoft.com domain.
        .PARAMETER DeviceCode
            Use device code flow instead of an interactive browser.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Organization,

        [Parameter(Mandatory = $false)]
        [switch]$DeviceCode
    )

    $checkName = 'Connect Exchange Online'

    try {
        Write-ADTSection -Title 'Connect Exchange Online'

        if (-not (Test-ADTCloudCommand -Name 'Connect-ExchangeOnline')) {
            Write-ADTCloudModuleMissing -Check $checkName -CmdletName 'Connect-ExchangeOnline' -PrereqName 'EXOModule'
            return
        }

        Write-ADTNote -Text 'ADT never writes tokens or credentials to disk.'
        Write-ADTNote -Text 'The Exchange Online module caches its own token under your user profile; use "Disconnect all cloud sessions" before handing a shared jump box back.'

        $organizationName = $Organization
        if ([string]::IsNullOrEmpty($organizationName)) {
            $organizationName = Read-ADTCloudTenant -Supplied '' -ServiceName 'Exchange Online (organisation)'
        }
        else {
            $organizationName = $organizationName.Trim()
        }

        $connectArgs = @{
            ShowBanner  = $false
            ErrorAction = 'Stop'
        }
        if (-not [string]::IsNullOrEmpty($organizationName)) { $connectArgs['Organization'] = $organizationName }
        if ($DeviceCode) {
            $connectArgs['Device'] = $true
            Write-ADTNote -Text 'Device code flow: a URL and a one-time code will be printed. Complete sign-in in a browser on any other machine.'
            $psMajor = 0
            try { $psMajor = [int]$PSVersionTable.PSVersion.Major } catch { $psMajor = 0 }
            if ($psMajor -lt 7) {
                Write-ADTNote -Text 'Microsoft documents -Device for PowerShell 7.0.3 and later. On Windows PowerShell 5.1 it may be ignored and a browser prompt may appear instead.'
            }
        }

        $null = Connect-ExchangeOnline @connectArgs

        $connection = Get-ADTCloudExoConnection
        if ($null -eq $connection) {
            $noConnWhy = 'Connect-ExchangeOnline returned without error but Get-ConnectionInformation reports no active connection, so no Exchange Online check would work.'
            $noConnFix = @(
                'Get-ConnectionInformation',
                'Connect-ExchangeOnline -ShowBanner:$false',
                'Test-NetConnection outlook.office365.com -Port 443'
            )
            Write-ADTResult -Check $checkName -Status FAIL -Detail 'No Exchange Online connection after connect.' -Why $noConnWhy -Fix $noConnFix
            return
        }

        $upnText = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $connection -Name 'UserPrincipalName') -EmptyText 'unknown'
        $orgText = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $connection -Name 'Organization')      -EmptyText ''
        if ([string]::IsNullOrEmpty($orgText)) {
            $orgText = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $connection -Name 'TenantID') -EmptyText 'unknown'
        }
        $stateText  = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $connection -Name 'State')      -EmptyText 'unknown'
        $expiryText = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $connection -Name 'TokenExpiryTimeUTC') -EmptyText 'unknown'

        Write-ADTNote -Text ('Organisation : ' + $orgText)
        Write-ADTNote -Text ('Account      : ' + $upnText)
        Write-ADTNote -Text ('State        : ' + $stateText)
        Write-ADTNote -Text ('Token expiry : ' + $expiryText + ' (UTC)')

        Write-ADTResult -Check $checkName -Status PASS `
            -Detail ('Connected to ' + $orgText + ' as ' + $upnText + ' (state ' + $stateText + ').') `
            -Data $connection
    }
    catch {
        $errFix = @(
            'Connect-ADTEXO -DeviceCode',
            'Connect-ADTEXO -Organization contoso.onmicrosoft.com',
            'Test-NetConnection outlook.office365.com -Port 443'
        )
        Write-ADTResult -Check $checkName -Status ERROR -Detail $_.Exception.Message -Fix $errFix
    }
}

#endregion

#region Context and disconnect

function Get-ADTCloudContext {
    <#
        .SYNOPSIS
            Current connection state for Graph, Azure and Exchange Online.
        .DESCRIPTION
            The one function every cloud check calls before it does anything. Deliberately
            returns an object to the pipeline (it is an API, not a check) and never throws,
            even when none of the cloud modules are installed.
        .OUTPUTS
            PSCustomObject with Graph, Az and EXO members, each carrying Connected (bool),
            Tenant (string) and Account (string).
    #>
    [CmdletBinding()]
    param()

    $graph = [PSCustomObject]@{ Connected = $false; Tenant = ''; Account = '' }
    $az    = [PSCustomObject]@{ Connected = $false; Tenant = ''; Account = '' }
    $exo   = [PSCustomObject]@{ Connected = $false; Tenant = ''; Account = '' }

    try {
        $graphContext = Get-ADTCloudGraphContext
        if ($null -ne $graphContext) {
            $graphTenant  = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $graphContext -Name 'TenantId')
            $graphAccount = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $graphContext -Name 'Account')
            # An app-only (certificate) context has no Account but is still a live session.
            if (-not [string]::IsNullOrEmpty($graphTenant) -or -not [string]::IsNullOrEmpty($graphAccount)) {
                $graph.Connected = $true
                $graph.Tenant    = $graphTenant
                $graph.Account   = $graphAccount
            }
        }
    }
    catch {
        $null = $_
    }

    try {
        $azContext = Get-ADTCloudAzContext
        if ($null -ne $azContext) {
            $azTenant  = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $azContext -Name 'Tenant')
            $azAccount = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $azContext -Name 'Account')
            if (-not [string]::IsNullOrEmpty($azTenant) -or -not [string]::IsNullOrEmpty($azAccount)) {
                $az.Connected = $true
                $az.Tenant    = $azTenant
                $az.Account   = $azAccount
            }
        }
    }
    catch {
        $null = $_
    }

    try {
        $exoConnection = Get-ADTCloudExoConnection
        if ($null -ne $exoConnection) {
            $exoTenant = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $exoConnection -Name 'Organization')
            if ([string]::IsNullOrEmpty($exoTenant)) {
                $exoTenant = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $exoConnection -Name 'TenantID')
            }
            $exoAccount = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $exoConnection -Name 'UserPrincipalName')
            $exoState   = ConvertTo-ADTCloudText -Value (Get-ADTCloudProperty -InputObject $exoConnection -Name 'State')
            if ([string]::IsNullOrEmpty($exoState) -or $exoState -eq 'Connected' -or $exoState -eq 'Opened') {
                $exo.Connected = $true
                $exo.Tenant    = $exoTenant
                $exo.Account   = $exoAccount
            }
        }
    }
    catch {
        $null = $_
    }

    return [PSCustomObject]@{
        Graph = $graph
        Az    = $az
        EXO   = $exo
    }
}

function Disconnect-ADTCloud {
    <#
        .SYNOPSIS
            Sign out of the cloud services this session is connected to.
        .DESCRIPTION
            Verified on Microsoft Learn: Disconnect-MgGraph takes no parameters and clears the
            cached token for the current context scope; Disconnect-AzAccount is the documented
            counterpart to Connect-AzAccount; Disconnect-ExchangeOnline -Confirm:$false
            disconnects silently. Each call is wrapped so one failure never stops the others.
        .PARAMETER All
            Also attempt a sign-out for services ADT cannot see a live session for. Use this to
            clear a stale cached token on a shared jump box, where Get-MgContext can report
            nothing while a token still sits in the user profile.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$All
    )

    try {
        $context = Get-ADTCloudContext

        # ---- Microsoft Graph -------------------------------------------------------------
        if ($context.Graph.Connected -or $All) {
            if (Test-ADTCloudCommand -Name 'Disconnect-MgGraph') {
                try {
                    $null = Disconnect-MgGraph -ErrorAction Stop
                    Write-ADTResult -Check 'Disconnect Microsoft Graph' -Status PASS -Detail 'Graph session ended and the cached token cleared.'
                }
                catch {
                    if ($context.Graph.Connected) {
                        Write-ADTResult -Check 'Disconnect Microsoft Graph' -Status WARN `
                            -Detail ('Disconnect-MgGraph failed: ' + $_.Exception.Message) `
                            -Why 'A Graph session ADT can see is still open, so the next person on this machine could reuse it.' `
                            -Fix @('Disconnect-MgGraph', 'Close this PowerShell window to drop the in-process token.')
                    }
                    else {
                        Write-ADTResult -Check 'Disconnect Microsoft Graph' -Status INFO -Detail 'No Graph session to end.'
                    }
                }
            }
            elseif ($context.Graph.Connected) {
                Write-ADTResult -Check 'Disconnect Microsoft Graph' -Status WARN `
                    -Detail 'Disconnect-MgGraph is not available but a Graph context is present.' `
                    -Why 'ADT cannot end a session whose module is no longer loadable.' `
                    -Fix @('Close this PowerShell window to drop the in-process token.')
            }
        }
        else {
            Write-ADTResult -Check 'Disconnect Microsoft Graph' -Status INFO -Detail 'Not connected; nothing to do.'
        }

        # ---- Azure ------------------------------------------------------------------------
        if ($context.Az.Connected -or $All) {
            if (Test-ADTCloudCommand -Name 'Disconnect-AzAccount') {
                try {
                    # -Confirm is present in every Disconnect-AzAccount parameter set, so pinning
                    # it to $false guarantees the menu never stalls on a confirmation prompt.
                    $null = Disconnect-AzAccount -Confirm:$false -ErrorAction Stop
                    Write-ADTResult -Check 'Disconnect Azure' -Status PASS -Detail 'Azure context removed.'
                }
                catch {
                    if ($context.Az.Connected) {
                        Write-ADTResult -Check 'Disconnect Azure' -Status WARN `
                            -Detail ('Disconnect-AzAccount failed: ' + $_.Exception.Message) `
                            -Why 'An Azure context ADT can see is still present, so the next person on this machine could reuse it.' `
                            -Fix @('Disconnect-AzAccount', 'Clear-AzContext -Scope CurrentUser -Force')
                    }
                    else {
                        Write-ADTResult -Check 'Disconnect Azure' -Status INFO -Detail 'No Azure context to remove.'
                    }
                }
            }
            elseif ($context.Az.Connected) {
                Write-ADTResult -Check 'Disconnect Azure' -Status WARN `
                    -Detail 'Disconnect-AzAccount is not available but an Azure context is present.' `
                    -Why 'ADT cannot end a session whose module is no longer loadable.' `
                    -Fix @('Close this PowerShell window to drop the in-process token.')
            }
        }
        else {
            Write-ADTResult -Check 'Disconnect Azure' -Status INFO -Detail 'Not connected; nothing to do.'
        }

        # ---- Exchange Online ---------------------------------------------------------------
        if ($context.EXO.Connected -or $All) {
            if (Test-ADTCloudCommand -Name 'Disconnect-ExchangeOnline') {
                try {
                    $null = Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop
                    Write-ADTResult -Check 'Disconnect Exchange Online' -Status PASS -Detail 'Exchange Online connection closed and its cache cleared.'
                }
                catch {
                    if ($context.EXO.Connected) {
                        Write-ADTResult -Check 'Disconnect Exchange Online' -Status WARN `
                            -Detail ('Disconnect-ExchangeOnline failed: ' + $_.Exception.Message) `
                            -Why 'An Exchange Online connection ADT can see is still open, so the next person on this machine could reuse it.' `
                            -Fix @('Disconnect-ExchangeOnline -Confirm:$false', 'Get-ConnectionInformation')
                    }
                    else {
                        Write-ADTResult -Check 'Disconnect Exchange Online' -Status INFO -Detail 'No Exchange Online connection to close.'
                    }
                }
            }
            elseif ($context.EXO.Connected) {
                Write-ADTResult -Check 'Disconnect Exchange Online' -Status WARN `
                    -Detail 'Disconnect-ExchangeOnline is not available but a connection is present.' `
                    -Why 'ADT cannot end a session whose module is no longer loadable.' `
                    -Fix @('Close this PowerShell window to drop the in-process connection.')
            }
        }
        else {
            Write-ADTResult -Check 'Disconnect Exchange Online' -Status INFO -Detail 'Not connected; nothing to do.'
        }
    }
    catch {
        Write-ADTResult -Check 'Disconnect cloud sessions' -Status ERROR -Detail $_.Exception.Message `
            -Fix @('Disconnect-MgGraph', 'Disconnect-AzAccount', 'Disconnect-ExchangeOnline -Confirm:$false')
    }
}

#endregion

#region Menu wrappers

function Invoke-ADTCloudContext {
    <#
        .SYNOPSIS
            Menu item: print the current cloud connection state and what is missing.
        .DESCRIPTION
            Wraps Get-ADTCloudContext so the menu gets printed results rather than an object on
            the pipeline. Also names the Install-ADTPrereq target for any cloud module that is
            not installed, because the launcher hides the matching Connect item when a module
            is absent and the engineer needs to be told why.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Cloud Context'

        $context = Get-ADTCloudContext

        $services = @(
            [PSCustomObject]@{ Name = 'Microsoft Graph';  State = $context.Graph; Prereq = 'GraphModule'; Probe = 'Get-MgContext';             Connect = 'Connect-ADTGraph' }
            [PSCustomObject]@{ Name = 'Azure';            State = $context.Az;    Prereq = 'AzModule';    Probe = 'Get-AzContext';             Connect = 'Connect-ADTAzure' }
            [PSCustomObject]@{ Name = 'Exchange Online';  State = $context.EXO;   Prereq = 'EXOModule';   Probe = 'Get-ConnectionInformation'; Connect = 'Connect-ADTEXO' }
        )

        $missingPrereqs = @()

        foreach ($service in $services) {
            $checkName = 'Cloud session: ' + $service.Name

            if ($service.State.Connected) {
                $tenantText  = $service.State.Tenant
                $accountText = $service.State.Account
                if ([string]::IsNullOrEmpty($tenantText))  { $tenantText  = 'unknown tenant' }
                if ([string]::IsNullOrEmpty($accountText)) { $accountText = 'unknown account' }
                Write-ADTResult -Check $checkName -Status PASS `
                    -Detail ('Connected to ' + $tenantText + ' as ' + $accountText + '.') -Data $service.State
                continue
            }

            $installed = $false
            try {
                $status = Get-ADTPrereqStatus -Name $service.Prereq | Select-Object -First 1
                if ($null -ne $status) { $installed = [bool]$status.Installed }
            }
            catch {
                $installed = (Test-ADTCloudCommand -Name $service.Probe)
            }

            if ($installed) {
                Write-ADTResult -Check $checkName -Status INFO `
                    -Detail ('Module present, no session. Run "' + $service.Connect + '" before any ' + $service.Name + ' check.')
            }
            else {
                $missingPrereqs += $service.Prereq
                $missingWhy = 'The launcher hides the "' + $service.Name + '" menu items while this module is missing, so nothing in that group can run on this machine.'
                Write-ADTResult -Check $checkName -Status INFO `
                    -Detail ('Not connected, and the PowerShell module is not installed (prerequisite ' + $service.Prereq + ').') `
                    -Why $missingWhy `
                    -Fix @(('Install-ADTPrereq -Name ' + $service.Prereq))
            }
        }

        if ($missingPrereqs.Count -gt 0) {
            Write-ADTNote -Text ('Missing prerequisites: ' + ($missingPrereqs -join ', ') + '. Install them from an elevated or user-scope session, then press R in the menu to re-detect.')
        }

        Write-ADTNote -Text 'Read-only Graph scopes ADT requests:'
        Write-ADTNote -Text ('  ' + (($script:ADTCloudGraphScopes | Sort-Object) -join ', '))
    }
    catch {
        Write-ADTResult -Check 'Cloud context' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTCloudDisconnect {
    <#
        .SYNOPSIS
            Menu item: sign out of every cloud service, including any stale cached session.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Disconnect Cloud Sessions'
        Disconnect-ADTCloud -All
    }
    catch {
        Write-ADTResult -Check 'Disconnect all cloud sessions' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

#region Module registration

Register-ADTModule -Name 'Cloud connect' -Group 'CLOUD' -Items @(
    @{ Label = 'Connect Microsoft Graph';       Function = 'Connect-ADTGraph';          Requires = @('HasGraphModule'); Snapshot = $false }
    @{ Label = 'Connect Azure';                 Function = 'Connect-ADTAzure';          Requires = @('HasAzModule');    Snapshot = $false }
    @{ Label = 'Connect Exchange Online';       Function = 'Connect-ADTEXO';            Requires = @('HasEXOModule');   Snapshot = $false }
    @{ Label = 'Show cloud context';            Function = 'Invoke-ADTCloudContext';    Requires = @();                 Snapshot = $false }
    @{ Label = 'Disconnect all cloud sessions'; Function = 'Invoke-ADTCloudDisconnect'; Requires = @();                 Snapshot = $false }
)

#endregion
