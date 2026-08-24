# ADT.ps1 - launcher: loads modules, builds the capability map, runs the menu or a snapshot.
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.

[CmdletBinding()]
param(
    [switch]$Snapshot,

    [string[]]$Modules,

    [switch]$NoTranscript
)

#region Launcher state

$script:ADTVersion         = '1.0'
$script:ADTResults         = @()
$script:ADTModules         = @()
$script:ADTCaps            = @{}
$script:ADTServiceCache    = $null
$script:ADTCurrentModule   = 'Launcher'
$script:ADTNonInteractive  = $Snapshot.IsPresent
$script:ADTTranscriptOn    = $false
$script:ADTExitCode        = 0
$script:ADTReady           = $false

if ($PSScriptRoot) {
    $script:ADTRoot = $PSScriptRoot
}
elseif ($MyInvocation.MyCommand.Path) {
    $script:ADTRoot = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
}
else {
    $script:ADTRoot = (Get-Location).Path
}

#endregion

#region Direct command catalogue
# Curated raw diagnostics, offered under a module's items as [c1]..[cN]. Every one of them
# only reports state - nothing here changes the target (contract rule 3). Keys are module
# Names exactly as registered; a module with no key here shows no command section at all.
#
# Definition properties:
#   Label           menu text
#   Exe             executable, resolved with Get-Command at run time
#   Args            fixed arguments, always passed
#   Requires        capability names, gated exactly like menu items
#   ArgPrompt       when set, Read-Host this before running
#   ArgTemplate     format string applied to the FIRST token of the answer ({0}); any
#                   remaining tokens are appended verbatim
#   ArgRequired     a blank answer skips the run rather than firing the tool with no target
#   DefaultFromCap  capability whose value stands in for a blank optional answer
#   Note            dimmed one-liner rendered under the menu row

$script:ADTCommandCatalog = @{

    'AD core' = @(
        @{
            Label    = 'dcdiag (quick, errors only)'
            Exe      = 'dcdiag.exe'
            Args     = @('/q')
            Requires = @('IsDC')
        }
        @{
            Label    = 'dcdiag (full verbose)'
            Exe      = 'dcdiag.exe'
            Args     = @('/v')
            Requires = @('IsDC')
            Note     = 'long output'
        }
        @{
            Label       = 'dcdiag single test'
            Exe         = 'dcdiag.exe'
            Args        = @()
            ArgPrompt   = 'Test name (e.g. DNS, Replications, Advertising, KnowsOfRoleHolders)'
            ArgTemplate = '/test:{0}'
            ArgRequired = $true
            Requires    = @('IsDC')
        }
        @{
            Label    = 'repadmin /replsummary'
            Exe      = 'repadmin.exe'
            Args     = @('/replsummary')
            Requires = @('IsDC')
        }
        @{
            Label       = 'repadmin /showrepl'
            Exe         = 'repadmin.exe'
            Args        = @('/showrepl')
            ArgPrompt   = 'Extra args (blank = this DC; e.g. "dc2" or "* /errorsonly")'
            ArgTemplate = '{0}'
            ArgRequired = $false
            Requires    = @('IsDC')
        }
        @{
            Label    = 'netdom query fsmo'
            Exe      = 'netdom.exe'
            Args     = @('query', 'fsmo')
            Requires = @('DomainJoined')
        }
        @{
            Label          = 'nltest /dclist'
            Exe            = 'nltest.exe'
            Args           = @()
            ArgPrompt      = 'Domain (blank = current domain)'
            ArgTemplate    = '/dclist:{0}'
            ArgRequired    = $false
            DefaultFromCap = 'DomainName'
            Requires       = @('DomainJoined')
        }
        @{
            Label    = 'w32tm /query /status'
            Exe      = 'w32tm.exe'
            Args     = @('/query', '/status')
            Requires = @()
        }
        @{
            Label    = 'klist (current Kerberos tickets)'
            Exe      = 'klist.exe'
            Args     = @()
            Requires = @()
        }
    )

    'DNS' = @(
        @{
            Label       = 'nslookup (one-shot)'
            Exe         = 'nslookup.exe'
            Args        = @()
            ArgPrompt   = 'Name to resolve, optionally followed by a DNS server (e.g. "host.corp.local 10.0.0.1")'
            ArgTemplate = '{0}'
            ArgRequired = $true
            Requires    = @()
        }
        @{
            Label    = 'dcdiag /test:dns'
            Exe      = 'dcdiag.exe'
            Args     = @('/test:dns')
            Requires = @('IsDC')
        }
        @{
            Label    = 'dnscmd /enumzones'
            Exe      = 'dnscmd.exe'
            Args     = @('/enumzones')
            Requires = @('HasDnsRole')
        }
        @{
            Label       = 'dnscmd /zoneinfo'
            Exe         = 'dnscmd.exe'
            Args        = @('/zoneinfo')
            ArgPrompt   = 'Zone name'
            ArgTemplate = '{0}'
            ArgRequired = $true
            Requires    = @('HasDnsRole')
        }
    )

    'DHCP' = @(
        @{
            Label    = 'netsh dhcp show server (authorised servers in AD)'
            Exe      = 'netsh.exe'
            Args     = @('dhcp', 'show', 'server')
            Requires = @('DomainJoined')
        }
    )

    'Network' = @(
        @{
            Label       = 'ping'
            Exe         = 'ping.exe'
            Args        = @()
            ArgPrompt   = 'Target host/IP (extra switches allowed, e.g. "dc1 /n 10")'
            ArgTemplate = '{0}'
            ArgRequired = $true
            Requires    = @()
        }
        @{
            Label       = 'tracert'
            Exe         = 'tracert.exe'
            Args        = @('/d')
            ArgPrompt   = 'Target host/IP'
            ArgTemplate = '{0}'
            ArgRequired = $true
            Requires    = @()
        }
        @{
            Label       = 'pathping'
            Exe         = 'pathping.exe'
            Args        = @()
            ArgPrompt   = 'Target host/IP'
            ArgTemplate = '{0}'
            ArgRequired = $true
            Requires    = @()
            Note        = 'takes several minutes'
        }
        @{
            Label    = 'ipconfig /all'
            Exe      = 'ipconfig.exe'
            Args     = @('/all')
            Requires = @()
        }
        @{
            Label    = 'netstat -ano'
            Exe      = 'netstat.exe'
            Args     = @('-ano')
            Requires = @()
        }
        @{
            Label    = 'route print'
            Exe      = 'route.exe'
            Args     = @('print')
            Requires = @()
        }
        @{
            Label    = 'arp -a'
            Exe      = 'arp.exe'
            Args     = @('-a')
            Requires = @()
        }
    )

    'Server health' = @(
        @{
            Label    = 'systeminfo'
            Exe      = 'systeminfo.exe'
            Args     = @()
            Requires = @()
        }
        @{
            Label    = 'gpresult /r'
            Exe      = 'gpresult.exe'
            Args     = @('/r')
            Requires = @()
        }
        @{
            Label    = 'whoami /all'
            Exe      = 'whoami.exe'
            Args     = @('/all')
            Requires = @()
        }
        @{
            Label    = 'quser (logged-on sessions)'
            Exe      = 'quser.exe'
            Args     = @()
            Requires = @()
        }
    )

    'File services' = @(
        @{
            Label    = 'net share'
            Exe      = 'net.exe'
            Args     = @('share')
            Requires = @()
        }
        @{
            Label    = 'net session'
            Exe      = 'net.exe'
            Args     = @('session')
            Requires = @()
        }
    )
}

#endregion

#region Launcher helpers

function Show-ADTBanner {
    <#
        .SYNOPSIS
            Print the header block: tool, host, user, elevation, domain and a caps one-liner.
    #>
    [CmdletBinding()]
    param()

    $rule = '=' * 76
    $user = $env:USERNAME
    try {
        $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    catch {
        $null = $_
    }

    $elevation = 'not elevated'
    if ($script:ADTCaps['IsElevated']) { $elevation = 'elevated' }

    $domain = 'workgroup'
    if ($script:ADTCaps['DomainJoined'] -and $script:ADTCaps['DomainName']) {
        $domain = [string]$script:ADTCaps['DomainName']
        if ($script:ADTCaps['IsDC']) { $domain = $domain + ' (this box is a DC)' }
    }

    Write-Host ''
    Write-Host $rule -ForegroundColor DarkCyan
    Write-Host ('  ADT - AD / Domain Troubleshooting toolkit   v' + $script:ADTVersion) -ForegroundColor White
    Write-Host $rule -ForegroundColor DarkCyan
    Write-Host ('  Host      : ' + $env:COMPUTERNAME + '   (' + [string]$script:ADTCaps['OSCaption'] + ')')
    Write-Host ('  User      : ' + $user + '   [' + $elevation + ']')
    Write-Host ('  Domain    : ' + $domain)
    Write-Host ('  PowerShell: ' + $PSVersionTable.PSVersion.ToString())
    Write-Host ('  Root      : ' + $script:ADTRoot)
    Write-Host ('  Caps      : ' + (Get-ADTCapsSummary))
    Write-Host $rule -ForegroundColor DarkCyan
}

function Get-ADTCapsSummary {
    <#
        .SYNOPSIS
            One-line, human-readable rendering of the capability map for the banner.
    #>
    [CmdletBinding()]
    param()

    $onPrem = @()
    if ($script:ADTCaps['IsDC'])             { $onPrem += 'DC' }
    if ($script:ADTCaps['HasADModule'])      { $onPrem += 'AD' }
    if ($script:ADTCaps['HasDnsRole'])       { $onPrem += 'DNS' }
    if ($script:ADTCaps['HasDhcpRole'])      { $onPrem += 'DHCP' }
    if ($script:ADTCaps['HasExchangeShell']) {
        if ($script:ADTCaps['ExchangeVersion']) {
            $onPrem += ('Exchange ' + [string]$script:ADTCaps['ExchangeVersion'])
        }
        else {
            $onPrem += 'Exchange'
        }
    }
    if ($script:ADTCaps['CitrixDDC'])            { $onPrem += 'CitrixDDC' }
    if ($script:ADTCaps['CitrixVDA'])            { $onPrem += 'CitrixVDA' }
    if ($script:ADTCaps['CitrixStoreFront'])     { $onPrem += 'StoreFront' }
    if ($script:ADTCaps['CitrixCloudConnector']) { $onPrem += 'CloudConnector' }

    $cloud = @()
    if ($script:ADTCaps['HasGraphModule']) { $cloud += 'Graph' }
    if ($script:ADTCaps['HasAzModule'])    { $cloud += 'Az' }
    if ($script:ADTCaps['HasEXOModule'])   { $cloud += 'EXO' }

    $net = 'no internet'
    if ($script:ADTCaps['HasInternet']) { $net = 'internet ok' }

    $onPremText = 'none detected'
    if ($onPrem.Count -gt 0) { $onPremText = ($onPrem -join ', ') }

    $cloudText = 'no cloud modules'
    if ($cloud.Count -gt 0) { $cloudText = ($cloud -join ', ') }

    return ($onPremText + ' | ' + $cloudText + ' | ' + $net)
}

function Get-ADTMissingCap {
    <#
        .SYNOPSIS
            Which of an item's required capabilities this box does not satisfy.
        .OUTPUTS
            The missing capability names. Nothing missing means the item is available.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Requires
    )

    $missing = @()

    if ($null -ne $Requires) {
        foreach ($requirement in $Requires) {
            if ([string]::IsNullOrEmpty($requirement)) { continue }
            $met = $false
            if ($script:ADTCaps.ContainsKey($requirement)) {
                if ($script:ADTCaps[$requirement]) { $met = $true }
            }
            if (-not $met) { $missing += $requirement }
        }
    }

    return $missing
}

function Get-ADTModuleList {
    <#
        .SYNOPSIS
            One object per registered module, in menu order (ON-PREM, CLOUD, TOOLS), with its
            items already resolved against the capability map.
        .DESCRIPTION
            Items are numbered inside their own module and only the available ones get a
            number, the same way the menu has always numbered them - just scoped to the module
            rather than to the whole tool. A module with at least one available item is itself
            numbered, sequentially across the entire main menu; a module with nothing available
            keeps Number 0, renders dimmed, and carries the union of the capabilities its items
            are waiting on.
        .OUTPUTS
            PSCustomObject per module. Callers wrap the call in @() - a single module would
            otherwise arrive as a bare object.
    #>
    [CmdletBinding()]
    param()

    $list = @()

    foreach ($group in @('ON-PREM', 'CLOUD', 'TOOLS')) {
        foreach ($module in $script:ADTModules) {
            if ($module.Group -ne $group) { continue }

            $items          = @()
            $itemNumber     = 0
            $availableCount = 0
            $missingCaps    = @()

            foreach ($item in $module.Items) {
                $missing   = @(Get-ADTMissingCap -Requires @($item.Requires))
                $available = ($missing.Count -eq 0)
                $number    = 0

                if ($available) {
                    $itemNumber     = $itemNumber + 1
                    $number         = $itemNumber
                    $availableCount = $availableCount + 1
                }
                else {
                    foreach ($cap in $missing) {
                        if ($missingCaps -notcontains $cap) { $missingCaps += $cap }
                    }
                }

                $items += [PSCustomObject]@{
                    Group      = $group
                    ModuleName = $module.Name
                    Label      = $item.Label
                    Function   = $item.Function
                    Requires   = @($item.Requires)
                    Snapshot   = $item.Snapshot
                    Missing    = @($missing)
                    Available  = $available
                    Number     = $number
                }
            }

            $list += [PSCustomObject]@{
                Group          = $group
                Name           = $module.Name
                Items          = @($items)
                ItemCount      = @($items).Count
                AvailableCount = $availableCount
                MissingCaps    = @($missingCaps)
                Available      = ($availableCount -gt 0)
                Number         = 0
            }
        }
    }

    $counter = 0
    foreach ($entry in $list) {
        if ($entry.Available) {
            $counter      = $counter + 1
            $entry.Number = $counter
        }
    }

    return $list
}

function Get-ADTMenuEntry {
    <#
        .SYNOPSIS
            Every registered item as one flat list, in menu order, resolved against the caps.
        .DESCRIPTION
            The two-level menu renders from Get-ADTModuleList; this flat projection is what the
            snapshot walks. Number here is the item's number WITHIN its module, not a global
            menu number - the snapshot never uses it.
    #>
    [CmdletBinding()]
    param()

    $entries = @()

    foreach ($module in @(Get-ADTModuleList)) {
        foreach ($item in @($module.Items)) {
            $entries += $item
        }
    }

    return $entries
}

function Get-ADTModuleCommand {
    <#
        .SYNOPSIS
            One module's direct-command catalogue, resolved against the capability map.
        .DESCRIPTION
            Numbering works the same way as the items: only available commands get a number,
            counted within the module, so the engineer sees c1..cN with no gaps. Unavailable
            ones keep Number 0 and carry the capabilities they are waiting on. Every optional
            property is normalised here - empty string for the text ones, $false for
            ArgRequired - so nothing downstream has to test for a missing key.
        .OUTPUTS
            PSCustomObject per command, or nothing when this module has no catalogue entry.
            Callers wrap the call in @() - a single command would otherwise arrive as a bare
            object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    $resolved = @()

    if ($null -eq $script:ADTCommandCatalog) { return $resolved }
    if (-not $script:ADTCommandCatalog.ContainsKey($ModuleName)) { return $resolved }

    $commandNumber = 0

    foreach ($definition in @($script:ADTCommandCatalog[$ModuleName])) {
        if ($null -eq $definition) { continue }

        $requires = @()
        if ($null -ne $definition.Requires) { $requires = @($definition.Requires) }

        $missing   = @(Get-ADTMissingCap -Requires $requires)
        $available = ($missing.Count -eq 0)
        $number    = 0

        if ($available) {
            $commandNumber = $commandNumber + 1
            $number        = $commandNumber
        }

        $arguments = @()
        if ($null -ne $definition.Args) {
            foreach ($argument in @($definition.Args)) {
                if ($null -eq $argument) { continue }
                $arguments += [string]$argument
            }
        }

        $argPrompt = ''
        if ($null -ne $definition.ArgPrompt) { $argPrompt = [string]$definition.ArgPrompt }

        # '{0}' means "the answer as typed" - the sane default for a prompt with no template.
        $argTemplate = '{0}'
        if ($null -ne $definition.ArgTemplate) { $argTemplate = [string]$definition.ArgTemplate }

        $argRequired = $false
        if ($definition.ArgRequired) { $argRequired = $true }

        $defaultFromCap = ''
        if ($null -ne $definition.DefaultFromCap) { $defaultFromCap = [string]$definition.DefaultFromCap }

        $note = ''
        if ($null -ne $definition.Note) { $note = [string]$definition.Note }

        $resolved += [PSCustomObject]@{
            ModuleName     = $ModuleName
            Label          = [string]$definition.Label
            Exe            = [string]$definition.Exe
            Args           = @($arguments)
            ArgPrompt      = $argPrompt
            ArgTemplate    = $argTemplate
            ArgRequired    = $argRequired
            DefaultFromCap = $defaultFromCap
            Note           = $note
            Requires       = @($requires)
            Missing        = @($missing)
            Available      = $available
            Number         = $number
        }
    }

    return $resolved
}

function Format-ADTMissingCapText {
    <#
        .SYNOPSIS
            Render unmet capability names as a one-line "(needs: ...)" tail, truncated with
            '...' when the list is too long to sit on a menu line.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Caps,

        [Parameter(Mandatory = $false)]
        [int]$MaxLength = 44
    )

    if ($Caps.Count -eq 0) { return '' }

    $full = ($Caps -join ', ')
    if ($full.Length -le $MaxLength) {
        return ('(needs: ' + $full + ')')
    }

    $shown  = @()
    $length = 0
    foreach ($cap in $Caps) {
        $addition = $cap.Length
        if ($shown.Count -gt 0) { $addition = $addition + 2 }
        if (($length + $addition) -gt ($MaxLength - 5)) { break }
        $shown  += $cap
        $length  = $length + $addition
    }
    if ($shown.Count -eq 0) { $shown = @($Caps[0]) }

    return ('(needs: ' + ($shown -join ', ') + ', ...)')
}

function Show-ADTMainMenu {
    <#
        .SYNOPSIS
            Render the top level: one line per registered module, grouped ON-PREM / CLOUD /
            TOOLS. The module's own items live one level down, in Show-ADTModuleMenu.
        .DESCRIPTION
            A module with at least one available item is numbered and tallied - "(5 items)"
            when everything is available, "(2 of 5 items)" when only part of it is. A module
            with nothing available is dimmed and names the capabilities it is waiting on.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$ModuleList
    )

    $rule = '=' * 76
    Write-Host ''
    Write-Host $rule -ForegroundColor DarkCyan
    Write-Host '  ADT MAIN MENU' -ForegroundColor White
    Write-Host $rule -ForegroundColor DarkCyan

    if ($ModuleList.Count -eq 0) {
        Write-Host '  No modules registered. Check the modules folder.' -ForegroundColor Yellow
    }
    else {
        $nameWidth = 12
        foreach ($module in $ModuleList) {
            if ($module.Name.Length -gt $nameWidth) { $nameWidth = $module.Name.Length }
        }
        if ($nameWidth -gt 28) { $nameWidth = 28 }

        foreach ($group in @('ON-PREM', 'CLOUD', 'TOOLS')) {
            $groupModules = @($ModuleList | Where-Object { $_.Group -eq $group })
            if ($groupModules.Count -eq 0) { continue }

            Write-Host ''
            Write-Host ('  ' + $group) -ForegroundColor Cyan

            foreach ($module in $groupModules) {
                $name = $module.Name.PadRight($nameWidth)

                if ($module.Available) {
                    $noun = 'items'
                    if ($module.ItemCount -eq 1) { $noun = 'item' }

                    if ($module.AvailableCount -eq $module.ItemCount) {
                        $tally = '(' + [string]$module.ItemCount + ' ' + $noun + ')'
                    }
                    else {
                        $tally = '(' + [string]$module.AvailableCount + ' of ' + [string]$module.ItemCount + ' ' + $noun + ')'
                    }

                    Write-Host ('    [{0,2}] {1}  {2}' -f $module.Number, $name, $tally)
                }
                else {
                    $reason = Format-ADTMissingCapText -Caps @($module.MissingCaps)
                    if ($module.ItemCount -eq 0) { $reason = '(no items registered)' }
                    Write-Host ('    [ -] {0}  {1}' -f $name, $reason) -ForegroundColor DarkGray
                }
            }
        }
    }

    Write-Host ''
    Write-Host '  [number] open module    [S] snapshot    [R] re-detect capabilities    [Q] quit' -ForegroundColor Gray
    Write-Host ''
}

function Show-ADTModuleMenu {
    <#
        .SYNOPSIS
            Render one module's items: available ones numbered within the module, unavailable
            ones dimmed with the capabilities they need.
        .DESCRIPTION
            A module that carries a direct-command catalogue gets a second section under its
            items, numbered c1..cN over the available commands only, gated and dimmed exactly
            like the items above it. A module with no catalogue entry renders as it always
            has, footer included.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Module,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Commands
    )

    $rule = '=' * 76
    Write-Host ''
    Write-Host $rule -ForegroundColor DarkCyan
    Write-Host ('  ' + $Module.Group + '  /  ' + $Module.Name) -ForegroundColor White
    Write-Host $rule -ForegroundColor DarkCyan
    Write-Host ''

    $items = @($Module.Items)

    if ($items.Count -eq 0) {
        Write-Host '  This module registered no items.' -ForegroundColor Yellow
    }
    else {
        foreach ($item in $items) {
            if ($item.Available) {
                $marker = ''
                if ($item.Snapshot) { $marker = '  *' }
                Write-Host ('    [{0,2}] {1}{2}' -f $item.Number, $item.Label, $marker)
            }
            else {
                $reason = Format-ADTMissingCapText -Caps @($item.Missing)
                Write-Host ('    [ -] {0}  {1}' -f $item.Label, $reason) -ForegroundColor DarkGray
            }
        }
    }

    $commandList = @()
    if ($null -ne $Commands) { $commandList = @($Commands) }
    $runnableCommands = @($commandList | Where-Object { $_.Available })

    if ($commandList.Count -gt 0) {
        Write-Host ''
        Write-Host '  Direct commands' -ForegroundColor Cyan

        foreach ($command in $commandList) {
            if ($command.Available) {
                # 'c1' is two characters, so the same {0,2} field keeps the command rows in
                # the same column as the numbered item rows above them.
                $tag = 'c' + [string]$command.Number
                Write-Host ('    [{0,2}] {1}' -f $tag, $command.Label)
            }
            else {
                $reason = Format-ADTMissingCapText -Caps @($command.Missing)
                Write-Host ('    [ -] {0}  {1}' -f $command.Label, $reason) -ForegroundColor DarkGray
            }

            if ($command.Note -ne '') {
                Write-Host ('         ' + $command.Note) -ForegroundColor DarkGray
            }
        }
    }

    Write-Host ''
    Write-Host '  * = included in the snapshot' -ForegroundColor DarkGray
    if ($runnableCommands.Count -gt 0) {
        Write-Host '  [number] run item    [cN] run command    [A] run all available items    [B] back    [Q] quit' -ForegroundColor Gray
    }
    else {
        Write-Host '  [number] run item    [A] run all available items    [B] back    [Q] quit' -ForegroundColor Gray
    }
    Write-Host ''
}

function Wait-ADTMenuPause {
    <#
        .SYNOPSIS
            Hold the screen after an item has printed its output, so the results can be
            read before the menu repaints. Any key (or Enter when input is redirected or
            the host has no ReadKey support) returns to the menu. Never pauses in
            non-interactive/snapshot mode.
    #>
    [CmdletBinding()]
    param()

    if ($script:ADTNonInteractive) { return }

    Write-Host ''
    Write-Host '  Press any key to return to the menu ...' -ForegroundColor DarkGray
    # With redirected stdin, RawUI.ReadKey reads the CONSOLE buffer (not the pipe) and
    # blocks forever - so pipes and scripts get Read-Host, real consoles get any-key.
    $redirected = $false
    try { $redirected = [Console]::IsInputRedirected } catch { $redirected = $false }
    if ($redirected) {
        $null = Read-Host
    }
    else {
        try {
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        }
        catch {
            $null = Read-Host
        }
    }
}

function Invoke-ADTMenuEntry {
    <#
        .SYNOPSIS
            Run one registered item. Modules already wrap their own bodies (contract rule 5);
            this is the belt-and-braces catch so the menu can never be killed by a module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Entry
    )

    $script:ADTCurrentModule = $Entry.ModuleName
    Write-ADTSection -Title ($Entry.ModuleName + ' - ' + $Entry.Label)

    try {
        $target = Get-Command -Name $Entry.Function -CommandType Function -ErrorAction SilentlyContinue
        if ($null -eq $target) {
            $missingWhy = 'The module registered this menu item but the function is not defined, so the module file is probably half-loaded.'
            Write-ADTResult -Check $Entry.Label -Status ERROR -Detail ('Function not found: ' + $Entry.Function) -Why $missingWhy
        }
        else {
            # Rule 8: checks report through the output engine only. Anything that leaks to the
            # pipeline is discarded here rather than being printed as raw objects.
            $null = & $Entry.Function
        }
    }
    catch {
        Write-ADTResult -Check $Entry.Label -Status ERROR -Detail $_.Exception.Message
    }
    finally {
        $script:ADTCurrentModule = 'Launcher'
    }
}

function Invoke-ADTDirectCommand {
    <#
        .SYNOPSIS
            Run one catalogue command and stream its output straight to the console.
        .DESCRIPTION
            These are raw diagnostics, not checks, so nothing goes through the output engine:
            no result is recorded, no status is counted, and the transcript already holds every
            line the tool printed. A command that takes an argument prompts for one first; a
            blank answer to a required prompt - which is also what Read-Host returns at
            end-of-stream on redirected input - skips the run rather than firing the tool with
            no target, and skips the pause with it so a piped session keeps moving.
            A non-zero exit code is reported, not treated as a failure: plenty of these tools
            exit non-zero to mean "found something".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Command
    )

    $exeName = [string]$Command.Exe

    $finalArgs = @()
    foreach ($argument in @($Command.Args)) {
        if ($null -eq $argument) { continue }
        $finalArgs += [string]$argument
    }

    if ($Command.ArgPrompt -ne '') {
        $answer = Read-Host -Prompt ('  ' + $Command.ArgPrompt)
        if ($null -eq $answer) { $answer = '' }
        $answer = $answer.Trim()

        if ($answer -eq '') {
            if ($Command.ArgRequired) {
                Write-Host '[INFO] no argument given - command skipped' -ForegroundColor Gray
                return
            }

            if ($Command.DefaultFromCap -ne '') {
                $fallback = ''
                if ($script:ADTCaps.ContainsKey($Command.DefaultFromCap)) {
                    if ($null -ne $script:ADTCaps[$Command.DefaultFromCap]) {
                        $fallback = [string]$script:ADTCaps[$Command.DefaultFromCap]
                    }
                }

                if ($fallback -eq '') {
                    Write-Host ('[INFO] no argument given and no ' + $Command.DefaultFromCap + ' known on this box - command skipped') -ForegroundColor Gray
                    return
                }

                $finalArgs += ($Command.ArgTemplate -f $fallback)
            }
        }
        else {
            # The template shapes the FIRST token only - '/test:{0}' turning Advertising into
            # /test:Advertising - and anything the engineer typed after it rides along
            # verbatim, so 'dc1 /n 10' and 'host.corp.local 10.0.0.1' both work.
            $tokens = @($answer -split '\s+' | Where-Object { $_ -ne '' })
            if ($tokens.Count -gt 0) {
                $finalArgs += ($Command.ArgTemplate -f $tokens[0])
                if ($tokens.Count -gt 1) {
                    foreach ($extra in $tokens[1..($tokens.Count - 1)]) {
                        $finalArgs += [string]$extra
                    }
                }
            }
        }
    }

    $application = $null
    try {
        $application = @(Get-Command -Name $exeName -CommandType Application -ErrorAction SilentlyContinue)
    }
    catch {
        $application = @()
    }

    if ($null -eq $application -or $application.Count -eq 0) {
        Write-Host ('[INFO] ' + $exeName + ' not found on this box') -ForegroundColor Gray
        return
    }

    # ApplicationInfo exposes the full path as Path; Source is the general CommandInfo view of
    # the same thing. Take whichever answers, and fall back to the bare name (which PATH will
    # resolve again) rather than failing over a property that came back empty.
    $exePath = ''
    if ($null -ne $application[0].Path) { $exePath = [string]$application[0].Path }
    if ($exePath -eq '' -and $null -ne $application[0].Source) { $exePath = [string]$application[0].Source }
    if ($exePath -eq '') { $exePath = $exeName }

    # Header shows the command as an engineer would type it, so the transcript records exactly
    # what was run and it can be pasted straight back into a shell.
    $display = $exeName
    if ($display.ToLower().EndsWith('.exe')) {
        $display = $display.Substring(0, $display.Length - 4)
    }
    if ($finalArgs.Count -gt 0) {
        $display = $display + ' ' + ($finalArgs -join ' ')
    }

    Write-Host ''
    Write-Host ('  --- ' + $display + ' ---') -ForegroundColor Cyan

    $exitCode = $null
    try {
        & $exePath @finalArgs 2>&1 | Out-Host
        $exitCode = $LASTEXITCODE
    }
    catch {
        Write-Host ('  --- ' + $exeName + ' could not be run: ' + $_.Exception.Message + ' ---') -ForegroundColor Magenta
    }

    $exitText = 'n/a'
    if ($null -ne $exitCode) { $exitText = [string]$exitCode }
    Write-Host ('  --- exit code ' + $exitText + ' ---') -ForegroundColor DarkGray

    Wait-ADTMenuPause
}

function Get-ADTResultExitCode {
    <#
        .SYNOPSIS
            0 all pass, 1 any warn, 2 any fail, 3 any error. Highest severity wins.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Results
    )

    $code = 0
    foreach ($result in $Results) {
        if ($result.Status -eq 'WARN' -and $code -lt 1) { $code = 1 }
        if ($result.Status -eq 'FAIL' -and $code -lt 2) { $code = 2 }
        if ($result.Status -eq 'ERROR') { $code = 3 }
    }
    return $code
}

function Write-ADTRunSummary {
    <#
        .SYNOPSIS
            Counts by status plus every WARN, FAIL and ERROR line, for the results recorded
            from $StartIndex onwards.
        .OUTPUTS
            The exit code implied by that slice of results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$StartIndex = 0,

        [Parameter(Mandatory = $false)]
        [string]$Title = 'Summary'
    )

    $slice = @()
    $total = @($script:ADTResults).Count
    if ($total -gt $StartIndex) {
        $slice = @($script:ADTResults[$StartIndex..($total - 1)])
    }

    Write-ADTSection -Title $Title

    if ($slice.Count -eq 0) {
        Write-Host '  No results were recorded.' -ForegroundColor DarkGray
        return 0
    }

    $order = @('PASS', 'WARN', 'FAIL', 'INFO', 'SKIP', 'ERROR')
    $counts = @{}
    foreach ($status in $order) { $counts[$status] = 0 }
    foreach ($result in $slice) {
        if ($counts.ContainsKey($result.Status)) {
            $counts[$result.Status] = $counts[$result.Status] + 1
        }
    }

    Write-Host ''
    Write-Host ('  {0,-8} {1,5}' -f 'STATUS', 'COUNT')
    Write-Host ('  {0,-8} {1,5}' -f '--------', '-----')
    foreach ($status in $order) {
        $colour = 'Gray'
        switch ($status) {
            'PASS'  { $colour = 'Green' }
            'WARN'  { $colour = 'Yellow' }
            'FAIL'  { $colour = 'Red' }
            'ERROR' { $colour = 'Magenta' }
        }
        Write-Host ('  {0,-8} {1,5}' -f $status, $counts[$status]) -ForegroundColor $colour
    }
    Write-Host ('  {0,-8} {1,5}' -f '--------', '-----')
    Write-Host ('  {0,-8} {1,5}' -f 'TOTAL', $slice.Count)

    $issues = @($slice | Where-Object { @('WARN', 'FAIL', 'ERROR') -contains $_.Status })
    if ($issues.Count -gt 0) {
        Write-Host ''
        Write-Host '  Needs attention:' -ForegroundColor Yellow
        foreach ($issue in $issues) {
            $tag = '[' + $issue.Status + ']'
            $colour = 'Yellow'
            if ($issue.Status -eq 'FAIL')  { $colour = 'Red' }
            if ($issue.Status -eq 'ERROR') { $tag = '[ERR ]'; $colour = 'Magenta' }
            Write-Host ('  {0} {1} / {2} : {3}' -f $tag, $issue.Module, $issue.Check, $issue.Detail) -ForegroundColor $colour
        }
    }
    else {
        Write-Host ''
        Write-Host '  Nothing needs attention.' -ForegroundColor Green
    }

    Write-Host ''
    return (Get-ADTResultExitCode -Results $slice)
}

function Invoke-ADTModuleMenu {
    <#
        .SYNOPSIS
            The second menu level: show one module's items and run them until the engineer
            goes back to the main menu or quits.
        .DESCRIPTION
            The module is looked up again by name on every repaint so the list always reflects
            the live capability map, and its direct-command catalogue is re-resolved with it.
            Running an item behaves exactly as it always has: record the result count, run it,
            print its own result summary, then hold the screen. Running a command (cN) is
            deliberately different - see Invoke-ADTDirectCommand.
        .OUTPUTS
            'BACK' to return to the main menu, 'QUIT' to end the session.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    while ($true) {
        $module = $null
        foreach ($candidate in @(Get-ADTModuleList)) {
            if ($candidate.Name -eq $ModuleName) {
                $module = $candidate
                break
            }
        }

        # A module can only vanish if the registration list changed underneath us. Treat it as
        # "go back" rather than looping forever on a menu that no longer exists.
        if ($null -eq $module) { return 'BACK' }

        # Re-resolved on every repaint for the same reason the module is: [R] on the main menu
        # can change what this box can do while the submenu is still open.
        $commands = @(Get-ADTModuleCommand -ModuleName $module.Name)

        Show-ADTModuleMenu -Module $module -Commands $commands

        $choice = Read-Host -Prompt 'Select'
        if ($null -eq $choice) { $choice = '' }
        $choice = $choice.Trim()

        if ($choice -eq '') {
            # Same end-of-stream guard as the main menu. A redirected run that has run dry has
            # to end the whole session here - bouncing back to the main menu would just hit the
            # same empty read and loop between the two levels forever.
            $redirected = $false
            try { $redirected = [Console]::IsInputRedirected } catch { $redirected = $false }
            if ($redirected) { return 'QUIT' }
            continue
        }
        elseif ($choice -match '^[Qq]$') {
            return 'QUIT'
        }
        elseif ($choice -match '^[Bb]$') {
            return 'BACK'
        }
        elseif ($choice -match '^[Aa]$') {
            $runnable = @($module.Items | Where-Object { $_.Available })
            if ($runnable.Count -eq 0) {
                Write-Host '[INFO] Nothing in this module is available on this machine.' -ForegroundColor Gray
            }
            else {
                $before = @($script:ADTResults).Count
                foreach ($item in $runnable) {
                    $null = Invoke-ADTMenuEntry -Entry $item
                }
                $null = Write-ADTRunSummary -StartIndex $before -Title ($module.Name + ' - run summary')
                Wait-ADTMenuPause
            }
        }
        elseif ($choice -match '^\d+$') {
            $wanted = [int]$choice
            $selected = @($module.Items | Where-Object { $_.Available -and $_.Number -eq $wanted })
            if ($selected.Count -eq 0) {
                Write-Host ('[INFO] There is no item numbered ' + $choice + ' in this module.') -ForegroundColor Gray
            }
            else {
                $before = @($script:ADTResults).Count
                $null = Invoke-ADTMenuEntry -Entry $selected[0]
                $null = Write-ADTRunSummary -StartIndex $before -Title ($selected[0].Label + ' - result summary')
                Wait-ADTMenuPause
            }
        }
        elseif ($choice -match '^[Cc]\d+$') {
            # No result summary and no result records: a direct command is not a check, so it
            # must not move the run's counters or its exit code. Invoke-ADTDirectCommand owns
            # its own pause - a command that never ran does not hold the screen.
            # TryParse, not a cast: 'c' followed by more digits than an int can hold would
            # throw, and rule 5 says the menu never dies. 0 matches no command, so an
            # unparseable number falls through to the "no command numbered" message.
            $wanted = 0
            if (-not [int]::TryParse($choice.Substring(1), [ref]$wanted)) { $wanted = 0 }
            $selectedCommand = @($commands | Where-Object { $_.Available -and $_.Number -eq $wanted })
            if ($selectedCommand.Count -eq 0) {
                Write-Host ('[INFO] There is no command numbered ' + $choice + ' in this module.') -ForegroundColor Gray
            }
            else {
                $null = Invoke-ADTDirectCommand -Command $selectedCommand[0]
            }
        }
        else {
            $runnableCommands = @($commands | Where-Object { $_.Available })
            if ($runnableCommands.Count -gt 0) {
                Write-Host '[INFO] Unrecognised choice. Enter an item number, cN, A, B or Q.' -ForegroundColor Gray
            }
            else {
                Write-Host '[INFO] Unrecognised choice. Enter an item number, A, B or Q.' -ForegroundColor Gray
            }
        }
    }
}

function Invoke-ADTSnapshot {
    <#
        .SYNOPSIS
            Run every registered item with Snapshot = $true whose Requires are met.
        .OUTPUTS
            The exit code implied by the results this snapshot produced.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$ModuleFilter
    )

    $startIndex = @($script:ADTResults).Count

    $candidates = @(Get-ADTMenuEntry | Where-Object { $_.Snapshot })

    if ($null -ne $ModuleFilter -and $ModuleFilter.Count -gt 0) {
        $filtered = @()
        foreach ($entry in $candidates) {
            foreach ($pattern in $ModuleFilter) {
                if ($entry.ModuleName -like $pattern) {
                    $filtered += $entry
                    break
                }
            }
        }
        $candidates = @($filtered)
    }

    $runnable = @($candidates | Where-Object { $_.Available })
    $blocked  = @($candidates | Where-Object { -not $_.Available })

    Write-ADTSection -Title ('SNAPSHOT - ' + $env:COMPUTERNAME + ' - ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

    if ($runnable.Count -eq 0) {
        Write-ADTNote -Text 'No snapshot items are available on this machine with the current capabilities and filter.'
    }

    if ($blocked.Count -gt 0) {
        Write-ADTNote -Text ([string]$blocked.Count + ' snapshot item(s) skipped because their required capabilities are missing.')
    }

    foreach ($entry in $runnable) {
        Invoke-ADTMenuEntry -Entry $entry
    }

    return (Write-ADTRunSummary -StartIndex $startIndex -Title 'SNAPSHOT SUMMARY')
}

#endregion

try {

    #region Transcript
    # Started before anything else so module load problems land in the log too. Common is not
    # loaded yet at this point, so the folder is created inline here.

    if (-not $NoTranscript) {
        try {
            $logDirectory = Join-Path -Path $script:ADTRoot -ChildPath 'Logs'
            if (-not (Test-Path -LiteralPath $logDirectory)) {
                $null = New-Item -Path $logDirectory -ItemType Directory -Force -ErrorAction Stop
            }
            $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
            $logName = 'ADT-' + $env:COMPUTERNAME + '-' + $stamp + '.log'
            $logPath = Join-Path -Path $logDirectory -ChildPath $logName
            $null = Start-Transcript -Path $logPath -ErrorAction Stop
            $script:ADTTranscriptOn = $true
        }
        catch {
            Write-Host ('[WARN] Transcript could not be started: ' + $_.Exception.Message) -ForegroundColor Yellow
        }
    }

    #endregion

    #region Module loading
    # Dot-sourcing must stay at script scope, so this block is deliberately inline rather
    # than wrapped in a function. Common first, CloudCommon second, then the rest by name.
    # A missing module file is not an error; its menu entries simply do not exist.

    $moduleDirectory = Join-Path -Path $script:ADTRoot -ChildPath 'modules'
    $commonPath      = Join-Path -Path $moduleDirectory -ChildPath 'ADT.Common.ps1'
    $cloudCommonPath = Join-Path -Path $moduleDirectory -ChildPath 'ADT.CloudCommon.ps1'

    if (-not (Test-Path -LiteralPath $commonPath)) {
        Write-Host ''
        Write-Host '[FAIL] modules\ADT.Common.ps1 is missing. ADT cannot start without it.' -ForegroundColor Red
        Write-Host ('  Looked in: ' + $moduleDirectory) -ForegroundColor Red
        $script:ADTExitCode = 3
    }
    else {
        $loadOrder = @($commonPath)
        if (Test-Path -LiteralPath $cloudCommonPath) { $loadOrder += $cloudCommonPath }

        $otherFiles = @()
        try {
            $otherFiles = @(Get-ChildItem -LiteralPath $moduleDirectory -Filter 'ADT.*.ps1' -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | Sort-Object -Property Name)
        }
        catch {
            $otherFiles = @()
        }

        foreach ($file in $otherFiles) {
            if ($file.FullName -eq $commonPath) { continue }
            if ($file.FullName -eq $cloudCommonPath) { continue }
            $loadOrder += $file.FullName
        }

        foreach ($modulePath in $loadOrder) {
            try {
                . $modulePath
            }
            catch {
                $leaf = Split-Path -Path $modulePath -Leaf
                Write-Host ('[ERR ] Module failed to load: ' + $leaf + ' - ' + $_.Exception.Message) -ForegroundColor Magenta
            }
        }

        if (Get-Command -Name 'Write-ADTResult' -CommandType Function -ErrorAction SilentlyContinue) {
            $script:ADTReady = $true
        }
        else {
            Write-Host '[FAIL] ADT.Common.ps1 loaded but the output engine is missing.' -ForegroundColor Red
            $script:ADTExitCode = 3
        }
    }

    #endregion

    if ($script:ADTReady) {

        if ($PSVersionTable.PSVersion.Major -lt 5) {
            Write-Host ''
            Write-Host ('[WARN] Windows PowerShell 5.1 is the supported floor; this host is ' + $PSVersionTable.PSVersion.ToString() + '. Some checks may not work.') -ForegroundColor Yellow
        }

        $null = Get-ADTCapabilities
        Show-ADTBanner

        if ($Snapshot) {

            #region Snapshot mode

            $script:ADTNonInteractive = $true
            $script:ADTExitCode = Invoke-ADTSnapshot -ModuleFilter $Modules

            #endregion
        }
        else {

            #region Interactive menu

            $sessionStart = @($script:ADTResults).Count
            $quit = $false

            while (-not $quit) {
                # $moduleList, not $modules - $Modules is the script parameter that carries the
                # -Modules snapshot filter, and PowerShell variable names are case-insensitive.
                $moduleList = @(Get-ADTModuleList)
                Show-ADTMainMenu -ModuleList $moduleList

                $choice = Read-Host -Prompt 'Select'
                if ($null -eq $choice) { $choice = '' }
                $choice = $choice.Trim()

                if ($choice -eq '') {
                    # At end-of-stream on redirected input, Read-Host returns '' forever;
                    # without this guard the menu would repaint in an infinite loop.
                    $redirected = $false
                    try { $redirected = [Console]::IsInputRedirected } catch { $redirected = $false }
                    if ($redirected) { $quit = $true }
                    continue
                }
                elseif ($choice -match '^[Qq]$') {
                    $quit = $true
                }
                elseif ($choice -match '^[Rr]$') {
                    Write-ADTNote -Text 'Re-detecting capabilities ...'
                    $null = Get-ADTCapabilities
                    Show-ADTBanner
                }
                elseif ($choice -match '^[Ss]$') {
                    $null = Invoke-ADTSnapshot -ModuleFilter $Modules
                    Wait-ADTMenuPause
                }
                elseif ($choice -match '^\d+$') {
                    $wanted = [int]$choice
                    $selected = @($moduleList | Where-Object { $_.Available -and $_.Number -eq $wanted })
                    if ($selected.Count -eq 0) {
                        Write-Host ('[INFO] There is no module numbered ' + $choice + '.') -ForegroundColor Gray
                    }
                    else {
                        $action = @(Invoke-ADTModuleMenu -ModuleName $selected[0].Name)
                        if ($action -contains 'QUIT') { $quit = $true }
                    }
                }
                else {
                    Write-Host '[INFO] Unrecognised choice. Enter a module number, S, R or Q.' -ForegroundColor Gray
                }
            }

            $script:ADTExitCode = Write-ADTRunSummary -StartIndex $sessionStart -Title 'END OF RUN SUMMARY'

            #endregion
        }
    }
}
finally {
    if ($script:ADTTranscriptOn) {
        try { $null = Stop-Transcript } catch { $null = $_ }
    }
}

# Only snapshot mode sets a process exit code; interactive runs leave the host session alone.
if ($Snapshot) {
    exit $script:ADTExitCode
}
