# ADT.Sysinternals.ps1 - inventory, fetch and launch Sysinternals tools from the Tools folder.
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.
#
# Writes are limited to the two the contract sanctions: downloads into Tools\, and
# HKCU\Software\Sysinternals\<Tool>\EulaAccepted when a tool is launched. Nothing on the
# target environment is touched.

#region Private helpers

function Get-ADTSysinternalsCatalog {
    <#
        .SYNOPSIS
            The AD field toolset: friendly name, the exe file names on live.sysinternals.com,
            and what each one is for.
        .DESCRIPTION
            File names and casing were taken from the live.sysinternals.com directory listing,
            including which tools ship a separate 64-bit executable. Windows file names are
            case-insensitive, so casing only matters for readability here.
    #>
    [CmdletBinding()]
    param()

    return @(
        [PSCustomObject]@{
            Name    = 'Process Explorer'
            Files   = @('procexp.exe', 'procexp64.exe')
            Purpose = 'Process tree, handles, DLLs, signature checks'
        }
        [PSCustomObject]@{
            Name    = 'Process Monitor'
            Files   = @('Procmon.exe', 'Procmon64.exe')
            Purpose = 'Live file, registry, process and network trace'
        }
        [PSCustomObject]@{
            Name    = 'AD Explorer'
            Files   = @('ADExplorer.exe', 'ADExplorer64.exe')
            Purpose = 'Browse and snapshot Active Directory, compare snapshots'
        }
        [PSCustomObject]@{
            Name    = 'AD Insight'
            Files   = @('ADInsight.exe', 'ADInsight64.exe')
            Purpose = 'Real-time LDAP trace of what an application asks AD'
        }
        [PSCustomObject]@{
            Name    = 'TCPView'
            Files   = @('tcpview.exe', 'tcpview64.exe')
            Purpose = 'Live TCP and UDP endpoints per process'
        }
        [PSCustomObject]@{
            Name    = 'Autoruns'
            Files   = @('Autoruns.exe', 'Autoruns64.exe')
            Purpose = 'Everything configured to start automatically'
        }
        [PSCustomObject]@{
            Name    = 'PsExec'
            Files   = @('PsExec.exe', 'PsExec64.exe')
            Purpose = 'Run a command on a remote machine'
        }
        [PSCustomObject]@{
            Name    = 'PsList'
            Files   = @('pslist.exe', 'pslist64.exe')
            Purpose = 'Process listing, local or remote'
        }
        [PSCustomObject]@{
            Name    = 'PsPing'
            Files   = @('psping.exe', 'psping64.exe')
            Purpose = 'ICMP, TCP, latency and bandwidth testing'
        }
        [PSCustomObject]@{
            Name    = 'PsLoggedon'
            Files   = @('PsLoggedon.exe', 'PsLoggedon64.exe')
            Purpose = 'Who is logged on locally and over shares'
        }
    )
}

function Get-ADTSysinternalsToolUrl {
    <#
        .SYNOPSIS
            Per-tool download URL. Verified endpoint: https://live.sysinternals.com/<name>.exe
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName
    )

    return ('https://live.sysinternals.com/' + $FileName)
}

function Get-ADTSysinternalsSuiteUrl {
    <#
        .SYNOPSIS
            Full suite zip. Verified endpoint.
    #>
    [CmdletBinding()]
    param()

    return 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
}

function Format-ADTByteSize {
    <#
        .SYNOPSIS
            Render a byte count as a short human-readable string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [double]$Bytes
    )

    if ($Bytes -ge 1048576) { return ('{0:N1} MB' -f ($Bytes / 1048576)) }
    if ($Bytes -ge 1024)    { return ('{0:N0} KB' -f ($Bytes / 1024)) }
    return ('{0:N0} B' -f $Bytes)
}

function Get-ADTSysinternalsFileVersion {
    <#
        .SYNOPSIS
            File version of a cached tool, or 'unknown' if it cannot be read. Never throws.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($null -ne $item.VersionInfo -and $item.VersionInfo.FileVersion) {
            return ([string]$item.VersionInfo.FileVersion).Trim()
        }
    }
    catch {
        $null = $_
    }
    return 'unknown'
}

function Invoke-ADTSysinternalsDownload {
    <#
        .SYNOPSIS
            Download one file into the Tools folder. Never throws.
        .DESCRIPTION
            TLS 1.2 is forced first. The file lands as .part and is only moved into place on
            success, so a broken transfer never leaves something that looks like a good tool.
        .OUTPUTS
            Hashtable with Success, Message and Bytes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    $outcome = @{ Success = $false; Message = ''; Bytes = 0 }
    $partial = $Destination + '.part'
    $savedProgress = $ProgressPreference

    try {
        $null = Enable-ADTTls12

        # Invoke-WebRequest's own progress bar makes downloads dramatically slower on
        # Windows PowerShell 5.1, so it is suppressed for the duration of the transfer.
        $ProgressPreference = 'SilentlyContinue'

        if (Test-Path -LiteralPath $partial) {
            Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
        }

        Invoke-WebRequest -Uri $Url -OutFile $partial -UseBasicParsing -TimeoutSec 300 -ErrorAction Stop

        if (-not (Test-Path -LiteralPath $partial)) {
            $outcome.Message = 'The download reported success but no file was written.'
            return $outcome
        }

        $partialItem = Get-Item -LiteralPath $partial -ErrorAction Stop
        if ($partialItem.Length -le 0) {
            Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
            $outcome.Message = 'The download produced a zero-byte file.'
            return $outcome
        }

        Move-Item -LiteralPath $partial -Destination $Destination -Force -ErrorAction Stop

        $outcome.Success = $true
        $outcome.Bytes = $partialItem.Length
    }
    catch {
        $outcome.Message = $_.Exception.Message
        if (Test-Path -LiteralPath $partial) {
            Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
        }
    }
    finally {
        $ProgressPreference = $savedProgress
    }

    return $outcome
}

function Set-ADTSysinternalsEula {
    <#
        .SYNOPSIS
            Record EULA acceptance for a tool under HKCU so it launches without a dialog.
        .DESCRIPTION
            This is one of the writes the contract explicitly sanctions:
            HKCU\Software\Sysinternals\<Tool>\EulaAccepted = 1. It touches the current user's
            hive only, never HKLM and never the target environment.

            UNVERIFIED: some Sysinternals tools key off a friendly name (for example
            'Process Explorer') rather than the executable name, so a EULA prompt can still
            appear for those. Both the exe name and the exe name without a trailing 64 are
            written, which covers the tools that use the executable name.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName
    )

    $written = @()

    try {
        $base = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
        $candidates = @($base)
        if ($base -match '64$' -and $base.Length -gt 2) {
            $candidates += $base.Substring(0, $base.Length - 2)
        }

        foreach ($candidate in $candidates) {
            $keyPath = 'HKCU:\Software\Sysinternals\' + $candidate
            try {
                if (-not (Test-Path -LiteralPath $keyPath)) {
                    $null = New-Item -Path $keyPath -Force -ErrorAction Stop
                }
                $null = New-ItemProperty -Path $keyPath -Name 'EulaAccepted' -Value 1 -PropertyType DWord -Force -ErrorAction Stop
                $written += $candidate
            }
            catch {
                $null = $_
            }
        }
    }
    catch {
        $null = $_
    }

    return $written
}

#endregion

#region Menu entries

function Invoke-ADTSysinternalsStatus {
    <#
        .SYNOPSIS
            List what is cached in Tools\ with file versions, and say what the AD set is missing.
    #>
    [CmdletBinding()]
    param()

    try {
        $toolsPath = Get-ADTToolsPath
        Write-ADTNote -Text ('Tools folder: ' + $toolsPath)

        $files = @()
        try {
            $files = @(Get-ChildItem -LiteralPath $toolsPath -Filter '*.exe' -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | Sort-Object -Property Name)
        }
        catch {
            $files = @()
        }

        $inventory = @()
        $totalBytes = 0
        foreach ($file in $files) {
            $totalBytes = $totalBytes + $file.Length
            $inventory += [PSCustomObject]@{
                Name     = $file.Name
                Version  = (Get-ADTSysinternalsFileVersion -Path $file.FullName)
                Size     = (Format-ADTByteSize -Bytes $file.Length)
                Modified = $file.LastWriteTime
                Path     = $file.FullName
            }
        }

        if ($inventory.Count -eq 0) {
            $emptyFix = @(
                'Run the TOOLS menu item "Get AD toolset" to fetch the per-tool set from https://live.sysinternals.com/',
                ('Offline: copy the exe files into ' + $toolsPath + ' by hand and re-run this check.')
            )
            Write-ADTResult -Check 'Sysinternals cache' -Status INFO -Detail ('No tools cached in ' + $toolsPath) -Fix $emptyFix
        }
        else {
            foreach ($entry in $inventory) {
                Write-ADTNote -Text ('{0,-22} v{1,-16} {2,10}   {3}' -f $entry.Name, $entry.Version, $entry.Size, $entry.Modified.ToString('yyyy-MM-dd'))
            }
            $cacheDetail = [string]$inventory.Count + ' tool(s) cached, ' + (Format-ADTByteSize -Bytes $totalBytes) + ' total'
            Write-ADTResult -Check 'Sysinternals cache' -Status INFO -Detail $cacheDetail -Data $inventory
        }

        # Which of the AD field set is missing? Missing tools are informational, not a fault.
        $missing = @()
        foreach ($tool in Get-ADTSysinternalsCatalog) {
            $present = $false
            foreach ($fileName in $tool.Files) {
                if (Test-Path -LiteralPath (Join-Path -Path $toolsPath -ChildPath $fileName)) { $present = $true }
            }
            if (-not $present) { $missing += $tool.Name }
        }

        if ($missing.Count -eq 0) {
            Write-ADTResult -Check 'Sysinternals AD toolset' -Status PASS -Detail 'All ten AD field tools are cached locally.'
        }
        else {
            $missingDetail = [string]$missing.Count + ' of 10 AD field tools missing: ' + ($missing -join ', ')
            Write-ADTResult -Check 'Sysinternals AD toolset' -Status INFO -Detail $missingDetail -Fix @('Run the TOOLS menu item "Get AD toolset".') -Data $missing
        }

        # Suite folder, if the full suite was ever pulled down.
        $suitePath = Join-Path -Path $toolsPath -ChildPath 'SysinternalsSuite'
        if (Test-Path -LiteralPath $suitePath) {
            $suiteFiles = @(Get-ChildItem -LiteralPath $suitePath -Filter '*.exe' -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer })
            Write-ADTResult -Check 'Sysinternals full suite' -Status INFO -Detail ([string]$suiteFiles.Count + ' executable(s) extracted in ' + $suitePath)
        }
    }
    catch {
        Write-ADTResult -Check 'Sysinternals status' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTSysinternalsGetADSet {
    <#
        .SYNOPSIS
            Download the ten-tool AD field set from live.sysinternals.com into Tools\.
    #>
    [CmdletBinding()]
    param()

    try {
        $toolsPath = Get-ADTToolsPath
        $catalog = @(Get-ADTSysinternalsCatalog)

        $wanted = @()
        foreach ($tool in $catalog) {
            foreach ($fileName in $tool.Files) {
                $wanted += [PSCustomObject]@{
                    Tool        = $tool.Name
                    FileName    = $fileName
                    Destination = (Join-Path -Path $toolsPath -ChildPath $fileName)
                    Url         = (Get-ADTSysinternalsToolUrl -FileName $fileName)
                }
            }
        }

        $existing = @($wanted | Where-Object { Test-Path -LiteralPath $_.Destination })

        $refresh = $false
        if ($existing.Count -gt 0) {
            Write-ADTNote -Text ([string]$existing.Count + ' of ' + [string]$wanted.Count + ' file(s) are already cached in ' + $toolsPath)
            $refresh = Confirm-ADTAction -Prompt 'Re-download and overwrite the files that are already there?'
            if (-not $refresh) {
                Write-ADTNote -Text 'Keeping the cached copies; only missing files will be fetched.'
            }
        }

        $queue = @($wanted)
        if (-not $refresh) {
            $queue = @($wanted | Where-Object { -not (Test-Path -LiteralPath $_.Destination) })
        }

        if ($queue.Count -eq 0) {
            Write-ADTResult -Check 'Sysinternals AD toolset' -Status PASS -Detail 'Nothing to download; the full AD field set is already cached.'
            return
        }

        Write-ADTNote -Text ('Downloading ' + [string]$queue.Count + ' file(s) from https://live.sysinternals.com/ ...')

        $downloaded = @()
        $failures = @()
        $index = 0

        foreach ($item in $queue) {
            $index = $index + 1
            Write-ADTNote -Text ('[{0}/{1}] {2} ...' -f $index, $queue.Count, $item.FileName)

            $outcome = Invoke-ADTSysinternalsDownload -Url $item.Url -Destination $item.Destination

            if ($outcome.Success) {
                $downloaded += $item.FileName
                Write-ADTNote -Text ('        ok, ' + (Format-ADTByteSize -Bytes $outcome.Bytes))
            }
            else {
                $failures += ($item.FileName + ': ' + $outcome.Message)
                Write-ADTNote -Text ('        failed - ' + $outcome.Message)
            }
        }

        $manualFix = @(
            ('Download the tools by hand from https://live.sysinternals.com/ and drop the exe files into ' + $toolsPath),
            'Behind a proxy: [Net.WebRequest]::DefaultWebProxy = New-Object Net.WebProxy("http://PROXY:PORT"); [Net.WebRequest]::DefaultWebProxy.Credentials = [Net.CredentialCache]::DefaultCredentials',
            'Already-cached tools still work offline: use the TOOLS menu item "Launch a tool".'
        )

        if ($failures.Count -eq 0) {
            Write-ADTResult -Check 'Sysinternals AD toolset' -Status PASS -Detail ('Downloaded ' + [string]$downloaded.Count + ' file(s) into ' + $toolsPath) -Data $downloaded
        }
        elseif ($downloaded.Count -gt 0) {
            $partialDetail = 'Downloaded ' + [string]$downloaded.Count + ' file(s); ' + [string]$failures.Count + ' failed.'
            Write-ADTResult -Check 'Sysinternals AD toolset' -Status WARN -Detail $partialDetail -Why ($failures -join ' | ') -Fix $manualFix -Data $failures
        }
        else {
            $offlineWhy = 'No file could be fetched. This machine most likely has no route to live.sysinternals.com, or a proxy is in the way. First failure: ' + $failures[0]
            Write-ADTResult -Check 'Sysinternals AD toolset' -Status FAIL -Detail ('All ' + [string]$queue.Count + ' download(s) failed.') -Why $offlineWhy -Fix $manualFix -Data $failures
        }
    }
    catch {
        Write-ADTResult -Check 'Sysinternals AD toolset' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTSysinternalsGetSuite {
    <#
        .SYNOPSIS
            Download the full Sysinternals Suite zip and extract it under Tools\.
    #>
    [CmdletBinding()]
    param()

    try {
        $toolsPath = Get-ADTToolsPath
        $zipPath = Join-Path -Path $toolsPath -ChildPath 'SysinternalsSuite.zip'
        $suitePath = Join-Path -Path $toolsPath -ChildPath 'SysinternalsSuite'
        $suiteUrl = Get-ADTSysinternalsSuiteUrl

        Write-ADTNote -Text 'WARNING: the full Sysinternals Suite is roughly 190 MB.'
        Write-ADTNote -Text 'On a metered link, a slow client VPN, or a small jump box, use "Get AD toolset" instead - it is a few MB.'
        Write-ADTNote -Text ('Source: ' + $suiteUrl)
        Write-ADTNote -Text ('Target: ' + $suitePath)

        if (Test-Path -LiteralPath $zipPath) {
            Write-ADTNote -Text 'A copy of SysinternalsSuite.zip is already cached here.'
        }

        if (-not (Confirm-ADTAction -Prompt 'Download roughly 190 MB now and extract it into the Tools folder?')) {
            $skipFix = @(
                'Prefer the small set: run the TOOLS menu item "Get AD toolset".',
                ('Or download ' + $suiteUrl + ' on another machine and unzip it into ' + $suitePath)
            )
            Write-ADTResult -Check 'Sysinternals full suite' -Status SKIP -Detail 'Not confirmed; nothing was downloaded.' -Fix $skipFix
            return
        }

        Write-ADTNote -Text 'Downloading SysinternalsSuite.zip ... this can take several minutes.'
        $outcome = Invoke-ADTSysinternalsDownload -Url $suiteUrl -Destination $zipPath

        if (-not $outcome.Success) {
            $suiteFix = @(
                ('Download ' + $suiteUrl + ' on a connected machine and unzip it into ' + $suitePath),
                'Behind a proxy: [Net.WebRequest]::DefaultWebProxy = New-Object Net.WebProxy("http://PROXY:PORT"); [Net.WebRequest]::DefaultWebProxy.Credentials = [Net.CredentialCache]::DefaultCredentials'
            )
            Write-ADTResult -Check 'Sysinternals full suite' -Status FAIL -Detail 'The suite download failed.' -Why $outcome.Message -Fix $suiteFix
            return
        }

        Write-ADTNote -Text ('Downloaded ' + (Format-ADTByteSize -Bytes $outcome.Bytes) + '. Extracting ...')

        $expandCmd = Get-Command -Name 'Expand-Archive' -ErrorAction SilentlyContinue
        if ($null -eq $expandCmd) {
            $noExpandWhy = 'Expand-Archive is not available on this host, so the zip was left in place rather than extracted.'
            Write-ADTResult -Check 'Sysinternals full suite' -Status WARN -Detail ('Downloaded to ' + $zipPath + ' but not extracted.') -Why $noExpandWhy -Fix @(('Unzip ' + $zipPath + ' into ' + $suitePath + ' by hand.'))
            return
        }

        try {
            $null = Initialize-ADTFolder -Path $suitePath
            Expand-Archive -LiteralPath $zipPath -DestinationPath $suitePath -Force -ErrorAction Stop
        }
        catch {
            Write-ADTResult -Check 'Sysinternals full suite' -Status WARN -Detail ('Downloaded to ' + $zipPath + ' but extraction failed.') -Why $_.Exception.Message -Fix @(('Unzip ' + $zipPath + ' into ' + $suitePath + ' by hand.'))
            return
        }

        $extracted = @(Get-ChildItem -LiteralPath $suitePath -Filter '*.exe' -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer })
        $suiteDetail = 'Downloaded and extracted ' + [string]$extracted.Count + ' executable(s) into ' + $suitePath
        Write-ADTResult -Check 'Sysinternals full suite' -Status PASS -Detail $suiteDetail -Data $suitePath
    }
    catch {
        Write-ADTResult -Check 'Sysinternals full suite' -Status ERROR -Detail $_.Exception.Message
    }
}

function Invoke-ADTSysinternalsLaunch {
    <#
        .SYNOPSIS
            Pick a cached tool from Tools\ and launch it, accepting its EULA under HKCU first.
    #>
    [CmdletBinding()]
    param()

    try {
        $toolsPath = Get-ADTToolsPath

        $files = @()
        try {
            $files = @(Get-ChildItem -LiteralPath $toolsPath -Filter '*.exe' -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | Sort-Object -Property Name)
        }
        catch {
            $files = @()
        }

        $suitePath = Join-Path -Path $toolsPath -ChildPath 'SysinternalsSuite'
        if (Test-Path -LiteralPath $suitePath) {
            try {
                $files += @(Get-ChildItem -LiteralPath $suitePath -Filter '*.exe' -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | Sort-Object -Property Name)
            }
            catch {
                $null = $_
            }
        }

        if ($files.Count -eq 0) {
            $noneFix = @(
                'Run the TOOLS menu item "Get AD toolset" to fetch them.',
                ('Offline: copy the exe files into ' + $toolsPath + ' by hand.')
            )
            Write-ADTResult -Check 'Launch a Sysinternals tool' -Status INFO -Detail ('No tools are cached in ' + $toolsPath) -Fix $noneFix
            return
        }

        if ($script:ADTNonInteractive) {
            Write-ADTResult -Check 'Launch a Sysinternals tool' -Status SKIP -Detail 'Launching a tool needs an interactive session.' -Why 'ADT is running non-interactively, so there is nobody to pick a tool or drive its window.'
            return
        }

        # This is a picker, not a result, so it uses Write-Host in the same way the launcher
        # menu does. Nothing here is recorded in $script:ADTResults.
        Write-ADTNote -Text ('Cached tools in ' + $toolsPath + ':')
        $index = 0
        $choices = @()
        foreach ($file in $files) {
            $index = $index + 1
            $version = Get-ADTSysinternalsFileVersion -Path $file.FullName
            $choices += [PSCustomObject]@{ Number = $index; File = $file }
            Write-Host ('      [{0,2}] {1,-24} v{2}' -f $index, $file.Name, $version)
        }
        Write-Host ''

        $answer = Read-Host -Prompt 'Tool number to launch (blank or Q to cancel)'
        if ($null -eq $answer) { $answer = '' }
        $answer = $answer.Trim()

        if ($answer -eq '' -or $answer -match '^[Qq]$') {
            Write-ADTResult -Check 'Launch a Sysinternals tool' -Status SKIP -Detail 'Cancelled; nothing was launched.'
            return
        }

        if ($answer -notmatch '^\d+$') {
            Write-ADTResult -Check 'Launch a Sysinternals tool' -Status SKIP -Detail ('"' + $answer + '" is not a tool number; nothing was launched.')
            return
        }

        $wanted = [int]$answer
        $picked = @($choices | Where-Object { $_.Number -eq $wanted })
        if ($picked.Count -eq 0) {
            Write-ADTResult -Check 'Launch a Sysinternals tool' -Status SKIP -Detail ('There is no tool numbered ' + $answer + '; nothing was launched.')
            return
        }

        $target = $picked[0].File

        # Sanctioned write: HKCU\Software\Sysinternals\<Tool>\EulaAccepted = 1, so the tool
        # does not stop on its licence dialog.
        $eulaKeys = @(Set-ADTSysinternalsEula -FileName $target.Name)
        if ($eulaKeys.Count -gt 0) {
            Write-ADTNote -Text ('EULA acceptance recorded under HKCU\Software\Sysinternals\ for: ' + ($eulaKeys -join ', '))
        }
        else {
            Write-ADTNote -Text 'Could not write EULA acceptance to HKCU; the tool may show its licence dialog.'
        }

        try {
            $null = Start-Process -FilePath $target.FullName -ErrorAction Stop
        }
        catch {
            $startWhy = 'Start-Process could not launch the executable. On a Server Core box or a session with no desktop, a GUI tool has nowhere to draw.'
            Write-ADTResult -Check 'Launch a Sysinternals tool' -Status FAIL -Detail ('Could not launch ' + $target.Name) -Why ($startWhy + ' Error: ' + $_.Exception.Message) -Fix @(('Start-Process -FilePath "' + $target.FullName + '"'))
            return
        }

        $launchDetail = 'Launched ' + $target.Name + ' (v' + (Get-ADTSysinternalsFileVersion -Path $target.FullName) + ')'
        Write-ADTResult -Check 'Launch a Sysinternals tool' -Status INFO -Detail $launchDetail -Data $target.FullName
    }
    catch {
        Write-ADTResult -Check 'Launch a Sysinternals tool' -Status ERROR -Detail $_.Exception.Message
    }
}

#endregion

Register-ADTModule -Name 'Sysinternals' -Group 'TOOLS' -Items @(
    @{ Label = 'Sysinternals status'; Function = 'Invoke-ADTSysinternalsStatus';   Requires = @();              Snapshot = $true }
    @{ Label = 'Get AD toolset';      Function = 'Invoke-ADTSysinternalsGetADSet'; Requires = @('HasInternet'); Snapshot = $false }
    @{ Label = 'Get full suite';      Function = 'Invoke-ADTSysinternalsGetSuite'; Requires = @('HasInternet'); Snapshot = $false }
    @{ Label = 'Launch a tool';       Function = 'Invoke-ADTSysinternalsLaunch';   Requires = @();              Snapshot = $false }
)
