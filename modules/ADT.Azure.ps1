# ADT.Azure.ps1 - Azure compute posture: inventory, VM hygiene, backup protection, Advisor digest.
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.

#region Private helpers

function Get-ADTAzCloudState {
    <#
        .SYNOPSIS
            Defensively read the Az connection state off Get-ADTCloudContext. Never throws.
        .DESCRIPTION
            The contract documents Get-ADTCloudContext as returning a PSCustomObject shaped
            "Graph/Az/EXO -> connected?, tenant, account". This reads
            Az.Connected / .Tenant / .Account defensively (PSObject.Properties checks rather
            than direct dot-access) so a minor shape difference in CloudCommon degrades to
            "not connected" - a safe SKIP - instead of an exception.
    #>
    [CmdletBinding()]
    param()

    $state = @{ Connected = $false; Tenant = ''; Account = '' }

    try {
        $cloudContextCmd = Get-Command -Name 'Get-ADTCloudContext' -ErrorAction SilentlyContinue
        if ($null -eq $cloudContextCmd) { return $state }

        $context = Get-ADTCloudContext
        if ($null -eq $context -or -not $context.PSObject.Properties['Az']) { return $state }

        $azState = $context.Az
        if ($null -eq $azState) { return $state }

        if ($azState.PSObject.Properties['Connected']) { $state.Connected = [bool]$azState.Connected }
        if ($azState.PSObject.Properties['Tenant'] -and $null -ne $azState.Tenant) { $state.Tenant = [string]$azState.Tenant }
        if ($azState.PSObject.Properties['Account'] -and $null -ne $azState.Account) { $state.Account = [string]$azState.Account }
    }
    catch {
        return @{ Connected = $false; Tenant = ''; Account = '' }
    }

    return $state
}

function Test-ADTAzCmdlet {
    <#
        .SYNOPSIS
            Is a cmdlet actually loaded right now? Never throws.
        .DESCRIPTION
            HasAzModule only proves Az.Accounts is present (see ADT.Common.ps1
            Get-ADTCapabilities). Az.Compute/Az.Network/Az.RecoveryServices/Az.Advisor are
            separate sub-modules; checking the cmdlet directly lets a missing sub-module
            degrade to a clean SKIP with install guidance instead of a hard error.
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

function Get-ADTAzVmPowerState {
    <#
        .SYNOPSIS
            Extract the PowerState display text ('VM running', 'VM stopped',
            'VM deallocated', ...) from a Get-AzVM -Status object's Statuses collection.
            Returns 'Unknown' on any shape mismatch or failure. Never throws.
        .DESCRIPTION
            Statuses[].Code ('PowerState/running', 'PowerState/deallocated', ...) and
            Statuses[].DisplayStatus ('VM running', 'VM stopped', 'VM deallocated', ...)
            verified on Microsoft Learn (Azure Virtual Machines states-billing doc's
            DisplayStatus JSON example, and the tutorial-manage-vm Statuses[1].Code usage).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Vm
    )

    try {
        if ($null -eq $Vm -or $null -eq $Vm.Statuses) { return 'Unknown' }
        $powerStatus = @($Vm.Statuses | Where-Object { [string]$_.Code -like 'PowerState/*' }) | Select-Object -First 1
        if ($null -eq $powerStatus) { return 'Unknown' }
        if ($powerStatus.PSObject.Properties['DisplayStatus'] -and -not [string]::IsNullOrEmpty($powerStatus.DisplayStatus)) {
            return [string]$powerStatus.DisplayStatus
        }
        return [string]$powerStatus.Code
    }
    catch {
        return 'Unknown'
    }
}

#endregion

#region Menu entries

function Invoke-ADTAzInventory {
    <#
        .SYNOPSIS
            Item 1: Subscription and VM inventory - current context, full VM list,
            stopped-but-allocated VMs flagged as still billing compute.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Subscription and VM inventory'

        $azState = Get-ADTAzCloudState
        if (-not $azState.Connected) {
            Write-ADTResult -Check 'Subscription and VM inventory' -Status 'SKIP' `
                -Detail 'not connected - run Connect Azure first' `
                -Why 'Every check in this item runs Az cmdlets against a subscription, and ADT never auto-connects inside a check.' `
                -Fix @('Connect-ADTAzure')
            return
        }

        # --- Current context ------------------------------------------------------------
        $context = $null
        try {
            $context = Get-AzContext -ErrorAction Stop
        }
        catch {
            Write-ADTResult -Check 'Get-AzContext' -Status 'ERROR' -Detail ('Failed: ' + $_.Exception.Message)
        }

        if ($null -eq $context) {
            Write-ADTResult -Check 'Current Azure context' -Status 'ERROR' -Detail 'Get-AzContext returned nothing even though Connect-ADTAzure reports connected.'
            return
        }

        $subName = 'Unknown'
        $subId = 'Unknown'
        $tenantId = 'Unknown'
        $accountId = 'Unknown'
        if ($null -ne $context.Subscription) {
            if ($context.Subscription.PSObject.Properties['Name'] -and -not [string]::IsNullOrEmpty([string]$context.Subscription.Name)) { $subName = [string]$context.Subscription.Name }
            if ($context.Subscription.PSObject.Properties['Id'] -and -not [string]::IsNullOrEmpty([string]$context.Subscription.Id)) { $subId = [string]$context.Subscription.Id }
        }
        if ($null -ne $context.Tenant -and $context.Tenant.PSObject.Properties['Id'] -and -not [string]::IsNullOrEmpty([string]$context.Tenant.Id)) { $tenantId = [string]$context.Tenant.Id }
        if ($null -ne $context.Account -and $context.Account.PSObject.Properties['Id'] -and -not [string]::IsNullOrEmpty([string]$context.Account.Id)) { $accountId = [string]$context.Account.Id }

        Write-ADTResult -Check 'Current Azure context' -Status 'INFO' `
            -Detail ('Subscription=' + $subName + ' (' + $subId + ') Tenant=' + $tenantId + ' Account=' + $accountId)

        # --- VM inventory -----------------------------------------------------------------
        $vms = @()
        try {
            $vms = @(Get-AzVM -Status -ErrorAction Stop)
        }
        catch {
            Write-ADTResult -Check 'Get-AzVM' -Status 'ERROR' -Detail ('Failed: ' + $_.Exception.Message)
            return
        }

        if ($vms.Count -eq 0) {
            Write-ADTResult -Check 'VM inventory' -Status 'INFO' -Detail 'No VMs found in this subscription.'
            return
        }

        foreach ($vm in $vms) {
            $powerState = Get-ADTAzVmPowerState -Vm $vm
            $osType = 'Unknown'
            if ($null -ne $vm.StorageProfile -and $null -ne $vm.StorageProfile.OsDisk -and $vm.StorageProfile.OsDisk.PSObject.Properties['OsType']) {
                $osType = [string]$vm.StorageProfile.OsDisk.OsType
            }
            $vmSize = 'Unknown'
            if ($null -ne $vm.HardwareProfile -and $vm.HardwareProfile.PSObject.Properties['VmSize']) { $vmSize = [string]$vm.HardwareProfile.VmSize }
            $vmDetail = 'RG=' + [string]$vm.ResourceGroupName + ' Size=' + $vmSize + ' Power=' + $powerState + ' OS=' + $osType

            if ($powerState -eq 'VM stopped') {
                Write-ADTResult -Check ('VM: ' + [string]$vm.Name) -Status 'WARN' -Detail $vmDetail `
                    -Why ('VM ' + [string]$vm.Name + ' is stopped but still allocated on a host, so it is still billing for compute - Azure only stops billing once a VM is deallocated (Stopped/Deallocated), not merely stopped.') `
                    -Fix @(('[SERVICE-AFFECTING] Stop-AzVM -ResourceGroupName ' + [string]$vm.ResourceGroupName + ' -Name ' + [string]$vm.Name + ' -Force   # deallocates the VM; confirm with the client it is really not needed first'))
            }
            else {
                Write-ADTResult -Check ('VM: ' + [string]$vm.Name) -Status 'INFO' -Detail $vmDetail
            }
        }
    }
    catch {
        Write-ADTResult -Check 'Subscription and VM inventory' -Status 'ERROR' -Detail ('Unhandled exception: ' + $_.Exception.Message)
    }
}

function Invoke-ADTAzHygiene {
    <#
        .SYNOPSIS
            Item 2: VM health and hygiene - per-VM agent status and boot diagnostics, plus
            subscription-wide unattached disks, unattached NICs, unassociated public IPs,
            and a capped disk-encryption sweep.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'VM health and hygiene'

        $azState = Get-ADTAzCloudState
        if (-not $azState.Connected) {
            Write-ADTResult -Check 'VM health and hygiene' -Status 'SKIP' `
                -Detail 'not connected - run Connect Azure first' `
                -Why 'Every check in this item runs Az cmdlets against a subscription, and ADT never auto-connects inside a check.' `
                -Fix @('Connect-ADTAzure')
            return
        }

        # --- Per-VM: agent status + boot diagnostics ---------------------------------------
        $vms = @()
        try {
            $vms = @(Get-AzVM -Status -ErrorAction Stop)
        }
        catch {
            Write-ADTResult -Check 'Get-AzVM' -Status 'ERROR' -Detail ('Failed: ' + $_.Exception.Message)
        }

        foreach ($vm in $vms) {
            $agentStatus = 'Unknown'
            try {
                if ($null -ne $vm.VMAgent -and $null -ne $vm.VMAgent.Statuses -and @($vm.VMAgent.Statuses).Count -gt 0) {
                    $agentStatus = [string]$vm.VMAgent.Statuses[0].DisplayStatus
                }
            }
            catch {
                $agentStatus = 'Unknown'
            }

            if ([string]::IsNullOrEmpty($agentStatus) -or $agentStatus -eq 'Unknown') {
                Write-ADTResult -Check ('VM agent: ' + [string]$vm.Name) -Status 'INFO' -Detail 'No VM agent status reported (Statuses was empty - common on Linux VMs without the extension, or the agent has not phoned home yet).'
            }
            elseif ($agentStatus -ne 'Ready') {
                Write-ADTResult -Check ('VM agent: ' + [string]$vm.Name) -Status 'WARN' -Detail ('DisplayStatus=' + $agentStatus) `
                    -Why 'The Azure VM agent is not reporting Ready, which can block extension installs (monitoring, disk encryption, patching) on this VM.' `
                    -Fix @(('Get-AzVM -ResourceGroupName ' + [string]$vm.ResourceGroupName + ' -Name ' + [string]$vm.Name + ' -Status | Select-Object -ExpandProperty VMAgent'), 'Inside the guest: confirm the Azure VM Agent (Windows) or WALinuxAgent (Linux) service is running.')
            }
            else {
                Write-ADTResult -Check ('VM agent: ' + [string]$vm.Name) -Status 'PASS' -Detail 'DisplayStatus=Ready'
            }

            $bootDiagEnabled = $false
            try {
                if ($null -ne $vm.DiagnosticsProfile -and $null -ne $vm.DiagnosticsProfile.BootDiagnostics -and $vm.DiagnosticsProfile.BootDiagnostics.PSObject.Properties['Enabled']) {
                    $bootDiagEnabled = [bool]$vm.DiagnosticsProfile.BootDiagnostics.Enabled
                }
            }
            catch {
                $bootDiagEnabled = $false
            }

            if ($bootDiagEnabled) {
                Write-ADTResult -Check ('Boot diagnostics: ' + [string]$vm.Name) -Status 'PASS' -Detail 'Enabled'
            }
            else {
                Write-ADTResult -Check ('Boot diagnostics: ' + [string]$vm.Name) -Status 'INFO' -Detail 'Disabled' `
                    -Why 'Boot diagnostics are cheap and are the fastest way to see the console/screenshot when a VM fails to boot - worth turning on if it is off by oversight rather than a deliberate choice.' `
                    -Fix @(
                        ('$targetVm = Get-AzVM -ResourceGroupName ' + [string]$vm.ResourceGroupName + ' -Name ' + [string]$vm.Name),
                        ('Set-AzVMBootDiagnostic -VM $targetVm -Enable -ResourceGroupName ' + [string]$vm.ResourceGroupName + ' -StorageAccountName <existingStorageAccountName>'),
                        ('Update-AzVM -VM $targetVm -ResourceGroupName ' + [string]$vm.ResourceGroupName)
                    )
            }
        }

        # --- Subscription-wide hygiene: unattached managed disks ---------------------------
        # DiskState 'Unattached' (exact PascalCase) verified on Microsoft Learn/dotnet API ref
        # (Disk.DiskState, DiskProperties.DiskState - both list 'Unattached' as a value).
        try {
            $disks = @(Get-AzDisk -ErrorAction Stop)
            $unattachedDisks = @($disks | Where-Object { [string]$_.DiskState -eq 'Unattached' })

            if ($unattachedDisks.Count -eq 0) {
                Write-ADTResult -Check 'Unattached managed disks' -Status 'PASS' -Detail '0 unattached disks.'
            }
            else {
                foreach ($disk in $unattachedDisks) {
                    $sizeGb = 'Unknown'
                    if ($disk.PSObject.Properties['DiskSizeGB']) { $sizeGb = [string]$disk.DiskSizeGB }
                    $skuName = 'Unknown'
                    if ($null -ne $disk.Sku -and $disk.Sku.PSObject.Properties['Name']) { $skuName = [string]$disk.Sku.Name }
                    Write-ADTResult -Check ('Unattached disk: ' + [string]$disk.Name) -Status 'WARN' `
                        -Detail ('RG=' + [string]$disk.ResourceGroupName + ' SizeGB=' + $sizeGb + ' SKU=' + $skuName) `
                        -Why 'An unattached managed disk is doing no work but is still billed for its provisioned size every month - pure cost with no VM using it.' `
                        -Fix @(('Confirm nothing needs it first, then: Remove-AzDisk -ResourceGroupName ' + [string]$disk.ResourceGroupName + ' -DiskName ' + [string]$disk.Name + ' -Force'))
                }
            }
        }
        catch {
            Write-ADTResult -Check 'Unattached managed disks' -Status 'ERROR' -Detail ('Get-AzDisk failed: ' + $_.Exception.Message)
        }

        # --- Unattached NICs (INFO count) ---------------------------------------------------
        # .VirtualMachine -eq $null as the "unattached" test is a long-standing community and
        # Microsoft Q&A accepted-answer pattern for Az.Network's PSNetworkInterface object;
        # a direct Microsoft Learn reference-page confirmation of this exact property was not
        # found this session, so this is flagged UNVERIFIED even though the source cmdlet
        # (Get-AzNetworkInterface) itself is fully verified.
        try {
            $nics = @(Get-AzNetworkInterface -ErrorAction Stop)
            $unattachedNics = @($nics | Where-Object { $null -eq $_.VirtualMachine })
            Write-ADTResult -Check 'Unattached network interfaces' -Status 'INFO' -Detail ($unattachedNics.Count.ToString() + ' of ' + $nics.Count.ToString() + ' NIC(s) not attached to a VM.')
        }
        catch {
            Write-ADTResult -Check 'Unattached network interfaces' -Status 'ERROR' -Detail ('Get-AzNetworkInterface failed: ' + $_.Exception.Message)
        }

        # --- Public IPs not associated to anything (WARN count) ------------------------------
        try {
            $publicIps = @(Get-AzPublicIpAddress -ErrorAction Stop)
            $unassociatedIps = @($publicIps | Where-Object { $null -eq $_.IpConfiguration })

            if ($unassociatedIps.Count -eq 0) {
                Write-ADTResult -Check 'Unassociated public IP addresses' -Status 'PASS' -Detail '0 unassociated public IPs.'
            }
            else {
                Write-ADTResult -Check 'Unassociated public IP addresses' -Status 'WARN' -Detail ($unassociatedIps.Count.ToString() + ' of ' + $publicIps.Count.ToString() + ' public IP(s) not associated with anything.') `
                    -Why 'An unassociated public IP (especially Standard SKU) is billed while sitting idle, and is worth an audit - it may be a leftover from a deleted resource rather than something intentionally reserved.' `
                    -Fix @('Get-AzPublicIpAddress | Where-Object { $null -eq $_.IpConfiguration } | Select-Object Name, ResourceGroupName, IpAddress, Sku')
            }
        }
        catch {
            Write-ADTResult -Check 'Unassociated public IP addresses' -Status 'ERROR' -Detail ('Get-AzPublicIpAddress failed: ' + $_.Exception.Message)
        }

        # --- Disk encryption status, capped at 20 VMs to avoid heavy per-VM RG round-trips ---
        # Get-AzVMDiskEncryptionStatus and its OsVolumeEncrypted/DataVolumesEncrypted
        # properties verified on Microsoft Learn (Az.Compute module reference + Azure Disk
        # Encryption sample-script/troubleshooting pages).
        if ($vms.Count -eq 0) {
            Write-ADTResult -Check 'Disk encryption status' -Status 'INFO' -Detail 'No VMs to check.'
        }
        else {
            $encCap = 20
            $vmsToCheck = @($vms | Select-Object -First $encCap)
            if ($vms.Count -gt $encCap) {
                Write-ADTNote -Text ('Disk encryption status: capped at the first ' + $encCap.ToString() + ' of ' + $vms.Count.ToString() + ' VM(s) - Get-AzVMDiskEncryptionStatus is a per-VM, per-resource-group round trip and gets expensive on a large subscription.')
            }

            foreach ($vm in $vmsToCheck) {
                try {
                    $encStatus = Get-AzVMDiskEncryptionStatus -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -ErrorAction Stop
                    $osEnc = 'Unknown'
                    if ($null -ne $encStatus -and $encStatus.PSObject.Properties['OsVolumeEncrypted']) { $osEnc = [string]$encStatus.OsVolumeEncrypted }
                    Write-ADTResult -Check ('Disk encryption: ' + [string]$vm.Name) -Status 'INFO' -Detail ('OsVolumeEncrypted=' + $osEnc)
                }
                catch {
                    Write-ADTResult -Check ('Disk encryption: ' + [string]$vm.Name) -Status 'ERROR' -Detail ('Get-AzVMDiskEncryptionStatus failed: ' + $_.Exception.Message)
                }
            }
        }
    }
    catch {
        Write-ADTResult -Check 'VM health and hygiene' -Status 'ERROR' -Detail ('Unhandled exception: ' + $_.Exception.Message)
    }
}

function Invoke-ADTAzBackup {
    <#
        .SYNOPSIS
            Item 3: Backup protection - Recovery Services vault inventory, per-VM protection
            status, unprotected VMs listed up to 15.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Backup protection'

        $azState = Get-ADTAzCloudState
        if (-not $azState.Connected) {
            Write-ADTResult -Check 'Backup protection' -Status 'SKIP' `
                -Detail 'not connected - run Connect Azure first' `
                -Why 'Every check in this item runs Az cmdlets against a subscription, and ADT never auto-connects inside a check.' `
                -Fix @('Connect-ADTAzure')
            return
        }

        if (-not (Test-ADTModuleAvailable -Name 'Az.RecoveryServices')) {
            Write-ADTResult -Check 'Backup protection' -Status 'SKIP' -Detail 'Az.RecoveryServices module is not installed.' `
                -Why 'Recovery Services vault and backup-status cmdlets ship in the Az.RecoveryServices module, which is not part of the core Az module set ADT expects by default.' `
                -Fix @('Install-Module Az.RecoveryServices -Scope CurrentUser -Force')
            return
        }

        $vaults = @()
        try {
            $vaults = @(Get-AzRecoveryServicesVault -ErrorAction Stop)
        }
        catch {
            Write-ADTResult -Check 'Get-AzRecoveryServicesVault' -Status 'ERROR' -Detail ('Failed: ' + $_.Exception.Message)
            return
        }

        if ($vaults.Count -eq 0) {
            Write-ADTResult -Check 'Recovery Services vaults' -Status 'WARN' -Detail '0 Recovery Services vaults found in this subscription.' `
                -Why 'No vault exists, so no Azure VM in this subscription can be protected by Azure Backup at all.' `
                -Fix @('New-AzRecoveryServicesVault -ResourceGroupName <rg> -Name <vaultName> -Location <region>   # then enable backup on the VMs that need it')
        }
        else {
            $vaultNames = (@($vaults | ForEach-Object { [string]$_.Name })) -join ', '
            Write-ADTResult -Check 'Recovery Services vaults' -Status 'INFO' -Detail ($vaults.Count.ToString() + ' vault(s): ' + $vaultNames)
        }

        $vms = @()
        try {
            $vms = @(Get-AzVM -ErrorAction Stop)
        }
        catch {
            Write-ADTResult -Check 'Get-AzVM' -Status 'ERROR' -Detail ('Failed: ' + $_.Exception.Message)
            return
        }

        if ($vms.Count -eq 0) {
            Write-ADTResult -Check 'VM backup protection' -Status 'INFO' -Detail 'No VMs found in this subscription.'
            return
        }

        # Get-AzRecoveryServicesBackupStatus -Name/-ResourceGroupName/-Type verified on
        # Microsoft Learn (Az.RecoveryServices module reference, "Name" parameter set,
        # Example 1). Output type ResourceBackupStatus with a confirmed .BackedUp Boolean
        # property. Returns null/empty for a resource with no protection in any vault.
        $unprotected = @()
        $checkErrors = @()

        foreach ($vm in $vms) {
            try {
                $backupStatus = Get-AzRecoveryServicesBackupStatus -Name $vm.Name -ResourceGroupName $vm.ResourceGroupName -Type 'AzureVM' -ErrorAction Stop
                $isBackedUp = $false
                if ($null -ne $backupStatus -and $backupStatus.PSObject.Properties['BackedUp']) {
                    $isBackedUp = [bool]$backupStatus.BackedUp
                }
                if (-not $isBackedUp) {
                    $unprotected += ([string]$vm.Name + ' (RG=' + [string]$vm.ResourceGroupName + ')')
                }
            }
            catch {
                $checkErrors += ([string]$vm.Name + ': ' + $_.Exception.Message)
            }
        }

        if ($unprotected.Count -eq 0) {
            Write-ADTResult -Check 'VM backup protection' -Status 'PASS' -Detail ($vms.Count.ToString() + ' VM(s) checked, all protected by some Recovery Services vault.')
        }
        else {
            $shown = @($unprotected | Select-Object -First 15)
            $moreNote = ''
            if ($unprotected.Count -gt 15) { $moreNote = (' (+' + ([string]($unprotected.Count - 15)) + ' more, not shown)') }
            Write-ADTResult -Check 'VM backup protection' -Status 'WARN' -Detail ($unprotected.Count.ToString() + ' of ' + $vms.Count.ToString() + ' VM(s) have no backup protection: ' + ($shown -join ', ') + $moreNote) `
                -Why 'A VM with no Azure Backup protection has no vault-based recovery point - a deletion, ransomware event, or bad patch on this VM cannot be restored from Azure Backup.' `
                -Fix @(
                    '$vault = Get-AzRecoveryServicesVault -ResourceGroupName <vaultRg> -Name <vaultName>',
                    '$policy = Get-AzRecoveryServicesBackupProtectionPolicy -Name <policyName> -VaultId $vault.ID',
                    'Enable-AzRecoveryServicesBackupProtection -Name <vmName> -ResourceGroupName <vmRg> -Policy $policy -VaultId $vault.ID'
                )
        }

        if ($checkErrors.Count -gt 0) {
            $errShown = (@($checkErrors | Select-Object -First 5)) -join ' | '
            Write-ADTResult -Check 'VM backup protection - lookup errors' -Status 'ERROR' -Detail ($checkErrors.Count.ToString() + ' VM(s) could not be checked: ' + $errShown)
        }
    }
    catch {
        Write-ADTResult -Check 'Backup protection' -Status 'ERROR' -Detail ('Unhandled exception: ' + $_.Exception.Message)
    }
}

function Invoke-ADTAzAdvisor {
    <#
        .SYNOPSIS
            Item 4: Advisor digest - counts by category, top 5 recommendations by impact.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-ADTSection -Title 'Advisor digest'

        $azState = Get-ADTAzCloudState
        if (-not $azState.Connected) {
            Write-ADTResult -Check 'Advisor digest' -Status 'SKIP' `
                -Detail 'not connected - run Connect Azure first' `
                -Why 'Advisor recommendations are read per subscription via Az cmdlets, and ADT never auto-connects inside a check.' `
                -Fix @('Connect-ADTAzure')
            return
        }

        if (-not (Test-ADTModuleAvailable -Name 'Az.Advisor')) {
            Write-ADTResult -Check 'Advisor digest' -Status 'SKIP' -Detail 'Az.Advisor module is not installed.' `
                -Why 'Get-AzAdvisorRecommendation ships in the Az.Advisor module, which is not part of the core Az module set ADT expects by default.' `
                -Fix @('Install-Module Az.Advisor -Scope CurrentUser -Force')
            return
        }

        $recommendations = @()
        try {
            $recommendations = @(Get-AzAdvisorRecommendation -ErrorAction Stop)
        }
        catch {
            Write-ADTResult -Check 'Get-AzAdvisorRecommendation' -Status 'ERROR' -Detail ('Failed: ' + $_.Exception.Message)
            return
        }

        if ($recommendations.Count -eq 0) {
            Write-ADTResult -Check 'Advisor digest' -Status 'PASS' -Detail 'No active Advisor recommendations for this subscription.'
            return
        }

        # Category (Cost/Security/HighAvailability/Performance/OperationalExcellence) and
        # Impact (High/Medium/Low) both verified on Microsoft Learn (Get-AzAdvisorRecommendation
        # reference examples and the Impact enum reference).
        $byCategory = @($recommendations | Group-Object -Property Category | Sort-Object -Property Count -Descending)
        $categoryText = (@(($byCategory | ForEach-Object { [string]$_.Name + '=' + [string]$_.Count }))) -join ', '
        Write-ADTResult -Check 'Advisor recommendations by category' -Status 'INFO' -Detail ($recommendations.Count.ToString() + ' total: ' + $categoryText)

        $impactRank = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2 }
        $topFive = @($recommendations | Sort-Object -Property @{ Expression = { if ($impactRank.ContainsKey([string]$_.Impact)) { $impactRank[[string]$_.Impact] } else { 99 } } } | Select-Object -First 5)

        foreach ($recommendation in $topFive) {
            # UNVERIFIED: whether Get-AzAdvisorRecommendation flattens the ShortDescription
            # Problem/Solution text onto the top-level object (ShortDescriptionProblem, per the
            # RecommendationProperties model's Origin=Inlined attribute) or nests it under a
            # .ShortDescription child object was not directly proven from a live example this
            # session - both dotnet API model shapes exist in the docs. Read defensively for
            # both, and fall back to the impacted-resource fields rather than guessing.
            $problemText = ''
            try {
                if ($recommendation.PSObject.Properties['ShortDescription'] -and $null -ne $recommendation.ShortDescription -and $recommendation.ShortDescription.PSObject.Properties['Problem']) {
                    $problemText = [string]$recommendation.ShortDescription.Problem
                }
                elseif ($recommendation.PSObject.Properties['ShortDescriptionProblem']) {
                    $problemText = [string]$recommendation.ShortDescriptionProblem
                }
            }
            catch {
                $problemText = ''
            }
            if ([string]::IsNullOrEmpty($problemText)) { $problemText = ([string]$recommendation.ImpactedField + ' / ' + [string]$recommendation.ImpactedValue) }

            Write-ADTResult -Check ('Advisor: ' + [string]$recommendation.Category + ' (' + [string]$recommendation.Impact + ')') -Status 'INFO' `
                -Detail ($problemText + '  [' + [string]$recommendation.ImpactedValue + ']')
        }
    }
    catch {
        Write-ADTResult -Check 'Advisor digest' -Status 'ERROR' -Detail ('Unhandled exception: ' + $_.Exception.Message)
    }
}

#endregion

Register-ADTModule -Name 'Azure' -Group 'CLOUD' -Items @(
    @{ Label = 'Subscription and VM inventory'; Function = 'Invoke-ADTAzInventory'; Requires = @('HasAzModule'); Snapshot = $false }
    @{ Label = 'VM health and hygiene';         Function = 'Invoke-ADTAzHygiene';   Requires = @('HasAzModule'); Snapshot = $false }
    @{ Label = 'Backup protection';             Function = 'Invoke-ADTAzBackup';    Requires = @('HasAzModule'); Snapshot = $false }
    @{ Label = 'Advisor digest';                Function = 'Invoke-ADTAzAdvisor';   Requires = @('HasAzModule'); Snapshot = $false }
)
