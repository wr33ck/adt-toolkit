# ADT Module Contract — v1.0 (23 Aug 2026)

Every file in this toolkit is built against this contract. A module that deviates fails
review. Read this whole file before writing any code.

## Purpose

ADT is an MSP field toolkit: discover an unknown environment, health-check it, and do
simple/intermediate troubleshooting — on-prem (AD, DNS, DHCP, file, network, Exchange,
Citrix) and cloud (Entra, M365, Azure compute). It is carried onto client servers and jump
boxes as a folder and run interactively or as a one-shot snapshot.

## Hard rules

1. **PowerShell 5.1 floor.** Everything must parse and run on Windows PowerShell 5.1
   (Server 2012 R2+). PS7 may be present but never required.
   BANNED syntax: ternary (`? :`), null-coalescing (`??`, `??=`), null-conditional
   (`?.`, `?[]`), pipeline chain operators (`&&`, `||`), `ForEach-Object -Parallel`,
   `clean {}` blocks, `$PSStyle`. If you are unsure a construct is 5.1-safe, don't use it.
2. **ASCII-only source.** No smart quotes, em dashes, box-drawing, emoji, or any
   non-ASCII byte anywhere in .ps1 files. Console output uses plain tags: [PASS] [WARN]
   [FAIL] [INFO] [SKIP] [ERR ].
3. **Read-only against target systems.** Checks NEVER change the environment. No
   Set-/Remove-/Restart-/Stop-/New- against AD, DNS, DHCP, Exchange, Citrix, Graph,
   Azure, or any service/registry of the target — remediation is always printed as FIX>
   text for the engineer to run manually.
   Sanctioned writes (the ONLY ones):
   - transcript/log files under the ADT folder `Logs\`
   - Sysinternals downloads into `Tools\`
   - `HKCU\Software\Sysinternals\<Tool>\EulaAccepted=1` when launching a tool
   - prerequisite installs (RSAT capability/feature, PS modules `-Scope CurrentUser`,
     Citrix Remote SDK) — ONLY inside `Install-ADTPrereq`, ONLY after `Confirm-ADTAction`
   - scratch under `$env:TEMP\ADT`
   Benign object creation (`New-Object`, `New-TimeSpan`, `New-PSSession` for remoting
   reads) is fine. Cloud connections are read-scope only.
4. **No stored secrets.** Never write credentials, tokens, or tenant details to disk.
   Cloud sessions live and die with the process.
5. **Never crash the menu.** Every menu-entry function wraps its body in try/catch and
   converts exceptions to an ERROR result. Sub-checks catch their own exceptions too.
6. **Verify, don't assume.** Every external cmdlet, parameter, registry path, URL, event
   ID and port you use must be verified against Microsoft Learn (use the Microsoft Learn
   MCP tools) or the vendor's own docs (WebSearch/fetch for Citrix). Anything you cannot
   verify gets a `# UNVERIFIED: <what and why>` comment on the line AND is listed in your
   completion report. Do not silently trust memory.
7. **No aliases** in code (`%`, `?`, `gci`, `iwr`, `select` etc.) — full cmdlet names.
   Single quotes unless interpolating. 4-space indent. `[CmdletBinding()]` on every
   public function. `#region` blocks for structure. No `global:` scope.
   **Array-literal precedence trap (caused real field bugs — non-negotiable):** inside
   ANY comma-separated list — `@()` literals, `-Fix @(...)`, `-Arguments @(...)` — wrap
   every expression that uses `+` in its own parentheses. PowerShell's comma binds
   tighter than `+`, so `@('a' + $x, 'b')` does NOT produce `'a<x>'`; it fragments the
   elements. Write `@(('a' + $x), 'b')`. This applies to single-element arrays too:
   `-Arguments @(('/flag:' + $v))`.
8. Check functions return nothing to the pipeline. All results flow through the output
   engine. Use `[void]` / `$null =` to suppress accidental output.

## Layout

```
ADT\
  ADT.ps1                  launcher (this is what the engineer runs)
  CONTRACT.md
  modules\
    ADT.Common.ps1         output engine, caps, helpers, prereq manager, confirm
    ADT.CloudCommon.ps1    cloud connect framework (Graph/Az/EXO)
    ADT.Discovery.ps1      ADT.ServerHealth.ps1
    ADT.AD.ps1             ADT.DNS.ps1        ADT.DHCP.ps1
    ADT.FileServices.ps1   ADT.Network.ps1
    ADT.Exchange.ps1       ADT.Citrix.ps1
    ADT.Entra.ps1          ADT.M365.ps1       ADT.Azure.ps1
    ADT.Sysinternals.ps1
  Tools\                   (created on demand)
  Logs\                    (created on demand)
```

Launcher dot-sources `modules\ADT.Common.ps1` first, then `ADT.CloudCommon.ps1` if
present, then every other `modules\ADT.*.ps1` sorted by name. A missing module file is
NOT an error — its menu entries simply don't exist. Every module file must therefore be
self-contained: functions + one `Register-ADTModule` call at the bottom, nothing at
script top level that does work on load (no I/O, no checks at dot-source time).

## Output engine (implemented in ADT.Common.ps1 — everyone else just calls it)

```powershell
Write-ADTResult -Check <string> -Status <PASS|WARN|FAIL|INFO|SKIP|ERROR>
                -Detail <string> [-Why <string>] [-Fix <string[]>] [-Data <object>]
```
- Prints one colour-coded line: `[PASS] Check name : detail` (Green PASS, Yellow WARN,
  Red FAIL, Gray INFO/SKIP, Magenta ERROR).
- WARN/FAIL with -Why prints a `  WHY> ` line. -Fix prints one `  FIX> ` line per string
  (exact copy-paste commands).
- Appends a PSCustomObject (Timestamp, Module, Check, Status, Detail, Why, Fix, Data) to
  `$script:ADTResults` for the end-of-run summary and snapshot exit code.

```powershell
Write-ADTSection -Title <string>     # visual section separator
Write-ADTNote -Text <string>         # neutral commentary line, not a result
Invoke-ADTNative -FilePath <string> -Arguments <string[]> [-TimeoutSec <int>]
    # runs an external exe, returns @{ExitCode;StdOut;StdErr}; never throws
Test-ADTPort -ComputerName <string> -Port <int> [-TimeoutMs <int=2000>]
    # async TcpClient, 5.1-safe, returns bool
Confirm-ADTAction -Prompt <string>   # y/N prompt; ALWAYS $false when $script:ADTNonInteractive
```

## Capability map (built once at launch by Get-ADTCapabilities in Common)

`$script:ADTCaps` — hashtable. Keys (all present, boolean unless noted):
`IsElevated, PSVersion (int), IsPS7, OSCaption (string), IsServer, DomainJoined,
DomainName (string|$null), IsDC, HasADModule, HasDnsRole, HasDnsModule, HasDhcpRole,
HasDhcpModule, HasExchangeShell, ExchangeVersion (string|$null), CitrixDDC, CitrixVDA,
CitrixStoreFront, CitrixCloudConnector, HasCitrixSnapin, HasGraphModule, HasAzModule,
HasEXOModule, HasInternet`
Detection must be cheap and never throw (wrap everything). Modules may read caps; only
Common writes them.

## Module registration

Bottom of every module file:

```powershell
Register-ADTModule -Name 'AD Core' -Group 'ON-PREM' -Items @(
    @{ Label='Replication health';  Function='Invoke-ADTReplication';  Requires=@('IsDC'); Snapshot=$true }
    @{ Label='Event sweep';         Function='Invoke-ADTEventSweep';   Requires=@('IsDC'); Snapshot=$false }
)
```
- Group: `ON-PREM`, `CLOUD`, or `TOOLS`.
- Requires: list of caps keys that must ALL be truthy. Empty list = always available.
- Snapshot: include in the one-shot health snapshot.
- `Register-ADTModule` (in Common) appends to `$script:ADTModules`. Launcher renders the
  menu from it: available items numbered, unavailable items shown dimmed with the missing
  cap named. Menu keys: number = run item, `S` = snapshot, `R` = re-detect caps, `Q` = quit.

## Launcher behaviour (ADT.ps1)

- Params: `[-Snapshot] [-Modules <string[]>] [-NoTranscript]`
- Starts transcript `Logs\ADT-<COMPUTERNAME>-<yyyyMMdd-HHmmss>.log` (Stop in finally).
- Banner: tool name/version, host, user, elevation, domain, caps one-liner.
- `-Snapshot`: no menu; run every registered item with Snapshot=$true whose Requires are
  met (optionally filtered by -Modules matching module Name), then summary table
  (counts by status + all WARN/FAIL/ERROR lines), exit code = 0 all pass / 1 warn /
  2 fail / 3 error. Sets `$script:ADTNonInteractive = $true`.
- Interactive: menu loop; after each item, summary line and return to menu. `S` runs the
  same snapshot in-session.

## Prereq manager (Common)

```powershell
Get-ADTPrereqStatus [-Name <string>]   # one or all: Installed?, Version, InstallHint
Install-ADTPrereq -Name <RSAT-AD|RSAT-DNS|RSAT-DHCP|RSAT-GPMC|GraphModule|AzModule|EXOModule|CitrixRemoteSDK>
```
- Confirm-gated. PS modules: `Install-Module -Scope CurrentUser -Force` with TLS 1.2
  forced first (`[Net.ServicePointManager]::SecurityProtocol`) and PSGallery reachability
  check. RSAT: `Add-WindowsCapability -Online` (client) / `Install-WindowsFeature`
  (server) — pick by OS type. CitrixRemoteSDK: download+run the Citrix Remote PowerShell
  SDK installer only after confirm; if URL cannot be verified, print where to get it
  instead of guessing.
- Graph: install `Microsoft.Graph.Authentication` + the specific sub-modules the Entra
  module needs — NOT the monolithic Microsoft.Graph rollup (too slow on field machines).

## Cloud connect API (ADT.CloudCommon.ps1)

```powershell
Connect-ADTGraph  [-TenantId <string>] [-DeviceCode]
Connect-ADTAzure  [-TenantId <string>] [-SubscriptionId <string>] [-DeviceCode]
Connect-ADTEXO    [-Organization <string>] [-DeviceCode]
Get-ADTCloudContext        # PSCustomObject: Graph/Az/EXO -> connected?, tenant, account
Disconnect-ADTCloud [-All]
```
- Each Connect prompts for tenant if not supplied, interactive browser auth by default,
  `-DeviceCode` for browserless jump boxes. Prints resulting context. Read-only Graph
  scope set lives in ONE variable in CloudCommon:
  Organization.Read.All, Directory.Read.All, Policy.Read.All, Reports.Read.All,
  AuditLog.Read.All, UserAuthenticationMethod.Read.All, SecurityEvents.Read.All,
  ServiceHealth.Read.All, ServiceMessage.Read.All
  (the last two added for the service communications API, which accepts only those;
  trim/extend only with justification; never a *.ReadWrite.* scope).
- Cloud module checks call `Get-ADTCloudContext` first and emit SKIP with a
  "run Connect first" detail when not connected — never auto-connect inside a check.
- Licence-gated data (e.g. sign-in logs need Entra P1): catch the specific failure and
  emit SKIP with Why explaining the licence gate — not ERROR.

## Fix guidance quality bar

A FIX> block is exact and runnable: `repadmin /replicate dc2 dc1 "DC=corp,DC=local"` —
not "investigate replication". If the fix depends on values, interpolate the real ones
from the check. If a fix is service-affecting (restart, reboot, failover), prefix the
line with `[SERVICE-AFFECTING] `.

## File header

Every file starts:
```powershell
# ADT.<Name>.ps1 - <one line purpose>
# Part of ADT (MSP field toolkit). Contract v1.0. PS 5.1+. Read-only by design.
```

## Builder completion report (return to orchestrator)

- Files written, functions + registered menu items list
- Every UNVERIFIED item
- Cmdlets/paths verified and against what source
- Anything you deliberately left out of scope and why
