# ADT — MSP Field Toolkit

Portable, read-only troubleshooting toolkit for Windows/AD environments: discover an
unknown environment, health-check it, and get exact remediation commands printed — never
executed. Built 23 Aug 2026; verified live on a Server 2025 DC (ras.lab).

## Run it

Copy the `ADT` folder (or a subset — missing module files simply hide their menu items)
onto the target server or jump box. From an **elevated** Windows PowerShell 5.1+ prompt:

```powershell
.\ADT.ps1                # interactive menu
.\ADT.ps1 -Snapshot      # one-shot: every applicable * item, summary, exit code
```

Snapshot exit codes: `0` all pass · `1` warnings · `2` failures · `3` a check itself
errored. Every run writes a transcript to `Logs\`.

The menu shows only what the box qualifies for (capability detection at launch: DC role,
DNS/DHCP roles, Exchange shell, Citrix roles, cloud modules). Greyed items name the
missing capability. `R` re-detects after you install something.

## Areas

**ON-PREM** — Discovery (box + domain map via AD/SPN scan) · Server health · AD core
(overview, replication, SYSVOL/DFSR, time/auth, event sweep) · DNS · DHCP · File
services · Network (config sanity, AD port matrix, path quality) · Exchange on-prem/
hybrid + Entra Connect · Citrix CVAD (DDC/VDA/StoreFront/Cloud Connector).

**CLOUD** — Connect first (`Connect Microsoft Graph` / `Azure` / `Exchange Online`;
device-code option for browserless jump boxes; read-only scopes only). Then Entra
(tenant, privileged access, CA/security posture, MFA registration, sync), M365 (service
health first — "is it Microsoft or us" — EXO posture incl. live MX/SPF/DKIM/DMARC
checks, SPO), Azure (VM inventory/hygiene, orphaned resources, backup protection,
Advisor). Cloud items never run in the unattended snapshot. **Disconnect when done on a
shared box** — the Graph SDK caches tokens in the user profile.

## Direct commands

Applicable submenus also carry a **Direct commands** section (`c1`, `c2`, ...) — curated
raw diagnostics run as-is with output streamed to console and transcript: `dcdiag`
(quick/verbose/single test), `repadmin /replsummary` and `/showrepl`, `netdom query fsmo`,
`nltest /dclist`, `w32tm`, `klist`, `nslookup`, `dnscmd`, `ping`/`tracert`/`pathping`,
`ipconfig /all`, `netstat`, `route`, `arp`, `systeminfo`, `gpresult /r`, `whoami /all`,
`quser`, `net share`/`session`. Commands that need a target prompt for it (extra switches
allowed). All read-only; command runs don't appear in the result summary — the transcript
captures them.

## Sysinternals

TOOLS menu downloads the AD field set (ProcExp, Procmon, ADExplorer, ADInsight, TCPView,
Autoruns, PsExec, PsList, PsPing, PsLoggedon + 64-bit variants) from live.sysinternals.com
into `Tools\`, or the full suite (~190 MB). Offline: pre-seed `Tools\` by hand — the
launcher uses whatever is cached. EULA is pre-accepted at launch time.

## Safety contract

Checks are read-only against the target. The only writes: `Logs\` transcripts, `Tools\`
downloads, the Sysinternals HKCU EulaAccepted keys, and prerequisite installs (RSAT / PS
modules / Citrix SDK) behind an explicit confirm. Every `FIX>` line is for **you** to run
after judgement. Fixes marked `[SERVICE-AFFECTING]` say so.

## Verification status

All 16 files parse-verified on Windows PowerShell 5.1 and the full on-prem suite executed
live on a domain controller. Exchange, Citrix, and cloud modules are doc-verified
(Microsoft Learn / Citrix docs) and capability-gate correctly, but have not yet run
against live Exchange/Citrix/tenant targets — they are read-only by design, so a first
live run is safe; treat lines commented `# UNVERIFIED:` with judgement
(`grep -r "# UNVERIFIED:" modules\` for the full register).

## Extending

`CONTRACT.md` defines the architecture: one file per area in `modules\`, output engine
API, capability keys, registration schema, style rules (PS 5.1-only syntax, the
array-literal parenthesisation rule, read-only discipline). A new module is a new
`modules\ADT.<Area>.ps1` following it — the launcher picks it up automatically.
