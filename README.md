# Sigma Rule Validation Scheduled Task Creation via COM Object

## At a Glance

| | |
|---|---|
| **Target rule** | Scheduled Task Creation Via Schtasks.EXE (92626ddd-662c-49e3-ac59-f6535f12d189) |
| **ATT&CK** | T1053.005 Scheduled Task/Job: Scheduled Task |
| **Result** | Target rule does not fire for this technique. Two alternate telemetry layers capture it, but both require non-default configuration, and only one has an actively maintained Sigma rule. |
| **Classification** | Candidate gap requiring further review confirmed structurally, with a documented compensating control at a different telemetry layer |
| **Environment** | corp.local lab, Windows 11 client (build 26100), Sysmon |


## Objective

Determine whether a scheduled task can be created using the `Schedule.Service` COM object without ever invoking `schtasks.exe`, and if so, characterize exactly what is and is not visible to the current SigmaHQ ruleset as a result.


## Existing Detection

`proc_creation_win_schtasks_creation.yml` detects scheduled task creation by matching process creation events where:

- `Image` ends with `\schtasks.exe`
- `CommandLine` contains `' /create '`
- Filters exclude SYSTEM context and known MS Office installer noise

This is a process creation rule. It can only ever see processes that get spawned. That is the structural constraint this project tests.


## Research Question

Can a scheduled task be created using the `Schedule.Service` COM object via PowerShell such that no `schtasks.exe` process creation event is ever generated, while the task registers normally in Task Scheduler? And if so, is that activity visible anywhere else in the default SigmaHQ ruleset?


## Hypothesis

The COM object exposes task registration as an in-process API call from the calling process (`powershell.exe`), not as a separate helper binary. A rule anchored solely on `schtasks.exe` in the `Image` field should therefore be structurally blind to this technique, regardless of payload content.


## Environment

- Windows 11 client, build 26100.8875 (corp.local Proxmox lab)
- Sysmon installed and active (57,158 events at time of testing)
- Splunk Universal Forwarder present as background process
- Three telemetry sources checked: Sysmon EID 1, TaskScheduler-Operational EID 106, Security EID 4698


## Telemetry Requirements

| Source | Default state on this build | Notes |
|---|---|---|
| Sysmon EID 1 | Enabled | Standard endpoint telemetry |
| Microsoft-Windows-TaskScheduler/Operational EID 106 | Disabled by default | Confirmed via Get-WinEvent -ListLog before testing |
| Security EID 4698 | Requires Advanced Audit Policy: Object Access > Other Object Access Events | Not enabled by default, confirmed via auditpol /get before testing |


## Methodology

Standard control then alternative then telemetry layer then sibling rule sequence. Every claim is backed by a command run on the lab VM and its actual output. Nothing is inferred or assumed.


## Control Test

Ran a standard scheduled task creation via `schtasks.exe`:

```
schtasks /create /tn "SigmaTest_Control" /tr "cmd.exe /c whoami" /sc once /st 23:59
```

Result: `SUCCESS: The scheduled task "SigmaTest_Control" has successfully been created.`

![03 control execution](screenshots/03%20control%20execution.png)

Sysmon EID 1 captured the event:

```
Image:              C:\Windows\System32\schtasks.exe
CommandLine:        schtasks.exe /create /tn SigmaTest_Control /tr "cmd.exe /c whoami" /sc once /st 23:59
ParentImage:        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User:               JAMES-VM\william
UtcTime:            2026-08-22 17:48:52.960
```

![05 control telemetry sysmon eid 1](screenshots/05%20control%20telemetry%20sysmon%20eid%201.png)

Manual field-by-field evaluation against rule `92626ddd`:

| Clause | Requires | Event value | Match |
|---|---|---|---|
| Image endswith | \schtasks.exe | C:\Windows\System32\schtasks.exe | Yes |
| CommandLine contains | ' /create ' | present | Yes |
| filter system user excludes | User contains AUTHORI or AUTORI | JAMES-VM\william | Not excluded |
| filter msoffice excludes | ParentImage is Office integrator | powershell.exe | Not excluded |

Condition evaluates true. Control confirmed: rule fires as designed.


## Alternative Test

Registered an equivalent task using the `Schedule.Service` COM object from PowerShell. The registration happens via in-process API calls inside `powershell.exe`. No `schtasks.exe` process is ever spawned.

```powershell
$TaskName = "SigmaTest_Alternative"
$service = New-Object -ComObject Schedule.Service
$service.Connect()
$rootFolder = $service.GetFolder("\")
$taskDef = $service.NewTask(0)
$taskDef.RegistrationInfo.Description = "Sigma validation test"
$action = $taskDef.Actions.Create(0)
$action.Path = "cmd.exe"
$action.Arguments = "/c whoami"
$trigger = $taskDef.Triggers.Create(1)
$trigger.StartBoundary = (Get-Date).AddDays(1).ToString("yyyy-MM-ddTHH:mm:ss")
$rootFolder.RegisterTaskDefinition($TaskName, $taskDef, 6, $null, $null, 3)
```

Task registered successfully: `State: 3 (Ready)`, `Enabled: True`, full XML definition confirmed.

![06 alternative execution](screenshots/06%20alternative%20execution.png)


## Raw Telemetry Analysis

### Layer 1: Sysmon EID 1

Queried Sysmon Operational for any `schtasks.exe` process creation in the test window. No match found. The only process creation events tied to this technique are for `powershell.exe` running the script.

```
Image:          C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine:    powershell.exe -ExecutionPolicy Bypass -File sigma-alt-schtasks-com.ps1
User:           JAMES-VM\william
```

`schtasks.exe` never appears at any point. The rule's `Image|endswith: '\schtasks.exe'` clause fails immediately. Rule does not fire. Confirmed structurally.

![08 alternative telemetry no schtasks process](screenshots/08%20alternative%20telemetry%20no%20schtasks%20process.png)

### Layer 2: Microsoft-Windows-TaskScheduler/Operational EID 106

Confirmed disabled by default before testing:

![02 taskscheduler log disabled by default](screenshots/02%20taskscheduler%20log%20disabled%20by%20default.png)

Enabled via `wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /e:true`. Log came up clean with zero records:

![02b taskscheduler log enabled clean slate](screenshots/02b%20taskscheduler%20log%20enabled%20clean%20slate.png)

Re-ran the alternative test. EID 106 fired:

```
TimeCreated:    8/22/2026 11:33:06 AM
Id:             106
Message:        User "JAMES-VM\william" registered Task Scheduler task "\SigmaTest_Alternative2"
```

![08b eid 106 task registered](screenshots/08b%20eid%20106%20task%20registered.png)

This log captures the technique cleanly, but only once manually enabled. It is off by default on this Windows 11 26100 build.

### Layer 3: Security EID 4698

Confirmed the required audit subcategory was disabled by default:

![09a audit policy disabled by default](screenshots/09a%20audit%20policy%20disabled%20by%20default.png)

Enabled via `auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable`:

![09b audit policy enabled](screenshots/09b%20audit%20policy%20enabled.png)

Re-ran the alternative test. EID 4698 fired with rich detail including the full task definition XML inline:

```
TimeCreated:    8/22/2026 11:43:43 AM
Id:             4698
Task Name:      \SigmaTest_Alternative3
Subject:        JAMES-VM\william
ClientProcessId: 13136
```

![09c eid 4698 task created security log](screenshots/09c%20eid%204698%20task%20created%20security%20log.png)

![09d eid 4698 full xml detail](screenshots/09d%20eid%204698%20full%20xml%20detail.png)

This is the richest of the three layers, but also requires non-default configuration.


## Detection Logic Comparison

Verified against a direct clone of SigmaHQ/sigma master on 2026-08-22.

| Rule | EID | Status | Fires? |
|---|---|---|---|
| proc_creation_win_schtasks_creation.yml | 1 | active | No Image never equals schtasks.exe |
| win_taskscheduler_rare_schtask_creation.yml | 106 | unsupported | Not in active ruleset |
| win_taskscheduler_execution_from_susp_locations.yml | 129 | active | No execution only |
| win_taskscheduler_lolbin_execution_via_task_scheduler.yml | 129 | active | No execution only |
| win_taskscheduler_susp_schtasks_delete_or_disable.yml | 4699/4701 | active | No deletion only |
| win_security_susp_scheduled_task_creation.yml | 4698 | active (test) | Partially payload dependent, non-default audit policy required |


## Finding

The `Schedule.Service` COM object technique produces a structural, confirmed evasion of `proc_creation_win_schtasks_creation.yml`. The rule can never match this technique regardless of payload, because no `schtasks.exe` process is ever created. This is not a tuning gap. It is a telemetry source limitation inherent to the rule's design.

The technique does not evade detection entirely. It is visible via TaskScheduler-Operational EID 106 and Security EID 4698, but both require telemetry sources that are disabled by default on this Windows 11 26100 build. Of the two, only EID 4698 has an actively maintained Sigma rule, and that rule's detection is payload-dependent. A low-signal payload with no suspicious path reference can still pass through it, as demonstrated directly in this test.

The EID 106-based creation rule (`b20f6158`) that previously covered this layer has been moved to `status: unsupported` and is no longer part of the active ruleset.


## Sibling Rule Analysis

Three rules currently active under `rules/windows/builtin/taskscheduler/` cover EID 129 (execution) and deletion only. None cover task creation at EID 106.

`win_taskscheduler_rare_schtask_creation.yml` exists at `unsupported/windows/` targeting EID 106, with `status: unsupported`. It uses a 7-day frequency count heuristic (`count() by TaskName < 5`) which likely contributed to its removal from the active set.

`win_security_susp_scheduled_task_creation.yml` (`3a734d25`, `status: test`) is the only active rule touching task creation events. Its own `definition` field already documents the audit policy prerequisite, so this is a known and not novel limitation from the rule author's side.


## Limitations

- Testing performed on a single Windows 11 build 26100 client. Behavior on Server SKUs or older builds was not verified and may differ.
- The test payload used a harmless command with no suspicious path reference. This was sufficient to demonstrate the process creation rule's blind spot but happened to fall short of tripping the EID 4698 sibling rule's path clause. A realistic malicious payload would likely be caught by that rule.
- The exact commit and rationale for `b20f6158` being moved to unsupported were not confirmed via git log, only via direct file presence in the repo. This would strengthen the writeup if verified before upstream submission.
- All rule logic verification was manual field-by-field comparison. No SIEM query conversion was performed.


## Recommendation

Do not propose a replacement EID 106 rule without first understanding why `b20f6158` was moved to unsupported. The more useful upstream contribution is likely one of these two angles:

1. Add a `related:` reference in `proc_creation_win_schtasks_creation.yml` pointing to `win_security_susp_scheduled_task_creation.yml` as a documented compensating control, so operators know where to look.
2. Evaluate whether the path clause in `win_security_susp_scheduled_task_creation.yml` is too strict for realistic adversary payloads that reference non-standard paths not currently in the list.


## Cleanup

All test artifacts removed and verified clean on 2026-08-22.

Tasks deleted: SigmaTest Control, SigmaTest Alternative, SigmaTest Alternative2, SigmaTest Alternative3

Scripts deleted: sigma-alt-schtasks-com.ps1, sigma-alt-schtasks-com2.ps1, sigma-alt-schtasks-com3.ps1

![10 cleanup verified](screenshots/10%20cleanup%20verified.png)

Audit policy and TaskScheduler-Operational log left enabled useful for ongoing lab visibility.


## References

- [proc_creation_win_schtasks_creation.yml](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_schtasks_creation.yml)
- [win_security_susp_scheduled_task_creation.yml](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_scheduled_task_creation.yml)
- [win_taskscheduler_rare_schtask_creation.yml (unsupported)](https://github.com/SigmaHQ/sigma/blob/master/unsupported/windows/win_taskscheduler_rare_schtask_creation.yml)
- [Microsoft: Event 4698](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698)
- [Microsoft: Event ID 106](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc774938(v=ws.10))
- [Latrodectus COM bypass — guardsix](https://guardsix.com/blog/shenanigans-of-scheduled-tasks)
- [DarkHotel COM detection — cyberandramen](https://cyberandramen.net/2022/03/30/detecting-com-object-tasks-by-darkhotel/)
- MITRE ATT&CK T1053.005


## Upstream Issue

[PLACEHOLDER — issue not yet submitted. Duplicate search performed prior to this project confirmed no existing SigmaHQ discussion of this specific technique.]
