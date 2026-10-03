# Threat Hunt Report: From Suspicious Logons to Persistence

## 1. Report overview

| Item | Details |
|---|---|
| Exercise | Module 1 — Core Investigation Skills |
| Case | Help Desk Ticket #4451 |
| Environment | Training lab; not a production incident |
| Investigation platform | Microsoft Defender / Microsoft Sentinel |
| Primary endpoint | `npt-ws01` |
| Additional endpoint of interest | `npt-srv01` |
| Main incident window | 22 April 2026, 04:30–06:00 UTC |
| Broad search window used | 21 April 2026, 04:00–23 April 2026, 08:00 UTC |
| Report status | Investigation write-up; response actions proposed, not executed |

This report documents a guided threat-hunting exercise completed while following a training video. The investigation examined authentication, execution, file delivery, network activity, persistence, and possible movement to another endpoint. The purpose is to demonstrate the investigation method and distinguish observations from conclusions that still require corroboration.

All indicators below belong to the exercise context. Their inclusion does not establish that an address or domain is currently malicious outside this dataset. Domain and public-IP indicators are defanged in the narrative to avoid accidental navigation.

## 2. Executive summary

The investigation began with a report from Mark Smith in Finance that his workstation had displayed repeated login prompts overnight. The exercise findings identify use of the `helpdesk` account, a suspicious executable named `WindowsUpdate.exe`, remote execution through a WMI-related process chain, outbound communication, multiple persistence mechanisms, and an additional local administrator account.

The most directly substantiated event in the reviewed exports is the creation of `C:\Windows\Temp\WindowsUpdate.exe` on `npt-ws01` at **05:17:03 UTC on 22 April 2026**. The event records an SMB request associated with `helpdesk`, with source address `10.3.0.10`, and supplies the file's SHA256.

An alert at **05:37:06 UTC** also associates `npt-srv01` with a suspicious PowerShell web request. This is a reason to extend the investigation. It does not independently prove that the attacker moved from the workstation to the server.

The worksheet describes a compromise sequence, but not every underlying result was included in the materials reviewed for this report. Exact execution and persistence timestamps, successful completion of administrative changes, initial credential acquisition, and any data theft remain unverified.

## 3. Trigger and investigation objectives

Ticket #4451 was received on **22 April 2026 at 09:14 UTC**. The reporter described overnight login prompts on `npt-ws01` and asked IT to investigate.

The investigation sought to establish:

1. Which account was used and where authentication originated.
2. What executed, and which process launched it.
3. How the suspicious file arrived and how to identify its contents.
4. Whether it communicated with an external destination.
5. What mechanisms were used to retain access.
6. Whether another endpoint required investigation.
7. What containment and recovery actions would be justified.

## 4. Scope and evidence quality

### 4.1 Sources reviewed

| Source | What it contributes | Limitation |
|---|---|---|
| Training worksheet | Scenario, objectives, hints, and recorded answers for 11 flags | Recorded answers are not a substitute for raw events |
| User-supplied KQL | Search method and selected fields | Query text alone does not prove an event occurred |
| File-event export: 520 rows | Direct evidence of the implant's creation and hash | File creation does not prove execution |
| Alert-evidence export: 288 rows | Host associations, alert titles, and timestamps | Evidence rows are not necessarily distinct alerts; titles are not a complete attack reconstruction |

### 4.2 Evidence labels

- **Verified in export:** an event or value was directly observed in a supplied CSV.
- **Worksheet-recorded:** a finding appears in the completed training worksheet; its underlying event was not independently reviewed here.
- **Assessment:** an interpretation of available evidence, with its limits stated.

The report does not claim live access to the workspace, independent execution of every query, or completion of response actions.

## 5. Investigation methodology

The hunt began with authentication events and then followed related accounts, processes, files, destinations, and hosts across tables.

| Table | Investigation question |
|---|---|
| `DeviceLogonEvents` | Who authenticated, how, and from where? |
| `DeviceProcessEvents` | What ran, under which account, and with which parent process? |
| `DeviceFileEvents` | What file appeared, where, and through which request? |
| `DeviceNetworkEvents` | Which process contacted which destination? |
| `DeviceRegistryEvents` | Were registry values written for automatic execution? |
| `AlertEvidence` | Which other endpoints were associated with relevant alerts? |

The broad search window provided context around the main incident. Findings outside 04:30–06:00 UTC were considered separately rather than automatically attributed to the same intrusion. Narrow projections made results easier to read; sorting by time helped reconstruct sequence.

## 6. Findings across the eleven flags

### 6.1 Flag 1 — Account used

**Worksheet-recorded account:** `helpdesk`.

The initial authentication query displayed event time, host, action, account, and remote address. Identifying an account is the starting point for subsequent pivots; it does not identify the human controlling it.

The worksheet's hints are not fully consistent about session character: one references network logon type 3, while another describes interactive access. The actual `LogonType` result must settle that distinction. This report therefore does not assign a verified logon type.

### 6.2 Flag 2 — Authentication source

**Worksheet-recorded external source:** `20[.]110[.]92[.]50`.

The correct analytical step is to read the source address on the successful authentication event for the suspicious account. A failed attempt from the same address would not establish successful access. The source event and exact timestamp were not included in the reviewed exports.

### 6.3 Flag 3 — Implant execution

**Worksheet-recorded command:**

```text
cmd.exe /Q /c start "" "C:\Windows\Temp\WindowsUpdate.exe"
```

The command starts an executable from a temporary directory. The Windows-like name alone does not make the file legitimate or malicious. Its role must be assessed using execution, delivery, network, and persistence evidence together.

### 6.4 Flag 4 — Parent process

**Worksheet-recorded parent:** `wmiprvse.exe`.

The parent process and command pattern are consistent with WMI-mediated execution. They support investigating remote administration abuse, but they do not uniquely prove which remote-execution tool was used. Source-side evidence and the complete process tree would strengthen attribution to a particular tool.

### 6.5 Flag 5 — Outbound destination

**Worksheet-recorded domain:** `updates[.]abordasync[.]website`.

The network query examined activity initiated under `helpdesk`. A complete confirmation should retain the initiating process, destination, port, action, and event time. The supplied materials do not independently demonstrate successful beaconing or historical DNS resolution to the external address.

### 6.6 Flag 6 — Implant file and hash

**Verified in the file-event export:**

| Field | Value |
|---|---|
| Time | 22 April 2026, 05:17:03 UTC |
| Device | `npt-ws01` |
| Action | `FileCreated` |
| Path | `C:\Windows\Temp\WindowsUpdate.exe` |
| Request protocol | `Smb` |
| Request account | `helpdesk` |
| Request source | `10.3.0.10` |
| Initiating process | `ntoskrnl.exe` |

**SHA256:**

```text
20cef6a013953890f9d38605d25d60dd63b42b09946bbb18ddb4a456da306e77
```

The `SHA256` field identifies the file involved in the event. `InitiatingProcessSHA256` identifies the initiating executable and would answer a different question. Renaming a file does not change its content hash, making the hash useful for searching other endpoints.

The kernel process appearing as initiator does not imply a malicious kernel. The SMB request fields provide additional delivery context. The internal source `10.3.0.10` must not be equated with the external authentication address without supporting infrastructure evidence.

### 6.7 Flag 7 — Registry persistence

**Worksheet-recorded Run value:** `WindowsHealthCheck`.

The hunt searched registry keys containing `run`. That is a discovery filter, not proof of a valid persistence entry. Verification requires the full key, `RegistryValueName`, value data, action, and time, followed by confirmation that the value points to the suspect executable.

The original projection omitted `RegistryValueName`, despite that field being the required flag. The revised appendix includes it.

### 6.8 Flag 8 — Scheduled task

**Worksheet-recorded task:** `GoogleUpdaterTask`.

The intended evidence is a task-creation command containing the task name and configured action. A process record establishes that a command was launched; task-state or task-registration evidence is needed to confirm successful creation. An updater-like name is contextual evidence of possible disguise, not proof on its own.

### 6.9 Flag 9 — Service

**Worksheet-recorded service:** `WindowsHealthSvc`.

The relevant process command should show `sc.exe create`, the service name, and its binary path. Confirming the configured path and service state is necessary before reporting that a working persistence mechanism was installed.

### 6.10 Flag 10 — Additional administrator account

**Worksheet-recorded account:** `nexus_admin`.

Two actions need to be correlated: account creation and addition to the local Administrators group. Finding only one does not establish both. Searches should include `net.exe` and `net1.exe`, because either may appear in the process records.

Any password present in command-line evidence should be redacted before publication. Confirmation of account and group state remains necessary to establish successful privilege assignment.

### 6.11 Flag 11 — Additional endpoint

**Worksheet-recorded endpoint:** `npt-srv01`.

The alert CSV directly includes the following row:

| Field | Value |
|---|---|
| Time | 22 April 2026, 05:37:06 UTC |
| Device | `npt-srv01` |
| Title | `Yesi GEbreselassie - PowerShell Suspicious Web Request` |
| Evidence role | `Impacted` |

The alert establishes a reason to investigate the server. It does not prove a successful workstation-to-server transition. Authentication source information, account/session correlation, and server process events are needed to reconstruct that chain.

Server alerts around 00:34–00:38 UTC fall outside the main incident window and are not automatically included in this intrusion sequence.

## 7. Evidence-based timeline

| UTC time | Event | Basis |
|---|---|---|
| 22 April, 05:17:03 | Implant file created on `npt-ws01` through an SMB request associated with `helpdesk` | Verified file event |
| 22 April, 05:37:06 | Suspicious PowerShell web-request alert associated with `npt-srv01` | Verified alert evidence |
| 22 April, 09:14 | Help desk receives report of overnight login prompts | Exercise briefing |
| Time not supplied | Successful authentication, implant launch, network destination, registry/task/service persistence, and administrator account creation | Worksheet-recorded findings; raw timestamps outstanding |

The remaining events are not assigned invented timestamps or presented as a verified chronological sequence.

## 8. Impact, scope, and root cause assessment

**Primary endpoint:** The verified delivery event, together with the worksheet's execution and persistence findings, supports treating `npt-ws01` as a suspected compromised endpoint.

**Identity exposure:** The exercise describes misuse of `helpdesk` and creation of `nexus_admin`. The complete scope of account use across the environment remains to be established.

**Additional endpoint:** `npt-srv01` requires follow-up. Confirmed compromise and the route of access are not established by the supplied alert alone.

**Data impact:** No supplied evidence establishes collection or exfiltration. Absence of such evidence in these exports is not proof that it did not occur.

**Root cause:** The exercise points to abuse of account access. It does not establish how credentials were acquired, whether brute force succeeded, which security control failed, or whether exploitation occurred. Those questions remain open.

## 9. Detection rationale

The strongest available investigation anchor is the file creation at 05:17:03 UTC. It provides a timestamp, host, path, content hash, requesting account, protocol, and source address that can be correlated with other tables.

A practical detection concept would correlate SMB delivery of an executable to a temporary location with subsequent WMI-associated execution and suspicious persistence or outbound activity. This is a proposed correlation approach, not a deployed or validated detection rule.

Filtering only on a temporary path, a Windows-like filename, or a single account would produce an incomplete assessment. Administrators and legitimate applications can generate similar individual events.

## 10. Proposed containment and recovery plan

### Immediate containment

1. Isolate `npt-ws01` using endpoint controls while preserving investigation access.
2. Restrict or disable `helpdesk`, assess dependencies, reset credentials, and terminate associated sessions through appropriate controls.
3. Investigate `npt-srv01` urgently; isolate it if compromise is corroborated or the incident assessment warrants precautionary containment.
4. Preserve relevant logs and volatile evidence before destructive remediation where feasible.

### Persistence removal and account remediation

1. Verify and remove the malicious `WindowsHealthCheck` Run value at its exact registry path.
2. Export and remove the confirmed malicious `GoogleUpdaterTask` task.
3. Preserve the service configuration and remove the confirmed malicious `WindowsHealthSvc` service.
4. Verify, disable, and remove the unauthorised `nexus_admin` account after preserving account and membership evidence.
5. Quarantine the implant and search for its hash elsewhere.

### Scope and infrastructure checks

1. Hunt for the hash, domain, account names, and persistence artifacts across the environment.
2. Establish the identity and role of `10.3.0.10`; do not assume it is equivalent to the public source.
3. Apply blocks for indicators confirmed malicious in the relevant environment, accounting for shared infrastructure and address reuse.
4. Review remote administrative access, account privileges, endpoint protection settings, and telemetry coverage.

### Recovery validation

Rebuild affected endpoints where integrity cannot be established. Confirm that persistence is absent, unauthorised accounts no longer function, required protection is active, and suspicious communication does not recur. Record validation results before closing the incident.

These are recommendations; no containment, blocking, deletion, or account changes were performed as part of this report.

## 11. Lessons learned

- Verify table names and available fields before writing increasingly complex filters.
- Use `project` to keep evidence readable, but retain the field required by the question.
- Declaring a host variable does not apply a host filter.
- `DeviceName == "HostInQuestion"` searches for literal text; `DeviceName == HostInQuestion` uses the variable.
- Run query blocks independently. Appending a new table expression after an unfinished query caused repeated syntax errors during this exercise.
- Distinguish a file hash from the initiating process hash.
- Distinguish an executed command from a confirmed successful configuration change.
- Expand host scope deliberately when investigating movement, and do not interpret every related alert as confirmed compromise.
- Keep worksheet answers, observed events, and analyst interpretations clearly separated.

## 12. KQL appendix

These are cleaned-up investigation queries based on the supplied workflow. They have not been independently rerun against the live workspace. Run **one code block at a time in a separate query tab**, and ensure the interface's time range includes the exercise dates.

The appendix uses `Timestamp` consistently for MDE event chronology. The original workflow also used `TimeGenerated`; those values matched on the reviewed implant-creation row, but equivalence is not assumed for every event.

### A. Successful authentication and source context

```kusto
DeviceLogonEvents
| where Timestamp >= datetime(2026-04-21T04:00:00Z)
| where Timestamp < datetime(2026-04-23T08:00:00Z)
| where DeviceName =~ "npt-ws01"
| where ActionType == "LogonSuccess"
| project Timestamp, DeviceName, ActionType, AccountName, LogonType, RemoteIP
| order by Timestamp asc
```

### B. Account execution and parent process

```kusto
DeviceProcessEvents
| where Timestamp >= datetime(2026-04-21T04:00:00Z)
| where Timestamp < datetime(2026-04-23T08:00:00Z)
| where DeviceName =~ "npt-ws01"
| where AccountName =~ "helpdesk"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

### C. Network activity under the account

```kusto
DeviceNetworkEvents
| where Timestamp >= datetime(2026-04-21T04:00:00Z)
| where Timestamp < datetime(2026-04-23T08:00:00Z)
| where DeviceName =~ "npt-ws01"
| where InitiatingProcessAccountName =~ "helpdesk"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

This account filter may miss later execution under another identity. Follow up using the identified executable, hash, and process relationships.

### D. Implant delivery and SHA256

```kusto
DeviceFileEvents
| where Timestamp >= datetime(2026-04-21T04:00:00Z)
| where Timestamp < datetime(2026-04-23T08:00:00Z)
| where DeviceName =~ "npt-ws01"
| where FileName =~ "WindowsUpdate.exe"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, ActionType, FolderPath, SHA256,
          InitiatingProcessFileName, RequestProtocol, RequestSourceIP,
          RequestAccountName
| order by Timestamp asc
```

### E. Run-key candidates

```kusto
DeviceRegistryEvents
| where Timestamp >= datetime(2026-04-21T04:00:00Z)
| where Timestamp < datetime(2026-04-23T08:00:00Z)
| where DeviceName =~ "npt-ws01"
| where RegistryKey endswith @"\CurrentVersion\Run"
    or RegistryKey endswith @"\CurrentVersion\RunOnce"
| project Timestamp, DeviceName, ActionType, RegistryKey,
          RegistryValueName, RegistryValueData
| order by Timestamp asc
```

### F. Scheduled-task creation commands

```kusto
DeviceProcessEvents
| where Timestamp >= datetime(2026-04-21T04:00:00Z)
| where Timestamp < datetime(2026-04-23T08:00:00Z)
| where DeviceName =~ "npt-ws01"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

### G. Service creation commands

```kusto
DeviceProcessEvents
| where Timestamp >= datetime(2026-04-21T04:00:00Z)
| where Timestamp < datetime(2026-04-23T08:00:00Z)
| where DeviceName =~ "npt-ws01"
| where FileName =~ "sc.exe"
| where ProcessCommandLine has "create"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

### H. Account creation and group membership commands

```kusto
DeviceProcessEvents
| where Timestamp >= datetime(2026-04-21T04:00:00Z)
| where Timestamp < datetime(2026-04-23T08:00:00Z)
| where DeviceName =~ "npt-ws01"
| where FileName in~ ("net.exe", "net1.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

Review the output for creation and Administrators membership commands. Redact passwords before sharing command-line results.

### I. Alert evidence across the fleet

```kusto
AlertEvidence
| where Timestamp >= datetime(2026-04-22T04:30:00Z)
| where Timestamp <= datetime(2026-04-22T06:00:00Z)
| where DeviceName startswith "npt-"
| project Timestamp, AlertId, DeviceName, Title, EntityType,
          EvidenceRole, AccountName, RemoteIP
| order by Timestamp asc
```

Retain `AlertId` when following an alert into its complete evidence. Multiple evidence rows can belong to the same alert.

## 13. Conclusion

This guided exercise demonstrates how an investigation can progress from a login complaint to file delivery, execution, persistence, and broader host scoping. The strongest reviewed evidence confirms the implant's creation and an additional server alert. The remaining worksheet findings form a useful investigation framework, but their raw events must be retained to complete a defensible incident timeline and validate the full attack sequence.
