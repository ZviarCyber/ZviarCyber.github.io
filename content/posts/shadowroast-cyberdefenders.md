---
title: "ShadowRoast — Threat Hunting an Active Directory Attack with Splunk"
date: 2026-03-16
tags: ["threat-hunting", "splunk", "active-directory", "kerberos", "dcshadow", "blueteam", "soc", "mitre-attack"]
categories: ["Write-up", "CyberDefenders"]
---

## Scenario

> As a cybersecurity analyst at TechSecure Corp, you are alerted to unusual activity in the company's
> Active Directory environment. Initial reports suggest unauthorized access and possible privilege
> escalation. Your task is to analyse the provided logs to uncover the extent of the attack and
> identify the malicious actions taken by the attacker.

**Tools used:** Splunk, Event Log Explorer.

## Investigation

### Q1. What is the malicious file used for initial access?

Hunting for process-creation events (Sysmon Event ID 1) on the most likely target (the Office
workstation), filtering for `cmd`/`powershell` images:

```spl
index=shadowroast AND "event.code"=1 AND "winlog.computer_name"="Office-PC.CORPNET.local"
AND ("winlog.event_data.Image"="*cmd*" OR "winlog.event_data.Image"="*powershell*")
```

![Initial access process](/img/shadowroast/01-q1-adobeupdater.png)

A suspicious process stands out: `AdobeUpdater.exe`, run by user `sanderson`, with PowerShell
spawned underneath it.

**Answer:** `AdobeUpdater.exe`

### Q2. What is the registry Run key name created for persistence?

Pivoting to registry-modification events (Sysmon Event ID 13) and filtering for `Run` paths:

```spl
index=shadowroast AND "event.code"=13 AND "winlog.computer_name"="Office-PC.CORPNET.local"
AND winlog.event_data.TargetObject=*Run*
```

![Run key persistence](/img/shadowroast/02-q2-runkey.png)

A single entry comes back, tied to the malicious file, with the key name visible.

**Answer:** `wyW5PZyF`

### Q3. What is the full path of the directory used to store dropped tools?

Going back to Q1, the PowerShell process tied to `AdobeUpdater.exe` has process ID 4780. Hunting on
that PID (as process or parent):

```spl
index="shadowroast" AND event.code=1 AND winlog.computer_name=Office-PC.CORPNET.local
AND (winlog.event_data.ProcessId=4780 OR winlog.event_data.ParentProcessId=4780)
```

![Dropped tools directory](/img/shadowroast/03-q3-tools-dir.png)

Two entries return; one is irrelevant, the other shows Mimikatz being run from the staging
directory, revealing where the attacker keeps their tooling.

**Answer:** `C:\Users\Default\AppData\Local\Temp\`

### Q4. What tool was used for privilege escalation and credential harvesting?

Everything tied to the staging directory is worth hunting:

```spl
index="shadowroast" AND event.code=1 AND winlog.computer_name=Office-PC.CORPNET.local
AND "winlog.event_data.CurrentDirectory"="C:\\Users\\Default\\AppData\\Local\\Temp\\"
```

(The path is double-escaped because of the SPL syntax.)

![Rubeus and Mimikatz](/img/shadowroast/04-q4-rubeus.png)

Two tools show up: Mimikatz, and Rubeus hiding under the name `BackupUtility.exe`. Rubeus was used
for an **AS-REP Roasting** attack, targeting accounts with Kerberos pre-authentication disabled to
extract crackable hashes. The attacker then ran Mimikatz (as `DefragTool.exe`) under a different
parent user, confirming a second compromised account, `CORPNET\tcooper`, in addition to the
earlier `CORPNET\sanderson`.

**Answer:** Rubeus

### Q5. Was credential harvesting successful? If so, which domain account was compromised?

As seen in Q4, the second compromised account is `tcooper`.

**Answer:** `tcooper`

### Q6. What tool registered a rogue Domain Controller to manipulate AD data?

Registering a rogue DC is the **DCShadow** technique (a Mimikatz capability). AD schema/object
changes are logged under Event ID 4929:

```spl
index="shadowroast" AND event.code=4929
```

![DCShadow event 4929](/img/shadowroast/05-q6-dcshadow.png)

The log confirms Mimikatz behind the rogue DC registration.

**Answer:** mimikatz

### Q7. What is the first command used to enable RDP for lateral movement?

Enabling RDP means setting the registry value `fDenyTSConnections` to 0. Hunting command lines for
it:

```spl
index="shadowroast" AND event.code=1 AND winlog.event_data.CommandLine=*fDenyTSConnections*
```

![Enable RDP command](/img/shadowroast/06-q7-rdp.png)

It was executed on DC01 and the file server, consistent with lateral movement.

**Answer:**

```
reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0
```

### Q8. What is the name of the archive created after compressing confidential files?

Searching the file server for file-creation events (Sysmon Event ID 11) with archive extensions:

```spl
index="shadowroast" AND winlog.computer_name=FileServer.CORPNET.local AND event.code=11
AND (winlog.event_data.TargetFilename=*.zip OR winlog.event_data.TargetFilename=*.7z OR winlog.event_data.TargetFilename=*.rar)
```

![Compressed archive](/img/shadowroast/07-q8-crashdump.png)

The log shows the archive name.

**Answer:** `CrashDump.zip`

## Timeline of the attack

| Step | Event |
|------|-------|
| 1 | Initial access via `AdobeUpdater.exe` on Office-PC (user `sanderson`), spawning PowerShell |
| 2 | Persistence: registry Run key `wyW5PZyF` |
| 3 | Tooling dropped to `C:\Users\Default\AppData\Local\Temp\` |
| 4 | Rubeus (`BackupUtility.exe`) runs AS-REP Roasting; Mimikatz (`DefragTool.exe`) dumps credentials |
| 5 | Second account compromised: `tcooper` |
| 6 | Mimikatz DCShadow registers a rogue domain controller (Event ID 4929) |
| 7 | RDP enabled on DC01 and the file server for lateral movement |
| 8 | Confidential files compressed into `CrashDump.zip` for exfiltration |

## Indicators of compromise (IOC)

| Type | Value |
|------|-------|
| Initial access binary | `AdobeUpdater.exe` |
| Persistence Run key | `wyW5PZyF` |
| Tool staging directory | `C:\Users\Default\AppData\Local\Temp\` |
| Rubeus (masqueraded) | `BackupUtility.exe` |
| Mimikatz (masqueraded) | `DefragTool.exe` |
| Compromised accounts | `sanderson`, `tcooper` |
| Exfil archive | `CrashDump.zip` |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Execution | User Execution: Malicious File | T1204.002 |
| Persistence | Registry Run Keys / Startup Folder | T1547.001 |
| Defense Evasion | Masquerading: Rename System Utilities | T1036.005 |
| Credential Access | Steal or Forge Kerberos Tickets: AS-REP Roasting | T1558.004 |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |
| Defense Evasion | Rogue Domain Controller (DCShadow) | T1207 |
| Lateral Movement | Remote Services: RDP | T1021.001 |
| Collection | Archive Collected Data | T1560.001 |

## References

- CyberDefenders — [ShadowRoast challenge](https://cyberdefenders.org/blueteam-ctf-challenges/shadowroast/)
- MITRE ATT&CK — T1558.004 (AS-REP Roasting), T1207 (Rogue Domain Controller), T1560.001 (Archive Collected Data)
