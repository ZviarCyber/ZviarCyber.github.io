---
title: "YellowRAT — Threat Intelligence on Yellow Cockatoo with VirusTotal"
date: 2025-12-24
tags: ["threat-intel", "virustotal", "yellow-cockatoo", "jupyter", "blueteam", "soc", "mitre-attack"]
categories: ["Write-up", "CyberDefenders"]
---

## Scenario

> During a routine IT security check at GlobalTech Industries, abnormal network traffic was detected
> from multiple workstations. Employees' search queries were being redirected to unfamiliar
> websites. Your task is to investigate the incident and gather as much information as possible.

**Tool used:** VirusTotal (plus open-source threat intel).

## Investigation

### Q1. What is the name of the malware family causing the abnormal traffic?

The challenge provides a file hash, so the starting point is a VirusTotal lookup. The file is
flagged by most vendors, with a popular threat label of `trojan.msil/polazert` and YARA matches for
`Windows_Trojan_Jupyter` and `Jupyter_Infostealer_DLL`. That label does not match the expected
answer format, so I checked the **Community** tab:

![VirusTotal detection](/img/yellowrat/01-q1-vt-detection.png)

A community comment names the family directly and links to Red Canary's report:

![VirusTotal community tab](/img/yellowrat/02-q1-community.png)

**Answer:** `Yellow Cockatoo` (also tracked as Jupyter / SolarMarker)

### Q2. What is the common filename associated with the malware?

On VirusTotal, the file name for the sample is shown next to the hash.

![Common filename](/img/yellowrat/03-q2-filename.png)

**Answer:** `111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll`

### Q3. What is the compilation timestamp of the malware?

Under **Details > Portable Executable Info > Header**, the compilation timestamp is listed.

![Compilation timestamp](/img/yellowrat/04-q3-compilation.png)

**Answer:** `2020-09-24 18:26:47 UTC`

### Q4. When was the malware first submitted to VirusTotal?

Still under **Details**, the **History** section shows the first submission date.

![First submission](/img/yellowrat/05-q4-first-submission.png)

**Answer:** `2020-10-15 02:47:37 UTC`

### Q5. What is the name of the .dat file dropped in the AppData folder?

Red Canary's report on Yellow Cockatoo documents a randomly generated string written to a `.dat`
file in the AppData\Roaming folder, used as a unique host identifier.

![Dropped .dat file](/img/yellowrat/06-q5-dat-file.png)

**Answer:** `solarmarker.dat` (full path `%USERPROFILE%\AppData\Roaming\solarmarker.dat`)

### Q6. What is the C2 server the malware communicates with?

The same Red Canary report lists the C2 the malware contacts to share host information and retrieve
commands.

![C2 server](/img/yellowrat/07-q6-c2.png)

**Answer:** `gogohid[.]com`

## Indicators of compromise (IOC)

| Type | Value |
|------|-------|
| Family | Yellow Cockatoo / Jupyter / SolarMarker |
| SHA-256 | `30e527e45f50d2ba82865c5679a6fa998ee0a1755361ab01673950810d071c85` |
| Filename | `111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll` |
| Dropped file | `%USERPROFILE%\AppData\Roaming\solarmarker.dat` |
| C2 domain | `gogohid[.]com` |
| C2 IP (subnet) | `45.146.165[.]X` (e.g. `45.146.165[.]221`) |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Drive-by Compromise (SEO / search redirects) | T1189 |
| Execution | User Execution: Malicious File | T1204.002 |
| Defense Evasion | Masquerading | T1036 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |

## References

- CyberDefenders — [YellowRAT challenge](https://cyberdefenders.org/blueteam-ctf-challenges/yellow-rat/)
- Red Canary — Yellow Cockatoo analysis
- VirusTotal
