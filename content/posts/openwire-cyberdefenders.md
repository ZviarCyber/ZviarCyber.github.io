---
title: "OpenWire — Investigating an Apache ActiveMQ RCE (CVE-2023-46604)"
date: 2026-06-19
tags: ["network-forensics", "wireshark", "activemq", "cve-2023-46604", "blueteam", "soc", "mitre-attack"]
categories: ["Write-up", "CyberDefenders"]
---

## Abstract

A network forensics walkthrough of the CyberDefenders **OpenWire** challenge. Starting from a
single PCAP and a tier-1 escalation about a public-facing server beaconing to suspicious IPs, I
trace an Apache ActiveMQ compromise via **CVE-2023-46604**: from the initial remote code
execution on the OpenWire port, through a malicious Spring XML payload that abuses
`java.lang.ProcessBuilder`, down to a dropped reverse shell talking to two separate C2 servers.

## Scenario

> During your shift as a tier-2 SOC analyst, you receive an escalation from a tier-1 analyst about
> a public-facing server. The server has been flagged for outbound connections to multiple
> suspicious IPs. Following the incident response process, the host is isolated from the network
> and a packet capture is pulled from the NSM sensor. Your task is to analyse the PCAP and assess
> for signs of malicious activity.

**Tool used:** Wireshark.

## The attack in one paragraph

The public server runs Apache ActiveMQ, exposed on TCP `61616` (the OpenWire protocol). The
attacker exploits **CVE-2023-46604**: a crafted OpenWire packet forces the broker to instantiate
a Spring `ClassPathXmlApplicationContext`, which fetches a remote XML file (`invoice.xml`) from the
first C2. That XML defines a bean that invokes `java.lang.ProcessBuilder` to run commands, drops a
reverse shell binary disguised as `docker`, and beacons out to a second C2. Two C2 servers, one
CVE, one legitimate service turned into an entry point.

## Investigation

### Q1. What is the IP of the C2 server that communicated with our server?

Opening the PCAP, the OpenWire protocol immediately stands out, with traffic involving
`146.190.21.92`. Following its TCP stream out of curiosity:

![PCAP showing OpenWire traffic](/img/openwire/01-pcap-openwire.png)

![TCP stream referencing ClassPathXmlApplicationContext](/img/openwire/02-tcp-stream-classpath.png)

The stream shows a Spring `ClassPathXmlApplicationContext` being used to pull an `invoice.xml`
from that same IP. That makes it the C2 server.

**Answer:** `146.190.21.92`

### Q2. What is the port number of the exploited service?

Inspecting the OpenWire frames, the recurring port is `61616`, the ActiveMQ OpenWire default.

![OpenWire frame on port 61616](/img/openwire/03-openwire-port-61616.png)

**Answer:** `61616`

### Q3. What is the name of the vulnerable service?

Looking up what runs on port `61616` confirms it is **Apache ActiveMQ**.

![Identifying the ActiveMQ service](/img/openwire/04-activemq-service.png)

**Answer:** Apache ActiveMQ

### Q4. What is the IP of the second C2 server?

Going to **Statistics > Endpoints** to list every host in the capture:

![Statistics > Endpoints view](/img/openwire/05-statistics-endpoints.png)

The victim (public server) is `134.209.197.3` and the first C2 is `146.190.21.92`. That leaves two
unknown addresses to check. Following their TCP streams and reading the content of the malicious
payload reveals the second C2:

![TCP stream of the payload traffic](/img/openwire/06-tcp-stream-payload.png)

![Second C2 address inside the payload](/img/openwire/07-second-c2.png)

**Answer:** `128.199.52.72`

### Q5. What is the name of the reverse shell executable dropped on the server?

The reverse shell surfaced in the previous step: the dropped binary is named `docker` (masquerading
as the legitimate Docker binary).

**Answer:** `docker`

### Q6. What Java class was invoked by the XML file to run the exploit?

Reading the XML payload that was served, the bean definition at the top invokes
`java.lang.ProcessBuilder` to execute commands on the host.

![ProcessBuilder invoked in the XML payload](/img/openwire/08-processbuilder-xml.png)

**Answer:** `java.lang.ProcessBuilder`

### Q7. What CVE identifier is associated with this vulnerability?

Searching the behaviour (ActiveMQ OpenWire, remote class instantiation, RCE) points to a single,
exact match.

![CVE identification](/img/openwire/09-cve-identification.png)

**Answer:** CVE-2023-46604

### Q8. In which Java class and method was the validation step added by the vendor?

The vendor fixed the flaw by adding a [validation step](https://github.com/apache/activemq/pull/1098/commits/3eaf3107f4fb9a3ce7ab45c175bfaeac7e866d5b)
so that only valid `Throwable` classes can be instantiated. Per the vendor patch and TrendMicro's
analysis, the check was added in:

![Validation added in createThrowable](/img/openwire/10-createthrowable-fix.png)

**Answer:** `BaseDataStreamMarshaller.createThrowable`

## Indicators of compromise (IOC)

| Type | Value |
|------|-------|
| C2 server #1 | `146.190.21.92` |
| C2 server #2 | `128.199.52.72` |
| Exploited service / port | Apache ActiveMQ / `61616` (OpenWire) |
| Malicious payload | `invoice.xml` (remote Spring XML) |
| Dropped reverse shell | `docker` (masqueraded binary) |
| Vulnerability | CVE-2023-46604 |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Execution | Command and Scripting Interpreter | T1059 |
| Defense Evasion | Masquerading (binary named `docker`) | T1036 |
| Command and Control | Application Layer Protocol | T1071 |
| Command and Control | Ingress Tool Transfer | T1105 |

## References

- CyberDefenders — *OpenWire* challenge
- NVD — CVE-2023-46604
- Apache ActiveMQ security advisory and patch (`BaseDataStreamMarshaller.createThrowable`)
- TrendMicro — analysis of CVE-2023-46604 exploitation
