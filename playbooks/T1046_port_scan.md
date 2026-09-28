# Playbook: Port scan (T1046)

| | |
|---|---|
| **Triggers** | Sigma `Port Scan From a Single Source` (draft) · Splunk [`net_port_scan_t1046.spl`](../queries/splunk/net_port_scan_t1046.spl) |
| **ATT&CK** | [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/), Discovery |
| **Default severity** | Medium (external source) · **High** (internal source) |
| **Target time to triage** | 30 minutes |

## 1. Where is it coming from?

Direction changes everything:

| Source | What it usually means |
|---|---|
| **Internet → your edge** | Background noise. Internet-wide scanners hit everyone all day. Low priority unless it's followed by exploitation attempts. |
| **Internal → internal** | Someone, or something, **already inside** is mapping the network. This is the one that matters. |
| **Internal → internet** | A host scanning outward: compromised, or a misused tool. |

## 2. Scope

```spl
index=firewall src_ip="<SOURCE_IP>" earliest=-24h
| stats dc(dst_port) as ports dc(dst_ip) as hosts values(action) by src_ip
```

- **One host, many ports:** vertical scan, profiling a target.
- **Many hosts, one or two ports** (445, 3389, 22): horizontal scan, looking for a way to move. Often worse.
- Did **any** connection get `allow` on a port that was scanned? Those services are what the scanner found.

## 3. Decide

| Finding | Verdict |
|---|---|
| Source is the vulnerability scanner (Nessus, Qualys, OpenVAS) on its schedule | **Benign TP**: exclude by source IP |
| External, denied, nothing allowed afterwards | **TP, no impact**: block at the edge, close |
| External, followed by exploit-looking traffic to an allowed port | **TP**: escalate, check the exposed service ([T1190](https://attack.mitre.org/techniques/T1190/)) |
| **Internal source, not a known scanner** | **TP, likely compromise**: isolate the source and escalate |

## 4. Contain

1. External: block the source at the perimeter. Consider blocking its whole range if the scanning persists.
2. Internal: **isolate the source host**, then look at what ran on it just before the scan (Sysmon 1 process creation, e.g. `nmap.exe`, PowerShell `Test-NetConnection` loops).

## 5. Escalate to L2 when

- the source is internal
- a scanned port was allowed and the service behind it is vulnerable or unpatched
- the scan is followed by brute force ([T1110](T1110_bruteforce.md)) or exploit attempts

## Tuning

Exclude scanners by **source IP and schedule** together. A scanner IP scanning outside its window is still worth a look.
