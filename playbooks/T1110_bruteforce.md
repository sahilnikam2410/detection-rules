# Playbook: Windows brute force (T1110)

| | |
|---|---|
| **Triggers** | Wazuh `100211` · Sigma `win_bruteforce_single_source` · Splunk [`win_bruteforce_t1110.spl`](../queries/splunk/win_bruteforce_t1110.spl) |
| **ATT&CK** | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/), Credential Access |
| **Default severity** | High. **Critical** if a successful logon (4624) follows from the same source |
| **Target time to triage** | 15 minutes |

## 1. Scope (first 5 minutes)

1. **Source:** which IP or host? Internal or external? Known scanner, jump box or VPN pool?
2. **Target:** which host, which account(s)? One account hammered, or many accounts tried once each (password spraying, [T1110.003](https://attack.mitre.org/techniques/T1110/003/))?
3. **Outcome:** any **4624 success** from the same source during or after the burst? Any **4740 lockout**?
4. **Volume:** is it still going?

**Splunk:** all logon activity from the source

```spl
index=wineventlog source="WinEventLog:Security" (EventCode=4625 OR EventCode=4624 OR EventCode=4740)
    IpAddress="<SOURCE_IP>" earliest=-1h
| stats count by EventCode, TargetUserName, WorkstationName, LogonType
| sort - count
```

**Wazuh (Threat Hunting, DQL):**

```
rule.id:(60122 or 60106 or 100211) and data.win.eventdata.ipAddress:"<SOURCE_IP>"
```

## 2. Decide

| Finding | Verdict | Action |
|---|---|---|
| Known service account or password manager retrying after a password change | **False positive** | Fix the credential at the source, request tuning, close |
| Authorised pentest or scan in the change calendar | **Benign true positive** | Confirm with the owner, note the ticket, close |
| Unknown source, failures only, no success | **True positive** | Contain (step 3) |
| Any **success after the burst** | **True positive, likely compromise** | Contain **and escalate to L2 now** |
| Many accounts, few attempts each | **Password spraying** | Treat as TP; scope every account the source touched |

## 3. Contain (least disruptive first)

1. **Block the source:** Wazuh active response `firewall-drop` on the target, or the perimeter firewall for external IPs.
2. **If a logon succeeded:** disable the account, reset its password, and end its sessions.
3. **If the source is internal:** isolate that host. Something on it is running the attack.

## 4. Escalate to L2 when

- a logon **succeeded** after the burst
- the target is a domain controller, or a privileged / admin account
- the source is internal and not a known scanner
- more than 5 accounts were targeted

## 5. Close out

```
Alert:     100211 / T1110        Time (UTC):
Source:    <ip/host> (internal|external)   Target: <host> / <account(s)>
Outcome:   failures only | success at <time> | lockout at <time>
Verdict:   FP | benign TP | TP
Actions:   blocked / disabled / reset / isolated
Escalated: no | yes → <L2, time>
Tuning:    none | <change requested>
```

## Tuning

- Exclude **known** service-account sources by IP, never by account name alone. An attacker can pick the name.
- `frequency 5 / 60s` is the lab value. Baseline your own environment for a week before changing it.
- Never remove `same_source_ip` to "catch more". Doing that turns this into a different detection with far more false positives.
