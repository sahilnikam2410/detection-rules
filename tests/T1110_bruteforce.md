# T1110 Brute Force: test procedure

Run only in a lab you own. The target is a Windows host with a Wazuh agent;
the source is any other host on the same isolated network.

## 1. Prove the pipeline first

One failed logon must reach the manager as rule `60122` (level 5) before
anything else is tested. If it does not, a missing alert later is an ingestion
problem, not a detection gap.

## 2. Noise: must NOT fire

Two single failures several minutes apart.

```powershell
net use \WIN-SERVER-2022\IPC$ /user:labuser WrongPassword1
```

Expected: two `60122` events, no `100211`.

## 3. Burst: must fire

Five failures from the same source inside 60 seconds.

```powershell
1..5 | % { net use \WIN-SERVER-2022\IPC$ /user:labuser WrongPassword1 2>$null }
```

Expected: `60122` events, then `100211` at level 12 tagged `T1110`.

## 4. Spread: must NOT fire (tests `same_source_ip`)

Same number of failures, split across different source hosts. Expected: no
`100211`. If it fires, `same_source_ip` is missing.

## 5. Success after burst (draft chain only)

Run step 3, then log on correctly from the same source inside two minutes.
Expected with the draft chain loaded: `100221`, then `100222`.

## Result log

| Date | Rule | Step | Result | Evidence |
|---|---|---|---|---|
| 2026-09-05 | 100211 | 3 (burst) | fired, level 12, 21:39:08 | [bruteforce-100211.png](../evidence/bruteforce-100211.png) |
| 2026-09-05 | 100211 | 2 (noise) | quiet on isolated 60122 at 21:31:39 and 21:34:21 | same capture |
