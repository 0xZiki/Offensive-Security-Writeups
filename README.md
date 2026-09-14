# 🛡️ Offensive Security & Tradecraft Portfolio

**Author:** Ahmed Elzeky
**Role:** Cybersecurity Software Engineer & Red Team Analyst  
**LinkedIn:** www.linkedin.com/in/ahmed-elzeky-a88a3641b

---

## 🎯 About This Repository
This repository serves as an ongoing technical log of enterprise-grade machine compromises across **TryHackMe**, **HackTheBox**, and **OffSec Proving Grounds**. 

Unlike standard CTF walkthroughs, the reports herein focus heavily on:
- **OS Internals & System Calls:** (e.g., `setresuid()`, POSIX standards).
- **Network Protocol Mechanics:** (e.g., TCP states, SMB ACLs vs NTFS permissions, RFC analysis).
- **Advanced Forensics & Carving:** Bypassing legacy constraints and dissecting magic bytes.
- **Defensive Evasion & OPSEC:** Fileless execution and memory-based post-exploitation.

---

## 📂 Engagement Index (Writeups & Reports)

| Platform | Machine Name | OS | Difficulty | Key Concepts & Mechanics | Read Report |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TryHackMe** | **Anonymous** | Linux | Medium | SUID/GTFOBins (`env`), Cron Job Hijacking, Reverse Shell Redirection | [View Report](./TryHackMe/Anonymous/README.md) |
| **TryHackMe** | **Agent Sudo** | Linux | Easy | CVE-2019-14287 (Sudo), HTTP Header Abuse, Binwalk/DD Carving | [View Report](./TryHackMe/Agent_Sudo/README.md) |
| **TryHackMe** | **Blue** | Windows | Easy | MS17-010 Mechanics, NonPaged Pool Grooming, WMIExec Evasion | [View Report](./TryHackMe/Blue/README.md) |
| **TryHackMe** | **Anonymous Playground** | Linux | Hard | IPS Evasion, Cookie Abuse, Custom Crypto Analysis, Binary Static Analysis | [View Report](./TryHackMe/Anonymous_Playground/README.md) |
| **TryHackMe** | **Basic Pentesting** | Linux | Easy | OSINT, SSH Brute-Forcing, File Permission Abuse (644 vs 600), Offline RSA Cracking | [View Report](./TryHackMe/Basic_Pentesting/README.md) |
| **TryHackMe** | **Attacktive Directory** | Windows | Medium | Active Directory, AS-REP Roasting, DCSync, Pass-The-Hash, WinRM | [View Report](./TryHackMe/Attacktive_Directory/README.md) |
| **TryHackMe** | **ColddBox: Easy** | Linux | Easy | OSINT, WPScan Brute-Force, CMS Theme RCE, GTFOBins (`find`) | [View Report](./TryHackMe/ColddBox_Easy/README.md) |
| **TryHackMe** | **Bounty Hacker** | Linux | Easy | FTP Active/Passive Ports, SSH Brute-Force, `dash` EUID Dropping, `tar` PrivEsc | [View Report](./TryHackMe/Bounty_Hacker/README.md) |
| **TryHackMe** | **Cyborg** | Linux | Easy | Web Path Recon, Apache `apr1` Hash Cracking, BorgBackup Extraction, Sudo Script (`getopts`) PrivEsc | [View Report](./TryHackMe/Cyborg/README.md) |
| **TryHackMe** | **Simple CTF** | Linux | Easy | Anonymous FTP, Time-Based SQLi (CVE-2019-9053), Sudo Misconfig (`vim`) | [View Report](./TryHackMe/Simple_CTF/README.md) |
| **TryHackMe** | **Enterprise** | Windows | Hard | AD Recon, OSINT (GitHub), SMB Exfiltration, Kerberoasting (GetUserSPNs), RDP | [View Report](./TryHackMe/Enterprise/README.md) |
| **TryHackMe** | **GamingServer** | Linux | Easy | OSINT, RSA Offline Cracking (`ssh2john`), LXD/LXC Namespaces PrivEsc | [View Report](./TryHackMe/GamingServer/README.md) |
| **TryHackMe** | **Ice** | Windows | Easy | Icecast BOF, UAC EventVwr Bypass, Process Migration, LSASS/Mimikatz | [View Report](./TryHackMe/Ice/README.md) |
| **HackTheBox** | **Dancing** | Windows | Very Easy | SMB Shares (Port 445), Null Sessions, ACLs vs NTFS, Data Leakage | [View Report](./HackTheBox/Dancing/README.md) |
| **HackTheBox** | **Fawn** | Linux | Very Easy | FTP RFC 959, Extended Passive Mode (EPSV), Anonymous Exfiltration | [View Report](./HackTheBox/Fawn/README.md) |
| **HackTheBox** | **Meow** | Linux | Very Easy | Cleartext Protocols (Telnet), PAM Mechanics, Null Password Hash | [View Report](./HackTheBox/Meow/README.md) |
| **HackTheBox** | **Redeemer** | Linux | Very Easy | Redis Protocol (RESP), In-Memory DBs, Unauthenticated Data Exfiltration | [View Report](./HackTheBox/Redeemer/README.md) |
| **HackTheBox** | **Appointment** | Linux | Very Easy | Boolean Logic, SQL Injection (SQLi), Authentication Bypass | [View Report](./HackTheBox/Appointment/README.md) |
| **HackTheBox** | **Sequel** | Linux | Very Easy | DB Enumeration, SQL Syntax, MariaDB Unauthenticated Access | [View Report](./HackTheBox/Sequel/README.md) |
| **HackTheBox** | **Crocodile** | Linux | Very Easy | Anonymous FTP Exfiltration, Directory Fuzzing, Credential Reuse | [View Report](./HackTheBox/Crocodile/README.md) |
| **HackTheBox** | **Three** | Linux | Very Easy | VHost Routing, AWS S3 Misconfiguration, Public Bucket Write, PHP RCE | [View Report](./HackTheBox/Three/README.md) |
| **HackTheBox** | **Responder** | Windows | Very Easy | LFI to UNC Path Injection, SMB NTLMv2 Coercion, WinRM | [View Report](./HackTheBox/Responder/README.md) |
| **HackTheBox** | **Vaccine** | Linux | Easy | Offline Cracking (MD5/Zip), PostgreSQL `COPY FROM PROGRAM`, GTFOBins `vi` Escape | [View Report](./HackTheBox/Vaccine/README.md) |
| **HackTheBox** | **Archetype** | Windows | Very Easy | MSSQL Windows Auth, Egress Bypassing, LOLBins (`certutil`), PSReadLine History | [View Report](./HackTheBox/Archetype/REDME.md) |
| **HackTheBox** | **Oopsie** | Linux | Easy | IDOR (Cookie Manipulation), File Upload, Hardcoded Credentials, SUID PATH Hijacking | [View Report](./HackTheBox/Oopsie/README.md) |
| **OffSec** | **Potato** | Linux | Fundamental | PHP `strcmp` Type Juggling, LFI/Path Traversal, Sudoers Wildcard Abuse (`nice`) | [View Report](./OffSec/Potato/README.md) |


---
*Disclaimer: All vulnerabilities exploited and documented in this repository were conducted within authorized, simulated, and isolated lab environments.*
