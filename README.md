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
| **HackTheBox** | **Dancing** | Windows | Very Easy | SMB Shares (Port 445), Null Sessions, ACLs vs NTFS, Data Leakage | [View Report](./HackTheBox/Dancing/README.md) |
| **HackTheBox** | **Fawn** | Linux | Very Easy | FTP RFC 959, Extended Passive Mode (EPSV), Anonymous Exfiltration | [View Report](./HackTheBox/Fawn/README.md) |
| **HackTheBox** | **Meow** | Linux | Very Easy | Cleartext Protocols (Telnet), PAM Mechanics, Null Password Hash | [View Report](./HackTheBox/Meow/README.md) |
| **HackTheBox** | **Redeemer** | Linux | Very Easy | Redis Protocol (RESP), In-Memory DBs, Unauthenticated Data Exfiltration | [View Report](./HackTheBox/Redeemer/README.md) |
| **HackTheBox** | **Appointment** | Linux | Very Easy | Boolean Logic, SQL Injection (SQLi), Authentication Bypass | [View Report](./HackTheBox/Appointment/README.md) |
| **HackTheBox** | **Sequel** | Linux | Very Easy | DB Enumeration, SQL Syntax, MariaDB Unauthenticated Access | [View Report](./HackTheBox/Sequel/README.md) |
| **HackTheBox** | **Crocodile** | Linux | Very Easy | Anonymous FTP Exfiltration, Directory Fuzzing, Credential Reuse | [View Report](./HackTheBox/Crocodile/README.md) |
| **HackTheBox** | **Three** | Linux | Very Easy | VHost Routing, AWS S3 Misconfiguration, Public Bucket Write, PHP RCE | [View Report](./HackTheBox/Three/README.md) |
| **HackTheBox** | **Responder** | Windows | Very Easy | LFI to UNC Path Injection, SMB NTLMv2 Coercion, WinRM | [View Report](./HackTheBox/Responder/README.md) |


---
*Disclaimer: All vulnerabilities exploited and documented in this repository were conducted within authorized, simulated, and isolated lab environments.*
