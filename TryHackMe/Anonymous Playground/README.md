# Anonymous Playground (THM) - IPS Evasion, Custom Cryptography & Binary Analysis

**Platform:** TryHackMe | **Target OS:** Linux (Ubuntu) | **Difficulty:** Hard  
**Focus:** IPS/IDS Evasion, HTTP Cookie Manipulation, Custom Cryptography (Cipher Logic), and Static Binary Analysis.

---

## 1. Executive Summary & Attack Surface
The "Anonymous Playground" machine tests an attacker's ability to chain logical web flaws with cryptographic reverse engineering. The successful attack path executed during this engagement included:
1. **Firewall/IDS Evasion:** Analyzing TCP state drops to bypass perimeter defenses during enumeration.
2. **Access Control Abuse:** Modifying HTTP cookies to bypass frontend authentication logic.
3. **Custom Cryptography Analysis:** Reverse-engineering a custom alphabetical index cipher to extract SSH credentials, yielding initial access to the internal network.
4. **Vulnerability Discovery:** Performing static analysis on an internal SUID binary to identify a critical Buffer Overflow vulnerability, documented for remediation.

---

## 2. Reconnaissance & IPS/IDS Evasion Mechanics

We initiated our enumeration phase. However, a significant operational anomaly occurred between standard full-connect tools and aggressive SYN scanners.

```bash
# RustScan (Full Connect Scan) - Succeeded
$ rustscan -a 10.114.138.173 -- -o ports.txt
Open 10.114.138.173:22
Open 10.114.138.173:80

# Nmap SYN Scan (-sS) - Failed / Dropped
$ sudo nmap -sS -sV -sC -O -p 22,80 10.114.138.173
PORT   STATE    SERVICE VERSION
22/tcp filtered ssh
80/tcp filtered http
```

**OS-Level TCP Stack Analysis:**
When Nmap executed a stealth SYN scan (`-sS`) combined with aggressive scripts, the target's Intrusion Prevention System (IPS) flagged the half-open connections (sending `RST` instead of completing the 3-way handshake) and dynamically dropped our IP. 
To bypass this, we pivoted to a legitimate TCP Connect scan (`-sT`), allowing the kernel to complete the `SYN -> SYN-ACK -> ACK` handshake, which successfully evaded the IPS rules.

---

## 3. Web Logic Abuse & Cryptographic Reverse Engineering

Enumerating the web server revealed an access control mechanism disguised within the `robots.txt` file and HTTP cookie parameters.

```bash
$ curl -I http://10.114.138.173/
Set-Cookie: access=denied;
```
By accessing the hidden `/zYdHuAKjP` directory and manipulating the HTTP Cookie header from `access=denied` to `access=granted`, we bypassed the restriction, revealing a cipher string:
`hEzAdCfHzA::hEzAdCfHzAhAiJzAeIaDjBcBhHgAzAfHfN`

**Cryptographic Analysis & Decryption:**
The double colon `::` indicated a `username::password` format. The custom cipher logic required converting alphabetical pairs into single characters by adding their alphabetical indexes (mod 26). We engineered a Python snippet to decode this pattern:

```python
def decode_cipher(string):
    res = []
    for i in range(0, len(string), 2):
        val = ( (ord(string[i]) & 31) + (ord(string[i+1]) & 31) ) % 26
        res.append(chr(val + 96) if val != 0 else 'z')
    return "".join(res)

print(decode_cipher("hEzAdCfHzA") + ":" + decode_cipher("hEzAdCfHzAhAiJzAeIaDjBcBhHgAzAfHfN"))
# Result -> magna:magnaisanelephant
```

Utilizing these credentials, we successfully established an SSH session and retrieved the initial access flag.

```bash
magna@ip-10-114-138-173:~$ cat flag.txt
9184177ecaa83073cbbf36f1414cc029
```

---

## 4. Post-Exploitation Finding: Vulnerable SUID Binary

After authenticating via SSH, local enumeration revealed a critical security misconfiguration. A custom binary named `hacktheworld` was discovered with the SUID bit set, owned by `root`.

```bash
magna@ip-10-114-138-173:~$ ls -la hacktheworld
-rwsr-xr-x 1 root root 8528 Jul 10  2020 hacktheworld

magna@ip-10-114-138-173:~$ strings hacktheworld | grep -i "call_bash"
call_bash
```

**Technical Finding (Buffer Overflow Risk):**
By running basic static analysis (`strings`), we identified that the binary executes an insecure input prompt (utilizing the deprecated `gets()` C function) and contains an unreferenced function named `call_bash`. 

*Security Implication:* The use of `gets()` lacks bounds checking. This architecture is a textbook example of a Buffer Overflow (Ret2Win) vulnerability. Supplying oversized input would overwrite the instruction pointer (RIP) and allow an attacker to call the `call_bash` function, yielding a root shell. While full exploit weaponization falls outside the scope of this network-focused assessment, the vulnerability is critically rated and requires immediate remediation.

---

## 5. Defensive Remediation & Secure Coding

- **Avoid Custom Cryptography:** The application should rely on industry-standard hashing algorithms (e.g., bcrypt, Argon2) rather than rolling custom, easily reversible alphabetical ciphers.
- **Secure C Programming:** The `hacktheworld` binary must be recompiled. The `gets()` function is deprecated and inherently unsafe. It should be replaced with `fgets(buffer, sizeof(buffer), stdin);`.
- **Remove SUID Bits:** Remove the SUID execution bit from custom or untested binaries immediately to prevent trivial privilege escalation:
  ```bash
  sudo chmod u-s /home/magna/hacktheworld
  ```
