# HTB Academy — CWES Broken Authentication Module Notes

## Key Techniques

### User Enumeration
- Different error messages (valid vs invalid username) → ffuf with `-fr`
- Same error message but different response SIZE → ffuf with `-fs`
- Always register a test account to establish a known-valid username for size baseline comparison

### Password Policy Filtering
- Always check the password policy before building a wordlist
- Use `awk` for complex filters (exact length + multiple char classes + exclusions) — single pass, much faster than chained grep
- Example: exactly 12 chars, upper+lower+digit, no special chars:
  ```bash
  awk 'length($0) == 12 && /[A-Z]/ && /[a-z]/ && /[0-9]/ && !/[^a-zA-Z0-9]/' rockyou.txt > filtered.txt
  ```

### Weak Reset Tokens
- 4-digit token = 10,000 possibilities → trivially brute-forceable with ffuf
- 6-digit token = 1,000,000 possibilities → still feasible
- `seq -w` pads with leading zeros to maintain consistent length
- Token is usually in a GET parameter; session cookie ties it to the user

### 2FA Brute Force
- Session expiry is the main enemy — too slow = session dies before hitting valid OTP
- 40 threads caused session expiry; 10-20 threads is the sweet spot
- After the correct OTP is found, all subsequent requests with that session get 302 (session is now fully authenticated)
- **Alternative:** if 2FA brute force keeps failing, try direct access bypass on the post-2FA page using the post-login session

### Rate Limit Bypass (X-Forwarded-For)
- Rate limits that use `X-Forwarded-For` to identify clients can be bypassed by spoofing this header
- Attacker sets arbitrary values → each request appears to come from a different IP
- CVE-2020-35590 is a real-world example

### Security Question Attacks
- Two attack vectors:
  1. Brute-force the answer (city wordlist: 26k+ cities)
  2. Manipulate hidden username parameter in reset form to target a different account
- Always inspect hidden fields in multi-step reset flows

### Direct Access Bypass
- PHP redirect without `exit`: `header("Location: x.php")` — page content still returned in 302 body
- Browsers follow the redirect; curl doesn't (without `-L`)
- Can bypass 2FA gate: use post-login session to access post-2FA protected page directly
- Fix: always `exit;` after `header("Location: ...")`

### Parameter Modification
- `user_id` in GET parameter controls which user's data loads
- Brute-force the ID range to find admin — filter by "access denied" error string
- Related to IDOR (covered in Web Attacks module)

### Session Token Forgery
- Check if session token is base64 or hex encoded plaintext
- If no integrity check (no HMAC/signature): decode → modify role → re-encode → use
- Also watch for URL encoding and incrementing/predictable tokens

---

## Common Pitfalls

| Pitfall | Fix |
|---------|-----|
| Same error message for invalid user and wrong password | Compare response SIZE instead |
| rockyou.txt binary warnings in awk/grep | Normal — still processes correctly |
| 2FA brute force session expires | Use 15-20 threads, or try direct access bypass instead |
| City wordlist not on Pwnbox | `curl -s <github_url> \| cut -d',' -f1 > city_wordlist.txt` |
| Protected page shows nothing in curl | Check response body without `-L` — might be in 302 body |
| awk slow on rockyou | It's 14M lines — still faster than chained grep, let it run |
