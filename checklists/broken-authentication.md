# Broken Authentication Checklist

**Rule:** Test every layer of auth independently — login, reset, 2FA, session tokens, protected pages. A bypass at any layer is game over.

---

## Reconnaissance
- [ ] `curl -s http://<TARGET>/login.php | grep -i "form\|input\|action\|method"` — get field names
- [ ] Check for linked endpoints: reset, register, 2fa, forgot
- [ ] Probe common endpoints: `reset.php`, `reset_password.php`, `2fa.php`, `profile.php`, `admin.php`, `dashboard.php`
- [ ] For any 302 endpoint: `curl -s http://<TARGET>/page.php | grep -i "flag\|HTB{"` — check for direct access bypass
- [ ] Register a test account to understand password policy

---

## User Enumeration
- [ ] Test invalid username vs valid username + wrong password — compare error message AND response size
- [ ] If same error text: use `-fs <invalid_size>` in ffuf
- [ ] If different error text: use `-fr "Unknown user"` in ffuf
- [ ] Wordlist: `xato-net-10-million-usernames.txt`

---

## Password Brute Force
- [ ] Register account to reveal password policy
- [ ] Filter rockyou.txt with awk (single pass, handles exact length + char class + exclusions)
- [ ] `wc -l custom_wordlist.txt` — verify filtered list size before attacking
- [ ] Run ffuf filtering by response size or error string
- [ ] On success: confirm credentials with manual curl login

---

## Password Reset Token
- [ ] Find reset endpoint: `reset.php`, `forgot.php`, etc.
- [ ] Trigger reset for target user, capture PHPSESSID
- [ ] Test one token to confirm exact error string
- [ ] `seq -w 0 9999 > tokens.txt` (4-digit) or `seq -w 0 999999` (6-digit)
- [ ] ffuf with `-fr "<error string>"`
- [ ] Use valid token to POST new password

---

## 2FA Brute Force
- [ ] Login → confirm redirect to 2FA page
- [ ] Note OTP field name and action path
- [ ] Test single OTP to confirm exact error string
- [ ] `seq -w 0 9999 > tokens.txt`
- [ ] ffuf with `-t 20` (balance speed vs session expiry)
- [ ] **If session keeps expiring:** try direct access bypass on the post-2FA protected page using the post-login session cookie

---

## Security Question
- [ ] Trigger reset for target user, capture PHPSESSID
- [ ] Download city wordlist: `curl -s <github_url> | cut -d',' -f1 > city_wordlist.txt`
- [ ] Test one response to confirm exact error string
- [ ] ffuf against `/security_question.php` with session cookie
- [ ] After solving: POST new password to `/reset_password.php`
- [ ] Check if username is a hidden field in the reset form → try swapping it to admin

---

## Direct Access Bypass
- [ ] Try accessing protected pages directly without auth: `curl -s http://<TARGET>/admin.php`
- [ ] Try with post-login session (before completing 2FA): `curl -s http://<TARGET>/profile.php -b "PHPSESSID=<SESSION>"`
- [ ] Look for flag/protected content in response body of 302 responses

---

## Parameter Modification
- [ ] After login, check redirect URL for user_id or similar parameters
- [ ] `seq 1 1000 > user_ids.txt` → ffuf filtering by "no access" error string
- [ ] Try user_id=0, user_id=1 manually first

---

## Session Token Analysis
- [ ] Capture token after login: look at Set-Cookie header
- [ ] Try base64 decode: `echo -n '<TOKEN>' | base64 -d`
- [ ] Try hex decode: `echo '<TOKEN>' | xxd -r -p`
- [ ] Try URL decode
- [ ] If plaintext data found → forge admin token → re-encode → use with curl

---

## Default Credentials
- [ ] Try `admin:admin`, `admin:password`, `root:root` manually
- [ ] Search CIRT.net for the product
- [ ] Google: `<product> default credentials`

---

## Rate Limit
- [ ] Check if rate limit kicks in after N failed attempts
- [ ] Try `X-Forwarded-For` header with different values — see if limit resets
- [ ] If yes: randomize `X-Forwarded-For` per request in ffuf

---

## Universal Reminders
- [ ] Always read the form HTML before building any ffuf command
- [ ] Test a single request manually before running ffuf — confirm field names and error strings
- [ ] Use awk (not chained grep) for complex wordlist filtering — faster, single pass
- [ ] 2FA brute force: session timeout is the main enemy — use enough threads to finish fast
- [ ] Direct access bypass: curl without `-L` shows 302 body; browser follows redirect and hides it
