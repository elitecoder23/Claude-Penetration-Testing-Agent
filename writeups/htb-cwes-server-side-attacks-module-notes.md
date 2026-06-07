# HTB Academy — CWES Server-Side Attacks Module Notes

---

## Module Overview

Four attack classes covered:
- **SSRF** — server fetches user-supplied URL → attacker borrows server's network position
- **SSTI** — user input injected into template string → template engine executes it
- **SSI Injection** — user input written into `.shtml` file → web server executes SSI directives
- **XSLT Injection** — user input inserted into XSL data → XSLT processor executes injected elements

---

## SSRF

### Core Concept
Web server fetches a URL based on user input. The server is a trusted internal device — once you control what it requests, you inherit its network access. Any request it makes comes from its IP, bypassing firewalls that block your direct access.

```
Internet → [Firewall] → Web Server → Internal Network
                                          ├── DB Server
                                          ├── Admin Panel
                                          └── Internal APIs
```

### URL Schemes
- `http://` / `https://` — reach internal endpoints, bypass firewall restrictions
- `file://` — read local files (LFI via SSRF)
- `gopher://` — send raw bytes to any TCP service; enables POST requests and interaction with non-HTTP services (SMTP, Redis, MySQL)

### Non-Blind vs Blind
- **Non-blind:** response body reflected back → full data exfiltration possible
- **Blind:** no response reflected → limited to port scanning and file existence checks (if error messages differ)

### Port Scanning via SSRF
Use ffuf with `-fr` to filter the closed-port error message. Always identify what the error says for a closed port before running the scan.

### gopher:// Double Encoding
When a gopher URL is sent inside a POST parameter, it must be URL-encoded twice:
1. First encoding: encode the raw HTTP request (spaces → `%20`, newlines → `%0D%0A`)
2. Second encoding: encode the entire gopher URL since it's itself a POST parameter value

### Gopherus Tool
Generates gopher URLs for SMTP, MySQL, Redis, FastCGI, PostgreSQL, Zabbix, and memcache variants. Requires Python 2.7.

---

## SSTI

### Core Concept
Template engines render templates by inserting values into them. SSTI occurs when user input is inserted into the template string itself (not as a value). The engine executes the injected code exactly as it would execute legitimate template code.

**Safe (not vulnerable):**
```python
render("Hello {{ name }}!", values={"name": user_input})
```

**Vulnerable:**
```python
render("Hello " + user_input + "!")
# user_input = "{{ 7*7 }}" → renders "Hello 49!"
```

### Engine Identification Flowchart
```
${7*7} → executed?
  Yes → Freemarker/other
  No  → {{7*7}} → executed?
           No  → other engine
           Yes → {{7*'7'}} → result?
                    7777777 → Jinja2
                    49      → Twig
```

### Critical Curl Note
Always use `-G --data-urlencode` — raw double-quoted URLs eat `{` and `}`, resulting in empty responses or mangled payloads.

### Jinja2 (Python/Flask)
- Accesses Python internals via `self.__init__.__globals__.__builtins__`
- `__import__('os').popen('cmd').read()` for RCE
- `open('/path').read()` for LFI — cleaner than RCE when path is known

### Twig (PHP)
- `{{ ['cmd'] | filter('system') }}` for RCE
- `{{ '/path'|file_excerpt(1,-1) }}` for LFI — Symfony framework only; falls back to `cat` via RCE if unavailable

### SSTImap
Modern replacement for tplmap. Python 3, actively maintained. Auto-detects engine, supports interactive shell, file download, and single command execution.

---

## SSI Injection

### Core Concept
SSI directives in HTML files are executed by the web server when the file is served. If user input is written into an `.shtml` file without sanitization, injected directives execute when the page is fetched.

### Critical Two-Step Process
1. Submit payload to `index.php` → writes directive into `page.shtml`
2. Fetch `page.shtml` → web server processes SSI and executes the directive

Output appears in the **fetch response**, not the **submission response**.

### Key Directives
- `<!--#exec cmd="..." -->` — OS command execution, path to RCE
- `<!--#printenv -->` — confirm injection (environment variables)
- `<!--#echo var="..." -->` — print specific variable
- `<!--#include virtual="..." -->` — include file from web root

### Detection
File extensions `.shtml`, `.shtm`, `.stm` hint at SSI. But servers can enable SSI for any extension — absence of these doesn't rule it out.

---

## XSLT Injection

### Core Concept
XSLT transforms XML documents using XSL stylesheets. User input inserted into XSL data before processing allows injecting additional XSL elements. If the processor supports PHP functions, this escalates to LFI and RCE.

### Key XSL Elements
- `<xsl:value-of select="...">` — extract and print node value
- `<xsl:for-each select="...">` — loop over nodes
- `<xsl:if test="...">` — conditional output
- `<xsl:sort select="..." order="...">` — sort in loop

### System Properties (Info Disclosure)
```xml
<xsl:value-of select="system-property('xsl:version')" />
<xsl:value-of select="system-property('xsl:vendor')" />
<xsl:value-of select="system-property('xsl:vendor-url')" />
```

### LFI Options
- `php:function('file_get_contents','/path')` — requires PHP functions enabled
- `unparsed-text('/path', 'utf-8')` — XSLT 2.0+ only

### RCE
`php:function('system','cmd')` — requires PHP functions enabled in XSLT processor config.

---

## Lessons from Exercises

### SSRF
- Internal admin pages may be IP-restricted (not password-protected) — routing through SSRF is enough to access them
- Port 3306 (MySQL) visible via SSRF port scan is a pivot opportunity with gopher://
- Blind SSRF: different error messages for open vs closed ports is what makes port scanning possible

### SSTI
- Flask apps don't have `index.php` — use `/` as the route
- Twig `file_excerpt` requires Symfony — always have the RCE fallback ready
- Raw curl with `{{}}` returns empty — `-G --data-urlencode` is mandatory

### SSI
- Output page caches the last injected command — can re-fetch `page.shtml` without resubmitting if testing multiple commands
- Parameter name and form action must be read from the HTML — was `msg` not `name`, form was GET not POST

### XSLT
- Command output appears before the HTML in the response (stdout printed before the template renders)
- `php:function` namespace must be declared in the XSLT stylesheet for it to work — the web app handles this; you just inject the element
