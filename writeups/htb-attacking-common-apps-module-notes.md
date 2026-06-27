# HTB Academy — Attacking Common Applications: Module Notes

**Status:** In progress (Sections 1–3 of 33 complete)

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
