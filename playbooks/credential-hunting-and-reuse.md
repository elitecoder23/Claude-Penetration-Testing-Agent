# Playbook — Credential Hunting & Reuse

**Trigger:** you have any shell, or read access to app files. Credentials on disk are one of the most common foothold→user and user→root pivots.

## Where to look
- **App config files** (highest value): DB creds + app secrets.
  - FreePBX: `/etc/freepbx.conf` (`AMPDBUSER/AMPDBPASS`), `/etc/amportal.conf` (`AMPMGRPASS`, `PHP_CONSOLE_PASSWORD`).
  - WordPress `wp-config.php`, Laravel `.env`, `config.php`, `settings.py`, `application.properties`, `web.config`.
- **History / dotfiles:** `~/.bash_history`, `~/.mysql_history`, `~/.*_history`, `~/.gitconfig`, `~/.ssh/`, `~/.aws/`, `~/.config/`.
- **DB contents:** dump user tables for hashes — `select * from ampusers\G`, `userman_users`, `wp_users`, `users`. `describe <table>` first (schemas vary).
- **Backups & temp:** `*.bak`, `*.old`, `*.zip`, `/var/backups`, `/tmp`, `/opt`, mail spools `/var/mail/*`.
- **Grep the filesystem:** `grep -rniE 'password|passwd|secret|api[_-]?key|token' /etc /var/www /opt 2>/dev/null | head`.

## Crack
- Identify hash type (`hashid`), then:
  - `john --format=raw-md5 hashes` / `--format=bcrypt` / `--format=sha256crypt` with `rockyou.txt`.
  - `hashcat -m <mode> hashes rockyou.txt` (e.g. `-m 0` md5, `-m 3200` bcrypt, `-m 1800` sha512crypt).

## Reuse everywhere (the point)
Every password/hash found gets tried against:
- `su <user>` for each real account in `/etc/passwd` (`grep -vE 'nologin|/false' /etc/passwd`).
- `ssh <user>@target`.
- Other web logins / admin panels, DB, service auth (AMI, Redis).
- **root** directly (`su root`, SSH) — password reuse to root is common on easy boxes.

Human-looking passphrases (e.g. `batteryhorsestaple`, `PHP_CONSOLE_PASSWORD`) are the strongest reuse candidates.

## Habits
- Loot **once**, maintain a creds list, and try the whole list at each auth boundary.
- Note which creds *didn't* work too — narrows the search.

→ back to `../Machines/machines-methodology.md` Phase 2/3. See also `../checklists/broken-authentication.md`, `../checklists/login-brute-forcing.md`.
