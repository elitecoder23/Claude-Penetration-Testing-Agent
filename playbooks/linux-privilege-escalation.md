# Playbook — Linux Privilege Escalation

**Trigger:** you have a shell as a non-root user. Work the cheap, high-signal checks first; most boxes fall before LinPEAS.

## Ordered enumeration (cost order)
1. **`id` + `sudo -l`** (needs a TTY). Try harvested passwords. NOPASSWD entries / GTFOBins-able binaries = often instant root.
2. **Creds on disk** (see `credential-hunting-and-reuse.md`): app configs, `.bash_history`, `.git`, backups, DB. Reuse against `su`/SSH/other users.
3. **SUID / SGID / capabilities:**
   - `find / -perm -4000 -type f 2>/dev/null`
   - `getcap -r / 2>/dev/null` (`cap_setuid`, `python …=ep` → root)
   - Cross-ref GTFOBins for any non-standard binary.
4. **Scheduled/triggered exec** (see `cron-incron-file-watchers.md`): cron, incron/file-watchers, systemd timers running a **writable** script or watched path.
5. **Root processes:** `ps -eo user,pid,cmd` — look for a root process with a **debug port** (Node `--inspect`, Java JDWP, Python debugpy), a **writable config/script**, or a **local network service**.
6. **Localhost-only services** (see `localhost-internal-services.md`): `ss -tlnp`.
7. **Writable sensitive files:** `find / -writable -not -path '/proc/*' 2>/dev/null` filtered to service dirs, `/etc`, systemd units, `$PATH` dirs.
8. **Groups:** `id` → `docker`, `lxd`, `disk`, `adm`, `shadow`, `sudo`, `wheel` each have known escalations (but confirm the tooling is actually installed — `lxd` group is useless with no LXD).
9. **Kernel / distro:** `uname -a`, `/etc/os-release` → known local exploits (last resort; noisy/unstable).
10. **LinPEAS / pspy** to sweep for anything missed (`pspy` catches short-lived root cron/processes).

## Root primitives (once you get root code-exec)
- `chmod +s /bin/bash` → `/bin/bash -p` (quiet, no listener). **Preferred single-shot.**
- Write attacker key to `/root/.ssh/authorized_keys`.
- Add a root cron / systemd unit; or reverse shell as root.
- `cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash` if `/bin/bash` shouldn't be modified.

## Decoy discipline
- A custom root service without a **local sink** (no `subprocess`/`os.system`/`eval`/file-write to a path you control) is likely a **decoy** — don't over-invest. Grep first, read second.
- A vector needing an **absent** component (uninstalled tool, missing module, no outbound connectivity) is bait.

→ back to `../Machines/machines-methodology.md` Phase 3/4. See also `../methodology/core-principles.md`.
