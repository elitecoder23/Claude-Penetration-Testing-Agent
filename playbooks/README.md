# Playbooks

Reusable, exploit/vuln-type playbooks — the "how" for specific situations that recur across machines and engagements. Distinct from:
- `../methodology/` — attack-phase frameworks per web-vuln class (HTB Academy derived).
- `../checklists/` — quick enumeration/attack checklists.
- `../Machines/machines-methodology.md` — the end-to-end box workflow that *routes into* these playbooks.

Each playbook is triggered by an **observation** and gives a decision flow + concrete commands. Grow this folder whenever a technique proves reusable across ≥2 boxes.

## Index
- [web-fingerprint-to-cve.md](web-fingerprint-to-cve.md) — turn a web app product+version into a working exploit.
- [reverse-shell-and-shell-stabilization.md](reverse-shell-and-shell-stabilization.md) — get, stabilize, and keep a shell; avoid PTY paste-corruption.
- [linux-privilege-escalation.md](linux-privilege-escalation.md) — ordered local enum → root vectors.
- [localhost-internal-services.md](localhost-internal-services.md) — exploit services bound to 127.0.0.1 after foothold (and spot decoys).
- [credential-hunting-and-reuse.md](credential-hunting-and-reuse.md) — find secrets on disk, crack, and reuse everywhere.
- [cron-incron-file-watchers.md](cron-incron-file-watchers.md) — abuse scheduled/triggered root execution.

## Known-service exploit references (in memory + reference notes)
- FreePBX endpoint unauth SQLi→RCE (CVE-2025-57819) and FreePBX sysadmin incron root — see `Machines/htb-connected.md`.
- OliveTin password-arg cmd injection (CVE-2026-27626), OpenSTAManager `.p7m` cmd injection (CVE-2025-69212) — see `Machines/htb-enigma.md`.
- Next.js React2Shell (CVE-2025-55182) + Node `--inspect` debug-port RCE — see `Machines/htb-reactor.md`.
