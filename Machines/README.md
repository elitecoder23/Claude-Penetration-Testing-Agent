# Machines

Writeups for individual machines — HackTheBox, TryHackMe, Proving Grounds, CTF boxes, and other standalone targets (as opposed to HTB Academy module skills assessments, which live in `writeups/`).

## Convention

- **One file per machine:** `<platform>-<machine-name>.md` (e.g. `htb-blue.md`, `thm-mrrobot.md`, `pg-nibbles.md`).
- Follow the core methodology in `methodology/core-principles.md`: enumerate first, never test blindly, simple before complex.
- Cross-reference the relevant `methodology/` playbook and `checklists/` file for the attack category involved.

## Writeup structure

Each machine writeup should capture the full attack chain so a future session starts with context:

```
# <Platform> — <Machine Name>

**Target:** <IP>   **OS:** <os>   **Difficulty:** <rating>   **Date:** <YYYY-MM-DD>

## Recon
- Nmap output (open ports, services, versions)
- Key enumeration findings

## Foothold
- Vulnerability identified and why
- Exploitation steps + key payloads
- Initial shell / user flag

## Privilege Escalation
- Enumeration that revealed the path
- Exploitation steps
- Root/system flag

## Lessons Learned
- What worked, what didn't, and the key gotchas
- Techniques worth reusing (link back to methodology/checklists)
```
