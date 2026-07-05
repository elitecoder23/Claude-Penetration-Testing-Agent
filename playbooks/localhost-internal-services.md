# Playbook — Localhost-Only Internal Services

**Trigger:** after foothold, `ss -tlnp` / `netstat -tulpn` shows services bound to `127.0.0.1` (or `::1`) that were invisible externally. These are frequently the privesc path because they're only reachable now that you're local.

## Enumerate
```
ss -tlnp            # who listens where + PID/program (as root shows all)
ps -eo user,pid,cmd # map each port's PID to its USER — root-owned = target
```
For each internal port, identify the service and **its owning user**. A root-owned internal service you can talk to = candidate root RCE. Curl HTTP ones, banner-grab others.

## Common internal services & angles
| Port | Service | Angle |
|---|---|---|
| 27017 | MongoDB | often **no auth**; but by itself just data — needs an app that trusts it |
| 6379 | Redis | often **no auth**; if root, write SSH key/cron/module → RCE; `CONFIG SET dir/dbfilename` |
| 3306/5432 | MySQL/Postgres | creds from app config; UDF/`COPY ... PROGRAM` RCE if privileged |
| 5038 | Asterisk AMI | `Originate`/`System` actions if creds known |
| 1337 | OliveTin | password-arg cmd injection (CVE-2026-27626), usually root |
| 4000/3000/8000 | custom node/python/aiohttp app | read the source; find local sink |
| 9229 / JDWP | debug port (Node `--inspect`, Java) | **unauth code exec as owner** |

## Reach them from Kali (optional, nicer tooling)
SSH local port-forward:
```
ssh -L 6379:127.0.0.1:6379 -L 27017:127.0.0.1:27017 user@target
```
Then run `redis-cli` / `mongosh` / exploit PoCs locally against `127.0.0.1`.

## ⚠ Decoy check (learned on Connected)
A custom internal app is only useful if it has a **local sink**. Before reversing it:
```
grep -rnE 'subprocess|os\.system|popen|eval\(|exec\(|pickle|yaml\.load|open\([^)]*["\x27]w' <app_dir>
```
- No sink, or it only proxies/relays to a *remote* device (e.g. `aiovega` → remote Vega) ⇒ **decoy**. Move on to cron/incron/SUID.
- Mongo/Redis with no privileged writer/app around them can also be decoys.

→ back to `../Machines/machines-methodology.md` Phase 3. Debug-port detail: `Machines/htb-reactor.md`. OliveTin: `Machines/htb-enigma.md`.
