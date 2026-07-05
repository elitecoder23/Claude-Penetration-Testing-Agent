# Playbook — Web App Fingerprint → CVE → Shell

**Trigger:** an HTTP(S) service is open and serves a recognizable application. This is the #1 foothold pattern on rated boxes.

## 1. Identify product + EXACT version
Look, in order, at:
- Redirect chain and default page (`curl -s -i -L http://host/`), `<title>`, `Server` / `X-Powered-By` headers.
- **Asset query strings / paths** — e.g. `?load_version=16.0.40.7` (FreePBX), `/wp-content` (WordPress), `_next/static` (Next.js).
- Login page footer, `readme`/`CHANGELOG`/`composer.json`/`package.json`, `<meta name="generator">`.
- Favicon hash, TLS cert CN/SAN, error-page fingerprints.
- `whatweb -a3 http://host/`.

> Deliverable: "**<product> <exact version>**." Vague version = keep enumerating; you can't pick the right CVE without it.

## 2. Map version → vulnerability
- Search `"<product> <version> CVE"`, `"<product> <version> exploit"`, `"<product> RCE PoC github"`.
- Prefer, in order: **auth-bypass/unauth RCE** > SQLi→RCE > auth'd RCE > file upload/LFI > SSRF.
- Cross-check the fix version — confirm the target's version is actually *below* it.
- Check `searchsploit <product>` and Metasploit (`search <product>`).

## 3. Choose & vet the exploit
- **Read the PoC before running it.** Understand the request it sends and the RCE mechanism (so you can fix it if it half-works).
- Set listener/LHOST to the **VPN (`tun0`) IP** explicitly; don't rely on auto-detect.
- Many PoCs self-host the listener (e.g. FreePBX cron PoC) — no separate `nc` needed.

## 4. Confirm before exploiting (context-driven)
- Fire the PoC's **validation** step (or a manual probe) to confirm the bug exists — e.g. unauth SQLi data-disclosure tell, version banner, reachable vuln endpoint — before the full chain.

## 5. Common mechanisms seen
| Product signal | Bug class | Note |
|---|---|---|
| FreePBX `?load_version=16.x` | endpoint unauth SQLi→cron RCE (CVE-2025-57819) | shell as `asterisk` |
| Next.js `_next/`, 15.x | RSC deserialization RCE (React2Shell) | version-pin; middleware-bypass CVE may be bait |
| OpenSTAManager footer version | `.p7m` filename cmd injection | needs any login |
| OliveTin `<title>OliveTin</title>` | password-arg cmd injection | often root on :1337 |
| Anything with `admin`/`config.php` login | default creds → targeted brute | try before exotic bugs |

## Pitfalls
- **Version-vulnerable ≠ exploitable.** If the bug needs a component/route/module that isn't present (no middleware, module not installed), it's bait — pivot. (Reactor CVE-2025-29927; Connected `freepbx_ha` absent.)
- Don't escalate to custom exploitation before checking the public CVE — especially on easy boxes.

→ back to `../Machines/machines-methodology.md` Phase 2.
