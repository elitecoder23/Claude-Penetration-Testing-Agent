# Web Fuzzing Methodology

**Wordlist default:** `/usr/share/seclists/Discovery/Web-Content/common.txt`  
**Tool:** `ffuf`

---

## Phase 1 — Directory & File Discovery

```bash
# Root directories
ffuf -w <wordlist> -u http://<TARGET>/FUZZ -ic -c -fs <baseline>

# Extension fuzz inside found directories (always do this — plain fuzz misses files)
ffuf -w <wordlist> -u http://<TARGET>/<dir>/FUZZ \
     -e .php,.html,.txt,.bak,.zip -ic -c -fs 0,281
```

Always curl every discovered page before fuzzing parameters — error messages often leak parameter names directly.

---

## Phase 2 — Parameter Fuzzing

### Identify baseline size first
```bash
curl -s http://<TARGET>/<page> | wc -c
```

### GET parameter name fuzz
```bash
ffuf -w <wordlist> -u "http://<TARGET>/<page>?FUZZ=1" -ic -c -fs <baseline>
```

### GET parameter value fuzz (when name is known)
```bash
ffuf -w <wordlist> -u "http://<TARGET>/<page>?<param>=FUZZ" -ic -c -fs <baseline>
```

### POST parameter fuzz
```bash
ffuf -w <wordlist> -u "http://<TARGET>/<page>" \
     -X POST -d "FUZZ=1" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -ic -c -fs <baseline>
```

---

## Phase 3 — Vhost / Subdomain Fuzzing

```bash
# Get baseline response size for the main domain
curl -s http://<DOMAIN>:<PORT>/ | wc -c

# Fuzz — filter baseline size AND 403s (Apache default for unknown vhosts)
ffuf -w <wordlist> \
     -u http://<DOMAIN>:<PORT>/ \
     -H "Host: FUZZ.<DOMAIN>" \
     -ic -c -fs <baseline> -fc 403
```

Add discovered vhosts to `/etc/hosts` before accessing them.

---

## Phase 4 — Recursive Fuzzing

Use when a directory is found but depth is unknown:

```bash
ffuf -w <wordlist> -u http://<TARGET>/FUZZ \
     -ic -c -recursion -recursion-depth 5 \
     -e .php,.html,.txt -fc 403
```

---

## Common Filter Flags

| Flag | Purpose |
|------|---------|
| `-fs <size>` | Filter by response size (remove baseline noise) |
| `-fc 403` | Filter 403s (essential for vhost fuzzing) |
| `-fc 301` | Filter redirects if following manually |
| `-ic` | Ignore wordlist comments |
| `-c` | Colorized output |

---

## Decision Flow

```
Root fuzz → directory found?
  └─ Yes → Extension fuzz that directory
         → curl each found page (read error messages for param names)
         → Parameter fuzz (name then value)
         → Does response mention a vhost/domain?
              └─ Yes → Add to /etc/hosts → vhost fuzz
                     → curl new vhost → follow hints
                     → Recursive fuzz from any hinted path
```
