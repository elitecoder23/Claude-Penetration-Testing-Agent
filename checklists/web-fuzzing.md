# Web Fuzzing Checklist

## Directory & File Discovery
- [ ] Fuzz root for directories (`/FUZZ`)
- [ ] Extension-fuzz every found directory (`/dir/FUZZ` with `-e .php,.html,.txt,.bak,.zip`)
- [ ] curl every discovered page — read the full response body
- [ ] Check response headers (`curl -I`) for framework/server hints

## Parameter Discovery
- [ ] Note baseline response size before fuzzing
- [ ] Fuzz GET parameter names (`?FUZZ=1`, filter baseline size)
- [ ] Fuzz POST parameter names (`-X POST -d "FUZZ=1"`, filter baseline size)
- [ ] If parameter name found in error message — go straight to value fuzzing
- [ ] Fuzz parameter value with wordlist (`?<param>=FUZZ`, filter baseline size)

## Vhost / Subdomain Discovery
- [ ] Get baseline size for main domain
- [ ] Fuzz with `Host: FUZZ.<domain>` header
- [ ] Filter baseline size AND `-fc 403`
- [ ] Add all discovered vhosts to `/etc/hosts`
- [ ] curl each new vhost and read response body for next hints

## Recursive / Deep Discovery
- [ ] If response hints at a path, fuzz from there with `-recursion -recursion-depth 5`
- [ ] Include extensions in recursive fuzz
- [ ] Check 200 responses with small sizes (likely the target page)
