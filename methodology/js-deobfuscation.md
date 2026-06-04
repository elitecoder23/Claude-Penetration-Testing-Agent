# JavaScript Deobfuscation Methodology

## Step 1 — Find the JS file
View HTML source for `<script src="...">` tags:
```bash
curl -s http://<TARGET>/ | grep -i script
```

## Step 2 — Identify Obfuscation Type

| Pattern | Type |
|---------|------|
| `eval(function(p,a,c,k,e,d){...})` | Packer (BeautifyTools / p,a,c,k,e,d) |
| `var _0x1ec6=[...]` + hex variable names | obfuscator.io (Base64/RC4) |
| `[][(![]+[])[+[]]...]` | JSFuck |
| All alpha-numeric, ends with `=` or `==` | Base64 |
| Only `0-9a-f` characters | Hex |
| Looks like random letters, `http` → `uggc` | ROT13 |

## Step 3 — Deobfuscate

### Packer (`eval(function(p,a,c,k,e,d)`)
- Online: https://matthewfl.com/unPacker.html
- Manual: extract the packed string + dictionary array, substitute each index

**Manual decode rule:**
- Base is the `a` argument (e.g., 30 means base-30 indexing)
- Dictionary is the `.split('|')` array
- Map: `0-9` = indices 0-9, `a-z` = indices 10-35
- **Empty string `''` values are falsy** → `k[c] || c.toString(a)` keeps the original character
- Only substitute non-empty dictionary entries

### obfuscator.io style
- Online: https://obf-io.deobfuscate.io/ or https://deobfuscate.io/

### Beautify minified code
- https://prettier.io/playground/
- https://beautifier.io/

## Step 4 — Analyze Deobfuscated Code
Look for:
- Hidden string variables (flags, keys, credentials)
- `console.log()` calls that fire on load
- `XMLHttpRequest` or `fetch()` — reveals API endpoints and methods
- Hardcoded URLs/paths

## Step 5 — Replicate HTTP Requests
If the JS makes an HTTP request, replicate with curl:
```bash
# GET
curl -s http://<TARGET>/<endpoint>

# POST (no data)
curl -s http://<TARGET>/<endpoint> -X POST

# POST with data
curl -s http://<TARGET>/<endpoint> -X POST -d "param=value"
```

## Step 6 — Decode Encoded Responses

### Base64
```bash
echo "<string>" | base64 -d
# Spot: alphanumeric + / + =, length multiple of 4
```

### Hex
```bash
echo "<string>" | xxd -p -r
# Spot: only 0-9 and a-f characters
```

### ROT13
```bash
echo "<string>" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# Spot: http → uggc pattern
```
