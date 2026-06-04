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

**Always run the code in jsconsole.com FIRST** before manual decoding — it instantly shows `console.log` output and saves time:
1. Paste the full `eval(...)` into https://jsconsole.com and hit Enter
2. Note any immediate output (console.log fires on load, outside function definitions)
3. Only do manual decoding if you need values inside functions or jsconsole fails

**Manual decode — step by step:**
1. Extract the packed string (first arg to the outer function)
2. Extract the dictionary: the `.split('|')` array — these are indexed 0–N
3. Identify the base: the `a` argument (e.g., `30` = base 30)
4. Map indices to characters: `0-9` = 0–9, `a-z` = 10–35 in that base
5. For each single-character token in the packed string that matches an index, substitute the dictionary value
6. **Falsy trap:** `k[c] || c.toString(a)` — if the dictionary value is `''` (empty string, falsy), the character is NOT replaced; it stays as the original index character (e.g., `j` stays `j`, `n` stays `n`)
7. **Literal non-word characters survive unchanged** — the regex used is `\b\w+\b`, so characters like `!`, `{`, `}`, `'`, `/` are never touched by substitution. A `!` in the packed string comes out as `!` in the decoded output. Do not drop these.

- Online tool: https://matthewfl.com/unPacker.html

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
