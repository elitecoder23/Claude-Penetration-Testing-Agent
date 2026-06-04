# JavaScript Deobfuscation Checklist

## Source Discovery
- [ ] curl the page and grep for `<script src="...">` tags
- [ ] curl the JS file directly and note its size/content

## Quick Wins Before Deobfuscating
- [ ] Run the raw obfuscated code in https://jsconsole.com — note any console.log output
- [ ] Scan the raw code for visible strings (flags, URLs, parameter names in cleartext)

## Identify Obfuscation Type
- [ ] `eval(function(p,a,c,k,e,d){...})` → Packer → use UnPacker or manual decode
- [ ] `var _0x...=[...]` with hex variable names → obfuscator.io → use deobfuscate.io
- [ ] Only `[]!+` characters → JSFuck → run in browser console
- [ ] Single long line, readable words → Minified → run through Prettier/Beautifier

## Packer Manual Decode (if needed)
- [ ] Extract packed string (first arg) and dictionary `.split('|')` array
- [ ] Identify base (`a` arg) — e.g., `30` = base-30
- [ ] Map each index to its dictionary value
- [ ] **Check for empty string entries** (`''`) — these are falsy; those characters stay unchanged
- [ ] **Preserve all non-word characters** (`!`, `{`, `}`, `/`, etc.) — regex never touches them
- [ ] Verify final result by running in jsconsole.com

## Analyze Deobfuscated Code
- [ ] Find all string variables — note flags, keys, credentials
- [ ] Find all `console.log()` calls — note output values
- [ ] Find all `XMLHttpRequest` / `fetch()` calls — note method (GET/POST) and URL
- [ ] Identify any encoding used (Base64, Hex, ROT13)

## Replicate HTTP Requests
- [ ] POST to discovered endpoints with curl
- [ ] Note raw server response — submit as-is if question asks for "the key returned"
- [ ] Decode response if encoded, then POST back with decoded value as `key=<decoded>`

## Decode Server Responses
- [ ] All alphanumeric + `=` padding → Base64 → `echo "<str>" | base64 -d`
- [ ] Only `0-9a-f` chars → Hex → `echo "<str>" | xxd -p -r`
- [ ] Random-looking letters, `http` looks like `uggc` → ROT13 → `tr 'A-Za-z' 'N-ZA-Mn-za-m'`
