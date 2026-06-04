# HTB Academy — CWES JavaScript Deobfuscation Module Notes

## Key Concepts

### Obfuscation Types
- **Minification** — single line, whitespace removed. Extension: `.min.js`
- **Packing** — `eval(function(p,a,c,k,e,d){...})` pattern, recognizable by 6 function args
- **obfuscator.io** — hex variable names (`_0x1ec6`), Base64/RC4 string arrays
- **JSFuck** — only `[]!+` characters, very slow execution
- **JJEncode / AAEncode** — niche, causes slow execution, used for filter bypass

### Obfuscation Tools
| Tool | URL |
|------|-----|
| BeautifyTools packer | http://beautifytools.com/javascript-obfuscator.php |
| obfuscator.io | https://obfuscator.io |
| JSFuck | http://www.jsfuck.com |

### Deobfuscation Tools
| Tool | Best For |
|------|---------|
| UnPacker | https://matthewfl.com/unPacker.html — packer-style |
| Prettier | https://prettier.io/playground/ — beautify/format |
| Beautifier | https://beautifier.io/ |
| JSConsole | https://jsconsole.com — run and test JS live |

## Critical Lessons Learned

### Run in jsconsole.com BEFORE manual decoding
Paste the full `eval(...)` code into https://jsconsole.com first. Any `console.log()` outside a function fires immediately and gives you values for free — no manual decode needed for those. Only decode manually when you need values inside functions.

### Literal non-word characters survive packer substitution unchanged
The packer uses `\b\w+\b` regex — it only replaces word characters (`[a-zA-Z0-9_]`). Any non-word character in the packed string (`!`, `{`, `}`, `'`, `/`, etc.) passes through exactly as written.

**Real mistake made:** The packed string contained `c0d3!` where `c` mapped to `c0d3` and `!` was literal. I dropped the `!` assuming it wasn't part of the flag. The correct flag was `HTB{n3v3r_run_0bfu5c473d_c0d3!}` — the `!` was real.

**Rule:** Never drop or ignore non-word characters when manually decoding a packer. What you see between word tokens is what you get.

### Packer empty-string falsy trap
When a dictionary entry is `''` (empty string), JavaScript's `||` operator treats it as falsy:
```javascript
d[c] = k[c] || c.toString(a)
// k[c] = '' (falsy) → falls back to c.toString(a) = original index char
```
**Result:** Characters like `j` and `n` that map to `''` in the dictionary are NOT replaced — they stay as themselves. `j` stays `j`, `n` stays `n`.

**Real mistake made:** Assumed `j` (index 19 → `''`) would become blank, giving `HTB{4v45c...}`. Actual output was `HTB{j4v45c...}` because `j` was preserved. jsconsole.com caught this.

### console.log fires on load
Any `console.log()` outside a function definition executes immediately when the script loads — running the script reveals these values without any deobfuscation.

### Error messages reveal parameter names
When a page returns an error like `"ensure accessID is set correctly"`, the parameter name is handed to you directly. Skip parameter name fuzzing entirely and go straight to value fuzzing.

## Encoding Quick Reference

| Type | Spot It | Decode |
|------|---------|--------|
| Base64 | alphanumeric + `/` + `=` padding | `echo "<str>" \| base64 -d` |
| Hex | only `0-9a-f` | `echo "<str>" \| xxd -p -r` |
| ROT13 | `http` looks like `uggc` | `echo "<str>" \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` |
