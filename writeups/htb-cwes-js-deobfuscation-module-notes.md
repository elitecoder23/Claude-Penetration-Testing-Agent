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

### Packer empty-string falsy trap
When a dictionary entry is `''` (empty string), JavaScript's `||` operator treats it as falsy:
```javascript
d[c] = k[c] || c.toString(a)
// k[c] = '' (falsy) → falls back to c.toString(a) = original index char
```
**Result:** Characters like `j` and `n` that map to empty strings in the dictionary are NOT replaced — they stay as themselves in the output. Always verify by running in jsconsole.com rather than assuming empty = blank.

### Always run the code to verify manual decoding
Manual packer decoding is error-prone. After decoding, verify in jsconsole.com. Discrepancies reveal edge cases like the falsy empty-string issue above.

### console.log fires on load
Any `console.log()` outside a function definition executes immediately when the script loads. Running the obfuscated script in a console will reveal these values without needing to deobfuscate first.

### Error messages reveal parameter names
When a page returns an error like "ensure accessID is set correctly", it has handed you the parameter name directly — skip parameter name fuzzing and go straight to value fuzzing.

## Encoding Quick Reference

| Type | Spot It | Decode |
|------|---------|--------|
| Base64 | alphanumeric + `/` + `=` padding | `echo "<str>" \| base64 -d` |
| Hex | only `0-9a-f` | `echo "<str>" \| xxd -p -r` |
| ROT13 | `http` looks like `uggc` | `echo "<str>" \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` |
