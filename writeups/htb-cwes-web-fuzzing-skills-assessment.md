# HTB Academy — CWES Web Fuzzing Skills Assessment

**Flag:** `HTB{w3b_fuzz1ng_sk1lls}`  
**Wordlist used throughout:** `/usr/share/seclists/Discovery/Web-Content/common.txt`  
**Target:** `154.57.164.83:30634`

---

## Attack Chain

### 1. Root Directory Fuzz
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://<TARGET>/FUZZ -ic -c
```
**Found:** `/admin` → 301

### 2. Extension Fuzz Inside `/admin/`
Plain directory fuzz of `/admin/FUZZ` only returned `index.php` (200, 13 bytes — "Access Denied").  
Extension fuzz revealed the real target:
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://<TARGET>/admin/FUZZ \
     -e .php,.html,.txt,.bak,.zip -ic -c -fs 0,281
```
**Found:** `/admin/panel.php`

### 3. Identify Parameter Name via Error Message
```bash
curl http://<TARGET>/admin/panel.php
# → "Invalid parameter, please ensure accessID is set correctly"
```
The error message leaked the parameter name directly: `accessID`.

### 4. Fuzz Parameter Value
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u "http://<TARGET>/admin/panel.php?accessID=FUZZ" \
     -ic -c -fs 58
```
**Found:** `accessID=getaccess` (68 bytes vs baseline 58)

### 5. Follow the Redirect to a New Vhost
```bash
curl "http://<TARGET>/admin/panel.php?accessID=getaccess"
# → "Head on over to the fuzzing_fun.htb vhost for some more fuzzing fun!"
```

### 6. Add Hosts Entry + Vhost Fuzz
```bash
echo "<TARGET_IP> fuzzing_fun.htb" | sudo tee -a /etc/hosts

# Baseline size:
curl -s http://fuzzing_fun.htb:<PORT>/ | wc -c   # → 136

ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://fuzzing_fun.htb:<PORT>/ \
     -H "Host: FUZZ.fuzzing_fun.htb" \
     -ic -c -fs 136 -fc 403
```
**Found:** `hidden.fuzzing_fun.htb` (200, 45 bytes)

### 7. Follow Hint + Recursive Fuzz
```bash
echo "<TARGET_IP> hidden.fuzzing_fun.htb" | sudo tee -a /etc/hosts
curl http://hidden.fuzzing_fun.htb:<PORT>/
# → "Wrong path, remember to be looking in /godeep"

ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://hidden.fuzzing_fun.htb:<PORT>/godeep/FUZZ \
     -ic -c -recursion -recursion-depth 5 \
     -e .php,.html,.txt -fc 403
```
**Found:** `/godeep/stoneedge/bbclone/typo3/index.php` (200, 23 bytes)

### 8. Get the Flag
```bash
curl http://hidden.fuzzing_fun.htb:<PORT>/godeep/stoneedge/bbclone/typo3/index.php
```

---

## Key Lessons

- **Always extension-fuzz directories** — plain directory fuzz missed `panel.php` entirely.
- **Error messages leak parameter names** — always curl a discovered page before fuzzing parameters.
- **Filter baseline response size with `-fs`** — critical for GET/POST parameter value fuzzing.
- **Vhost fuzzing requires `-fc 403`** — default Apache returns 403 for unknown vhosts, drowning out real hits.
- **Recursive fuzzing finds deep paths** — `-recursion -recursion-depth 5` caught a 4-level-deep file.
- **Pages redirect to next steps** — read every response body, not just status codes.
