# HTB Academy — CWES JavaScript Deobfuscation Skills Assessment

**Target:** `154.57.164.81:30452`

---

## Questions & Solutions

### Q1 — Find the JavaScript file name
```bash
curl -s http://<TARGET>/
# Look for <script src="..."> in HTML
```
**Answer:** `api.min.js`

### Q2 — Run the JS, what do you get?
Paste the obfuscated `api.min.js` into https://jsconsole.com and run it.  
The `console.log()` at the bottom fires immediately on execution.  
**Answer:** `HTB{j4v45cr1p7_3num3r4710n_15_k3y}`

### Q3 — Deobfuscate and retrieve the `flag` variable
Use https://matthewfl.com/unPacker.html or decode manually (see below).  
**Answer:** `HTB{n3v3r_run_0bfu5c473d_c0d3!}`

### Q4 — Replicate the function to get the secret key
Deobfuscated code POSTs to `/keys.php` with no data:
```bash
curl -s http://<TARGET>/keys.php -X POST
```
**Answer:** `4150495f70336e5f37333537316e365f31355f66756e`

The question asks for the key the server returns — which is the raw encoded hex string, not the decoded plaintext. Submit the hex as-is.

### Q5 — Decode the key and POST it back
```bash
echo "4150495f70336e5f37333537316e365f31355f66756e" | xxd -p -r
# → API_p3n_73571n6_15_fun

curl -s http://<TARGET>/keys.php -X POST -d "key=API_p3n_73571n6_15_fun"
```
**Flag:** `HTB{r34dy_70_h4ck_my_w4y_1n_2_HTB}`

---

## Manual Packer Decode Walkthrough

The obfuscated code uses the `eval(function(p,a,c,k,e,d){...})` packer pattern (base 30).

### Dictionary (from `.split('|')`)
```
0=xhr, 1=HTB, 2=_0x437f8b, 3=k3y, 4=keys, 5=apiKeys, 6=var, 7=flag,
8=3v3r_, 9=run_0, a=bfu5c, b=473d_, c=c0d3, d=new, e=XMLHttpRequest,
f=open, g=php, h=n_15_, i=POST, j=(empty*), k=send, l=null, m=console,
n=(empty*), o=log, p=4v45c, q=r1p7_, r=3num3, s=r4710, t=function
```

**Critical rule:** Empty string values `''` are **falsy** in JavaScript.  
The packer uses `k[c] || c.toString(a)` — so when the dictionary value is `''`, it falls back to the original index character. `j` stays `j`, `n` stays `n`.

### Decoded output
```javascript
function apiKeys() {
  var flag = 'HTB{n3v3r_run_0bfu5c473d_c0d3!}',
      xhr = new XMLHttpRequest(),
      _0x437f8b = '/keys.php';
  xhr['open']('POST', _0x437f8b, true),
  xhr['send'](null)
}
console['log']('HTB{j4v45cr1p7_3num3r4710n_15_k3y}');
```
