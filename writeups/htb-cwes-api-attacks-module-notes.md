# HTB Academy — API Attacks Module Notes

**Module:** API Attacks (Sections 1–13)  
**Topics:** REST API Attacks | OWASP API Top 10 | Auth Bypass | BOLA | Mass Assignment | Rate Limiting | Injection | Security Misconfigurations

---

## Flags Summary

| Section | Attack | Flag |
|---------|--------|------|
| (populated as sections are completed) | | |

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
