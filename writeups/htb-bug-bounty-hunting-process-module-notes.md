# HTB Academy — Bug Bounty Hunting Process: Module Notes

**Status:** COMPLETE — all 6 sections. This module has no lab targets or skills assessment; it's process/reporting theory (program structure, CVSS/CWE, communication, three report templates). See the Module Summary at the bottom.

**Focus of this module:** the *process* of bug bounty hunting — how programs work, scoping, methodology, and (heavily) **documentation and reporting**. Less about individual exploits, more about how to hunt effectively and communicate findings so they get triaged, accepted, and paid.

---

## Section 1 — Bug Bounty Programs

### Key Concepts
- **Bug bounty program (BBP)**, aka **Vulnerability Rewards Program (VRP)**: a crowdsourcing initiative where individuals get **recognition and compensation** for finding and reporting software bugs. More than a one-off — it's **continuous, proactive security testing** that supplements internal code audits and pentests and completes an org's vulnerability-management strategy. HackerOne's framing: *"Continuous testing, constant protection,"* integrated into the existing development lifecycle.

- **BBP vs. VDP — do not use interchangeably:**
  - **VDP (Vulnerability Disclosure Program):** only provides *guidance on how an org prefers to receive* vulnerability info from third parties. No monetary reward — it's a "see something, say something" channel.
  - **BBP (Bug Bounty Program):** *incentivizes* third parties to find and report bugs; hunters receive **monetary rewards**.

### Program Types
| Type | Who can participate |
|---|---|
| **Private** | Invite-only. Most programs **start private**, then go public once the org can handle triage. Invitations are based on **track record, consistency of valid findings, and violation record**; some require a **background check**. |
| **Public** | Open to the entire hacking community. |
| **Parent/Child** | A parent company and its subsidiaries **share a bounty pool and one security team**. A subsidiary's program (child) links to the parent program. |

### Code of Conduct — critical
- The **Code of Conduct / policy** is what **establishes expectations for behavior** in a program. *(Q1 answer.)*
- Your **violation record follows you** — always taken into account for future (esp. private) invites. Adhering to each program's/platform's code of conduct is paramount.
- Reading it thoroughly doesn't just keep you compliant — it makes you **more effective and successful** in your submissions.
- To succeed long-term: **balance professionalism with technical capability.**
- Reference: HackerOne's Code of Conduct.

### Anatomy of a Bug Bounty Program (the "Policy")
The **Policy** section is where an org publishes its program specifics. It typically includes:

| Element | What it defines |
|---|---|
| **Vendor Response SLAs** | When/how the vendor will reply |
| **Access** | How to create/obtain accounts for research |
| **Eligibility Criteria** | e.g. must be the **first reporter** of a vuln to be eligible |
| **Responsible Disclosure Policy** | Disclosure timelines, coordination for safe disclosure, user safety |
| **Rules of Engagement** | What you may/may not do while testing |
| **Scope** | In-scope IP ranges, domains, vulnerabilities |
| **Out of Scope** | Out-of-scope IP ranges, domains, vulnerabilities |
| **Reporting Format** | How reports must be structured |
| **Rewards** | Payout structure |
| **Safe Harbor** | Legal protection for good-faith research |
| **Legal Terms & Conditions** | — |
| **Contact Information** | — |

- **Scope** is usually defined by **domain name** (web apps) or specific **App Store / Play Store** apps (mobile).
- In HackerOne, all of the above generally lives inside each program's **Policy**.

### Tips & Approaches
- **Read the policy and code of conduct meticulously before testing.** Meeting expectations up front avoids back-and-forth and wasted time — **in bug bounty hunting, time is of the essence.**
- Study real examples to learn the format: **Alibaba BBP** and **Amazon Vulnerability Research Program** (read their "Policy").
- **Finding programs:** **HackerOne's Directory** is a top resource — it lists orgs with programs *and* contact info for reporting ethically-found vulns.

### Documentation Takeaways
- Before any engagement, confirm: **scope, out-of-scope, rules of engagement, eligibility (first-reporter?), reporting format, and safe harbor.** These are the guardrails every report is judged against.

### Lab Answers
- **Q1:** the **Code of Conduct** (establishes expectations for behavior while participating).

---

## Section 2 — Writing a Good Report

### Key Concepts
- A good report is **clear and concise** so the security/triage team gets the point fast. Above all, it must show **how to reproduce exploitation step-by-step**.
- **Know your audience:** for **less mature companies**, translate technical issues into **business terms** so they grasp the real impact.
- **Readable, well-formatted reports drastically cut reproduction time and time-to-triage** — which is exactly what gets a bug accepted and paid quickly.

### The Essential Elements of a Bug Report (order can vary)
| Element | Purpose |
|---|---|
| **Vulnerability Title** | Vuln **type + affected domain/parameter/endpoint + impact**. |
| **CWE & CVSS score** | Communicate the vuln's **characteristics (CWE)** and **severity (CVSS)**. |
| **Vulnerability Description** | Explain the **cause** so the reader understands it. |
| **Proof of Concept (PoC)** | **Steps to reproduce** the exploit, clearly and concisely. |
| **Impact** | What an attacker **achieves** with full exploitation — include **business impact and maximum damage**. |
| **Remediation** | **Optional** in bug bounty, but good to include. |

### Why CWE & CVSS?
- **CWE (Common Weakness Enumeration)** — MITRE's community list of software/hardware **weakness types**. A common language and baseline for identification/mitigation/prevention.
  - **In a vulnerability chain, pick the CWE of the *initial* vulnerability.**
- **CVSS (Common Vulnerability Scoring System)** — the worldwide published standard for communicating **severity**. Use the **CVSS v3.1 Calculator**; for reports, focus on the **Base Score**.

### CVSS v3.1 Base Metrics (memorize these)

**Exploitability metrics:**

| Metric | Values | Meaning |
|---|---|---|
| **Attack Vector (AV)** | **N**etwork / **A**djacent / **L**ocal / **P**hysical | *How* it's exploited. **N** = remote over network; **A** = same physical/logical network (incl. secure VPN); **L** = local access (keyboard/terminal), remote via SSH, or via user interaction; **P** = physical interaction. |
| **Attack Complexity (AC)** | **L**ow / **H**igh | Conditions beyond the attacker's control. **L** = no special prep, repeatable; **H** = needs special prep / recon. |
| **Privileges Required (PR)** | **N**one / **L**ow / **H**igh | **N** = unauthenticated; **L** = standard user (affects user-owned/non-sensitive assets); **H** = admin (affects the whole system). |
| **User Interaction (UI)** | **N**one / **R**equired | **N** = attacker acts alone; **R** = a user must do something first. |
| **Scope (S)** | **U**nchanged / **C**hanged | **U** = impact stays within the vulnerable component's security authority; **C** = impact crosses to a *different* security authority (e.g. webserver vuln → impacts the browser). |

**Impact metrics** (Confidentiality / Integrity / Availability — each **N**one / **L**ow / **H**igh):

| Metric | None | Low | High |
|---|---|---|---|
| **Confidentiality (C)** | no info impact | some info leaked, no control over what | total/serious disclosure, attacker controls what is obtained |
| **Integrity (I)** | no data impact | limited modification, no control over consequence | modify all/critical data, total loss of integrity |
| **Availability (A)** | no impact | reduced performance, can't fully deny service | total/severe loss, can deny service to users |

### Worked Examples
- **Cisco ASA IKEv1/IKEv2 Buffer Overflow (CVE-2016-1287) → 9.8 Critical.**
  AV:N (internet-facing VPN), AC:L (just run the exploit), PR:N (unauthenticated), UI:N, **S:U** (can pivot *using* the box but the overflow itself doesn't cross authorities), C:H / I:H / A:H (reverse shell = full control, can power off).
  - *Teaching point:* "you can use it as a pivot" still = **Scope Unchanged**; scope is about the vuln's *direct* impact crossing a security authority, not what you do post-exploitation.
- **Stored XSS in an admin panel (malicious admin → admin) → 5.5 Medium.**
  AV:N, AC:L (just store the payload), **PR:H** (needs admin to reach the panel), UI:N (victim admin just browses a regularly-visited page), **S:C** (vulnerable component = webserver, impacted component = browser), C:L (DOM access), I:L (XSS lightly affects integrity), A:N (XSS can't deny service).
  - *Teaching point:* XSS is the classic **Scope: Changed** case — server-side flaw whose impact lands in a different component (the browser).

### Tips & Approaches
- Title formula: **[Vuln type] in [endpoint/parameter] on [domain] → [impact]**.
- Let the CVSS vector *justify itself* in prose (like the examples) — one sentence per metric explaining your choice. This preempts triage disputes.
- Study HackerOne's curated **good report examples** (SSRF→root in Exchange, RCE in Slack desktop, stored/reflected XSS cases, broken access control on store email, etc.) for tone, structure, and PoC clarity.
- Follow the target program's **Reporting Format** exactly (Section 1) and HackerOne's **Submitting Reports** process for the mechanics.

### Documentation Takeaways
- Every report = **Title → CWE/CVSS → Description → PoC (repro steps) → Impact (business terms) → (optional) Remediation.**
- **Impact must speak business risk**, not just technical detail — especially for less mature orgs.
- **CVSS for chains:** score/CWE the **initial** vulnerability.

### Lab Answers
- **Q1:** **Adjacent (A)** — the **Attack Vector** value for an attacker in the same physical/logical network (secure VPN included).

---

## Section 3 — Interacting with Organizations / BBP Hosts

### Key Concept
- After submitting a report, **professional communication matters as much as the professional report itself.** Stay calm and behave as a security professional would throughout.

### After You Submit — the Golden Rule
- **Do not interact.** Give the security/triage team time to process, validate, and possibly ask questions.
- Check the program's **Vendor Response SLAs / response-efficiency metrics** to gauge how long a reply should take.
- **Do not spam** the team in a short window.
- If they **don't respond in a reasonable time** and you submitted via a platform, contact **Mediation** (the platform's dispute/escalation service).

### Ongoing Communication Etiquette
- Once someone responds, **note their username and tag them** in future communications — they'll likely own your submission.
- **Only use official channels.** Never reach out via social media or other unofficial channels.

### Handling Disagreements (severity or bounty)
A bug's **impact and severity drive the bounty amount**, so disputes happen. Resolve them in this order:
1. **Explain your rationale.** Walk the team through **each CVSS metric value** you selected in the calculator — this is exactly why you justify every metric in the report (Section 2). Usually leads to agreement.
2. **Re-check policy and scope.** Confirm your submission complies with both, and that the offered bounty **matches the program's stated reward policy**.
3. **Escalate to Mediation** (or the equivalent platform service) if the above doesn't resolve it.

### Tips & Approaches
- Patience up front > pestering. The SLA is your clock — let it run before nudging.
- Keep the CVSS justification from your report handy; it's your primary tool in any severity dispute.
- Mediation is the *last* resort, not the first move — exhaust rational, policy-based discussion first.

### Documentation Takeaways
- The **CVSS-per-metric justification** you wrote in the report does double duty: it triages faster *and* it's your evidence in a severity/bounty dispute. Another reason to always include it.

### Lab Answers
- *(No questions in this section.)*

---

## Section 4 — Example 1: Reporting Stored XSS (full report template)

A complete real-world-style report. Use it as a **template for the structure and tone**.

### The Report, Element by Element
- **Title:** `Stored Cross-Site Scripting (XSS) in X Admin Panel`
  - *(Follows the formula: vuln type + affected component.)*
- **CWE:** **CWE-79** — Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting').
- **CVSS 3.1 Score:** **5.5 (Medium)**.
- **Description** (the *cause*, precise and located): the "X for administrators" app is vulnerable to stored XSS due to **inadequate sanitization of user-supplied data**. Pinpoints the exact path — file upload at `Admin Info → Secure Data Transfer → Load of Data` — where the **uploaded file's filename** is both **reflected to the browser** and **stored in the DB** without sanitization, so JS in the filename field yields **reflected + stored XSS**.
- **Impact** (mechanism + business risk): explains what XSS is (untrusted data rendered without validation/escaping → attacker script runs in the victim's browser), the consequences (**credential theft, session hijacking, defacement, malicious redirects**), and *who* is exposed. Crucially it stresses the **business-specific severity**: uploaded files are **visible to every administrator**, so **any admin can be targeted**.
- **PoC** (numbered, reproducible):
  1. Malicious admin uploads a file whose **filename is the payload** (viewable by all admins regardless of uploader). Payload used on a Linux machine:
     ```
     "><svg onload = alert(document.cookie)>.docx
     ```
  2. When another admin clicks **view** to open the file, the JS in the filename **executes in their browser** (PoC shows `alert(document.cookie)` firing = session/cookie access).
- **CVSS Score Breakdown** (one justification per metric — matches Section 2's admin-panel XSS example):
  - **AV:N** — mountable over the internet.
  - **AC:L** — attacker just supplies the payload that gets stored.
  - **PR:H** — only admins can reach the admin panel.
  - **UI:N** — victim admins are hit simply by browsing a regularly-visited page.
  - **S:C** — vulnerable component = webserver, impacted component = browser.
  - **C:L** — DOM access possible.
  - **I:L** — XSS slightly affects integrity.
  - **A:N** — XSS can't deny service.

### Tips & Approaches (what this example teaches)
- **Locate the flaw exactly** — name the menu path / parameter (`filename` field) so triage can jump straight to it.
- **Say it's both reflected AND stored** when true — completeness strengthens the report.
- **Payload delivery detail matters:** the filename itself is the injection vector, and it was crafted **on Linux** (Windows filename restrictions would block `"`, `<`, `>` — a practical gotcha worth remembering).
- **Impact section names the victims** ("any administrator") — ties the technical bug to concrete business exposure.
- Every CVSS metric gets a **one-line reason**, ready to defend in mediation (Section 3).

### Documentation Takeaways — reusable report skeleton
```
Title:        [Vuln type] in [component]
CWE:          CWE-XX: [name]
CVSS 3.1:     [score] ([severity])   + AV/AC/PR/UI/S/C/I/A vector
Description:  Root cause + exact location (path/parameter). What input, reflected/stored, missing control.
Impact:       Mechanism -> consequences -> WHO is affected -> business risk.
PoC:          Step 1..N, reproducible, with exact payload(s) and screenshots.
CVSS Breakdown: one sentence justifying each metric value.
(Remediation): optional but nice.
```

### Lab Answers
- *(No questions in this section.)*

---

## Section 5 — Example 2: Reporting CSRF (second report template)

Same report structure applied to a **Cross-Site Request Forgery** finding.

### The Report, Element by Element
- **Title:** `Cross-Site Request Forgery (CSRF) in Consumer Registration`.
- **CWE:** **CWE-352** — Cross-Site Request Forgery (CSRF).
- **CVSS 3.1 Score:** **5.4 (Medium)**.
- **Description** (define the class + locate it): the consumer-registration page is vulnerable to CSRF. Explains CSRF: an attacker tricks the victim into loading a page with a **malicious request that inherits the victim's identity and privileges** to perform an undesired action on their behalf (change email/address/password, make a purchase). Generally targets **state-changing** functions but can also access sensitive data.
- **Impact:** varies with the vulnerable functionality — an attacker can perform **any operation the victim can**; **scope is limited only by the victim's privileges**. Here specifically: **register a fintech application and create an API key as the victim.**
- **PoC** (numbered, with proxy evidence):
  1. Via an intercepting proxy, inspected the "create new fintech application" request → **no anti-CSRF protections** present.
  2. Crafted a **malicious HTML page** that, if visited by a victim with an active session, issues the cross-site request → creates an attacker-specified fintech app.
  3. Deliver the malicious page to a victim with an open session; shows the actual cross-site request that fires.
  4. Result: victim inadvertently creates the app (`Unwanted_FinTech App`). **Note the chaining callout:** *"this attack could have taken place in the background if combined with finding 6.1.1"* (an XSS vuln) — i.e., CSRF + XSS = silent, no-click exploitation.
- **CVSS Score Breakdown:**
  - **AV:N** — over the internet.
  - **AC:L** — just trick a user with an open session into visiting a malicious site.
  - **PR:N** — attacker needs no privileges.
  - **UI:R** — victim **must click** the crafted link.
  - **S:U** — vulnerable component = webserver, impacted component = webserver (same authority).
  - **C:L** — can create an app and obtain limited info.
  - **I:L** — can modify data (create an app) but limitedly.
  - **A:N** — no DoS via this CSRF.

### Tips & Approaches — contrast with the XSS report (why the vectors differ)
| Metric | Stored XSS (Ex.1) | CSRF (Ex.2) | Why |
|---|---|---|---|
| **PR** | **High** | **None** | XSS needed admin access to the panel; CSRF works against any logged-in victim, attacker unauthenticated. |
| **UI** | **None** | **Required** | Stored XSS fires on a normally-browsed page; CSRF needs the victim to click the attacker's link. |
| **Scope** | **Changed** | **Unchanged** | XSS impact lands in the *browser* (different component); CSRF's impact stays within the *webserver's* authority. |

- **Prove the missing control**, don't just assert it — the PoC explicitly notes "no anti-CSRF protections" seen in the intercepted request.
- **Call out chaining potential.** Noting that CSRF + a separate XSS (finding 6.1.1) enables background/no-interaction exploitation raises the *demonstrated* risk and shows you understand the attack surface holistically.
- Screenshots at each step (form → intercepted POST → crafted HTML → resulting confirmation) make the chain undeniable.

### Documentation Takeaways
- The **report skeleton is identical across vuln classes** — only the CWE, payload, and per-metric CVSS justifications change. Reuse the Section 4 skeleton.
- When findings interact, **reference the related finding ID** and describe the combined impact — triage rewards demonstrated real-world severity.

### Lab Answers
- *(No questions in this section.)*

---

## Section 6 — Example 3: Reporting RCE (third report template — Critical)

Same structure applied to a **critical Remote Code Execution** finding via insecure deserialization.

### The Report, Element by Element
- **Title:** `IBM WebSphere Java Object Deserialization RCE`.
- **CWE:** **CWE-502** — Deserialization of Untrusted Data.
- **CVSS 3.1 Score:** **9.8 (Critical)**.
- **Description** (cause + how it was found): the WebSphere app server is vulnerable to **insecure Java object deserialization** → arbitrary command execution. A request over **HTTPS on port 8880** revealed **raw serialized Java objects, base64-encoded** — identifiable by the **`rO0` header** (the base64 signature of serialized Java data). A **SOAP request containing a malicious serialized Java object** exploits the vuln in the **Apache Commons Collections (ACC)** library WebSphere uses. The crafted object carried a `ping` command as proof.
- **Impact:** explains command-injection class — untrusted data reaching the app without auth/validation gets executed as a command **under the app's security context**. If the app runs as a **privileged account (e.g. SYSTEM)**, it can lead to **complete takeover** of the affected system.
- **PoC** (numbered, with capture evidence):
  1. Captured and decoded a request to **port 8880** → confirmed the server uses **serialized data objects** (shows request + decoded response).
  2. Crafted a **SOAP request** carrying a command; the payload makes the affected server **ping the attacker's host** (shows crafted request + decoded Java object in Burp Decoder).
  3. Sent the crafted SOAP request; **Wireshark captured the ICMP ping** coming *from* the WebSphere server *to* the attacker → **proves code execution** without needing a full shell.
- **CVSS Score Breakdown:**
  - **AV:N** — over the internet.
  - **AC:L** — just send one crafted request.
  - **PR:N** — unauthenticated.
  - **UI:N** — no user interaction.
  - **S:U** — vulnerable component = webserver, impacted component = webserver (same authority).
  - **C:H / I:H / A:H** — RCE = total control of information, can modify all/critical data, and can deny service (power off). → drives the **9.8**.

### Tips & Approaches (what this example teaches)
- **Prove RCE safely.** A **ping/DNS callback** (out-of-band interaction captured in Wireshark) is a clean, non-destructive proof of execution — you don't need a reverse shell to demonstrate impact, and it avoids overstepping scope/causing damage.
- **Fingerprint the vuln by its signature:** the **`rO0`** prefix = base64-encoded serialized Java → an immediate tell for deserialization attack surface. (Raw hex `AC ED 00 05` is the non-encoded equivalent.)
- **Name the vulnerable library/version** (Apache Commons Collections) — specificity accelerates triage and remediation.
- **Show the decode step.** Capturing the request, decoding the base64, and displaying the object in Burp Decoder makes the finding transparent and reproducible.

### Documentation Takeaways
- **The three examples share one skeleton** (Title → CWE → CVSS+vector → Description → Impact → numbered PoC with evidence → per-metric CVSS breakdown). Only CWE, payload, evidence, and metric justifications change.
- **CVSS pattern by class (from all three examples):**
  - **Unauthenticated RCE / deserialization** → AV:N, AC:L, PR:N, UI:N, S:U, C/I/A:H → **~9.8 Critical**.
  - **CSRF** → PR:N, **UI:R**, S:U, C/I:L, A:N → **~5.4 Medium**.
  - **Privileged/stored XSS** → **PR:H**, UI:N, **S:C**, C/I:L, A:N → **~5.5 Medium**.
- **Evidence type should match the vuln:** payload-in-filename screenshots (XSS), intercepted request + crafted HTML (CSRF), decoded object + packet capture (RCE).

### Lab Answers
- *(No questions in this section — module ends here; "Finish".)*

---

## Module Summary — Bug Bounty Hunting Process (6/6 complete)

**This module is about *process and communication*, not exploitation.** The through-line:

1. **Know the program (Sec 1).** BBP ≠ VDP (rewards vs. guidance-only). Read the **Policy** (scope, out-of-scope, RoE, SLAs, eligibility, safe harbor) and the **Code of Conduct** *before* testing — your **violation record follows you** and gates future private invites.
2. **Write a report that triages itself (Sec 2).** Title → **CWE** (characteristics) + **CVSS** (severity) → Description → **PoC (repro steps)** → **Impact in business terms** → optional Remediation. Justify **every CVSS base metric** in one line each. For chains, CWE the **initial** vuln.
3. **Communicate like a professional (Sec 3).** After submitting: **don't interact** until the SLA elapses; **official channels only**; resolve severity/bounty disputes by walking the team through your **CVSS metrics → policy/scope check → Mediation** (last resort).
4. **Templates (Sec 4–6).** Three worked reports — **Stored XSS (5.5)**, **CSRF (5.4)**, **Deserialization RCE (9.8)** — all sharing one skeleton, differing only in CWE, payload, evidence, and metric justifications.

**Reusable assets in these notes:** the CVSS v3.1 base-metric reference (Sec 2), the report skeleton (Sec 4), the XSS-vs-CSRF metric-contrast table (Sec 5), and the CVSS-pattern-by-vuln-class cheatsheet (Sec 6).

**Key mindset:** clarity + reproducibility + honest, business-framed impact = faster triage, fewer disputes, better bounties. Time is of the essence — a clean report and disciplined comms save everyone time.
