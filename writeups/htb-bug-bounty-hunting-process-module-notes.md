# HTB Academy — Bug Bounty Hunting Process: Module Notes

**Status:** In progress — notes being built section by section.

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
