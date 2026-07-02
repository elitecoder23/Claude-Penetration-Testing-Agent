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
