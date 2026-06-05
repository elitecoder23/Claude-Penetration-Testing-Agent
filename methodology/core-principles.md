# Core Penetration Testing Principles

These principles apply to every module, every tool, every target. They are the foundation of strong attack methodology.

---

## Never Test Blindly

Every test, payload, and exploit must be based on something you observed. If you don't know why you're running a command, you're not ready to run it yet.

**What this looks like in practice:**
- Curl the target before launching any tool — understand what's there
- Read the page source before building a SQLMap command
- Read tool warnings and errors before adding flags
- Identify the injection context (GET, POST, JSON, cookie, header, response type) before testing
- Know what response you expect before sending the payload

**What blind testing looks like (avoid this):**
- Running `--level=5 --risk=3` without understanding the response type
- Adding tamper scripts "just in case" without observing WAF behavior
- Trying every auth bypass payload without confirming the field is injectable first
- Escalating immediately when the first attempt fails, instead of reading the failure

---

## Enumerate First, Exploit Second

You cannot exploit what you don't understand. Enumeration isn't a phase — it's a constant loop throughout the engagement.

```
Observe → Understand → Test → Observe again
```

Every time a test fails or returns unexpected output, that's new information. Stop, read it, update your understanding, then test again.

---

## Simple Before Complex

The right answer is almost always one step away from the simplest possible approach. If your approach is getting complicated, you probably skipped an enumeration step.

- Start with the baseline command, not the escalated one
- Start with a single quote probe, not a full UNION payload
- Start with the technique the current module taught, not the full arsenal
- Add one thing at a time — each addition should have a specific reason

---

## Match the Tool to the Context

Every tool flag, tamper script, and technique exists to solve a specific problem. Use them when you've observed that problem — not before.

| Observation | Action |
|-------------|--------|
| Response body is empty | Don't use boolean-based blind — switch to time-based |
| sqlmap warns `>` is filtered | Add `--tamper=between` |
| Data retrieval garbled | Add `--hex` |
| WAF blocking on spaces | Add `--tamper=space2comment` |
| Parameter is dynamically generated | Fetch page first, then use `--randomize` |
| UNION extraction failing | Add `--no-cast` |
| Default level not finding injection | Escalate `--level`/`--risk` — but only after confirming the parameter is actually injectable |

---

## Why HTB Is Hard (and How to Approach It)

HTB is difficult because it requires methodology, not just tool knowledge. The boxes and modules that trip people up are almost always cases where:

1. A step got skipped
2. Testing started before enumeration was complete
3. A tool was run without understanding what the target returns

The solution isn't to know more tools — it's to slow down, enumerate properly, and let the target tell you what to test. The answer is always in the context.
