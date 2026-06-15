# Module Learning Process

This file defines the process Claude follows for every section in an HTB Academy module and for every skills assessment. Read this before starting any learning session.

---

## For Every Module Section

When going through a section, document all of the following in the module's notes file (`writeups/htb-cwes-<module-name>-module-notes.md`):

### 1. Commands
- Every command introduced or demonstrated in the section
- What the command does (plain explanation of its purpose)
- Which scenario it is used for (what condition or situation calls for this command)

### 2. Tools
- Every tool introduced in the section
- How to use it (syntax, key flags, invocation)
- When to use it (what conditions or indicators tell you to reach for this tool)
- Helpful commands shown in the learning material for that tool

### 3. What Works and What Doesn't
- Techniques, payloads, or approaches confirmed to work in the section exercises
- Techniques, payloads, or approaches that fail and why
- Edge cases, gotchas, or surprising behaviors observed

### 4. Section Exercise
- Target IP and port
- What was done step by step
- Key commands run and their output
- Flag(s) obtained
- Key lessons from the exercise

---

## For Every Skills Assessment

The skills assessment is the most important part of every module. Before starting it:

1. **Write the pre-assessment playbook** — based only on what was covered in the module, document:
   - What works and what doesn't for each attack type
   - The methodology to follow
   - Key commands and payloads to use
   - Decision flow for choosing between techniques

2. **During the assessment** — take live notes after each command output:
   - What the response revealed
   - What it rules in or out
   - Current enumeration stage
   - Next step

3. **After the assessment** — write the full skills assessment writeup (`writeups/htb-cwes-<module-name>-skills-assessment.md`) including:
   - Full attack chain from recon to flag
   - Key payloads used
   - Lessons learned

---

## Commit and Push

After completing sections or the skills assessment, commit all new/updated files and immediately push:

```bash
git add <files>
git commit -m "..."
git push origin main
```

Never leave commits only local.
