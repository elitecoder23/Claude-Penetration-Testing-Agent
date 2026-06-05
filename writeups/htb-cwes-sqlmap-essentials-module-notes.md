# HTB Academy — SQLMap Essentials Module Notes

## What Worked

### Use only what the module teaches
Every case in this module had a direct flag from the section content. The fastest path was always: read the section, identify the relevant flag, craft one clean command. Overthinking or adding extra flags consistently caused problems.

### `--batch` on every command
Never run sqlmap without `--batch` in a CTF/lab context. It removes all interactive prompts and lets the tool run to completion.

### `*` marker for non-obvious injection points
Case 3 required injecting into a POST body where the parameter name wasn't a simple GET param. Adding `*` to the value told sqlmap exactly where to inject. Without it, sqlmap either missed the point or flagged the wrong location.

### `--no-cast` fixes UNION extraction failures
Case 7 had 5 columns and UNION was returning "something went wrong" on data retrieval even after injection was confirmed. Adding `--no-cast` fixed it immediately. Use this when UNION injection is confirmed but data extraction fails.

### Fetch dynamic parameters before using `--randomize`
Case 9 had a server-generated uid. Hardcoding `uid=1` was rejected ("Bad UID"). The fix: `curl` the page first to get a real uid (e.g., `115688661`), then use `--randomize=uid -p id` so sqlmap uses random valid-format values per request.

### `--technique=E` for `--os-shell`
Error-based technique works most reliably for getting an interactive shell. Stack injections (`--technique=S`) require specific DB/driver support. Default to `-technique=E` when using `--os-shell`.

### `--prefix` for known query structure
When the injection point is inside a function call or subquery (e.g., `WHERE id=( SELECT ... )`) and you know the closing characters needed, `--prefix=')'` or similar saves sqlmap from wasting time trying every variant.

---

## What Didn't Work / Lessons Learned

### `--csrf-token` split by terminal newline
When pasting a long sqlmap command with a freshly grabbed CSRF token, the terminal wrapped the line and broke the command (`bash: --csrf-token=...: command not found`). Fix: store the token in `$TOKEN` first, then build the command on a single line using the variable.

### Non-existent SSL flags
`--no-check-certificate`, `--ignore-ssl`, `-k` — none of these are valid sqlmap flags. SQLMap handles HTTPS automatically. Drop all SSL flags entirely.

### Hardcoded static value for dynamic parameter
Case 9: assumed `uid=1` was a valid static value. It wasn't — the app generates a unique uid per page load. Always check if a parameter looks dynamic before hardcoding it. A quick `curl | grep` of the page reveals the real format.

### Over-escalating too early
Adding `--level=5 --risk=3` on every case added significant scan time and noise without benefit for straightforward cases. Default level/risk handles most lab cases. Escalate only when the baseline fails.

---

## Key Commands by Case Type

| Case | Key flags |
|------|-----------|
| Basic GET | `sqlmap -u "URL?id=1" --batch` |
| POST body | `--data="param=val" --batch` |
| Burp request file | `-r request.txt --batch` |
| Non-obvious inject point | Add `*` to param: `--data="id=1*"` |
| Anti-CSRF token | `--csrf-token="t0ken"` |
| Dynamic/randomized param | `--randomize=uid -p id` |
| Calculated/hash param | `--eval="import hashlib; h=..."` |
| UNION extraction failing | `--no-cast` |
| WAF blocking | `--tamper=between,randomcase,space2comment` |
| OS shell | `--os-shell --technique=E` |
| File read | `--file-read="/path/to/file"` |
| File write | `--file-write="local" --file-dest="/remote/path"` |

---

## The Right Mindset for SQLMap

SQLMap is a tool that executes what you tell it. The job is to understand the injection context well enough to give it the right instruction on the first try:

1. **Read the page source** before building the command — understand the parameter, its format, and any token/validation logic
2. **Match the flag to the problem** — each special case has one flag that solves it; find that flag
3. **Escalate in steps** — default → level/risk → prefix/suffix → tamper
4. **Trust the tool** — if injection is confirmed, sqlmap will find the data; the issue is almost always the command, not the tool
