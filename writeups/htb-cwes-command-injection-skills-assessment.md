# HTB Academy — CWES Command Injection Skills Assessment

**Target:** `154.57.164.80:31504`  
**App:** Tiny File Manager v2.4.6  
**Credentials:** guest / guest  
**Goal:** Read `/flag.txt`

---

## Status: IN PROGRESS

---

## Recon

Login redirects to `index.php?to=` (not `index.php` or `/`).

```bash
# Login and save session cookie
curl -v -c /tmp/fm.txt -X POST 'http://154.57.164.80:31504/?to=' -d "fm_usr=guest&fm_pwd=guest"
# → 302 redirect to http://154.57.164.80:31504/index.php?to=
# → Sets cookie: filemanager=<session>
```

App structure:
- Web root: `/var/www/html/files`
- Files listing at `index.php?to=` (root) and `index.php?to=tmp` (subfolder)
- `tmp` folder is empty
- 10 `.txt` files in root, all 31 bytes except one (78 bytes)
- Running on Apache/2.4.41 (Ubuntu)

### Parameters Identified
| Parameter | Location | Purpose |
|-----------|----------|---------|
| `to` | GET | Directory navigation |
| `view` | GET | View file content |
| `dl` | GET | Download file |
| `from` | GET | Copy source file |
| `new` | GET | New file/folder name |
| `p` | GET/POST | Path for operations |
| `type` | GET/POST | File type or action type |
| `ren` | GET | Rename source |
| `finish` | GET | Confirm copy/move |
| `move` | GET | Move flag (vs copy) |
| `content` | POST | Search query / file save content |

### Search Endpoint Notes
The Advanced Search feature POSTs to `window.location` with:
```javascript
{ajax: true, content: searchTxt, path: path, type: 'search'}
```
All attempts to trigger AJAX search handler returned full HTML (handler not triggered).
TFM's search internally uses PHP's `RecursiveDirectoryIterator` — NOT a shell command.

---

## Injection Point Investigation

### GET Parameters Tested (all returned no command output)
- `?to=.%0awhoami` — no output
- `?to=&view=test%0aid` — no output  
- `?to=&dl=test%0aid` — no output
- `?to=tmp&from=test%0aid&finish=1` — no output
- `?to=tmp%0aid&from=51459716.txt&finish=1` — no output
- `?p=.%0aid&new=test&type=file` — no output
- `?p=&new=test%0aid&type=file` — no output

---

## TODO: Complete Skills Assessment
- Continue testing remaining parameters and POST actions
- Test `ren` parameter
- Test backup POST action (`path=&file=&type=backup&ajax=true`)
- Compare response sizes (`wc -c`) to detect blind injection
- Test with existing filenames in injection (e.g. `view=51459716.txt%0aid`)

---

## Key Lessons (from module sections, pre-assessment)

- **Front-end validation bypass:** Inject directly via curl/Burp — browser pattern check is bypassed
- **Enumerate filter layers independently:** Test operator alone → space alone → command alone
- **Newline (`%0a`) is the go-to operator** — almost never blacklisted
- **Character + command are two separate filter layers** — newline passed but `whoami` was still blocked by command filter in exercises
- **Full bypass stack:** `%0a` + `${IFS}` + `${PATH:0:1}` + `ca$@t` covered all exercise filters
- **Base64 nuclear option:** Encodes entire command including pipes, spaces, slashes — nothing needs to survive filter
  ```bash
  echo -n 'cmd with | pipes and /slashes' | base64
  bash<<<$(base64${IFS}-d<<<BASE64)
  ```
- **Always use single quotes in curl** to prevent local `${IFS}` shell expansion
