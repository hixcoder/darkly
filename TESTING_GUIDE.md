# Darkly Testing Guide

## Step-by-Step Testing Methodology

### Phase 1: Information Gathering

1. **Browse the entire website**

   - Click through all pages and links
   - Note all URLs and parameters
   - Check for hidden links in source code
   - Look for comments in HTML/JavaScript

2. **Check common files**

   - `/robots.txt` - May reveal hidden directories (e.g., `/.hidden`, `/whatever`)
   - `/.git/` - May expose source code
   - `/.env` - May contain credentials
   - `/backup/`, `/old/`, `/test/` - Common backup directories
   - `/phpinfo.php` - May reveal system information

3. **Inspect HTTP headers**

   - Use browser DevTools Network tab
   - Look for server information, cookies, tokens
   - Check for security headers (or lack thereof)
   - Examine cookies for sensitive data (e.g., `I_am_admin`)

4. **Source code inspection**
   - View page source (Ctrl+U / Cmd+Option+U)
   - Check for hidden form fields
   - Look for client-side validation
   - Search for comments containing hints

### Phase 2: Input Testing

For each input field, test systematically:

#### SQL Injection Testing

1. **Basic tests** - Start with simple payloads:

   ```
   '
   ''
   ' OR '1
   ' OR '1'='1
   ' OR '1'='1'--
   ```

2. **Union-based** - If basic tests work, enumerate columns:

   ```
   ' UNION SELECT NULL--
   ' UNION SELECT NULL,NULL--
   ' UNION SELECT NULL,NULL,NULL--
   ' UNION SELECT 1,2,3--
   ```

3. **Extract data** - Once column count is known:

   ```
   ' UNION SELECT table_name, 1 FROM information_schema.tables--
   ' UNION SELECT column_name, 1 FROM information_schema.columns WHERE table_name=0x7573657273--
   ' UNION SELECT Commentaire, countersign FROM users--
   ```

4. **Bypass filters** - Use hex encoding for strings:
   ```
   0x7573657273  (hex for "users")
   0x6c6973745f696d61676573  (hex for "list_images")
   ```

#### XSS Testing

1. **Reflected XSS** - Test URL parameters and search fields:

   ```
   <script>alert('XSS')</script>
   <img src=x onerror=alert(1)>
   <svg onload=alert(1)>
   ```

2. **Stored XSS** - Test comment sections, guestbooks:

   ```
   <script>alert('XSS')</script>
   <img src=x onerror=alert('XSS')>
   ```

3. **Data URI bypass** - For media/file inclusion:
   ```
   data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=
   ```

#### Path Traversal Testing

1. **Basic traversal**:

   ```
   ../../etc/passwd
   ....//....//etc/passwd
   ..%2F..%2Fetc%2Fpasswd
   ```

2. **URL encoded**:
   ```
   %2e%2e%2f%2e%2e%2fetc%2fpasswd
   ..%252F..%252Fetc%252Fpasswd
   ```

### Phase 3: Authentication Testing

1. **Cookie manipulation**

   - Inspect cookies in DevTools
   - Look for hashed values (MD5, SHA)
   - Decrypt hashes using [CrackStation](https://crackstation.net/)
   - Modify cookie values (e.g., `I_am_admin`)

2. **Default credentials**

   - Try: `admin/admin`, `admin/password`, `root/root`
   - Check for exposed credential files (`.htpasswd`)

3. **SQL Injection in login**

   ```
   admin'--
   admin' OR '1'='1'--
   ' OR '1'='1'--
   ```

4. **Brute force**

   - Use wordlists (e.g., `10k-most-common.txt`)
   - Check for rate limiting
   - Automate with scripts

5. **Header manipulation**
   - Test `User-Agent` header
   - Test `Referer` header
   - Modify headers to bypass checks

### Phase 4: File Operations

1. **File Upload**

   - Try uploading PHP files: `<?php phpinfo(); ?>`
   - Try different extensions: `.php`, `.phtml`, `.php3`
   - Try MIME type manipulation
   - Check for path traversal in filenames

2. **File Inclusion**
   - Test parameters like `?page=`, `?file=`, `?include=`
   - Try: `?page=../../etc/passwd`
   - Test with null bytes: `?page=../../etc/passwd%00`

### Phase 5: Hidden Data Discovery

1. **Hidden form fields**

   - View page source
   - Use browser DevTools to inspect forms
   - Look for `<input type="hidden">` fields

2. **Directory listing**

   - Check if directories show file listings
   - Use `wget` or custom crawlers for recursive discovery
   - Filter results to find unique content

3. **Sensitive files**
   - Check `robots.txt` for disallowed paths
   - Look for `.htpasswd`, `.env`, backup files
   - Check for exposed configuration files

### Phase 6: Redirect Testing

1. **Open redirect**

   - Test redirect parameters: `?page=redirect&site=XXX`
   - Try external URLs
   - Check if validation exists

2. **Unvalidated redirects**
   - Modify redirect destinations
   - Test with different protocols

## Testing Workflow

### For Each Page:

1. **Map the functionality**

   - What does this page do?
   - What inputs does it accept?
   - What outputs does it produce?

2. **Identify input points**

   - URL parameters (`?id=1`, `?page=signin`)
   - Form fields (username, password, search)
   - Headers (User-Agent, Referer, Cookies)
   - File uploads

3. **Test systematically**

   - Start with basic payloads
   - Escalate if initial tests succeed
   - Document all findings

4. **Verify results**
   - Check if flag appears
   - Confirm vulnerability exists
   - Capture proof (screenshots, responses)

## Tools and Techniques

### Browser DevTools

- **Elements** - Inspect HTML, find hidden fields
- **Network** - Monitor requests/responses, check headers
- **Application/Storage** - View cookies, local storage
- **Console** - Execute JavaScript, test XSS

### Command Line Tools

- **curl** - Make HTTP requests, test endpoints
- **wget** - Recursive web crawling
- **grep** - Search for patterns in responses
- **md5/sha256** - Generate hashes

### Custom Scripts

- **scraper.sh** - Recursive directory crawler
- **bruteforce_login.sh** - Password brute force automation

## Common Patterns

### Finding Flags

Flags are typically:

- 64-character hexadecimal strings
- Hidden in:
  - Database query results
  - HTML comments
  - Response headers
  - File contents
  - Cookie values (after manipulation)

### Error Messages

Look for:

- Database errors (reveal SQL structure)
- File system errors (reveal paths)
- PHP errors (reveal code structure)
- Stack traces (reveal internal logic)

### Success Indicators

- Different page content
- Redirects to new pages
- Flags in response
- Altered functionality
- New cookies or headers

## Documentation

For each vulnerability found:

1. Document how you discovered it
2. Explain the exploitation steps
3. Capture proof (flag, screenshots)
4. Explain how to fix it

Save everything in the breach folder's `Resources/` directory.
