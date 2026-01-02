# Darkly Project - OWASP Vulnerabilities & Learning Guide

## Overview

This document outlines all OWASP Top 10 (2021) vulnerabilities found in the Darkly project and the knowledge/skills required to identify and exploit them.

---

## OWASP Vulnerabilities Found (14 Breaches)

### A01:2021 - Broken Access Control (3 breaches)

#### 1. Directory Traversal (Breach #3)

- **What it is:** Unrestricted access to files outside the web root directory
- **How found:** Testing URL parameters (`?page=`) with path traversal sequences
- **Skills needed:**
  - Understanding of file system structure (Linux paths)
  - Knowledge of path traversal techniques (`../`, `....//`)
  - Understanding of PHP `include()`/`require()` functions
  - URL encoding knowledge

#### 2. Unvalidated Redirect (Breach #6)

- **What it is:** Server redirects users to arbitrary URLs without validation
- **How found:** Inspecting redirect links in footer, modifying parameters
- **Skills needed:**
  - Understanding HTTP redirects (301, 302)
  - Knowledge of URL parameter manipulation
  - Understanding of open redirect attacks

#### 3. Hidden Crawler / Forced Browsing (Breach #7)

- **What it is:** Accessing hidden directories and files through directory listing
- **How found:** Checking `robots.txt`, discovering directory listing enabled
- **Skills needed:**
  - Understanding of `robots.txt` file
  - Web crawling/automation skills (wget, bash scripting)
  - Pattern matching and filtering (grep)
  - Understanding directory listing vulnerabilities

---

### A02:2021 - Cryptographic Failures (1 breach)

#### 4. Sensitive Data Exposure (Breach #11)

- **What it is:** Exposed credential files with weak hashing (MD5)
- **How found:** Checking `robots.txt`, accessing `/whatever/` directory, finding `.htpasswd`
- **Skills needed:**
  - Understanding of hash formats (MD5, SHA)
  - Knowledge of rainbow tables and hash cracking
  - Understanding of credential file formats (`.htpasswd`)
  - Directory enumeration skills

---

### A03:2021 - Injection (3 breaches)

#### 5. SQL Injection - Member Search (Breach #2)

- **What it is:** SQL injection in member ID parameter
- **How found:** Testing input fields with SQL payloads (`1 OR 1=1`)
- **Skills needed:**
  - **SQL fundamentals:** SELECT, UNION, WHERE clauses
  - **SQL injection techniques:** Union-based, error-based, blind
  - **Database schema knowledge:** information_schema tables
  - **Encoding techniques:** Hex encoding to bypass filters (`0x7573657273`)
  - **Hash operations:** MD5 decryption, SHA-256 generation
  - **Tools:** SQL syntax knowledge, hash crackers (CrackStation)

#### 6. SQL Injection - Image Search (Breach #13)

- **What it is:** SQL injection in image search functionality
- **How found:** Testing boolean conditions (`1 AND 1=1` vs `1 AND 1=0`)
- **Skills needed:**
  - Same as Breach #2, plus:
  - **Blind SQL injection:** Understanding boolean-based testing
  - **Converting blind to union-based:** Escalation techniques

#### 7. Reflected XSS - Media (Breach #4)

- **What it is:** Cross-site scripting via media source parameter
- **How found:** Testing `src` parameter with malicious payloads
- **Skills needed:**
  - **JavaScript fundamentals:** Understanding script execution
  - **XSS payloads:** `<script>`, event handlers, encoded payloads
  - **Data URI scheme:** Understanding `data:text/html;base64,`
  - **Base64 encoding:** Encoding payloads to bypass filters
  - **Browser security model:** How browsers execute scripts

#### 8. Stored XSS - Guestbook (Breach #9)

- **What it is:** Persistent XSS stored in database
- **How found:** Testing comment/guestbook forms with XSS payloads
- **Skills needed:**
  - Same as Reflected XSS, plus:
  - **Understanding stored vs reflected:** Difference in attack vectors
  - **Database interaction:** How data persists and is retrieved

---

### A04:2021 - Insecure Design (3 breaches)

#### 9. Hidden Field Manipulation (Breach #5)

- **What it is:** Trusting client-side hidden form fields
- **How found:** Inspecting HTML source, finding hidden input fields
- **Skills needed:**
  - **HTML form understanding:** Input types, hidden fields
  - **Browser DevTools:** Inspector/Elements tab usage
  - **Client-side vs server-side:** Understanding what can be trusted
  - **HTTP request manipulation:** Modifying form data before submission

#### 10. Survey Tampering (Breach #8)

- **What it is:** Client controls business logic (vote weight)
- **How found:** Inspecting form values, modifying option values
- **Skills needed:**
  - Same as Hidden Field Manipulation, plus:
  - **Business logic understanding:** How applications process votes/scores
  - **Parameter tampering:** Modifying form values

#### 11. File Upload MIME Type Spoofing (Breach #10)

- **What it is:** Trusting client-sent MIME type headers
- **How found:** Testing file upload with spoofed Content-Type
- **Skills needed:**
  - **HTTP headers:** Understanding Content-Type header
  - **MIME types:** Understanding file type indicators
  - **File upload security:** Extension vs content validation
  - **curl usage:** Spoofing headers in requests
  - **PHP file execution:** Understanding how servers execute files

---

### A05:2021 - Security Misconfiguration (2 breaches)

#### 12. Directory Listing (Breach #7 - part of Hidden Crawler)

- **What it is:** Web server configured to list directory contents
- **Skills needed:**
  - **Web server configuration:** Apache/Nginx settings
  - **Directory listing:** Understanding when it's enabled
  - **Automation:** Scripting to crawl directories

#### 13. Header-Based Authentication (Breach #12)

- **What it is:** Using HTTP headers (User-Agent, Referer) for access control
- **How found:** Inspecting HTML comments, finding header requirements
- **Skills needed:**
  - **HTTP headers:** User-Agent, Referer understanding
  - **Header spoofing:** Using curl to modify headers (`-A`, `-e`)
  - **Source code inspection:** Finding hints in HTML comments
  - **Understanding authentication:** Why headers shouldn't be trusted

---

### A07:2021 - Identification and Authentication Failures (2 breaches)

#### 14. Cookie Tampering (Breach #1)

- **What it is:** Storing authentication state in client-side cookies
- **How found:** Inspecting cookies in DevTools, recognizing MD5 hashes
- **Skills needed:**
  - **Cookie understanding:** How cookies work, HttpOnly, Secure flags
  - **Hash recognition:** Identifying MD5 format (32 hex chars)
  - **Hash cracking:** Using rainbow tables (CrackStation)
  - **Hash generation:** Creating MD5 hashes (`echo -n "text" | md5`)
  - **Browser DevTools:** Application/Storage tab usage
  - **Session management:** Understanding secure session handling

#### 15. Brute Force Login (Breach #14)

- **What it is:** Weak passwords and lack of rate limiting
- **How found:** Testing login page, noticing no CAPTCHA/lockout
- **Skills needed:**
  - **Password security:** Understanding weak vs strong passwords
  - **Brute force attacks:** Understanding automated password guessing
  - **Bash scripting:** Writing automation scripts
  - **curl usage:** Making HTTP requests programmatically
  - **Wordlists:** Understanding common password lists
  - **Response analysis:** Detecting successful vs failed logins
  - **Rate limiting:** Understanding why it's needed

---

## Essential Knowledge & Skills to Learn

### 1. Web Fundamentals

**HTML & CSS:**

- Form elements (input, select, hidden fields)
- HTML structure and attributes
- Viewing page source
- Understanding client-side code

**HTTP Protocol:**

- Request/Response cycle
- HTTP methods (GET, POST)
- Headers (User-Agent, Referer, Content-Type, Cookie)
- Status codes (200, 301, 302, 404)
- URL structure and parameters

**Browser DevTools:**

- Elements/Inspector tab
- Network tab (monitoring requests)
- Application/Storage tab (cookies, local storage)
- Console tab (JavaScript execution)

### 2. Backend Technologies

**PHP Basics:**

- `$_GET`, `$_POST`, `$_FILES` superglobals
- `include()`, `require()` functions
- String concatenation vulnerabilities
- File handling

**SQL Fundamentals:**

- SELECT, UNION, WHERE clauses
- Database schema (tables, columns)
- `information_schema` database
- SQL injection concepts

**Web Server Configuration:**

- Apache/Nginx settings
- Directory listing configuration
- `.htaccess` files

### 3. Security Concepts

**Injection Attacks:**

- SQL Injection (union-based, blind, error-based)
- Cross-Site Scripting (reflected, stored, DOM-based)
- Command Injection
- Path Traversal

**Authentication & Authorization:**

- Session management
- Cookie security
- Password security
- Access control

**Input Validation:**

- Client-side vs server-side validation
- Encoding/decoding (URL, Base64, Hex)
- Filter bypass techniques

### 4. Tools & Techniques

**Command Line:**

- `curl` - HTTP requests, header manipulation
- `wget` - Web crawling, recursive downloads
- `grep` - Pattern matching, filtering
- `md5`, `sha256` - Hash generation
- `base64` - Encoding/decoding

**Browser Tools:**

- DevTools (all tabs)
- View Source
- Inspect Element
- Network monitoring

**Online Resources:**

- Hash crackers (CrackStation)
- SQL learning (SQLZoo)
- Security tutorials (PortSwigger)

**Scripting:**

- Bash scripting basics
- Loop structures
- String manipulation
- File operations

### 5. Encoding & Cryptography

**Encoding Schemes:**

- URL encoding (`%20`, `%2F`)
- Base64 encoding
- Hex encoding (`0x7573657273`)
- HTML entities

**Hashing:**

- MD5 (32 hex characters, easily cracked)
- SHA-256 (64 hex characters)
- Hash recognition
- Rainbow tables

### 6. Attack Techniques

**Reconnaissance:**

- Checking `robots.txt`
- Directory enumeration
- Source code inspection
- Comment analysis

**Testing Methodology:**

- Systematic input testing
- Payload construction
- Response analysis
- Error message interpretation

**Automation:**

- Scripting repetitive tasks
- Web crawling
- Brute force automation

---

## Learning Roadmap

### Phase 1: Foundations (Week 1-2)

1. **HTML/HTTP Basics**

   - Learn HTML form structure
   - Understand HTTP request/response
   - Practice with browser DevTools

2. **Basic Security Concepts**
   - What is SQL Injection?
   - What is XSS?
   - What is authentication vs authorization?

### Phase 2: Core Vulnerabilities (Week 3-4)

1. **SQL Injection**

   - Learn SQL basics (SQLZoo)
   - Practice union-based injection
   - Learn about information_schema
   - Practice hex encoding

2. **XSS**

   - Learn JavaScript basics
   - Practice XSS payloads
   - Understand Data URI scheme
   - Learn Base64 encoding

3. **Path Traversal**
   - Understand file system paths
   - Practice traversal sequences
   - Learn URL encoding

### Phase 3: Advanced Techniques (Week 5-6)

1. **Authentication Issues**

   - Learn about cookies and sessions
   - Understand hash functions
   - Practice hash cracking
   - Learn about brute force attacks

2. **File Operations**

   - Understand file upload security
   - Learn MIME types
   - Practice header manipulation

3. **Client-Side Manipulation**
   - Learn about hidden fields
   - Understand form tampering
   - Practice with DevTools

### Phase 4: Automation & Tools (Week 7-8)

1. **Command Line Tools**

   - Master `curl` for HTTP requests
   - Learn `wget` for crawling
   - Practice `grep` for filtering

2. **Scripting**
   - Learn Bash scripting basics
   - Write automation scripts
   - Practice parsing responses

### Phase 5: Advanced Reconnaissance (Week 9-10)

1. **Information Gathering**

   - Master `robots.txt` analysis
   - Learn directory enumeration
   - Practice source code inspection
   - Understand error messages

2. **Header Manipulation**
   - Learn all HTTP headers
   - Practice header spoofing
   - Understand authentication headers

---

## Recommended Learning Resources

### SQL Injection

- **SQLZoo** (https://sqlzoo.net/) - Learn SQL interactively
- **PortSwigger Web Security Academy** (https://portswigger.net/web-security/sql-injection) - SQL injection tutorials
- **OWASP SQL Injection Guide** - Comprehensive SQLi documentation

### XSS

- **PortSwigger XSS Labs** - Practice XSS vulnerabilities
- **OWASP XSS Prevention Cheat Sheet** - Understanding XSS
- **MDN JavaScript Guide** - Learn JavaScript fundamentals

### General Web Security

- **OWASP Top 10** - Official OWASP documentation
- **PortSwigger Web Security Academy** - Free web security training
- **HackTheBox** - Practice platform (after basics)
- **TryHackMe** - Beginner-friendly security training

### Tools

- **curl Manual** - Master HTTP requests
- **Bash Scripting Guide** - Learn automation
- **Browser DevTools Documentation** - Chrome/Firefox DevTools guides

### Hash Cracking

- **CrackStation** (https://crackstation.net/) - Online hash cracker
- **Hashcat** - Advanced hash cracking tool (later)

---

## Key Takeaways

1. **Never trust client input** - Always validate and sanitize on the server
2. **Security by obscurity doesn't work** - Hidden doesn't mean secure
3. **Understand the technology stack** - Know how PHP, SQL, HTTP work
4. **Systematic testing** - Test every input point methodically
5. **Automation is your friend** - Script repetitive tasks
6. **Read error messages** - They reveal valuable information
7. **Inspect everything** - Source code, headers, cookies, files
8. **Think like an attacker** - What can go wrong?

---

## Practice Exercises

1. **Set up a test environment** - Install XAMPP/WAMP, create vulnerable apps
2. **Practice SQL injection** - Build a simple search page, test it
3. **Practice XSS** - Create a comment system, test XSS payloads
4. **Learn curl** - Make 50 different HTTP requests
5. **Write a brute force script** - Automate password guessing
6. **Crawl a website** - Use wget to download entire site structure
7. **Inspect real websites** - Use DevTools on any website (ethically)
8. **Read source code** - Find open-source PHP projects, analyze them

---

## Conclusion

The Darkly project covers 6 out of 10 OWASP Top 10 categories, with a focus on:

- **Injection** (SQL, XSS)
- **Broken Access Control**
- **Insecure Design**
- **Security Misconfiguration**
- **Identification and Authentication Failures**
- **Cryptographic Failures**

Mastering these vulnerabilities requires:

- Strong understanding of web technologies (HTML, HTTP, PHP, SQL)
- Security mindset (thinking about what can go wrong)
- Tool proficiency (DevTools, curl, scripting)
- Systematic testing methodology
- Continuous learning and practice

Start with the fundamentals, practice each vulnerability type, and gradually build your skills. The key is hands-on practice and understanding the "why" behind each vulnerability.
