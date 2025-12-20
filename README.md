# Darkly - Web Security Project

## Project Overview

This project is an introduction to cybersecurity in the field of the Web. The goal is to find and exploit 14 different web vulnerabilities on a target website running at `http://localhost:8080`.

## Project Structure

Each breach has its own numbered folder with the following structure:

```
{Breach name}/
├── flag                    # The flag obtained
└── Resources/              # Documentation and tools
    ├── README.md           # Detailed explanation of the breach
    └── (scripts/tools)     # Any custom scripts used
```

## Completed Breaches (14/14)

1. **Cookie_Tampering** - Manipulating client-side cookies to escalate privileges
2. **SQL_Injection_Member** - SQL injection in member search functionality
3. **Directory_Traversal** - Path traversal to access sensitive files
4. **Reflected_XSS_Media** - Cross-site scripting in media page
5. **Hidden_Field_Recover** - Recovering hidden form fields
6. **Unvalidated_Redirect** - Open redirect vulnerability
7. **Hidden_Crawler** - Web crawling to find hidden directories
8. **Survey_Tampering** - Manipulating survey form data
9. **Stored_XSS_Guestbook** - Persistent XSS in guestbook
10. **File_Upload_MIME_Type** - File upload vulnerability via MIME type bypass
11. **Sensitive_Data_Admin** - Exposed sensitive data in admin area
12. **User_Agent_Referer** - Header manipulation for authentication bypass
13. **SQL_Injection_Images** - SQL injection in image gallery
14. **Brute_Force_Login** - Password brute forcing attack

## Common Web Vulnerabilities to Look For

Based on OWASP Top 10 and common web security issues, here are vulnerabilities you should check for:

### 1. **SQL Injection (SQLi)**

- Test input fields, URL parameters, and forms
- Look for database error messages
- Try: `' OR '1'='1`, `' UNION SELECT NULL--`, etc.

### 2. **Cross-Site Scripting (XSS)**

- Reflected XSS: Check URL parameters, search fields
- Stored XSS: Check comment sections, user profiles
- DOM-based XSS: Check JavaScript handling of user input
- Try: `<script>alert('XSS')</script>`, `<img src=x onerror=alert(1)>`

### 3. **Cross-Site Request Forgery (CSRF)**

- Check if forms lack CSRF tokens
- Test state-changing operations (password change, profile update)

### 4. **File Upload Vulnerabilities**

- Upload malicious files (PHP shells, executable files)
- Check for file type validation bypass
- Path traversal in file names

### 5. **Path Traversal / Directory Traversal**

- Check file inclusion: `../../etc/passwd`
- Look for file download/read functionality
- Try: `....//....//etc/passwd`, URL encoding variations

### 6. **Command Injection**

- Test system commands in input fields
- Look for ping, whois, or other system command features
- Try: `; ls`, `| cat /etc/passwd`, `$(whoami)`

### 7. **Authentication Bypass**

- Weak passwords, default credentials
- SQL injection in login forms
- Session manipulation
- Direct access to protected pages

### 8. **Insecure Direct Object References (IDOR)**

- Access other users' data by changing IDs
- Check URL parameters like `?id=1`, `?user=2`

### 9. **Security Misconfiguration**

- Default credentials
- Exposed sensitive files (.git, .env, backup files)
- Verbose error messages revealing system info

### 10. **Sensitive Data Exposure**

- Unencrypted data transmission
- Exposed API keys, credentials in source code
- Weak encryption

### 11. **XML External Entity (XXE)**

- If XML parsing is present
- Try injecting external entities

### 12. **Server-Side Request Forgery (SSRF)**

- Check for URL fetching functionality
- Test internal network access

### 13. **Local File Inclusion (LFI) / Remote File Inclusion (RFI)**

- File inclusion parameters
- Try: `?page=../../etc/passwd`, `?include=file.php`

### 14. **Session Management Issues**

- Session fixation
- Weak session tokens
- Session hijacking

## Methodology

### 1. **Reconnaissance**

- Map the website structure by browsing all pages
- Check `robots.txt` for hidden directories
- Inspect HTML source code for comments and hidden fields
- Use browser DevTools to examine cookies, headers, and network requests
- Identify all input points (forms, URL parameters, headers)

### 2. **Systematic Testing**

- Test each input field with various payloads
- Use the guides in this repository:
  - **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - Step-by-step testing methodology
  - **[PAYLOADS.md](PAYLOADS.md)** - Quick reference for common payloads
- Document findings as you go
- Save flags immediately when found

### 3. **Documentation**

Each breach folder contains a `Resources/README.md` with:

- **How I Found It** - Discovery process
- **Exploitation Steps** - Detailed attack methodology
- **Proof** - Flag and vulnerability classification
- **How to Fix** - Remediation recommendations

### 4. **Custom Tools**

Some breaches required custom scripts:

- **Hidden_Crawler**: `scraper.sh` - Recursive web crawler using `wget`
- **Brute_Force_Login**: `bruteforce_login.sh` - Password brute force script

## Tools Used

### Essential Tools

- **Browser DevTools** - Inspect elements, network requests, cookies, storage
- **curl** - Command-line HTTP requests for testing
- **wget** - Web crawler for directory traversal
- **grep** - Pattern matching in responses
- **md5/sha256** - Hash generation and verification

### Online Resources

- **[CrackStation](https://crackstation.net/)** - Hash decryption/rainbow tables
- **[SQLZoo](https://sqlzoo.net/wiki/SELECT_basics)** - SQL learning resource
- **[PortSwigger Web Security](https://portswigger.net/web-security/sql-injection)** - SQL injection tutorials

### Custom Scripts

- `scraper.sh` - Recursive directory crawler
- `bruteforce_login.sh` - Password brute force automation
- `setup_breach.sh` - Template generator for new breach folders

## Important Notes

- **NO BINARIES** in Resources folder - Only documentation and scripts
- **Understanding over automation** - You must be able to explain every step
- **Manual exploitation preferred** - Automated tools should be used with full understanding
- **Documentation is key** - Each breach must have clear documentation
- **Flag format** - 64-character hexadecimal strings

## Getting Started

### 1. Set Up the Virtual Machine

**⚠️ Mac M1/M2/M3 Users:** VirtualBox doesn't work on Apple Silicon! See **[MAC_M1_SETUP.md](MAC_M1_SETUP.md)** for UTM setup instructions.

**For Intel Macs/Windows/Linux:**

1. Install VirtualBox
2. Create a new VM (Linux, 32-bit, 512MB-1GB RAM)
3. Mount the provided Darkly ISO file
4. Start the VM and note the IP address displayed
5. Access the website at `http://[VM_IP]` or configure port forwarding to `http://localhost:8080`

### 2. Start Testing

1. **Browse the website** - Map all pages and functionality
2. **Check robots.txt** - Often reveals hidden directories
3. **Inspect source code** - Look for comments, hidden fields, client-side logic
4. **Test systematically** - Use [TESTING_GUIDE.md](TESTING_GUIDE.md) and [PAYLOADS.md](PAYLOADS.md)
5. **Document everything** - Create breach folders as you find vulnerabilities

### 3. Document Each Breach

Use the `setup_breach.sh` script to create a new breach folder:

```bash
./setup_breach.sh "Breach Name"
```

Then document your findings in `Resources/README.md` following the template.

## Flag Format

Flags are 64-character hexadecimal strings, for example:

```
b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f
```

Save each flag in the respective breach folder as a file named `flag`.

## Project Status

✅ **14/14 Breaches Completed**

All vulnerabilities have been identified, exploited, and documented. Each breach folder contains:

- The obtained flag
- Detailed documentation in `Resources/README.md`
- Any custom scripts or tools used
