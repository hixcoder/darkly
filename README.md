# Darkly - Web Security Project

## Project Overview

This project is an introduction to cybersecurity in the field of the Web. You need to find and exploit 14 different web vulnerabilities on a target website.

## Project Structure

Each breach should have its own folder with the following structure:

```
{Breach name}/
├── flag                    # The flag you obtained
└── Resources/              # Proof and explanation files
    └── (your files here)
```

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

1. **Reconnaissance**

   - Map the website structure
   - Identify all input points (forms, URLs, cookies)
   - Check source code for comments and hidden fields
   - Use browser dev tools to inspect requests/responses

2. **Testing Each Vulnerability**

   - Test systematically
   - Document your findings
   - Capture proof (screenshots, requests/responses)
   - Save flags as you find them

3. **Documentation**
   - For each breach, document:
     - How you found it
     - How you exploited it
     - How to fix it
   - Save this in the Resources folder

## Tools You Might Need

- Browser (with DevTools)
- Burp Suite or OWASP ZAP (optional, but helpful)
- curl or wget for testing
- SQLMap (but remember: you need to explain your approach manually)

## Important Notes

- **NO BINARIES** in Resources folder
- You must be able to explain everything
- You may need to fix the breaches during evaluation
- Understanding is more important than exploitation
- No automated tools like sqlmap without explanation

## Getting Started

### First: Set Up the Virtual Machine

**📖 See [VM_SETUP.md](VM_SETUP.md) for detailed instructions on setting up the virtual machine.**

**⚠️ Mac M1/M2/M3 Users:** VirtualBox doesn't work on Apple Silicon! See **[MAC_M1_SETUP.md](MAC_M1_SETUP.md)** instead.

Quick steps:

1. Install virtualization software (VirtualBox recommended for macOS)
2. Create a new VM (Linux, 32-bit, 512MB-1GB RAM)
3. Mount the provided ISO file
4. Start the VM and note the IP address displayed
5. Access the website in your browser using that IP address

### Then: Start Testing

1. Browse the website and map its structure
2. Start exploring and testing systematically
3. Use the guides in this repository (TESTING_GUIDE.md, PAYLOADS.md)
4. Document each breach as you find it

## Flag Format

Flags are typically in the format: `XXXXXXXXXXXXXXXXXXXXXXXXXXX`

Save each flag in the respective breach folder as a file named `flag`.
