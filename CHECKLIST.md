# Darkly Project Checklist

## Breaches to Complete (14 total)

- [ ] Breach 1: **********\_**********
- [ ] Breach 2: **********\_**********
- [ ] Breach 3: **********\_**********
- [ ] Breach 4: **********\_**********
- [ ] Breach 5: **********\_**********
- [ ] Breach 6: **********\_**********
- [ ] Breach 7: **********\_**********
- [ ] Breach 8: **********\_**********
- [ ] Breach 9: **********\_**********
- [ ] Breach 10: **********\_**********
- [ ] Breach 11: **********\_**********
- [ ] Breach 12: **********\_**********
- [ ] Breach 13: **********\_**********
- [ ] Breach 14: **********\_**********

## Testing Checklist

### Initial Reconnaissance

- [ ] Map all pages and endpoints
- [ ] Identify all forms and input fields
- [ ] Check source code for comments
- [ ] Inspect cookies and session management
- [ ] Check robots.txt
- [ ] Look for hidden directories/files

### SQL Injection Testing

- [ ] Test login forms
- [ ] Test search functionality
- [ ] Test URL parameters
- [ ] Test all input fields

### XSS Testing

- [ ] Test all input fields for reflected XSS
- [ ] Test comment/user content areas for stored XSS
- [ ] Check URL parameters
- [ ] Test DOM manipulation

### File Upload Testing

- [ ] Test file upload functionality
- [ ] Try uploading different file types
- [ ] Test for path traversal in filenames
- [ ] Check file execution

### Authentication Testing

- [ ] Test default credentials
- [ ] Test SQL injection in login
- [ ] Test password reset functionality
- [ ] Check session management

### Other Tests

- [ ] Path traversal in file operations
- [ ] Command injection in system features
- [ ] IDOR in user data access
- [ ] CSRF in state-changing operations
- [ ] Check for exposed sensitive files
- [ ] Test for XXE if XML is present
- [ ] Test for SSRF if URL fetching exists

## Documentation Checklist (for each breach)

- [ ] Flag obtained and saved
- [ ] Explanation written (how you found it)
- [ ] Exploitation steps documented
- [ ] Fix/solution explained
- [ ] Screenshots or proof saved in Resources folder
