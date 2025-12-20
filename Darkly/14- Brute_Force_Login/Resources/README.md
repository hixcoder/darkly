# Brute_Force_Login - Documentation

## How I Found It

I targeted the **Sign In** page (`index.php?page=signin`). Since I had previously found a username "admin" via SQL Injection , I suspected the password might be weak or contained in a common wordlist. The lack of CAPTCHA or account lockout mechanisms suggested it was vulnerable to Brute Force attacks.

## Exploitation Steps

1.  **Strategy:** I wrote a custom Bash script to automate the login attempts using a list of the 10,000 most common passwords.
2.  **Tooling:**
    - Language: Bash
    - Tools: `curl` (for requests), `grep` (for parsing results).
    - Wordlist: `10k-most-common.txt`.
3.  **The Script Logic:**
    - Iterate through usernames (`admin`, `root`).
    - Iterate through the password list.
    - Send a POST request to the login form.
    - Check the response size or content for success indicators (like the presence of a flag).
4.  **Execution:** I ran the script. After a few seconds, it cracked the credential `admin:shadow`.
5.  **Result:** The script extracted the flag from the successful login response.

## Proof

**Credentials Found:**

- User: `admin`
- Password: `shadow`

**Flag:** `b3a6e43ddf8b4bbb4125e5e7d23040433827759d4de1c04ea63907479a80a6b2`

**Vulnerability Type:**

- **Weak Authentication** / **Weak Passwords**.
- **Lack of Rate Limiting** (Brute Force).
- **OWASP A07:2021 - Identification and Authentication Failures**.

## How to Fix

The vulnerability exists because the system allows unlimited login attempts and the user had a weak password found in public dictionaries.

### The Fix

1.  **Rate Limiting:** Implement a mechanism to slow down or block IP addresses after too many failed attempts (e.g., Fail2Ban, exponential backoff).
2.  **Account Lockout:** Lock the account after 3-5 failed attempts (requiring email reset or admin intervention).
3.  **Strong Password Policy:** Enforce minimum length, complexity (special chars, numbers), and disallow common dictionary words.
4.  **Multi-Factor Authentication (MFA):** Require a second code (SMS/App) to log in, rendering password guessing useless.
