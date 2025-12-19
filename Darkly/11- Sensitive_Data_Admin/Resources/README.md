# Sensitive_Data_Admin - Documentation

## How I Found It

I started by inspecting the `robots.txt` file (`http://localhost:8080/robots.txt`), which is used to instruct search engine crawlers. I noticed a Disallow rule for a path named `/whatever`.

`Disallow: /whatever`

I navigated to this URL manually (`http://localhost:8080/whatever/`) and found a directory listing containing a file (`htpasswd`).

## Exploitation Steps

1.  **Reconnaissance:** I checked `robots.txt` and found the hidden path `/whatever`.
2.  **Data Extraction:** I opened the file found in that directory. It contained credentials in the format `user:hash`:
    `root:437394baff5aa33daa618be47b75cb49`
3.  **Decryption:**
    - I identified the hash `437394baff5aa33daa618be47b75cb49` as **MD5** (32 hexadecimal characters).
    - I used an online rainbow table/cracker to decrypt the hash.
    - **Result:** The password was `qwerty123@`
4.  **Access:** I located an administrative login page at `http://localhost:8080/admin/`
5.  **Execution:** I logged in using the credentials:
    - **User:** `root`
    - **Password:** `qwerty123@`
6.  **Result:** The login was successful, and the dashboard revealed the flag.

## Proof

**Flag:** `d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff`

**Vulnerability Type:**

- **Sensitive Data Exposure** (OWASP A02:2021 - Cryptographic Failures).
- **Security Misconfiguration** (Leaving credential files accessible).
- **Weak Authentication** (Using MD5 for passwords).

## How to Fix

The vulnerability exists because a critical credential file was left in a public directory and advertised via `robots.txt`.

### The Fix

1.  **Remove the File:** Delete `.htpasswd` or any credential dumps from the public web root (`/var/www/html`) immediately.
2.  **Access Control:** Store configuration and password files in a directory outside the web root that cannot be accessed via a browser.
3.  **Clean Robots.txt:** Do not list sensitive paths in `robots.txt`; it serves as a roadmap for attackers.
4.  **Update Hashing:** Stop using MD5 for passwords. It is insecure and easily cracked. Use **bcrypt** or **Argon2**.
