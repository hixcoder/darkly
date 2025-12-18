# Cookie_Tampering - Documentation

## How I Found It

While inspecting the website using the browser's Developer Tools, I checked the **Storage / Cookies** tab to see how the site manages user sessions. I noticed a suspicious cookie named `I_am_admin` with a 32-character alphanumeric value: `68934a3e9455fa72420237eb05902327`.

Recognizing the format as a standard hash, I identified it as an **MD5 hash**. By using an online decrypter (or command line tool), I discovered that this hash corresponded to the string: **"false"**.

This indicated that the website relies on a simple, client-side cookie to determine administrator privileges.

## Exploitation Steps

1.  **Generate the Payload:** Since the server expects an MD5 hash, and the current value is the hash of "false", I deduced that I needed the MD5 hash of **"true"** to escalate my privileges.

    - Command: `echo -n "true" | md5`
    - Result: `b326b5062b2f0e69046810717534cb09`

2.  **Inject the Payload:** I returned to the Developer Tools (Storage tab), double-clicked the value of the `I_am_admin` cookie, and replaced the old hash with the new one (`b326b5062b2f0e69046810717534cb09`).

3.  **Execute:** I refreshed the page. The server read the modified cookie, interpreted it as "true", and granted me admin access, revealing the flag.

## Proof

**Flag:** `df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3`

**Vulnerability Type:** Broken Authentication / Insecure Cookie Handling (OWASP A07:2021 - Identification and Authentication Failures).

## How to Fix

The vulnerability exists because the application trusts sensitive state information (admin status) stored on the client side without verification.

**Remediation:**

1.  **Server-Side Sessions:** Do not store privilege levels (like `is_admin`) in client cookies. Instead, store a random Session ID in the cookie, and keep the user's privilege level in a secure database on the server.
2.  **Signed Cookies:** If data must be stored in cookies, sign them cryptographically so the server can detect if the user tampered with them.
3.  **Avoid Weak Hashing:** MD5 is cryptographically broken and should not be used for security purposes.

## Additional Notes

This is a classic example of "Security by Obscurity." The developer assumed that hashing the word "false" would hide the logic from the user, but MD5 is easily reversible (or guessable) using rainbow tables.
