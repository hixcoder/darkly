# User_Agent_Referer - Documentation

## How I Found It

I discovered a specific page (`index.php?page=b7e44...`) that contained a music video about Albatrosses. By inspecting the source code of this page (`curl` or View Source), I found **two** hidden HTML comments:

1.  `<!-- You must come from : "https://www.nsa.gov/". -->`
2.  `<!-- Let's use this browser : "ft_bornToSec". It will help you a lot. -->`

This indicated that the server requires **two** specific HTTP headers to be present simultaneously to grant access to the flag.

## Exploitation Steps

1.  **Target:** The hidden Albatross page.
2.  **Vulnerabilities:**
    - **Improper Access Control**: Relying on the `User-Agent` string (client identity).
    - **Improper Access Control**: Relying on the `Referer` header (previous page).
3.  **Attack:**
    - I constructed a `curl` command to spoof both headers at the same time.
    - **-A**: Sets the User-Agent to `ft_bornToSec`.
    - **-e**: Sets the Referer to `https://www.nsa.gov/`.
    - **Command:**
      ```bash
      curl -A "ft_bornToSec" -e "https://www.nsa.gov/" "http://localhost:8080/index.php?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f"
      ```
4.  **Result:** The server validated both headers and returned the flag in the HTML response.

## Proof

**Flag:** `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

**Vulnerability Type:**

- **Security Misconfiguration** (OWASP A05:2021).
- **Broken Access Control**: Headers are controlled by the user and should not be used for authentication.

## How to Fix

The application checks headers that the client can easily falsify.

**Vulnerable Code Logic:**

```php
if ($_SERVER['HTTP_USER_AGENT'] == "ft_bornToSec" && $_SERVER['HTTP_REFERER'] == "https://www.nsa.gov/") {
    echo $flag;
}
```

### The Fix

Never use HTTP headers (like Referer or User-Agent) for authentication or authorization. Use Session Cookies, Tokens, or IP Allow-listing (if internal) instead.
