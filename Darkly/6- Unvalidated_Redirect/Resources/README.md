# Unvalidated_Redirect - Documentation

## How I Found It

I inspected the social media icons (Facebook, Twitter, etc.) on the website's footer/sidebar. Instead of linking directly to the social media platforms (e.g., `https://facebook.com`), the links pointed to an internal PHP page with a parameter:
`index.php?page=redirect&site=facebook`

This pattern indicates that the server takes the `site` parameter and uses it to redirect the user's browser. I suspected that this redirection logic did not validate the destination properly.

## Exploitation Steps

1.  **Target:** The `site` parameter in the URL `index.php?page=redirect&site=facebook`.
2.  **Vulnerability:** The application trusts the user input to determine the redirect destination. This is often called an "Open Redirect."
3.  **Attack:**
    - I copied the URL to the address bar.
    - I modified the `site` parameter from `facebook` to an arbitrary string, in this case, `google` (or a similar modification).
    - **Modified URL:** `http://localhost:8080/index.php?page=redirect&site=google`
4.  **Execute:** I pressed Enter. The server attempted to process this unexpected input and, recognizing the tampering (or failing to find the hardcoded mapping), it displayed the flag.

## Proof

**Flag:** `b9e775a0291fed784a2d9680fcfad7edd6b8cdf87648da647aaf4bba288bcab3`

**Vulnerability Type:**

- **Unvalidated Redirects and Forwards**.
- **OWASP A01:2021 - Broken Access Control**.

## How to Fix

The vulnerability exists because the code accepts any input for the redirection target, or fails gracefully by showing a flag when it shouldn't.

**Vulnerable Code Logic:**

```php
$site = $_GET['site'];
header("Location: " . $site); // Redirects to whatever the user typed
```

### The Fix (Use an Allowlist)

Do not use the user input directly in the header. Use the input as a "key" to look up the real URL in a safe array on the server.

```php

$site_key = $_GET['site'];

$allowed_sites = [
    'facebook' => 'https://www.facebook.com',
    'twitter'  => 'https://www.twitter.com',
    'instagram'=> 'https://www.instagram.com'
];

if (array_key_exists($site_key, $allowed_sites)) {
    header("Location: " . $allowed_sites[$site_key]);
} else {
    // Show error, do not redirect
    echo "Invalid destination.";
}
```
