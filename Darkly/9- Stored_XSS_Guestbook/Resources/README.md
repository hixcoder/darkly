# Stored_XSS_Guestbook - Documentation

## How I Found It

I navigated to the **Guestbook** (or Feedback) page (`index.php?page=guestbook`). This page allows users to post comments that are saved to the database and displayed to other visitors.

I suspected that the application was not properly sanitizing user input before saving it (Persistent/Stored XSS), specifically in fields like "Name" or "Message".

## Exploitation Steps

1.  **Target:** The input fields on the Guestbook form (specifically the **Name** or **Message** field).
2.  **Vulnerability:** The application takes the user's input and saves it directly to the database. When the page loads, it outputs that input as raw HTML without encoding it.
3.  **Attack:**
    - I entered the following payload into the form:
      `<script>alert('XSS')</script>`
      _(Alternative payload used: `<img src=x onerror=alert('XSS')>`)_
    - I submitted the form.
4.  **Execute:**
    - The page reloaded. Because the malicious script was saved in the database, the browser executed it immediately, displaying an alert box.
    - Although the alert proved the hack, the flag was not in the alert. I inspected the HTML source code near my posted comment.

## Proof

**Flag:** `0fbb54bbf7d099713ca4be297e1bc7da0173d8b3c21c1811b916a3a86652724e`

**Vulnerability Type:**

- **Stored Cross-Site Scripting (Stored XSS)**.
- **OWASP A03:2021 - Injection**.

## How to Fix

The vulnerability exists because the application outputs user-supplied data to the browser without Neutralizing malicious characters.

**Vulnerable Code Logic:**

```php
$name = $_POST['name'];
$message = $_POST['message'];
// Save to DB...
// Later, display it:
echo "<div>Name: " . $name . "</div>"; // Browser executes <script> if it's in $name
```

### The Fix (Output Encoding)

Convert special characters into their HTML entities before displaying them. This turns
`<script> into &lt;script&gt;,` which the browser treats as text, not code.

```php

echo "<div>Name: " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "</div>";
```
