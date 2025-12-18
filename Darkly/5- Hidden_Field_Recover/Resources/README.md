# Hidden_Field_Recover - Documentation

## How I Found It

I navigated to the **Recover Password** (or "Forgot Password") page. While analyzing the HTML form to understand how the password recovery mechanism works, I inspected the source code using the browser's Developer Tools (Inspector).

I discovered a suspicious HTML tag inside the form:
`<input type="hidden" name="mail" value="webmaster@borntosec.com" />`

This hidden field appeared to define the destination email address for the recovery system. This indicates that the client (my browser) is telling the server where to send the email, rather than the server knowing it internally.

## Exploitation Steps

1.  **Target:** The hidden input field named `mail`.
2.  **Vulnerability:** The website trusts the user to provide the correct "webmaster" email address via a hidden HTML field. Hidden fields are part of the HTML source and can be easily modified by the user before the form is submitted.
3.  **Attack:**
    - I opened the **Inspector** tool.
    - I located the hidden input: `<input type="hidden" name="mail" value="webmaster@borntosec.com">`.
    - I double-clicked the email address and changed it to an arbitrary email (e.g., `hamza@hacker.com`).
4.  **Execute:** I clicked the **Submit** button on the form. The server accepted my modified hidden value and processed the request, revealing the flag.

## Proof

**Flag:** `1d4855f7337c0c14b6f44946872c4eb33853f40b2d54393fbe94f49f1e19bbb0`

**Vulnerability Type:**

- **Hidden Field Manipulation**.
- **Improper Input Validation**.
- **OWASP A04:2021 - Insecure Design** (Trusting client-side data).

## How to Fix

The vulnerability exists because the "receiver" email address is stored in the insecure HTML of the user's browser, instead of being hardcoded or looked up securely on the server.

**Vulnerable Code Logic:**

```html
<!-- The browser sends the email address -->
<form method="POST">
  <input type="hidden" name="mail" value="webmaster@borntosec.com" />
  <input type="submit" />
</form>
```

### The Fix

Never rely on the client to define administrative emails. Define them Server-Side.

```php

// The server defines the email
$to = "webmaster@borntosec.com"; // Hardcoded or fetched from a secure database
mail($to, "Password Reset", ...);
```
