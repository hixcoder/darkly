# XSS_Media - Documentation

## How I Found It

I clicked on the "NSA" image on the home page and noticed the URL changed to `index.php?page=media&src=nsa`.
The `src` parameter implies that the page is loading an external resource or file to display it to the user. I suspected that this input was not validated to ensure it was a safe image file or a valid URL, potentially allowing me to inject malicious content using different URI schemes.

## Exploitation Steps

1.  **Target:** The `src` parameter in the URL.
2.  **Concept:** I used the **Data URI Scheme** (`data:`). This scheme allows you to include data (like HTML or images) in-line in a web page as if they were external resources.
3.  **Payload Construction:**
    - I wanted to execute JavaScript: `<script>alert('XSS')</script>`
    - To bypass basic filters and ensure the browser renders it, I encoded this script into **Base64**:
      `PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=`
    - I constructed the full Data URI indicating that the content is HTML:
      `data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=`
4.  **Injection:** I replaced the value `nsa` with my payload in the URL:
    `http://localhost:8080/index.php?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=`
5.  **Execute:** I pressed Enter. The browser interpreted the Data URI as an HTML file containing my script, executed the alert, and revealed the flag.

## Proof

**Flag:** `928d819fc19405ae09921a2b71227bd9aba106f9d2d37ac412e9e5a750f1506d`

**Vulnerability Type:**

- **Cross-Site Scripting (XSS)**.
- **OWASP A03:2021 - Injection**.

## How to Fix

The vulnerability exists because the application allows any string into the `src` attribute without checking the protocol or file type.

**Vulnerable Code:**

```php
$src = $_GET['src'];
echo "<object data='$src'></object>"; // or <embed> / <iframe>
```

### The Fix

The code should not trust the src parameter blindly. It should implement an Allowlist:

1. **Check the Schema:** Only allow inputs that start with http:// or https://. Explicitly block data: or javascript:.

2. **Check the File Type:** Ensure the link ends with a safe image extension like .jpg or .png

```php
// THE FIX:
// 1. Check if it starts with "http" (Safe)
// 2. Check if it DOES NOT start with "data:" (Dangerous)

if (str_starts_with($user_input, "http")) {
    echo "This is safe to display.";
}
else if (str_starts_with($user_input, "data:")) {
    echo "ERROR: Hacking attempt blocked!";
}
```
