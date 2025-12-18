# Directory_Traversal - Documentation

## How I Found It

I examined the URL structure of the website, specifically the `page` parameter (e.g., `index.php?page=member`). This pattern strongly suggests that the website is using a PHP function like `include()` or `require()` to dynamically load files based on user input.

I suspected that the input was not being validated, allowing me to ask the server for files **outside** of the intended web directory.

## Exploitation Steps

1.  **Target:** The `page` parameter in the URL.
2.  **Payload:** I crafted a path using the "Dot Dot Slash" technique (`../`) to move up the directory tree to the server's root filesystem. My goal was to read the `/etc/passwd` file, a standard file on Linux systems that lists all users.

    **URL used:**
    `http://localhost:8080/index.php?page=../../../../../../../etc/passwd`

3.  **Execute:** I pressed Enter. Instead of loading a web page, the server followed the path, retrieved the contents of the `/etc/passwd` file, and displayed the flag.

## Proof

**Flag:** `b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0`

**Vulnerability Type:**

- **Path Traversal** (also known as Directory Traversal).
- **Local File Inclusion (LFI)**.
- **OWASP A01:2021 - Broken Access Control**.

## How to Fix

The vulnerability exists because the application accepts the user's input string and uses it directly as a filename.

**Vulnerable Code:**

```php
$page = $_GET['page']; // User sends "../../etc/passwd"
include($page);        // Server executes: include("../../etc/passwd")
```

### The Fix

Strictly define exactly which pages are allowed to be loaded.
code PHP

```php

$allowed_pages = ['home', 'member', 'signin'];
if (in_array($\_GET['page'], $allowed_pages)) {
    include($\_GET['page'] . '.php');
} else {
// Show error page
}

```
