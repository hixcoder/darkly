# File_Upload_MIME_Type - Documentation

## How I Found It

I navigated to the **Upload** page (`index.php?page=upload`). This page allows users to upload image files. I suspected that the file validation might rely on client-side headers (like Content-Type) rather than verifying the actual file content on the server.

## Exploitation Steps

1.  **Target:** The file upload form.
2.  **Vulnerability:** The server trusts the `Content-Type` HTTP header sent by the browser. If the header says "image/jpeg", the server accepts the file, even if the file extension is `.php` and contains executable code.
3.  **Attack:**
    - I created a malicious PHP file named `exploit.php` containing: `<?php echo "Hacked"; ?>`.
    - I used `curl` to upload the file while spoofing the Content-Type.
    - **Command:**
      ```bash
      curl -v -F "uploaded=@exploit.php;type=image/jpeg" -F "Upload=Upload" "http://localhost:8080/index.php?page=upload"
      ```
    - The part `type=image/jpeg` forces curl to lie to the server about the file type.
4.  **Result:** The server accepted the file and displayed the flag.

## Proof

**Flag:** `46910d9ce35b385885a9f7e2b336249d622f29b267a1771fbacf52133beddba8`

**Vulnerability Type:**

- **Unrestricted File Upload**.
- **Improper Input Validation (MIME Type Spoofing)**.
- **OWASP A04:2021 - Insecure Design**.

## How to Fix

The vulnerability exists because the server trusts the HTTP header, which is controlled by the user.

**Vulnerable Code Logic:**

```php
if ($_FILES['uploaded']['type'] == "image/jpeg") {
    // Save file...
}
```

### The Fix

Check the File Extension: Ensure the file ends in .jpg, .png, etc.
