# Survey_Tampering - Documentation

## How I Found It

I navigated to the **Survey** page (`?page=survey`), which presented a form to vote for a candidate. I suspected that the "weight" or "value" of the vote might be defined in the HTML form itself, which is controlled by the client.

## Exploitation Steps

1.  **Target:** The `<select>` menu in the voting form.
2.  **Vulnerability:** The application trusts the `value` attribute of the selected option sent by the browser. It likely adds this numeric value directly to the candidate's total score without verifying if it matches a valid, expected vote count (e.g., 1).
3.  **Attack:**
    - I opened the **Inspector** tool on the dropdown menu.
    - I found the options looking like: `<option value="1">Candidate Name</option>`.
    - I double-clicked the `value="1"` and changed it to a much higher number (e.g., `9999` or `1111`).
    - **Modified HTML:** `<option value="9999">Candidate Name</option>`
4.  **Execute:** I selected that candidate and clicked the **Submit** button. The server added the massive number to the score, bypassed the win condition threshold, and revealed the flag.

## Proof

**Flag:** `03a944b434d5baff05f46c4bede5792551a2595574bcafc9a6e25f67c382ccaa`

**Vulnerability Type:**

- **Parameter Tampering**.
- **Improper Input Validation**.
- **OWASP A04:2021 - Insecure Design** (Business Logic Error).

## How to Fix

The vulnerability exists because the server uses the value sent by the user as the _amount_ to add to the score.

**Vulnerable Code Logic:**

```php
$vote_value = $_POST['vote']; // User sends "9999"
$current_score += $vote_value; // Score increases by 9999
```

### The Fix:

Never trust the client to define the "weight" of an action. Define the logic on the server.

```php

// Check if the user sent a valid candidate ID
$valid_candidates = [1, 2, 3];
if (in_array($_POST['candidate_id'], $valid_candidates)) {
    // IGNORE the value sent by the user for the score.
    // Hardcode the increment to 1.
    $scores[$_POST['candidate_id']] += 1;
}

```
