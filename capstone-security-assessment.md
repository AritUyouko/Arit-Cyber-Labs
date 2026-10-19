# Capstone Project — Comprehensive Security Assessment Report

**Author:** Arit Uyouko
**Projects:** 1 — Web Application Access Control Exploitation (IDOR) · 2 — Legacy Wi-Fi Handshake Analysis · 3 — SQL Injection at Medium Security Level (DVWA)

> **Note:** All exploitation in this report was performed against intentionally vulnerable, authorized training targets: PortSwigger Web Security Academy labs, a provided AltSchool training WPA capture, and a local DVWA instance. Credentials, hashes, and keys shown below are lab-issued or deliberately exposed training artifacts, not production secrets.

---

## Project 1: Web Application Access Control Exploitation (IDOR)

### Part 1 — Baseline Authentication & Traffic Routing

**Environment:**
- Target: PortSwigger Web Security Academy — "User ID controlled by request parameter with password disclosure"
- Testing environment: VirtualBox VM running Kali Linux
- Proxy: Burp Suite Community Edition v2025.7.4
- Baseline credentials: lab-issued low-privilege account

**Steps:**
1. Launched Burp Suite and the integrated Chromium browser, navigated to the lab URL.
2. Authenticated with the low-privilege lab credentials.
3. Verified the application loaded the My Account dashboard for that user.

### Part 2 — Parameter Manipulation & Interception Analysis

With Burp intercept enabled, the My Account request was captured and examined. The object identifier was found directly in the query string: `GET /my-account?id=<username> HTTP/1.1` — a direct, predictable identifier with no session-based server-side validation.

### Part 3 — Privileged Account Takeover & Information Disclosure

An **Insecure Direct Object Reference (IDOR)** vulnerability was exploited by changing the `id` parameter to reference the administrator account. Due to missing server-side authorization checks, the application disclosed the administrator's profile — including a plaintext password exposed in the HTML source (extracted via Inspect Element on the masked password field).

### Part 4 — Administrative Authentication & Lab Completion

Using the recovered administrator credentials, a privileged session was established, the Admin Panel became accessible, and the target low-privilege account was deleted to complete the lab objective.

### Part 5 — Impact Assessment

This vulnerability let a low-privileged authenticated user extract credentials for *any* account — including the administrator — just by modifying a URL parameter. An attacker with this access could take over any account, escalate to full admin control, exfiltrate personal data, or perform destructive actions. This constitutes a critical data privacy violation that would breach standards such as GDPR and PCI-DSS.

### Part 6 — Remediation & Defensive Mitigation

| Issue | Recommended fix | Security benefit |
|-------|------------------|-------------------|
| Server trusts client-supplied `?id=` without validation | Enforce server-side session checks against the requested resource | Prevents access to other users' data regardless of URL manipulation |
| Direct, guessable identifiers in URLs | Replace with opaque, session-scoped UUIDs or indirect reference maps | Eliminates enumeration of valid account identifiers |
| Admin password returned in plaintext HTML | Never send passwords client-side; omit credential fields from profile responses | Prevents credential harvesting via browser inspection |
| No RBAC on admin resources | Verify user role server-side before rendering elevated-privilege UI/data | Blocks vertical privilege escalation |

---

## Project 2: Legacy Wi-Fi Deployment Handshake Analysis

### Part 1 — Environment & File Verification

- Target file: a WPA capture obtained from the authorized AltSchool Africa training repository
- Verified as a valid packet capture via `file`
- Confirmed a valid WPA/WPA2 4-way handshake was present via `aircrack-ng`

### Part 2 — Password Recovery (Proof of Concept)

An offline dictionary attack was run against the captured handshake using the `rockyou.txt` wordlist.

**Steps:**
1. Cloned the authorized training repository to obtain the capture file.
2. Verified EAPOL packets were present: `aircrack-ng <capture>.cap`
3. Decompressed the wordlist: `sudo gunzip /usr/share/wordlists/rockyou.txt.gz`
4. Ran the dictionary attack: `aircrack-ng -w /usr/share/wordlists/rockyou.txt <capture>.cap`
5. The attack matched the hash and recovered the plaintext passphrase (a weak, common dictionary word).

### Part 3 — Technical Analysis

WPA/WPA2-PSK relies on a 4-way handshake exchanging values (ANonce, SNonce, MAC addresses) in plaintext over the air to derive session keys. An attacker who captures this handshake can perform a fully offline attack, iterating a wordlist and checking each candidate against the handshake's Message Integrity Code (MIC). Attack speed depends entirely on password complexity — here, a weak dictionary password was cracked within seconds.

### Part 4 — Mitigation

- **Stronger passwords:** 16+ character passphrases combining upper/lowercase, numbers, and symbols make offline attacks computationally infeasible.
- **WPA3 upgrade:** Replaces the vulnerable PSK exchange with SAE (Dragonfly handshake), a zero-knowledge proof mechanism — even a captured handshake can't be offline-attacked. Also adds forward secrecy.

### Part 5 — Technical Challenges & Troubleshooting

| Issue | Root cause | Resolution |
|-------|-----------|------------|
| `aircrack-ng` reported "unsupported file format" | Downloaded capture was corrupted (contained HTML placeholder, not binary data) | Verified file size/type with `ls -lh` and `file`; re-flagged and documented |
| Wordlist couldn't be read | Shipped compressed by default in Kali | Decompressed with `gunzip` |

---

## Project 3: SQL Injection at Medium Security Level (DVWA)

### Part 1 — Environment Verification

- DVWA running locally on a VirtualBox Kali VM
- Security level confirmed set to Medium via the DVWA settings page
- Target module: SQL Injection
- Proxy: Burp Suite Community Edition v2025.7.4 on `127.0.0.1:8080`

### Part 2 — Understanding the Defence

At **Low** level, DVWA applies no sanitization. At **Medium** level, two measures are added:

- `mysql_real_escape_string()` escapes SQL-significant characters (quotes, backslashes, NULL bytes), neutralizing simple string-based payloads.
- The free-text input is replaced with a dropdown limited to User IDs 1–5 — a **client-side-only** restriction.

**Why simple injection fails:** classic payloads like `' OR '1'='1` fail because the escaping prevents breaking out of the SQL string context.

**The developer mistakes that remain exploitable:**
- No server-side type enforcement — the `id` parameter is never cast to an integer; the backend assumes the dropdown always supplies clean numeric input.
- Client-side controls are bypassable — Burp can intercept the POST request after the browser sends it and freely modify `id`.

This means any payload avoiding quote characters — like a UNION-based integer injection — bypasses the filter entirely.

### Part 3 — Exploitation: Discovery & Bypass

With Burp intercept enabled, the captured POST request showed:

```
POST /dvwa/vulnerabilities/sqli/ HTTP/1.1
Host: 127.0.0.1
Cookie: security=medium
id=1&Submit=Submit
```

The `id` parameter is a plain integer sent via POST body with no quotes — confirming quote-based payloads would be filtered but integer-context UNION injection would not.

A baseline quote-based payload (`' OR '1'='1`) was confirmed blocked, demonstrating the escaping was active.

**Successful bypass:** a UNION-based payload with no special characters was injected directly into the intercepted POST request:

```
id=1 UNION SELECT user, password FROM users&Submit=Submit
```

This works because `mysql_real_escape_string()` has nothing to escape in this payload, the UNION SELECT appends a second query pulling `user`/`password` from the `users` table, and the client-side dropdown restriction is irrelevant since the payload is injected at the proxy level after the browser already sent the request.

### Part 4 — Evidence of Exploitation

The combined query executed was effectively:

```sql
SELECT first_name, last_name FROM users WHERE user_id = 1
UNION SELECT user, password FROM users
```

The application rendered all database usernames and their MD5 password hashes in the browser output. MD5 is a cryptographically broken hashing algorithm — these lab hashes are trivially reversible via rainbow tables.

### Part 5 — Defence & Remediation

**Why Medium-level protection is insufficient:** it relies on blacklisting specific dangerous characters rather than preventing the structural mixing of data and SQL code. Any payload avoiding the blacklisted characters bypasses it entirely. The root cause is direct concatenation of user input into SQL query strings.

**Vulnerable pattern:**

```php
$id = mysqli_real_escape_string($conn, $_POST['id']);
$query = "SELECT first_name, last_name FROM users WHERE user_id = $id";
```

Even after escaping, `$id` is still concatenated directly — if the value needs no escaping, the function has no effect.

**Correct fix — prepared statements:**

```php
$stmt = $conn->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->bind_param("i", $_POST['id']);  // "i" enforces integer type
$stmt->execute();
$result = $stmt->get_result();
```

This separates SQL structure from user data at the driver level, making injection structurally impossible — a malicious string just fails to match any `user_id`.

**Remediation table:**

| Issue | Fix | Security benefit |
|-------|-----|-------------------|
| UNION-based injection via untyped `id` | Prepared statements (MySQLi/PDO) | Input treated as data, never executable SQL |
| Reliance on `mysql_real_escape_string()` | Retire escape-based sanitization; use parameterized queries exclusively | Closes all injection vectors regardless of payload |
| No server-side type enforcement | Explicitly cast/validate `id` as integer server-side | Rejects non-integer input before the query layer |
| Client-side dropdown used as a security control | Never rely on client-side restrictions; validate server-side | Prevents proxy-based bypass |
| Unsalted MD5 password hashes | Replace with bcrypt or Argon2 + unique per-user salts | Prevents rainbow table / offline cracking |

---

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP IDOR / BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [DVWA GitHub](https://github.com/digininja/DVWA)
- [PortSwigger Web Security Academy — Access Control](https://portswigger.net/web-security/access-control)
- [PortSwigger Web Security Academy — SQL Injection](https://portswigger.net/web-security/sql-injection)
- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
- [Wi-Fi Alliance — WPA3 SAE](https://www.wi-fi.org/discover-wi-fi/security)
- [PHP MySQLi Prepared Statements](https://www.php.net/manual/en/mysqli.prepare.php)
