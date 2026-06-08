# WexAAF Usage Examples

This document provides detailed examples of how to use WexAAF for ethical web security testing.

## Table of Contents

1. [Basic Usage](#basic-usage)
2. [SQL Injection Testing](#sql-injection-testing)
3. [XSS Vulnerability Scanning](#xss-vulnerability-scanning)
4. [WAF Detection](#waf-detection)
5. [URL Discovery](#url-discovery)
6. [Full Security Scan](#full-security-scan)

---

## Basic Usage

### Running a Basic Scan

```bash
python wexaaf.py -u https://example.com
```

This will run all available security checks and generate a comprehensive report.

### Output Explanation

The tool will display:
1. Banner and legal disclaimer
2. Target information
3. Progress of each test
4. Results of each vulnerability check
5. Final AI analysis and recommendations
6. Location of saved report

---

## SQL Injection Testing

### Full SQL Injection Test

```bash
python wexaaf.py -u https://example.com/page.php?id=1 --sql-only
```

### What This Tests

- **Boolean-based SQL Injection**: Tests true/false conditions
- **Error-based SQL Injection**: Triggers database errors
- **Union-based SQL Injection**: Attempts to combine queries
- **Time-based SQL Injection**: Measures response delays
- **Column Detection**: Finds number of columns in query
- **Database Enumeration**: Attempts to extract database info

### Example Scenario

Target: `https://example.com/product.php?id=1`

**Tool Output:**
```
[+] Running SQL Injection Tests...
[i] Analyzing URL parameters...
[i] Found parameters: id
[i] Testing parameter: id
[!] SQL Injection detected (Boolean-based) in parameter: id
[✓] Columns detected: 5
[✓] Database found: shop_db
[✓] Database version: 8.0.32
```

**Note**: This is for educational purposes only. Always test on systems you own or have permission to test.

---

## XSS Vulnerability Scanning

### Full XSS Scan

```bash
python wexaaf.py -u https://example.com/search?query=test --xss-only
```

### What This Tests

- **Reflected XSS**: Scripts reflected in HTTP response
- **Stored XSS**: Scripts stored and later displayed
- **DOM-based XSS**: Client-side script execution
- **Header-based XSS**: Scripts in HTTP headers
- **Form-based XSS**: Scripts submitted through forms

### Example Scenario

Target: `https://example.com/search?query=test`

**Tool Output:**
```
[+] Running XSS Vulnerability Scan...
[i] Testing URL parameters: query
[!] XSS Vulnerabilities Found:
    - Type: Reflected
      Payload: <script>alert(1)</script>
      Location: https://example.com/search?query=<script>alert(1)</script>
[✓] XSS scan complete. Found 3 potential vulnerabilities
```

### XSS Payload Types Tested

- Script tags (`<script>alert(1)</script>`)
- Image onerror (`<img src=x onerror=alert(1)>`)
- SVG onload (`<svg onload=alert(1)>`)
- Event handlers (`onmouseover=alert('XSS')`)
- Encoded payloads URL encoding)

---

## WAF Detection

### Detect WAF

```bash
python wexaaf.py -u https://example.com --no-sql --no-xss
```

### What This Checks

- Header signatures (Cloudflare, Fortinet, Akamai, etc.)
- Cookie patterns
- Response to malicious payloads
- Known WAF fingerprints

### Bypass Testing

When a WAF is detected, WexAAF automatically tests:
- URL encoding
- Double encoding
- Comment injection
- Case variation
- Whitespace variation
- Null byte injection
- Line break injection
- Random noise injection

### Example Output

```
[+] Running WAF Detection...
[i] Analyzing WAF signatures...
[!] WAF signature matched: Cloudflare (cf-ray)
[!] WAF Detected: Cloudflare
[i] Testing WAF Bypass Techniques...
[✓] URL Encoding: Potentially bypassable
[✗] Comment Injection: Blocked
[✓] Double Encoding: Potentially bypassable
```

---

## URL Discovery

### Discover Hidden Paths

```bash
python wexaaf.py -u https://example.com
```

The URL bruteforce module runs automatically in full scan mode.

### What This Discovers

- Common administrative paths (`/admin`, `/login`)
- Backup files (`backup.sql`, `.env.bak`)
- Configuration files (`config.php`)
- API endpoints (`/api/v1`)
- Hidden directories and files
- Sensitive paths like `/wp-admin`, `/cpanel`

### Example Output

```
[+] Running URL Bruteforce...
[i] Performing directory bruteforce...
[+] Found: https://example.com/admin (200)
[+] Found: https://example.com/api (200)
[!] Backup/config found: https://example.com/.env.bak (200)
[i] Checking robots.txt...
[+] Disallowed path: /admin
[+] Disallowed path: /config
[✓] Found 15 unique URLs after testing 85 URLs
```

---

## Full Security Scan

### Complete Security Assessment

```bash
python wexaaf.py -u https://example.com
```

### Scan Workflow

1. **Basic Security Analysis**
   - Server information
   - Technology detection
   - Security headers check

2. **WAF Detection**
   - WAF identification
   - Bypass technique testing

3. **SQL Injection Testing**
   - Parameter vulnerability testing
   - Column detection
   - Database enumeration

4. **XSS Vulnerability Scan**
   - Multiple XSS vector testing
   - Context analysis

5. **URL Discovery**
   - Directory bruteforce
   - Backup file detection
   - API endpoint discovery

6. **AI-Powered Analysis**
   - Risk scoring
   - Priority recommendations
   - Remediation suggestions

### Example Full Output

```
╔═══════════════════════════════════════════════════════════════╗
║                    WexAAF v1.0                                ║
║            AI Powered Web Penetration Testing Tool            ║
║                   Ethical Security Only                       ║
╚═══════════════════════════════════════════════════════════════╝

⚠️  IMPORTANT LEGAL DISCLAIMER ⚠️
[WexAAF disclaimer text...]

[!] This tool is for EDUCATIONAL PURPOSES ONLY!
    You must own or have permission to test: https://example.com
[?] Do you want to proceed? (yes/no): yes

[*] Target initialized: https://example.com
[*] Modules loaded successfully

═══════════════════════════════════════════════════════════════
          🛡️  Starting WexAAF Security Scan  🛡️                   
═══════════════════════════════════════════════════════════════

[+] Running Basic Security Analysis...
──────────────────────────────────────────────────────────────
[✓] Server: nginx/1.18.0
[✓] Status Code: 200
[✓] Response Time: 0.452s
[✓] Content-Length: 15234 bytes

[i] Security Headers Analysis:
[✓] X-Frame-Options: True
[✗] X-Content-Type-Options: Missing
[✓] X-XSS-Protection: True
[✗] Strict-Transport-Security: Missing

[+] Running WAF Detection...
──────────────────────────────────────────────────────────────
[i] No WAF detected

[+] Running SQL Injection Tests...
──────────────────────────────────────────────────────────────
[i] Found parameters: id, category
[i] Testing parameter: id
[✓] Parameter id appears safe
[i] Testing parameter: category
[!] SQL Injection detected (Union-based) in parameter: category
[i] Detecting number of columns...
[✓] Columns detected: 4
[i] Attempting database enumeration...
[✓] Database found: ecommerce_db

[+] Running XSS Vulnerability Scan...
──────────────────────────────────────────────────────────────
[!] XSS Vulnerabilities Found:
    - Type: Reflected
      Payload: <script>alert(1)</script>
      Location: https://example.com/search?q=<script>alert(1)</script>
[✓] XSS scan complete. Found 2 potential vulnerabilities

[+] Running URL Bruteforce...
──────────────────────────────────────────────────────────────
[+] Found: https://example.com/admin (200)
[+] Found: https://example.com/backup.sql (200)
[✓] Found 12 unique URLs after testing 75 URLs

[+] Running AI-Powered Analysis...
──────────────────────────────────────────────────────────────
[✓] AI Analysis Complete
    Overall Risk Level: High
    Vulnerability Count: 3
    Recommendations:
        1. Implement parameterized queries to fix SQL injection
        2. Use output encoding for XSS prevention
        3. Remove backup files from web-accessible directories
        4. Implement Content Security Policy
        5. Add missing security headers

[✓] Results saved to: output/scan_20240101_120000.txt

═══════════════════════════════════════════════════════════════
          🎉 Scan Completed Successfully! 🎉                         
═══════════════════════════════════════════════════════════════

======================================================================
REMEMBER: This tool is for EDUCATIONAL PURPOSES ONLY!
TRY IT ON YOUR OWN SERVER - WE ARE NOT RESPONSIBLE FOR MISUSE
======================================================================
```

---

## Advanced Usage

### Custom Scan Configuration

You can create a custom scan by selectively enabling/disabling modules:

```bash
# Only test SQL injection and WAF
python wexaaf.py -u https://example.com --sql --waf --no-xss --no-brute

# Skip WAF detection and result saving
python wexaaf.py -u https://example.com --no-waf --no-output

# Test everything except full AI analysis
python wexaaf.py -u https://example.com --no-ai
```

### Testing Multiple Targets

Create a script to test multiple targets:

```bash
#!/bin/bash
targets=(
  "https://example1.com"
  "https://example2.com"
  "https://example3.com"
)

for target in "${targets[@]}"; do
  echo "Scanning $target..."
  python wexaaf.py -u "$target"
done
```

### Integrating with CI/CD

```bash
# In your CI/CD pipeline
python wexaaf.py -u https://your-staging-site.com
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo "Security issues detected!"
  exit 1
fi
```

---

## Interpreting Results

### Risk Levels

- **Critical**: Immediate action required
- **High**: Fix within 1-2 days
- **Medium**: Plan to fix within 1 week
- **Low**: Fix when convenient

### What to Do After a Scan

1. **Review the full report** in the `output/` directory
2. **Prioritize Critical and High** severity findings
3. **Verify findings** manually before fixing
4. **Implement fixes** following recommendations
5. **Re-scan** after fixes to verify resolved issues
6. **Document** all findings and fixes

### Example Remediation Steps

**SQL Injection Finding:**
```
Found: SQL injection in parameter 'id'
Recommendation: Use parameterized queries

Before (Vulnerable):
query = "SELECT * FROM users WHERE id = " + user_input

After (Fixed):
cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
```

**XSS Finding:**
```
Found: Reflected XSS in search parameter
Recommendation: Use output encoding

Before (Vulnerable):
return f"Search results for {user_input}"

After (Fixed):
from html import escape
return f"Search results for {escape(user_input)}"
```

---

## Testing Your Own Server

For learning purposes, you can set up a vulnerable test server:

### Using DVWA (Damn Vulnerable Web Application)

1. Download DVWA from GitHub
2. Set up on localhost using XAMPP/WAMP/Docker
3. Access at `http://localhost/dvwa`
4. Test with WexAAF:

```bash
python wexaaf.py -u http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit
```

### Using OWASP Juice Shop

1. Run OWASP Juice Shop in Docker
2. Access at `http://localhost:3000`
3. Test various endpoints

---

## Safety Guidelines

✅ **DO:**
- Test on systems you own or have permission to test
- Use isolated testing environments
- Document your findings
- Report vulnerabilities responsibly
- Learn and improve security

❌ **DON'T:**
- Test systems without permission
- Use for malicious purposes
- Share exploit details publicly
- Modify data on production systems
- Violate any laws or regulations

---

## Troubleshooting

### Connection Issues

```bash
# Increase timeout for slow servers
# Edit config/settings.json and set:
{
  "settings": {
    "timeout": 30
  }
}
```

### SSL Certificate Errors

WexAAF disables SSL verification by default for testing. If you encounter issues:

```bash
# The tool handles this automatically
# No manual intervention needed
```

### Module Import Errors

```bash
# Reinstall dependencies
pip install -r requirements.txt --upgrade
```

---

## Performance Tips

1. **Use selective scans** for faster results
2. **Limit scope** to specific modules
3. **Adjust concurrency** in settings.json
4. **Test during off-peak hours** for production systems

---

## Getting Help

- Check the README.md for full documentation
- Review examples in this file
- Examine the output directory for detailed reports
- Run `python wexaaf.py --help` for command options

---

**Remember: WexAAF is for educational and ethical purposes only!**  
**Always test on systems you own or have explicit permission to test.**